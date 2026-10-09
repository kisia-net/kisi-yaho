import copy
import hmac
import json
import re
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from pathlib import Path

import pytest
from flask import Flask, abort, g, jsonify, redirect, request, session, url_for

from hawki_vr import reader
from hawki_vr.catalog import Invalid, OPS, plan, normalize, definition_fingerprint, FLOW
from hawki_vr.service import preview
from hawki_vr.store import Store
from hawki_vr.transport import RemoteError
from hawki_vr.web import install
from hawki_vr.worker import Worker

FIX=Path(__file__).parent/"fixtures"
C1="C.0000000000000001"
C2="C.0000000000000002"
SCHEMAS=json.loads((FIX/"artifact_schemas.json").read_text())


class FakeAPI:
    """Recorded contract shapes; no endpoint or database contact."""
    def __init__(self):
        self.defs=copy.deepcopy(SCHEMAS)
        self.calls=[];self.collections=[];self.raise_collect=False
        self.flows={};self.rows={}
    def query(self,vql,env=None,**kw):
        p=(env or {}).get("Payload",{});self.calls.append((vql,p))
        if "whoami()" in vql:return [{"identity":"test-writer"}]
        if "artifact_definitions" in vql:return [a for a in self.defs if a["name"] in p["names"]]
        if "FROM clients(" in vql:
            ids=[p["client_id"]] if "client_id" in p else [C1,C2]
            return [dict(client_id=c,hostname="test-host-"+c[-1],os="linux",last_seen_at=1790911556883730) for c in ids]
        if "collect_client(" in vql:
            self.collections.append(p)
            if self.raise_collect:raise RemoteError("timeout")
            fid="F.TEST"+str(len(self.collections))
            self.flows[fid]=dict(flow_id=fid,client_id=p["client_id"],state="RUNNING",create_time=1790911556883730,request={"artifacts":p["artifacts"]},artifacts_with_results=[])
            return [{"result":{"flow_id":fid,"request":{"client_id":p["client_id"]}}}]
        if "FROM flows(" in vql:
            if "flow_id=P.flow_id" in vql:return [self.flows[p["flow_id"]]] if p["flow_id"] in self.flows else []
            data=list(self.flows.values())
            if p.get("artifact"):data=[f for f in data if p["artifact"] in f["request"]["artifacts"]]
            return sorted(data,key=lambda x:x["create_time"],reverse=True)
        if "source(" in vql:
            return self.rows.get(p["flow_id"],[])[p.get("offset",0):]
        if "SELECT hunt(" in vql:return [{"result":{"hunt_id":"H.TEST1"}}]
        if "hunt_add(" in vql:return [{"result":True}]
        if "cancel_flow(" in vql:return [{"result":True}]
        if "FROM hunts()" in vql or "flow_logs(" in vql or "uploads(" in vql:return []
        raise AssertionError(vql)


@pytest.fixture
def store(tmp_path):return Store(tmp_path/"workspace.sqlite3")

def make_request(api,store,**overrides):
    body=dict(operation="files",params={"path":"/tmp/*"},client_ids=[C1],incident="INC-test",idempotency_key="test-request-key-001",hunt=False)
    body.update(overrides)
    return preview(api,store,"1:analyst",body)


def test_catalog_parameters_match_supplied_server_capture():
    for key,op in OPS.items():
        values={f["name"]:f["default"] for f in op["fields"]}
        for k,v in {"sha256":"a"*64,"rule":"rule check { condition: false }","path":"/tmp/test"}.items():
            if k in values:values[k]=v
        _,spec=plan(key,values)
        assert definition_fingerprint(SCHEMAS,list(spec),spec)


@pytest.mark.parametrize("value",["/**","/proc/*","/sys/**","/tmp/../../etc/*","/{tmp,etc}/**","relative","/tmp/\x00x"])
def test_unbounded_or_ambiguous_paths_rejected(value):
    with pytest.raises(Invalid):normalize("files",{"path":value})


def test_vql_payload_does_not_become_code(store):
    api=FakeAPI()
    path="/tmp/'; SELECT collect_client(client_id='server') --"
    job=make_request(api,store,params={"path":path})
    store.submit(job["id"],"1:analyst")
    Worker(store,api).dispatch(store.claim())
    write=[(q,p) for q,p in api.calls if "collect_client(" in q]
    assert len(write)==1 and path not in write[0][0]
    assert write[0][1]["env"]["SearchFilesGlob"]==path


def test_tampered_or_unrecognized_fields_rejected(store):
    for body in [dict(operation=[]),dict(params={"shell":"id"}),dict(client_ids=[{}]),dict(client_ids=["server"]),dict(params={"path":"/tmp/*","hash":"false"})]:
        with pytest.raises(Invalid):make_request(FakeAPI(),store,**body)


def test_same_request_is_idempotent_and_cannot_change(store):
    api=FakeAPI();a=make_request(api,store);b=make_request(api,store)
    assert a["id"]==b["id"]
    with pytest.raises(Invalid):make_request(api,store,params={"path":"/etc/*"})
    store.submit(a["id"],"1:analyst");store.submit(a["id"],"1:analyst")
    assert len(store.get(a["id"])["units"])==1


def test_atomic_claim_across_concurrent_web_workers(store):
    j=make_request(FakeAPI(),store);store.submit(j["id"],"1:analyst")
    with ThreadPoolExecutor(max_workers=8) as pool:claims=list(pool.map(lambda _:store.claim(),range(8)))
    assert sum(x is not None for x in claims)==1


def test_multi_host_requires_approval_and_hunt_stays_scoped(store):
    api=FakeAPI();j=make_request(api,store,client_ids=[C1,C2])
    assert j["manifest"]["hunt"] and j["manifest"]["approval_required"]
    store.submit(j["id"],"1:analyst");assert store.claim() is None
    store.decide(j["id"],"2:approver",True)
    worker=Worker(store,api)
    worker.dispatch(store.claim());worker.dispatch(store.claim())
    hunts=[(q,p) for q,p in api.calls if "SELECT hunt(" in q]
    assert len(hunts)==1 and "pause=TRUE" in hunts[0][0]
    assert set(x["client_id"] for x in api.collections)=={C1,C2}
    links=[p for q,p in api.calls if "hunt_add(" in q]
    assert len(links)==2 and all(FLOW.fullmatch(p["flow_id"]) for p in links)


def test_definition_changed_since_review_prevents_dispatch(store):
    api=FakeAPI();j=make_request(api,store);store.submit(j["id"],"1:analyst")
    for a in api.defs:
        if a["name"]=="Linux.Search.FileFinder":a["sources"]=[{"query":"SELECT 42 FROM scope()"}]
    Worker(store,api).dispatch(store.claim())
    assert not api.collections and store.get(j["id"])["units"][0]["state"]=="failed"


def test_timeout_never_retries_collection(store):
    api=FakeAPI();j=make_request(api,store);store.submit(j["id"],"1:analyst")
    api.raise_collect=True;worker=Worker(store,api);worker.dispatch(store.claim());store.finish_jobs()
    assert store.get(j["id"])["state"]=="submission_unknown"
    for _ in range(3):worker.tick()
    assert len(api.collections)==1


def test_restart_keeps_ambiguous_submission_unknown(store):
    api=FakeAPI();j=make_request(api,store);store.submit(j["id"],"1:analyst");assert store.claim()
    store.recover();store.finish_jobs()
    assert store.get(j["id"])["state"]=="submission_unknown" and store.claim() is None


def test_failed_status_poll_preserves_running_work(store):
    api=FakeAPI();j=make_request(api,store);store.submit(j["id"],"1:analyst")
    w=Worker(store,api);w.dispatch(store.claim());api.flows={};w.poll()
    assert store.get(j["id"])["units"][0]["state"]=="submitted"


def test_cancel_does_not_claim_endpoint_cancelled(store):
    api=FakeAPI();j=make_request(api,store);store.submit(j["id"],"1:analyst")
    w=Worker(store,api);w.dispatch(store.claim());store.cancel(j["id"],"2:approver");w.poll()
    u=store.get(j["id"])["units"][0]
    assert u["state"]=="cancel_requested" and u["error"]=="cancel_sent"
    api.flows[u["flow_id"]]["state"]="FINISHED";w.poll();store.finish_jobs()
    assert store.get(j["id"])["state"]=="finished"


def test_named_source_and_native_gui_collection():
    api=FakeAPI();api.flows["F.GUI"]=dict(flow_id="F.GUI",state="FINISHED",request={"artifacts":["Generic.Client.Info"]},artifacts_with_results=["Generic.Client.Info/BasicInformation"],create_time=1)
    api.rows["F.GUI"]=[{"Name":"test"}]
    with pytest.raises(Invalid):reader.results(api,C1,"F.GUI","Generic.Client.Info")
    assert len(reader.results(api,C1,"F.GUI","Generic.Client.Info/BasicInformation")["items"])==1


def test_flow_sort_precedes_limit():
    api=FakeAPI();reader.flows(api,C1,size=10)
    q=api.calls[-1][0];assert q.index("ORDER BY create_time DESC")<q.index("LIMIT 11")


def test_directory_components_read_existing_listing():
    api=FakeAPI();api.flows["F.VFS"]=dict(flow_id="F.VFS",create_time=1,state="FINISHED",request={"artifacts":["System.VFS.ListDirectory"],"specs":[{"artifact":"System.VFS.ListDirectory","parameters":{"env":[{"key":"Components","value":'["tmp"]'}]}}]},artifacts_with_results=["System.VFS.ListDirectory/Listing"])
    api.rows["F.VFS"]=[{"Name":"entry","OSPath":"/tmp/entry"}]
    assert reader.directory(api,C1,"/tmp")["items"][0]["Name"]=="entry"
    assert not api.collections


def test_no_baseline_inference_from_partial_scan(store):
    api=FakeAPI()
    for i in (1,2):
        j=make_request(api,store,idempotency_key="compare-request-00"+str(i))
        store.submit(j["id"],"1:analyst");Worker(store,api).dispatch(store.claim())
        f=api.flows["F.TEST"+str(i)];f.update(state="FINISHED",create_time=i,total_collected_rows=1,artifacts_with_results=["Linux.Search.FileFinder"])
        api.rows[f["flow_id"]]=[{"OSPath":"/tmp/"+str(i),"MTime":"2026-10-01T00:00:00Z"}]
    result=reader.compare(api,store,C1,"F.TEST1","F.TEST2")
    assert {r["change"] for r in result["items"]}=={"새로 관측됨","목록에서 사라짐"}
    api.flows["F.TEST2"]["total_collected_rows"]=2
    with pytest.raises(Invalid):reader.compare(api,store,C1,"F.TEST1","F.TEST2")


@pytest.fixture
def flask_app(store):
    app=Flask(__name__);app.secret_key="test-only"
    connection=sqlite3.connect(":memory:");connection.row_factory=sqlite3.Row
    connection.execute("CREATE TABLE users(id INTEGER,username TEXT,role TEXT,is_active INTEGER,created_at TEXT,last_login_at TEXT)")
    for i,role in enumerate(("viewer","analyst","approver","admin"),1):connection.execute("INSERT INTO users VALUES(?,?,?,1,'','')",(i,role,role))
    scope=dict(globals(),app=app,ROLE_LEVELS={"viewer":1,"analyst":2,"approver":3,"admin":4},PUBLIC_ENDPOINTS={"static"},get_db=lambda:connection)
    exec((FIX/"auth_hooks.py").read_text(),scope)
    api=FakeAPI();events=[]
    install(app,scope["role_required"],lambda *x:events.append(x),transport=api,store=store)
    app.config.update(TESTING=True)
    return app,api,store


def logged_client(app,role=2):
    client=app.test_client()
    with client.session_transaction() as s:s["user_id"]=role;s["_csrf_token"]="token"
    return client


def test_authentication_csrf_roles_and_unconfigured_execution(flask_app):
    app,api,store=flask_app
    assert app.test_client().get("/api/vr/clients").status_code==401
    viewer=logged_client(app,1);assert viewer.get("/api/vr/clients").status_code==403
    client=logged_client(app)
    b=dict(operation="processes",params={},client_ids=[C1],idempotency_key="web-request-00001")
    assert client.post("/api/vr/preview",json=b).status_code==400
    headers={"X-CSRF-Token":"token"}
    r=client.post("/api/vr/preview",json=b,headers=headers);assert r.status_code==201
    job=r.json["id"]
    assert client.post(f"/api/vr/jobs/{job}/submit",json={},headers=headers).status_code==503
    store.beat(True)
    assert client.post(f"/api/vr/jobs/{job}/submit",json={},headers=headers).status_code==202
    assert client.post(f"/api/vr/jobs/{job}/decision",json={"approve":True},headers=headers).status_code==403
    assert client.post(f"/api/vr/jobs/{job}/cancel",json={},headers=headers).status_code==403
    assert not api.collections


def test_query_failures_are_not_empty_success(flask_app):
    app,api,_=flask_app
    def failure(*a,**k):raise RemoteError("permission_denied")
    api.query=failure
    r=logged_client(app).get("/api/vr/clients")
    assert r.status_code==503 and r.json["code"]=="permission_denied"


def test_argument_repetition_and_unknown_input_rejected(flask_app):
    app,_,_=flask_app;c=logged_client(app)
    assert c.get("/api/vr/clients?search=x&search=y").status_code==400
    assert c.get("/api/vr/clients?query=arbitrary").status_code==400
    assert c.get("/api/vr/flows?client_id=server").status_code==400
    assert c.get("/api/vr/results?client_id="+C1+"&flow_id=F.X&artifact=x&size=100000").status_code==400
