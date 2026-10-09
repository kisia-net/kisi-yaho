"""Read-only deployment checks. Never schedules a flow or a hunt."""
import json
import os

from . import VERSION, reader
from .catalog import OPS, plan, definition_fingerprint
from .store import Store
from .transport import Transport, run


def main():
    from app import app
    from flask import render_template
    t=Transport()
    identity=run(t,"SELECT whoami() AS identity FROM scope()",max_rows=1)
    if not identity or not identity[0].get("identity"):
        raise SystemExit("Read API identity verification failed")
    listing=reader.clients(t,size=2)
    for c in listing["items"]:
        reader.client(t,c["client_id"])
        data=reader.flows(t,c["client_id"],size=2)
        if data["items"]:
            f=data["items"][0]
            reader.results(t,c["client_id"],f["flow_id"],"",size=1,kind="logs")
            for source in (f.get("artifacts_with_results") or [])[:1]:
                reader.results(t,c["client_id"],f["flow_id"],source,size=1)
    reader.hunts(t,size=1)
    definitions=reader.definitions(t,sorted({a for op in OPS.values() for a in op["artifacts"]}))
    available=[]
    for key,op in OPS.items():
        values={f["name"]:f["default"] for f in op["fields"]}
        values.update({k:v for k,v in {"sha256":"0"*64,"rule":"rule check { condition: false }","path":"/tmp/" if key=="directory" else "/tmp/check"}.items() if k in values})
        _,spec=plan(key,values)
        definition_fingerprint(definitions,list(spec),spec)
        available.append(key)
    with app.test_client() as client:
        for url in ("/api/vr/catalog","/api/vr/clients","/api/vr/jobs","/api/vr/flows?client_id=C.0000000000000000"):
            if client.get(url).status_code!=401:
                raise SystemExit("Anonymous access protection failed")
    with app.test_request_context("/hunts"):
        for page,mode in (("hunts","files"),("response","host")):
            html=render_template(page+".html",active_page=page,page_title=page,velociraptor_url="/velociraptor/app/index.html",asset_version=VERSION,vendor_scripts=[])
            if 'id="vr-workspace"' not in html or f'data-mode="{mode}"' not in html or 'filename=\'app.js\'' in html or 'src="/static/app.js' in html:
                raise SystemExit("Workspace rendering failed")
            if "-agent-form" in html:
                raise SystemExit("Legacy page form is still active")
    print(json.dumps(dict(version=VERSION,uid=os.getuid(),gid=os.getgid(),read_api="ok",available_operations=available,authentication="ok",templates="ok",worker=Store().health()),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
