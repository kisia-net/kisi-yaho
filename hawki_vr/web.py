import json
from functools import wraps

from flask import Blueprint, g, jsonify, request

from . import VERSION, reader
from .catalog import OPS, CLIENT, Invalid, checked
from .service import preview
from .store import Store
from .transport import Transport, RemoteError


def install(app, role_required, append_audit, *, transport=None, store=None):
    t=transport or Transport()
    db=store or Store()
    bp=Blueprint("vr_workspace",__name__,url_prefix="/api/vr")

    def actor():
        return f"{g.user['id']}:{g.user['username']}"

    def protected(role="analyst"):
        def deco(fn):
            @wraps(fn)
            def wrapper(*args,**kw):
                try:
                    if request.content_length and request.content_length>32768:
                        return jsonify(error="요청 크기가 초과되었습니다."),413
                    result=fn(*args,**kw)
                    return result
                except Invalid as exc:
                    return jsonify(error=str(exc)),400
                except RemoteError as exc:
                    messages={"permission_denied":"수집 서버의 조회 권한이 없습니다.","timeout":"조회 시간이 초과되었습니다.","result_too_large":"결과가 너무 큽니다. 조회 범위를 줄이세요.","query_rejected":"수집 서버가 조회를 처리하지 못했습니다."}
                    return jsonify(error=messages.get(exc.code,"수집 서버에 연결할 수 없습니다."),code=exc.code),503
            return role_required(role)(wrapper)
        return deco

    def args(allowed):
        if set(request.args)-set(allowed) or any(len(request.args.getlist(k))!=1 for k in request.args):
            raise Invalid("지원하지 않는 조회 조건입니다.")
        return request.args.to_dict()

    def body():
        data=request.get_json(silent=True)
        if not isinstance(data,dict):
            raise Invalid("올바른 요청 본문을 입력하세요.")
        return data

    @bp.after_request
    def no_cache(response):
        response.headers["Cache-Control"]="no-store"
        return response

    @bp.get("/catalog")
    @protected()
    def catalog():
        names=sorted({a for o in OPS.values() for a in o["artifacts"]})
        definitions=reader.definitions(t,names)
        installed={a.get("name") for a in definitions if a.get("type")=="client" and not a.get("required_permissions")}
        items=[dict(id=k,**v,available=set(v["artifacts"])<=installed) for k,v in OPS.items()]
        return jsonify(version=VERSION,items=items,worker=db.health(),can_approve=g.user["role"] in {"approver","admin"})

    @bp.get("/clients")
    @protected()
    def clients():
        return jsonify(reader.clients(t,**args({"search","offset","size"})))

    @bp.get("/flows")
    @protected()
    def flows():
        values=args({"client_id","offset","size","artifact"})
        if not values.get("client_id"): raise Invalid("클라이언트를 선택하세요.")
        return jsonify(reader.flows(t,**values))

    @bp.get("/client")
    @protected()
    def client():
        values=args({"client_id"})
        if not values.get("client_id"): raise Invalid("클라이언트를 선택하세요.")
        return jsonify(reader.client(t,values["client_id"]))

    @bp.get("/results")
    @protected()
    def results():
        values=args({"client_id","flow_id","artifact","offset","size","kind","order"})
        for k in ("client_id","flow_id"):
            if not values.get(k): raise Invalid("수집을 선택하세요.")
        values.setdefault("artifact","")
        return jsonify(reader.results(t,**values))

    @bp.get("/directory")
    @protected()
    def directory():
        values=args({"client_id","path","offset"})
        if not values.get("client_id") or not values.get("path"): raise Invalid("클라이언트와 경로를 선택하세요.")
        return jsonify(reader.directory(t,**values))

    @bp.get("/hunts")
    @protected()
    def hunts():
        return jsonify(reader.hunts(t,**args({"offset","size"})))

    @bp.get("/compare")
    @protected()
    def compare():
        values=args({"client_id","old_flow","new_flow","offset"})
        if any(not values.get(k) for k in ("client_id","old_flow","new_flow")):
            raise Invalid("비교할 수집 두 개를 선택하세요.")
        return jsonify(reader.compare(t,db,**values))

    @bp.get("/hunt-flows")
    @protected()
    def hunt_flows():
        values=args({"hunt_id","offset","size"})
        if not values.get("hunt_id"): raise Invalid("헌트를 선택하세요.")
        return jsonify(reader.hunt_flows(t,**values))

    @bp.get("/jobs")
    @protected()
    def jobs():
        values=args({"offset","client_id"})
        offset,_=reader.pagination(values.get("offset",0))
        cid=values.get("client_id","")
        if cid: checked(cid,CLIENT)
        return jsonify(db.list(offset,cid))

    @bp.get("/jobs/<job_id>")
    @protected()
    def job(job_id):
        return jsonify(db.get(job_id))

    @bp.post("/preview")
    @protected()
    def prepare():
        result=preview(t,db,actor(),body())
        append_audit("velociraptor_collection_reviewed",dict(job_id=result["id"],operation=result["manifest"]["operation"],client_ids=result["manifest"]["client_ids"]))
        return jsonify(result),201

    @bp.post("/jobs/<job_id>/submit")
    @protected()
    def submit(job_id):
        if body(): raise Invalid("수집 내용은 검토 후 변경할 수 없습니다.")
        if not db.health()["ready"]:
            return jsonify(error="수집 실행 서비스에 연결할 수 없습니다."),503
        db.submit(job_id,actor())
        append_audit("velociraptor_collection_submitted",dict(job_id=job_id))
        return jsonify(db.get(job_id)),202

    @bp.post("/jobs/<job_id>/decision")
    @protected("approver")
    def decide(job_id):
        data=body()
        if set(data)!={"approve"} or type(data["approve"]) is not bool: raise Invalid("승인 여부를 선택하세요.")
        db.decide(job_id,actor(),data["approve"])
        append_audit("velociraptor_collection_decision",dict(job_id=job_id,approve=data["approve"]))
        return jsonify(db.get(job_id))

    @bp.post("/jobs/<job_id>/cancel")
    @protected("approver")
    def cancel(job_id):
        if body(): raise Invalid("지원하지 않는 취소 요청입니다.")
        db.cancel(job_id,actor())
        append_audit("velociraptor_collection_cancel_requested",dict(job_id=job_id))
        return jsonify(db.get(job_id)),202

    app.register_blueprint(bp)
    app.extensions["hawki_vr"]={"store":db,"transport":t}
