from . import reader
from .catalog import OPS, VERSION, CLIENT, Invalid, checked, plan, budget, definition_fingerprint


def preview(transport, store, actor, body):
    if not isinstance(body, dict) or set(body)-{"operation","params","client_ids","incident","idempotency_key","hunt"}:
        raise Invalid("올바른 수집 요청을 입력하세요.")
    operation = body.get("operation")
    params, spec = plan(operation, body.get("params", {}))
    ids = body.get("client_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 10 or any(not isinstance(x,str) for x in ids) or len(set(ids)) != len(ids):
        raise Invalid("서로 다른 클라이언트를 1–10개 선택하세요.")
    targets = []
    for cid in ids:
        checked(cid, CLIENT)
        info = reader.client(transport,cid)
        if str(info.get("os", "")).lower() != "linux":
            raise Invalid("이 수집은 Linux 클라이언트를 지원합니다.")
        targets.append(info)
    hunt = body.get("hunt", False)
    if type(hunt) is not bool:
        raise Invalid("올바른 헌트 범위를 선택하세요.")
    if len(ids) > 1:
        hunt = True
    incident = body.get("incident", "")
    if not isinstance(incident,str) or len(incident)>160 or any(ord(c)<32 for c in incident):
        raise Invalid("올바른 사건 번호를 입력하세요.")
    definitions = reader.definitions(transport, list(spec))
    if len(definitions)>=301:
        raise Invalid("아티팩트 의존성 검토가 필요합니다.")
    manifest = dict(version=VERSION, operation=operation, label=OPS[operation]["label"],
                    params=params, spec=spec, client_ids=sorted(ids), targets=targets,
                    limits=budget(operation), incident=incident, hunt=hunt,
                    approval_required=bool(hunt or OPS[operation].get("approval")),
                    definition_hash=definition_fingerprint(definitions,list(spec),spec))
    key = body.get("idempotency_key")
    inputs={k:v for k,v in body.items() if k!="idempotency_key"}
    return store.get(store.draft(actor,key,inputs,manifest))


def validate_dispatch(transport, manifest):
    operation=manifest["operation"]
    params,spec=plan(operation,manifest["params"])
    if manifest["version"] != VERSION or spec != manifest["spec"] or budget(operation)!=manifest["limits"]:
        raise Invalid("수집 정의가 변경되어 다시 검토해야 합니다.")
    definitions=reader.definitions(transport,list(spec))
    if len(definitions)>=301 or definition_fingerprint(definitions,list(spec),spec)!=manifest["definition_hash"]:
        raise Invalid("아티팩트가 변경되어 다시 검토해야 합니다.")
    return spec
