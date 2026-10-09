"""Existing evidence, independent of where its collection was created."""
import json
from datetime import datetime, timezone

from .catalog import CLIENT, FLOW, HUNT, SOURCE, Invalid, checked, path_value
from .transport import run


def page(rows, offset, size):
    return dict(items=rows[offset:offset + size], has_more=len(rows) > offset + size,
                offset=offset, page_size=size, checked_at=datetime.now(timezone.utc).isoformat())


def pagination(offset, size=50):
    try:
        offset, size = int(offset), int(size)
    except (ValueError, TypeError) as exc:
        raise Invalid("올바른 페이지를 선택하세요.") from exc
    if not 0 <= offset <= 10000 or not 1 <= size <= 100:
        raise Invalid("조회 범위를 초과했습니다.")
    return offset, size


def clients(t, search="", offset=0, size=50):
    offset, size = pagination(offset, size)
    if not isinstance(search, str) or len(search) > 200:
        raise Invalid("검색어가 너무 깁니다.")
    n = offset + size + 1
    rows = run(t, f"SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, os_info.release AS release, labels, last_seen_at FROM clients(search=P.search) ORDER BY client_id LIMIT {n}", dict(search=search), max_rows=n)
    return page(rows, offset, size)


def client(t, client_id):
    checked(client_id, CLIENT)
    rows = run(t, "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, os_info.release AS release, labels, last_seen_at FROM clients(client_id=P.client_id) LIMIT 2", dict(client_id=client_id), max_rows=2)
    if len(rows) != 1 or rows[0].get("client_id") != client_id:
        raise Invalid("클라이언트를 찾을 수 없습니다.")
    return rows[0]


FLOW_COLUMNS = "session_id AS flow_id, client_id, state, status, create_time, start_time, active_time, total_collected_rows, total_uploaded_bytes, request, artifacts_with_results"


def flows(t, client_id, offset=0, size=50, artifact=""):
    checked(client_id, CLIENT)
    offset, size = pagination(offset, size)
    if artifact:
        checked(artifact, SOURCE)
    n = offset + size + 1
    where = "WHERE P.artifact IN request.artifacts" if artifact else ""
    rows = run(t, f"SELECT {FLOW_COLUMNS} FROM flows(client_id=P.client_id, summary=FALSE) {where} ORDER BY create_time DESC LIMIT {n}", dict(client_id=client_id, artifact=artifact), max_rows=n)
    return page(rows, offset, size)


def flow(t, client_id, flow_id):
    checked(client_id, CLIENT); checked(flow_id, FLOW)
    rows = run(t, f"SELECT {FLOW_COLUMNS} FROM flows(client_id=P.client_id, flow_id=P.flow_id, summary=FALSE) LIMIT 2", dict(client_id=client_id, flow_id=flow_id), max_rows=2)
    if len(rows) != 1 or rows[0].get("flow_id") != flow_id:
        raise Invalid("수집을 찾을 수 없습니다.")
    return rows[0]


def definitions(t, names):
    return run(t, "SELECT * FROM artifact_definitions(names=P.names, deps=TRUE) LIMIT 301", dict(names=names), max_rows=301)


def results(t, client_id, flow_id, artifact, offset=0, size=50, kind="rows", order=""):
    checked(artifact, SOURCE) if kind == "rows" else None
    offset, size = pagination(offset, size)
    info = flow(t, client_id, flow_id)
    selector = dict(client_id=client_id, flow_id=flow_id, artifact=artifact, offset=offset)
    # Named sources are authoritative. Never silently substitute a parent artifact.
    if kind == "rows":
        sources = info.get("artifacts_with_results") or []
        if artifact not in sources:
            raise Invalid("이 수집에 해당 결과 소스가 없습니다.")
        if order:
            if order != "mtime" or artifact != "Linux.Search.FileFinder":
                raise Invalid("지원하지 않는 정렬입니다.")
            n=offset+size+1
            query=f"SELECT * FROM source(client_id=P.client_id, flow_id=P.flow_id, artifact=P.artifact) ORDER BY MTime DESC LIMIT {n}"
            rows=run(t,query,selector,max_rows=n)
            data=page(rows,offset,size)
        else:
            query = f"SELECT * FROM source(client_id=P.client_id, flow_id=P.flow_id, artifact=P.artifact, start_row=P.offset) LIMIT {size + 1}"
            rows = run(t, query, selector, max_rows=size + 1)
            data = page(rows, 0, size)
            data["offset"] = offset
    elif kind in {"logs", "uploads"}:
        plugin = "flow_logs" if kind == "logs" else "uploads"
        n = offset + size + 1
        rows = run(t, f"SELECT * FROM {plugin}(client_id=P.client_id, flow_id=P.flow_id) LIMIT {n}", selector, max_rows=n)
        data = page(rows, offset, size)
    else:
        raise Invalid("지원하지 않는 결과입니다.")
    return dict(data, client_id=client_id, flow_id=flow_id, artifact=artifact, kind=kind, flow=info)


def hunts(t, offset=0, size=50):
    offset, size = pagination(offset, size)
    n = offset + size + 1
    rows = run(t, f"SELECT hunt_id, hunt_description, state, create_time, expires, start_request, stats, condition FROM hunts() ORDER BY create_time DESC LIMIT {n}", max_rows=n)
    return page(rows, offset, size)


def hunt_flows(t, hunt_id, offset=0, size=50):
    checked(hunt_id, HUNT)
    offset, size = pagination(offset, size)
    rows = run(t, "SELECT * FROM hunt_flows(hunt_id=P.hunt_id, start_row=P.offset, limit=P.limit)", dict(hunt_id=hunt_id, offset=offset, limit=size+1), max_rows=size+1)
    data = page(rows, 0, size); data["offset"] = offset
    return data


def directory(t, client_id, path, offset=0):
    path_value(path, root=True)
    # Use the actual requested Path from saved native VFS collections. This
    # never reads the Velociraptor server's local filesystem via vfs_ls().
    candidates = flows(t, client_id, size=100, artifact="System.VFS.ListDirectory")
    for item in candidates["items"]:
        specs = item.get("request", {}).get("specs", [])
        for spec in specs:
            if spec.get("artifact") != "System.VFS.ListDirectory":
                continue
            env = {v.get("key"): v.get("value") for v in spec.get("parameters", {}).get("env", [])}
            collected_path=env.get("Path") or "/"
            if env.get("Components"):
                try:
                    parts=json.loads(env["Components"])
                    if not isinstance(parts,list) or any(not isinstance(p,str) or "/" in p for p in parts):
                        continue
                    collected_path="/"+"/".join(parts)
                except (ValueError,TypeError):
                    continue
            if collected_path.rstrip("/") != path.rstrip("/") or env.get("Accessor", "file") != "file":
                continue
            name = "System.VFS.ListDirectory/Listing"
            if name not in (item.get("artifacts_with_results") or []):
                return dict(items=[], flow=item, path=path, has_more=False, offset=int(offset), no_source=True)
            return dict(results(t, client_id, item["flow_id"], name, offset), path=path)
    return dict(items=[], path=path, has_more=False, offset=int(offset), uncached=True, search_incomplete=candidates["has_more"])


def compare(t,store,client_id,old_flow,new_flow,offset=0):
    offset,size=pagination(offset)
    if old_flow==new_flow: raise Invalid("서로 다른 수집을 선택하세요.")
    infos=[flow(t,client_id,fid) for fid in (old_flow,new_flow)]
    if any(str(i.get("state"))!="FINISHED" for i in infos):
        raise Invalid("완료된 파일 수집만 비교할 수 있습니다.")
    if float(infos[0].get("create_time",0))>=float(infos[1].get("create_time",0)):
        raise Invalid("기준 수집은 비교 수집보다 이전이어야 합니다.")
    manifests=[]
    with store.connect() as conn:
        for fid in (old_flow,new_flow):
            row=conn.execute("SELECT j.manifest FROM jobs j JOIN units u ON u.job_id=j.id WHERE u.client_id=? AND u.flow_id=? AND u.artifact='Linux.Search.FileFinder'",(client_id,fid)).fetchone()
            if not row: raise Invalid("범위와 아티팩트 버전을 확인할 수 있는 파일 수집 두 개가 필요합니다.")
            manifests.append(json.loads(row[0]))
    keys=("definition_hash","params","spec","version")
    if any(manifests[0][k]!=manifests[1][k] for k in keys):
        raise Invalid("검색 범위와 수집 조건이 동일해야 합니다.")
    snapshots=[]
    for fid,info in zip((old_flow,new_flow),infos):
        if "Linux.Search.FileFinder" not in (info.get("artifacts_with_results") or []):
            # A source absent entirely cannot establish a complete empty baseline.
            raise Invalid("완전한 파일 목록을 확인할 수 없습니다.")
        rows=run(t,"SELECT * FROM source(client_id=P.client_id, flow_id=P.flow_id, artifact='Linux.Search.FileFinder') LIMIT 10001",dict(client_id=client_id,flow_id=fid),max_rows=10001,max_bytes=16*1048576)
        if len(rows)>=10000 or info.get("total_collected_rows")!=len(rows):
            raise Invalid("전체 결과를 확인할 수 없어 비교를 중단했습니다.")
        snapshot={}
        for r in rows:
            p=r.get("OSPath")
            if not p: raise Invalid("파일 경로를 확인할 수 없습니다.")
            key=json.dumps(p,sort_keys=True,ensure_ascii=False)
            if key in snapshot: raise Invalid("중복 경로가 있어 비교할 수 없습니다.")
            snapshot[key]=r
        snapshots.append(snapshot)
    old,new=snapshots
    changes=[]
    for key in sorted(old.keys()|new.keys()):
        a,b=old.get(key),new.get(key)
        kind="새로 관측됨" if a is None else "목록에서 사라짐" if b is None else "변경됨" if any(a.get(k)!=b.get(k) for k in ("Size","MTime","CTime","Mode","Hash","Inode")) else None
        if kind:changes.append(dict(change=kind,OSPath=(b or a)["OSPath"],before=a,after=b))
    return dict(page(changes,offset,size),old_flow=old_flow,new_flow=new_flow,client_id=client_id,total_changes=len(changes),comparison="complete_comparable_snapshots")
