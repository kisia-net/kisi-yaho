"""Reviewed operations. No browser-supplied artifact names or VQL."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

VERSION = 1
CLIENT = re.compile(r"C\.[0-9a-fA-F]{16,64}\Z")
FLOW = re.compile(r"F\.[A-Za-z0-9_-]{1,100}\Z")
HUNT = re.compile(r"H\.[A-Za-z0-9_-]{1,100}\Z")
SOURCE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)?\Z")


class Invalid(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def checked(value, regex):
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise Invalid("잘못된 식별자입니다.")
    return value


def field(name, label, kind="text", default="", required=False, **extra):
    return dict(name=name, label=label, kind=kind, default=default, required=required, **extra)


PATH = field("path", "검색 경로 / Glob", default="/tmp/*", required=True)
AFTER = field("after", "수정 시각 이후", "datetime")
BEFORE = field("before", "수정 시각 이전", "datetime")
MAX_SIZE = field("max_size", "최대 파일 크기 (MiB)", "integer", 20, True, min=1, max=100)

OPS = {
    "files": dict(label="파일 메타데이터 검색", area="files", fields=[PATH, AFTER, BEFORE, field("hash", "해시 계산", "boolean", False)], artifacts=["Linux.Search.FileFinder"]),
    "hash": dict(label="SHA-256 일치 검색", area="files", fields=[PATH, field("sha256", "SHA-256", required=True), MAX_SIZE, AFTER, BEFORE], artifacts=["Generic.Detection.HashHunter"]),
    "yara": dict(label="YARA 파일 검사", area="files", fields=[PATH, field("rule", "YARA 규칙", "textarea", required=True), MAX_SIZE, AFTER, BEFORE], artifacts=["Generic.Detection.Yara.Glob"], approval=True),
    "directory": dict(label="디렉터리 목록 수집", area="files", fields=[field("path", "디렉터리", default="/tmp", required=True)], artifacts=["System.VFS.ListDirectory"]),
    "acquire": dict(label="파일 증거 수집", area="files", fields=[field("path", "파일 전체 경로", required=True)], artifacts=["System.VFS.DownloadFile"], approval=True),
    "processes": dict(label="프로세스", area="host", fields=[], artifacts=["Linux.Sys.Pslist"]),
    "network": dict(label="네트워크 연결", area="host", fields=[], artifacts=["Linux.Network.NetstatEnriched"]),
    "services": dict(label="서비스", area="host", fields=[], artifacts=["Linux.Sys.Services"]),
    "cron": dict(label="예약 작업", area="host", fields=[], artifacts=["Linux.Sys.Crontab"]),
    "keys": dict(label="SSH 인증 키", area="host", fields=[], artifacts=["Linux.Ssh.AuthorizedKeys"]),
    "users": dict(label="사용자 계정", area="host", fields=[], artifacts=["Linux.Sys.Users", "Linux.Sys.Groups"]),
    "logins": dict(label="최근 로그인", area="host", fields=[field("days", "조회 기간 (일)", "integer", 7, True, min=1, max=30)], artifacts=["Linux.Sys.LastUserLogin"]),
    "disk": dict(label="디스크 사용량", area="host", fields=[], artifacts=["Generic.Client.DiskSpace"]),
    "triage": dict(label="초동 조사", area="host", fields=[], artifacts=["Linux.Sys.Pslist", "Linux.Network.NetstatEnriched", "Linux.Sys.Services", "Linux.Sys.Crontab", "Linux.Ssh.AuthorizedKeys", "Linux.Sys.Users", "Linux.Sys.Groups", "Linux.Sys.LastUserLogin", "Generic.Client.DiskSpace"]),
}


def timestamp(value):
    if not value:
        return ""
    if not isinstance(value, str) or len(value) > 40:
        raise Invalid("올바른 시각을 입력하세요.")
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if t.tzinfo is None:
            raise ValueError()
        return t.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError as exc:
        raise Invalid("시각에 시간대가 필요합니다.") from exc


def path_value(value, glob=False, root=False):
    if not isinstance(value, str) or not 1 <= len(value) <= 1000 or not value.startswith("/"):
        raise Invalid("절대 경로를 입력하세요.")
    if any(ord(c) < 32 for c in value) or ".." in value.split("/") or "\\" in value or "://" in value:
        raise Invalid("지원하지 않는 경로입니다.")
    if not glob and any(c in value for c in "*?[]{}"):
        raise Invalid("정확한 경로를 입력하세요.")
    if glob:
        # A literal top-level directory is mandatory. No root-wide scans or brace bypass.
        top = value.split("/")[1]
        if not top or any(c in top for c in "*?[]{}") or any(c in value for c in "{}"):
            raise Invalid("검색할 디렉터리를 지정하세요.")
        if top in {"proc", "sys", "dev", "run", "snap"}:
            raise Invalid("가상 파일시스템 검색은 지원하지 않습니다.")
    elif value == "/" and not root:
        raise Invalid("파일 또는 하위 디렉터리를 지정하세요.")
    return value


def normalize(operation, params):
    if not isinstance(operation,str) or operation not in OPS or not isinstance(params, dict):
        raise Invalid("지원하지 않는 수집입니다.")
    op = OPS[operation]
    if set(params) - {f["name"] for f in op["fields"]}:
        raise Invalid("지원하지 않는 매개변수입니다.")
    result = {}
    for f in op["fields"]:
        k, kind = f["name"], f["kind"]
        v = params.get(k, f["default"])
        if kind == "boolean":
            if type(v) is not bool:
                raise Invalid("올바른 선택 값을 입력하세요.")
        elif kind == "integer":
            if type(v) is not int or not f["min"] <= v <= f["max"]:
                raise Invalid(f"{f['label']}: {f['min']}–{f['max']}")
        elif kind == "datetime":
            v = timestamp(v)
        elif not isinstance(v, str) or len(v) > (16000 if k == "rule" else 1000):
            raise Invalid("입력 길이가 초과되었습니다.")
        elif f["required"] and not v.strip():
            raise Invalid(f"{f['label']}을 입력하세요.")
        result[k] = v
    if "path" in result:
        result["path"] = path_value(result["path"], glob=operation in {"files", "hash", "yara"}, root=operation == "directory")
    if operation == "hash":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", result["sha256"]):
            raise Invalid("64자리 SHA-256을 입력하세요.")
        result["sha256"] = result["sha256"].lower()
    if operation == "yara" and re.search(r"(?m)^\s*include\s", result["rule"]):
        raise Invalid("독립된 YARA 규칙을 입력하세요.")
    if result.get("after") and result.get("before") and result["after"] >= result["before"]:
        raise Invalid("조회 시작 시각이 종료 시각보다 늦습니다.")
    return result


def plan(operation, params):
    p = normalize(operation, params)
    spec = {a: {} for a in OPS[operation]["artifacts"]}
    if operation == "files":
        spec["Linux.Search.FileFinder"] = dict(SearchFilesGlob=p["path"], SearchFilesGlobTable="Glob\n", YaraRule="", Upload_File="N", Calculate_Hash="Y" if p["hash"] else "N", MoreRecentThan=p["after"], ModifiedBefore=p["before"], ExcludePathRegex="^/(proc|sys|dev|run|snap)(/|$)", LocalFilesystemOnly="Y", OneFilesystem="Y", DoNotFollowSymlinks="Y", ROOT="", ACCESSOR="file", UPLOAD_IS_RESUMABLE="N")
    elif operation == "hash":
        spec["Generic.Detection.HashHunter"] = dict(TargetGlob=p["path"], Accessor="file", DateAfter=p["after"], DateBefore=p["before"], SizeMin="0", SizeMax=str(p["max_size"] * 1048576), MD5List="", SHA1List="", SHA256List=p["sha256"])
    elif operation == "yara":
        spec["Generic.Detection.Yara.Glob"] = dict(PathGlob=p["path"], YaraRule=p["rule"], YaraUrl="", SizeMax=str(p["max_size"] * 1048576), SizeMin="0", DateAfter=p["after"], DateBefore=p["before"], UploadHits="N", NumberOfHits="20", ContextBytes="0")
    elif operation == "directory":
        spec["System.VFS.ListDirectory"] = dict(Path=p["path"], Components="", Accessor="file", Depth="0")
    elif operation == "acquire":
        spec["System.VFS.DownloadFile"] = dict(Path=p["path"], Components="", Accessor="file", Recursively="N", UPLOAD_IS_RESUMABLE="N")
    if "Linux.Ssh.AuthorizedKeys" in spec:
        spec["Linux.Ssh.AuthorizedKeys"] = dict(AlsoUpload="N")
    if "Linux.Sys.LastUserLogin" in spec:
        spec["Linux.Sys.LastUserLogin"] = dict(MaxCount="2000", recent_x_days=str(p.get("days", 7)))
    return p, spec


def budget(operation):
    return dict(timeout=300, cpu_limit=30, iops_limit=100, max_rows=10000,
                max_bytes=50 * 1048576 if operation == "acquire" else 1048576)


def definition_fingerprint(definitions, artifacts, spec):
    by_name = {a.get("name"): a for a in definitions}
    for name in artifacts:
        a = by_name.get(name)
        if not a or a.get("type") != "client":
            raise Invalid("필요한 수집 아티팩트가 없습니다.")
        if a.get("required_permissions"):
            raise Invalid("아티팩트의 추가 권한 검토가 필요합니다.")
        if set(spec[name]) - {x["name"] for x in a.get("parameters", [])}:
            raise Invalid("아티팩트 매개변수가 변경되었습니다.")
    # Include dependency VQL, not just the parameter names; ignore nonfunctional
    # metadata that differs between an installed and a sanitized definition.
    semantic = []
    for a in definitions:
        semantic.append({k: a.get(k) for k in ("name", "type", "parameters", "sources", "precondition", "export", "imports", "tools", "required_permissions")})
    return digest(sorted(semantic, key=lambda a: a.get("name") or ""))
