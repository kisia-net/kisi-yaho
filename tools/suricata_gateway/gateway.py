#!/usr/bin/env python3
"""HAW-KI Suricata 배포 게이트웨이. 센서 VM에서 실행합니다.

HAW-KI가 승인된 Suricata 조치를 `POST /actions`로 보내면:

1. 토큰, 조치 종류, 룰 한 줄, SID, 허용된 동작(기본 alert만)을 확인합니다.
2. 관리 파일(hawki.rules)의 새 내용을 임시 파일로 만들고
   `suricata -T -S <임시 파일>`로 먼저 검사합니다. 실패하면 아무것도 바꾸지 않습니다.
3. 통과하면 원래 파일을 .bak으로 남기고 교체한 뒤 룰 다시 읽기를 요청합니다.
   다시 읽기 요청이 실패하면 .bak으로 되돌립니다.

`GET /health`는 토큰 없이 Suricata 프로세스가 살아 있는지만 알려 줍니다.
표준 라이브러리만 씁니다 (Python 3.8+).
"""
from __future__ import annotations

import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ACTION_TYPES = {"suricata_rule", "suricata_rule_disable"}
RULE_ACTIONS = {"alert", "drop", "reject", "pass"}
ACTION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
SID_PATTERN = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
REV_PATTERN = re.compile(r"\brev\s*:\s*(\d+)\s*;")
MAX_BODY = 256 * 1024
HEADER = "# HAW-KI가 관리하는 파일입니다. 손으로 고치지 말고 HAW-KI 승인으로 바꾸세요.\n"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return list(default)
    value = json.loads(raw)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{name} must be a JSON list of strings")
    return value


class Config:
    def __init__(self) -> None:
        self.token = os.getenv("HAWKI_GW_TOKEN", "")
        self.bind = os.getenv("HAWKI_GW_BIND", "127.0.0.1")
        self.port = int(os.getenv("HAWKI_GW_PORT", "8095"))
        self.rules_file = Path(os.getenv("HAWKI_GW_RULES_FILE", "/var/lib/suricata/rules/hawki.rules"))
        self.conf = os.getenv("HAWKI_GW_SURICATA_CONF", "/etc/suricata/suricata.yaml")
        self.state_file = Path(os.getenv("HAWKI_GW_STATE_FILE", "/var/lib/hawki-gateway/applied.jsonl"))
        self.allowed_actions = {
            item.strip().lower() for item in os.getenv("HAWKI_GW_ALLOWED_ACTIONS", "alert").split(",") if item.strip()
        }
        self.sensor_host = os.getenv("HAWKI_GW_SENSOR_HOST", "").strip()
        self.sensor_interface = os.getenv("HAWKI_GW_SENSOR_INTERFACE", "").strip()
        # {conf} and {rules} are filled in; no shell is ever used.
        # unix-command off: a test run must never take over the live daemon's socket.
        self.test_cmd = json_list(
            "HAWKI_GW_TEST_CMD",
            ["suricata", "--set", "unix-command.enabled=no", "-T", "-c", "{conf}", "-S", "{rules}"],
        )
        self.reload_cmd = json_list("HAWKI_GW_RELOAD_CMD", ["suricatasc", "-c", "ruleset-reload-nonblocking"])
        self.status_cmd = json_list("HAWKI_GW_STATUS_CMD", ["pidof", "suricata"])
        self.command_timeout = int(os.getenv("HAWKI_GW_COMMAND_TIMEOUT", "60"))
        if not self.token or len(self.token) < 24:
            raise SystemExit("HAWKI_GW_TOKEN is required (24+ characters)")
        unknown = self.allowed_actions - RULE_ACTIONS
        if unknown:
            raise SystemExit(f"HAWKI_GW_ALLOWED_ACTIONS has unknown actions: {sorted(unknown)}")


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.detail = status, code, message, detail


def run(cmd: list[str], conf: Config, rules: str = "") -> subprocess.CompletedProcess:
    argv = [part.replace("{conf}", conf.conf).replace("{rules}", rules) for part in cmd]
    return subprocess.run(argv, capture_output=True, text=True, timeout=conf.command_timeout, check=False)


def tail(result: subprocess.CompletedProcess) -> str:
    text = (result.stderr or "") + (result.stdout or "")
    return text.strip()[-1500:]


def read_rules(path: Path) -> dict[int, str]:
    rules: dict[int, str] = {}
    if not path.exists():
        return rules
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = SID_PATTERN.search(line)
        if match:
            rules[int(match.group(1))] = line
    return rules


def render_rules(rules: dict[int, str]) -> str:
    return HEADER + "".join(f"{rules[sid]}\n" for sid in sorted(rules))


def applied_before(conf: Config, action_id: str) -> dict[str, Any] | None:
    if not conf.state_file.exists():
        return None
    for line in conf.state_file.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("action_id") == action_id and item.get("status") == "applied":
            return item
    return None


def record(conf: Config, entry: dict[str, Any]) -> None:
    conf.state_file.parent.mkdir(parents=True, exist_ok=True)
    with conf.state_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def validate(conf: Config, body: Any) -> tuple[str, str, int, int, str]:
    if not isinstance(body, dict):
        raise GatewayError(400, "bad_body", "Body must be a JSON object.")
    action_id = str(body.get("id", ""))
    action_type = str(body.get("type", ""))
    payload = body.get("payload")
    if not ACTION_ID.match(action_id):
        raise GatewayError(400, "bad_id", "Action id is missing or malformed.")
    if action_type not in ACTION_TYPES:
        raise GatewayError(400, "bad_type", "Only Suricata rule actions are accepted.")
    if not isinstance(payload, dict):
        raise GatewayError(400, "bad_payload", "Payload must be an object.")
    if conf.sensor_host and str(payload.get("host", "")).strip() != conf.sensor_host:
        raise GatewayError(409, "wrong_host", "Action targets a different sensor host.")
    if conf.sensor_interface and str(payload.get("interface", "")).strip() != conf.sensor_interface:
        raise GatewayError(409, "wrong_interface", "Action targets a different sensor interface.")
    try:
        sid = int(payload.get("sid"))
        revision = int(payload.get("revision", 1))
    except (TypeError, ValueError):
        raise GatewayError(400, "bad_sid", "SID and revision must be integers.") from None
    if not 1_000_000 <= sid <= 4_294_967_295 or not 1 <= revision <= 65_535:
        raise GatewayError(400, "bad_sid", "SID or revision out of range.")
    rule = str(payload.get("rule", "")).strip()
    if action_type == "suricata_rule":
        if not rule or len(rule) > 8000 or "\n" in rule or "\r" in rule:
            raise GatewayError(400, "bad_rule", "Rule must be one line of at most 8000 characters.")
        verb = rule.split(None, 1)[0].lower()
        if verb not in RULE_ACTIONS:
            raise GatewayError(400, "bad_rule", "Rule must start with a Suricata action.")
        if verb not in conf.allowed_actions:
            raise GatewayError(403, "action_not_allowed", f"'{verb}' rules are not allowed on this sensor.")
        sid_match, rev_match = SID_PATTERN.search(rule), REV_PATTERN.search(rule)
        if not sid_match or int(sid_match.group(1)) != sid:
            raise GatewayError(400, "sid_mismatch", "The rule's sid does not match the action's SID.")
        if rev_match and int(rev_match.group(1)) != revision:
            raise GatewayError(400, "rev_mismatch", "The rule's rev does not match the action's revision.")
    return action_id, action_type, sid, revision, rule


class Gateway:
    def __init__(self, conf: Config) -> None:
        self.conf = conf
        self.lock = threading.Lock()

    def health(self) -> tuple[int, dict[str, Any]]:
        try:
            running = run(self.conf.status_cmd, self.conf).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            running = False
        try:
            count = len(read_rules(self.conf.rules_file))
        except OSError:
            count = None
        return (200 if running else 503), {"ok": running, "suricata_running": running, "managed_rules": count}

    def apply(self, body: Any) -> dict[str, Any]:
        action_id, action_type, sid, revision, rule = validate(self.conf, body)
        with self.lock:
            previous = applied_before(self.conf, action_id)
            if previous:
                return {**previous, "repeated": True}
            path = self.conf.rules_file
            rules = read_rules(path)
            operation = "deploy" if action_type == "suricata_rule" else "disable"
            if operation == "deploy":
                rules[sid] = rule
            else:
                rules.pop(sid, None)

            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temp_name = tempfile.mkstemp(prefix=".hawki-", suffix=".rules", dir=str(path.parent))
            temp = Path(temp_name)
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as out:
                    out.write(render_rules(rules))
                if rules:
                    try:
                        tested = run(self.conf.test_cmd, self.conf, str(temp))
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        raise GatewayError(500, "test_unavailable", "suricata -T could not run.", str(exc)) from None
                    if tested.returncode != 0:
                        raise GatewayError(422, "test_failed", "suricata -T rejected the rule set.", tail(tested))
                backup = path.with_name(path.name + ".bak")
                had_file = path.exists()
                if had_file:
                    shutil.copy2(path, backup)
                os.chmod(temp, 0o644)
                os.replace(temp, path)
            finally:
                if temp.exists():
                    temp.unlink()

            try:
                reloaded = run(self.conf.reload_cmd, self.conf)
                reload_detail = tail(reloaded)
                # suricatasc exits 0 even when Suricata answers NOK (for example
                # "reload already in progress"), so read the answer as well.
                reload_ok = reloaded.returncode == 0 and '"NOK"' not in reload_detail and not reload_detail.startswith("Error")
            except (OSError, subprocess.TimeoutExpired) as exc:
                reload_ok, reload_detail = False, str(exc)
            if not reload_ok:
                if had_file:
                    shutil.copy2(backup, path)
                else:
                    path.unlink(missing_ok=True)
                raise GatewayError(502, "reload_failed", "Suricata did not accept the reload; the file was restored.", reload_detail)

            entry = {
                "status": "applied", "action_id": action_id, "operation": operation, "sid": sid,
                "revision": revision, "managed_rules": len(rules), "applied_at": utc_now(),
            }
            record(self.conf, entry)
            return entry


def make_handler(gateway: Gateway):
    class Handler(BaseHTTPRequestHandler):
        server_version = "hawki-suricata-gateway"

        def send_json(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt: str, *args: Any) -> None:  # one line per request to stderr (journald)
            sys.stderr.write(f"{utc_now()} {self.address_string()} {fmt % args}\n")

        def do_GET(self) -> None:
            if self.path != "/health":
                self.send_json(404, {"error": "not_found"})
                return
            status, body = gateway.health()
            self.send_json(status, body)

        def do_POST(self) -> None:
            if self.path != "/actions":
                self.send_json(404, {"error": "not_found"})
                return
            supplied = self.headers.get("Authorization", "")
            expected = f"Bearer {gateway.conf.token}"
            if not hmac.compare_digest(supplied.encode(), expected.encode()):
                self.send_json(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_BODY:
                self.send_json(413 if length > MAX_BODY else 400, {"error": "bad_length"})
                return
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                self.send_json(400, {"error": "bad_json"})
                return
            try:
                self.send_json(200, gateway.apply(body))
            except GatewayError as exc:
                entry = {"status": "refused", "action_id": str((body or {}).get("id", ""))[:80] if isinstance(body, dict) else "",
                         "error": exc.code, "detail": exc.detail[-500:], "at": utc_now()}
                try:
                    record(gateway.conf, entry)
                except OSError:
                    pass
                self.send_json(exc.status, {"error": exc.code, "message": exc.message, "detail": exc.detail})

    return Handler


def main() -> None:
    conf = Config()
    server = ThreadingHTTPServer((conf.bind, conf.port), make_handler(Gateway(conf)))
    sys.stderr.write(f"{utc_now()} listening on {conf.bind}:{conf.port}, rules {conf.rules_file}, allowed {sorted(conf.allowed_actions)}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
