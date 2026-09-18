from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from typing import Any

from .models import CanonicalEvent, parse_timestamp


def stable_event_id(source_type: str, raw: Any, timestamp: str) -> str:
    encoded = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(f"{source_type}|{timestamp}|{encoded}".encode("utf-8")).hexdigest()[:16]
    return f"evt-{digest}"


def severity_from_suricata(value: Any) -> str:
    try:
        level = int(value)
    except (TypeError, ValueError):
        return "medium"
    if level <= 1:
        return "critical"
    if level == 2:
        return "high"
    if level == 3:
        return "medium"
    return "low"


def severity_from_wazuh(value: Any) -> str:
    try:
        level = int(value)
    except (TypeError, ValueError):
        return "medium"
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


class IgnoredEvent(Exception):
    """A producer record that is deliberately not a security event.

    Distinct from a parse failure: nothing went wrong, the record simply
    describes the sensor rather than the network. Repositories count these
    separately so they do not appear as unreadable lines.
    """


# Suricata reports its own health into the same file as its detections. A live
# sensor writes one of these every few seconds, so on any real capture they
# would outnumber the security events.
SURICATA_SELF_REPORTING_TYPES = {"stats", "engine"}


class SuricataAdapter:
    source_type = "suricata"

    def normalize(self, raw: dict[str, Any], *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        timestamp = str(raw.get("timestamp", ""))
        event_type = str(raw.get("event_type", "event"))
        if event_type in SURICATA_SELF_REPORTING_TYPES:
            raise IgnoredEvent(f"suricata {event_type} record describes the sensor, not the network")
        alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
        http_raw = raw.get("http") if isinstance(raw.get("http"), dict) else {}

        http: dict[str, Any] = {}
        if http_raw:
            if http_raw.get("http_method"):
                http.setdefault("request", {})["method"] = http_raw["http_method"]
            if http_raw.get("url"):
                http.setdefault("request", {})["uri"] = http_raw["url"]
            if http_raw.get("hostname"):
                http.setdefault("request", {})["host"] = http_raw["hostname"]
            if http_raw.get("http_user_agent"):
                http.setdefault("request", {})["user_agent"] = http_raw["http_user_agent"]
            if http_raw.get("status") is not None:
                # Preserve the semantic role. HTTP 200 is a response status, not port 200.
                http.setdefault("response", {})["status_code"] = http_raw["status"]
            if http_raw.get("length") is not None:
                http.setdefault("response", {})["body_bytes"] = http_raw["length"]

        dns_raw = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
        dns: dict[str, Any] = {}
        if queried := str(dns_raw.get("rrname") or "").strip():
            dns["question"] = {
                key: value
                for key, value in {"name": queried, "type": dns_raw.get("rrtype")}.items()
                if value
            }
            if dns_raw.get("rcode"):
                dns["response_code"] = dns_raw["rcode"]

        rule: dict[str, Any] = {}
        if alert:
            rule = {
                "id": str(alert.get("signature_id", "")),
                "name": str(alert.get("signature", "")),
                "category": str(alert.get("category", "")),
                "action": str(alert.get("action", "")),
            }

        categories = ["network"]
        if event_type == "alert":
            categories.append("intrusion_detection")
        if http_raw or str(raw.get("app_proto", "")).lower() == "http":
            categories.append("web")

        tls_raw = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
        tls: dict[str, Any] = {}
        if tls_raw:
            tls = {
                key: value
                for key, value in {
                    "server_name": str(tls_raw.get("sni") or "").strip(),
                    "version": str(tls_raw.get("version") or "").strip(),
                    "subject": str(tls_raw.get("subject") or "").strip(),
                    "issuer": str(tls_raw.get("issuerdn") or "").strip(),
                    "ja3": (tls_raw.get("ja3") or {}).get("hash")
                    if isinstance(tls_raw.get("ja3"), dict)
                    else None,
                }.items()
                if value
            }

        file_raw = raw.get("fileinfo") if isinstance(raw.get("fileinfo"), dict) else {}
        file_data: dict[str, Any] = {}
        if file_raw:
            name = str(file_raw.get("filename") or "").strip()
            file_data = {
                key: value
                for key, value in {
                    "path": name,
                    "name": name.rsplit("/", 1)[-1] if name else "",
                    "size": file_raw.get("size"),
                }.items()
                if value not in (None, "")
            }
            hashes = {
                algorithm: str(file_raw[algorithm]).lower()
                for algorithm in ("sha256", "sha1", "md5")
                if file_raw.get(algorithm)
            }
            if hashes:
                file_data["hash"] = hashes

        # Every event type gets a message that says what it recorded. Left
        # generic, a real capture fills the case with rows carrying nothing but
        # a pair of addresses.
        request = http.get("request", {})
        queried = (dns.get("question") or {}).get("name", "")
        if rule.get("name"):
            message = rule["name"]
        elif event_type == "dns" and queried:
            direction = "answer" if str(dns_raw.get("type", "")) == "answer" else "query"
            answers = [
                str(item.get("rdata", "")).strip()
                for item in (dns_raw.get("answers") or [])
                if isinstance(item, dict) and item.get("rdata")
            ]
            message = f"DNS {direction} {queried}" + (f" -> {', '.join(answers[:3])}" if answers else "")
        elif event_type == "tls" and tls.get("server_name"):
            message = f"TLS connection to {tls['server_name']}" + (
                f" ({tls['version']})" if tls.get("version") else ""
            )
        elif event_type == "fileinfo" and file_data.get("name"):
            size = file_data.get("size")
            message = f"File transferred: {file_data['name']}" + (f" ({size} bytes)" if size else "")
        elif event_type == "anomaly":
            anomaly = raw.get("anomaly") if isinstance(raw.get("anomaly"), dict) else {}
            message = f"Protocol anomaly: {anomaly.get('event', 'unspecified')}"
        elif request.get("uri"):
            message = f"HTTP {request.get('method', '')} {request['uri']}".strip()
        elif event_type == "flow":
            flow = raw.get("flow") if isinstance(raw.get("flow"), dict) else {}
            message = (
                f"Flow {flow.get('state', 'recorded')}, "
                f"{flow.get('pkts_toserver', 0)} packets to server / "
                f"{flow.get('pkts_toclient', 0)} to client"
            )
        else:
            message = f"Suricata {event_type} event"

        return CanonicalEvent(
            id=stable_event_id(self.source_type, raw, timestamp),
            timestamp=parse_timestamp(timestamp).isoformat(),
            source_type=self.source_type,
            source_dataset="suricata.eve",
            kind="alert" if event_type == "alert" else "event",
            category=list(dict.fromkeys(categories)),
            severity=severity_from_suricata(alert.get("severity")) if alert else "info",
            message=message,
            host_name=str(defaults.get("host_name", "")),
            source_ip=str(raw.get("src_ip", "")),
            source_port=int(raw["src_port"]) if raw.get("src_port") is not None else None,
            destination_ip=str(raw.get("dest_ip", "")),
            destination_port=int(raw["dest_port"]) if raw.get("dest_port") is not None else None,
            network_transport=str(raw.get("proto", "")).lower(),
            network_application=str(raw.get("app_proto", "") or (event_type if event_type in {"http", "dns", "tls"} else "")).lower(),
            http=http,
            dns=dns,
            tls=tls,
            file=file_data,
            rule=rule,
            tags=[str(value) for value in raw.get("tags", []) if value],
            raw=raw,
            scenario_id=scenario_id,
            correlation={"flow_id": str(raw.get("flow_id", ""))} if raw.get("flow_id") is not None else {},
        )


NGINX_COMBINED = re.compile(
    r'^(?P<remote>\S+)\s+\S+\s+(?P<user>\S+)\s+' 
    r'\[(?P<time>[^\]]+)\]\s+' 
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+' 
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+' 
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"$'
)


class NginxAdapter:
    source_type = "nginx"

    def normalize(self, raw: str, *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        match = NGINX_COMBINED.match(raw.strip())
        if not match:
            raise ValueError(f"Unsupported Nginx combined log line: {raw[:120]}")
        fields = match.groupdict()
        timestamp = datetime.strptime(fields["time"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
        status = int(fields["status"])
        body_bytes = None if fields["bytes"] == "-" else int(fields["bytes"])
        user = "" if fields["user"] == "-" else fields["user"]
        http = {
            "request": {
                "method": fields["method"],
                "uri": fields["uri"],
                "protocol": fields["protocol"],
                "user_agent": fields["agent"],
                "referer": fields["referer"],
            },
            "response": {
                "status_code": status,
                "body_bytes": body_bytes,
            },
        }
        return CanonicalEvent(
            id=stable_event_id(self.source_type, raw, timestamp),
            timestamp=parse_timestamp(timestamp).isoformat(),
            source_type=self.source_type,
            source_dataset="nginx.access",
            kind="event",
            category=["web", "network"],
            severity="info",
            message=f'{fields["method"]} {fields["uri"]} -> HTTP {status}',
            host_name=str(defaults.get("host_name", "")),
            source_ip=fields["remote"],
            source_port=None,
            destination_ip=str(defaults.get("destination_ip", "")),
            destination_port=int(defaults["destination_port"]) if defaults.get("destination_port") is not None else None,
            network_transport="tcp",
            network_application="http",
            user_name=user,
            http=http,
            raw=raw,
            scenario_id=scenario_id,
        )


class ApacheAdapter(NginxAdapter):
    """Apache combined access log.

    Apache and Nginx share the combined log format, so the parsing is shared.
    The source identity is kept distinct because provenance matters when an
    analyst asks where a line came from.
    """

    source_type = "apache"

    def normalize(self, raw: str, *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        event = super().normalize(raw, scenario_id=scenario_id, defaults=defaults)
        event.source_type = self.source_type
        event.source_dataset = "apache.access"
        event.id = stable_event_id(self.source_type, raw, event.timestamp)
        return event


# RFC 3164 style: "Aug 11 10:21:09 web-01 sshd[3841]: message"
SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Structured details that appear verbatim in common auth messages. Only
# unambiguous forms are read; nothing is guessed from surrounding prose.
AUTH_SOURCE = re.compile(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(?P<port>\d{1,5}))?")
AUTH_USER = re.compile(r"\bfor(?:\s+invalid\s+user)?\s+(?P<user>[A-Za-z0-9_.\-\\$]+)\s+from\b")
SUDO_USER = re.compile(r"^\s*(?P<user>[A-Za-z0-9_.\-\\$]+)\s*:\s*TTY=")
SUDO_COMMAND = re.compile(r"\bCOMMAND=(?P<command>.+)$")
AUTH_FAILURE = re.compile(
    r"\b(failed password|authentication failure|invalid user|failure|denied|refused)\b", re.I
)
AUTH_SUCCESS = re.compile(r"\b(accepted password|accepted publickey|session opened|new session)\b", re.I)


class SyslogAdapter:
    """Linux syslog / auth.log lines in RFC 3164 form.

    Syslog carries no year, so the manifest supplies one through
    `defaults.year`; without it the current year is assumed, which is stated
    on the event rather than hidden.
    """

    source_type = "syslog"
    dataset = "linux.syslog"

    def normalize(self, raw: str, *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        match = SYSLOG_LINE.match(raw.strip())
        if not match:
            raise ValueError(f"Unsupported syslog line: {raw[:120]}")
        fields = match.groupdict()

        year = int(defaults.get("year") or datetime.now(timezone.utc).year)
        stamp = datetime.strptime(
            f"{year} {fields['month']} {int(fields['day']):02d} {fields['time']}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)

        program = fields["program"]
        message = fields["message"].strip()
        tags = [] if defaults.get("year") else ["assumed-year"]

        process: dict[str, Any] = {"name": program}
        if fields["pid"]:
            process["pid"] = int(fields["pid"])

        source_ip = ""
        source_port: int | None = None
        user = ""
        outcome = ""
        categories = ["host"]

        if source_match := AUTH_SOURCE.search(message):
            source_ip = source_match.group("ip")
            if source_match.group("port"):
                source_port = int(source_match.group("port"))
        if user_match := AUTH_USER.search(message):
            user = user_match.group("user")
        elif sudo_match := SUDO_USER.match(message):
            user = sudo_match.group("user")
        if command_match := SUDO_COMMAND.search(message):
            process["command_line"] = command_match.group("command").strip()

        if program in {"sshd", "sudo", "su", "login", "systemd-logind", "polkitd"} or source_ip:
            categories.append("authentication")
            # Outcome is stated by the producer's own wording, not inferred
            # from whether the activity looks suspicious.
            if AUTH_FAILURE.search(message):
                outcome = "failure"
            elif AUTH_SUCCESS.search(message):
                outcome = "success"
        if "command_line" in process:
            categories.append("process")

        return CanonicalEvent(
            id=stable_event_id(self.source_type, raw, stamp.isoformat()),
            timestamp=stamp.isoformat(),
            source_type=self.source_type,
            source_dataset=str(defaults.get("dataset") or self.dataset),
            kind="event",
            category=list(dict.fromkeys(categories)),
            severity="info",
            outcome=outcome,
            message=f"{program}: {message}" if message else program,
            host_name=str(defaults.get("host_name") or fields["host"]),
            source_ip=source_ip,
            source_port=source_port,
            user_name=user,
            process=process,
            tags=tags,
            raw=raw,
            scenario_id=scenario_id,
        )


class AuthLogAdapter(SyslogAdapter):
    """auth.log: syslog structurally, authentication by dataset."""

    source_type = "authlog"
    dataset = "linux.auth"


def severity_from_modsecurity(value: Any) -> str:
    """Map a ModSecurity/CRS severity to the canonical scale.

    ModSecurity counts down from EMERGENCY(0), the opposite of Wazuh. CRS marks
    most attack rules CRITICAL(2).
    """
    words = {
        "emergency": 0, "alert": 1, "critical": 2, "error": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7,
    }
    text = str(value or "").strip().lower()
    level = words.get(text)
    if level is None:
        try:
            level = int(text)
        except (TypeError, ValueError):
            return "medium"
    if level <= 2:
        return "critical"
    if level == 3:
        return "high"
    if level == 4:
        return "medium"
    return "low"


MODSEC_TIME_FORMATS = (
    "%a %b %d %H:%M:%S %Y",       # ModSecurity v3: "Tue Aug 11 10:21:03 2026"
    "%a %b %d %H:%M:%S.%f %Y",
    "%d/%b/%Y:%H:%M:%S %z",       # ModSecurity v2: "11/Aug/2026:10:21:03 +0000"
)

# ModSecurity v2 writes its messages as prose with bracketed options rather
# than as structured objects.
MODSEC_V2_OPTION = re.compile(r'\[(?P<key>[a-zA-Z_]+)\s+"(?P<value>(?:\\.|[^"\\])*)"\]')
MODSEC_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<protocol>\S+))?$")


def parse_modsecurity_time(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("ModSecurity record carries no timestamp")
    for fmt in MODSEC_TIME_FORMATS:
        try:
            stamp = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    return parse_timestamp(text)


def _modsecurity_messages(raw: dict[str, Any], audit: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize v3 structured messages and v2 message strings to one shape."""
    entries: list[dict[str, Any]] = []
    messages = raw.get("messages")
    if not isinstance(messages, list):
        messages = audit.get("messages") if isinstance(audit.get("messages"), list) else []

    for item in messages:
        if isinstance(item, dict):
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            entries.append(
                {
                    "id": str(details.get("ruleId", "")).strip(),
                    "message": str(item.get("message", "")).strip(),
                    "severity": details.get("severity", ""),
                    "data": str(details.get("data", "")).strip(),
                    "match": str(details.get("match", "")).strip(),
                    "file": str(details.get("file", "")).strip(),
                    "version": str(details.get("ver", "")).strip(),
                    "tags": [str(tag) for tag in details.get("tags", [])]
                    if isinstance(details.get("tags"), list)
                    else [],
                }
            )
        elif isinstance(item, str):
            options = {
                match.group("key").lower(): match.group("value")
                for match in MODSEC_V2_OPTION.finditer(item)
            }
            tags = [
                match.group("value")
                for match in MODSEC_V2_OPTION.finditer(item)
                if match.group("key").lower() == "tag"
            ]
            entries.append(
                {
                    "id": options.get("id", ""),
                    "message": options.get("msg", item.split("[")[0].strip()),
                    "severity": options.get("severity", ""),
                    "data": options.get("data", ""),
                    "match": "",
                    "file": options.get("file", ""),
                    "version": options.get("ver", ""),
                    "tags": tags,
                }
            )
    return [entry for entry in entries if entry["id"] or entry["message"]]


class ModSecurityAdapter:
    """ModSecurity WAF audit log, JSON format (v2 and v3/nginx).

    A transaction that triggered rules is a detection, so it is normalized with
    kind "alert"; a transaction that triggered nothing stays an event. The
    triggered CRS rule ids are preserved in full, because they are the baseline
    a rule-only decision would have produced — the thing an LLM assessment has
    to be measured against.
    """

    source_type = "modsecurity"

    def normalize(self, raw: dict[str, Any], *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        # v3 nests everything under "transaction"; v2 keeps request/response at
        # the top level and puts detections under "audit_data".
        transaction = raw.get("transaction") if isinstance(raw.get("transaction"), dict) else {}
        body = transaction if transaction.get("request") else raw
        audit = raw.get("audit_data") if isinstance(raw.get("audit_data"), dict) else {}

        request = body.get("request") if isinstance(body.get("request"), dict) else {}
        response = body.get("response") if isinstance(body.get("response"), dict) else {}

        timestamp = parse_modsecurity_time(
            transaction.get("time_stamp") or transaction.get("time") or raw.get("time_stamp") or ""
        )

        method = str(request.get("method", "")).strip()
        uri = str(request.get("uri", "")).strip()
        if not method and (line := str(request.get("request_line", "")).strip()):
            if match := MODSEC_REQUEST_LINE.match(line):
                method = match.group("method")
                uri = match.group("uri")

        headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
        lowered = {str(key).lower(): value for key, value in headers.items()}
        status = response.get("http_code", response.get("status"))

        http: dict[str, Any] = {}
        if method or uri:
            http["request"] = {
                key: value
                for key, value in {
                    "method": method,
                    "uri": uri,
                    "host": str(lowered.get("host", "")).strip(),
                    "user_agent": str(lowered.get("user-agent", "")).strip(),
                    "referer": str(lowered.get("referer", "")).strip(),
                }.items()
                if value
            }
        if status is not None:
            try:
                # A status code stays a status code.
                http["response"] = {"status_code": int(status)}
            except (TypeError, ValueError):
                pass

        entries = _modsecurity_messages(body, audit)
        # The most severe match names the alert; every match is retained.
        primary = min(
            entries,
            key=lambda entry: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                severity_from_modsecurity(entry["severity"]), 4
            ),
            default=None,
        ) if entries else None

        producer = body.get("producer") if isinstance(body.get("producer"), dict) else {}
        engine_mode = str(
            producer.get("secrules_engine") or audit.get("engine_mode") or ""
        ).strip()

        rule: dict[str, Any] = {}
        if primary:
            rule = {
                "id": primary["id"],
                "name": primary["message"],
                "severity": primary["severity"],
                "matched_data": primary["data"],
                "ruleset": primary["version"] or ", ".join(
                    str(item) for item in producer.get("components", [])
                    if isinstance(producer.get("components"), list)
                ),
                "engine_mode": engine_mode,
                # Every rule the transaction triggered, in file order. This is
                # the rule-only baseline.
                "matched_rules": [
                    {
                        "id": entry["id"],
                        "message": entry["message"],
                        "severity": entry["severity"],
                    }
                    for entry in entries
                ],
            }

        tags: list[str] = []
        for entry in entries:
            tags.extend(entry["tags"])

        source_port = transaction.get("client_port", transaction.get("remote_port"))
        destination_port = transaction.get("host_port", transaction.get("local_port"))

        def port(value: Any) -> int | None:
            try:
                number = int(value)
            except (TypeError, ValueError):
                return None
            return number if 0 <= number <= 65535 else None

        message = (
            f"{primary['message']} ({method} {uri})".strip()
            if primary
            else f"{method} {uri}".strip() or "ModSecurity transaction"
        )

        return CanonicalEvent(
            id=stable_event_id(self.source_type, raw, timestamp.isoformat()),
            timestamp=timestamp.isoformat(),
            source_type=self.source_type,
            source_dataset="modsecurity.audit",
            kind="alert" if entries else "event",
            category=["web", "network"] + (["intrusion_detection"] if entries else []),
            severity=severity_from_modsecurity(primary["severity"]) if primary else "info",
            message=message,
            host_name=str(defaults.get("host_name", "")),
            source_ip=str(transaction.get("client_ip") or transaction.get("remote_address") or ""),
            source_port=port(source_port),
            destination_ip=str(transaction.get("host_ip") or transaction.get("local_address") or ""),
            destination_port=port(destination_port),
            network_transport="tcp",
            network_application="http",
            http=http,
            rule=rule,
            tags=list(dict.fromkeys(tags)),
            raw=raw,
            scenario_id=scenario_id,
            correlation={"transaction_id": str(transaction.get("unique_id") or transaction.get("transaction_id") or "")}
            if (transaction.get("unique_id") or transaction.get("transaction_id"))
            else {},
        )


class WazuhAdapter:
    source_type = "wazuh"

    def normalize(self, raw: dict[str, Any], *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        timestamp = str(raw.get("timestamp", ""))
        rule_raw = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        agent_raw = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        process = data.get("process") if isinstance(data.get("process"), dict) else {}
        file_data = data.get("file") if isinstance(data.get("file"), dict) else {}
        network = data.get("network") if isinstance(data.get("network"), dict) else {}
        mitre = rule_raw.get("mitre") if isinstance(rule_raw.get("mitre"), dict) else {}

        tags = []
        for key in ("id", "tactic", "technique"):
            values = mitre.get(key)
            if isinstance(values, list):
                tags.extend(str(value) for value in values)

        return CanonicalEvent(
            id=stable_event_id(self.source_type, raw, timestamp),
            timestamp=parse_timestamp(timestamp).isoformat(),
            source_type=self.source_type,
            source_dataset="wazuh.alerts",
            kind="alert",
            category=["host", "process"] if process else ["host"],
            severity=severity_from_wazuh(rule_raw.get("level")),
            message=str(rule_raw.get("description", "Wazuh alert")),
            host_name=str(agent_raw.get("name", defaults.get("host_name", ""))),
            source_ip=str(network.get("source_ip", "")),
            source_port=int(network["source_port"]) if network.get("source_port") is not None else None,
            destination_ip=str(network.get("destination_ip", "")),
            destination_port=int(network["destination_port"]) if network.get("destination_port") is not None else None,
            network_transport=str(network.get("transport", "")).lower(),
            network_application=str(network.get("application", "")).lower(),
            user_name=str(data.get("user", {}).get("name", "")) if isinstance(data.get("user"), dict) else "",
            process=process,
            file=file_data,
            rule={
                "id": str(rule_raw.get("id", "")),
                "name": str(rule_raw.get("description", "")),
                "level": rule_raw.get("level"),
                "mitre": mitre,
            },
            tags=tags,
            raw=raw,
            scenario_id=scenario_id,
        )


# Sysmon event id -> (canonical categories, action name).
SYSMON_EVENT_CATEGORIES: dict[int, tuple[list[str], str]] = {
    1: (["process"], "process_creation"),
    2: (["file"], "file_creation_time_changed"),
    3: (["network"], "network_connection"),
    5: (["process"], "process_terminated"),
    6: (["driver"], "driver_loaded"),
    7: (["process", "library"], "image_loaded"),
    8: (["process"], "create_remote_thread"),
    9: (["process"], "raw_access_read"),
    10: (["process"], "process_access"),
    11: (["file"], "file_create"),
    12: (["registry"], "registry_key_event"),
    13: (["registry"], "registry_value_set"),
    14: (["registry"], "registry_key_renamed"),
    15: (["file"], "file_create_stream_hash"),
    17: (["pipe"], "pipe_created"),
    18: (["pipe"], "pipe_connected"),
    22: (["network", "dns"], "dns_query"),
    23: (["file"], "file_delete"),
    25: (["process"], "process_tampering"),
    26: (["file"], "file_delete_detected"),
}


def parse_sysmon_hashes(value: Any) -> dict[str, str]:
    """Parse Sysmon's "SHA256=...,MD5=..." hash string into a mapping."""
    hashes: dict[str, str] = {}
    if isinstance(value, dict):
        return {str(key).lower(): str(item).lower() for key, item in value.items() if item}
    for part in str(value or "").split(","):
        if "=" not in part:
            continue
        algorithm, _, digest = part.partition("=")
        algorithm = algorithm.strip().lower()
        digest = digest.strip().lower()
        if algorithm and digest:
            hashes[algorithm] = digest
    return hashes


def _index_by_leaf(payload: Any) -> dict[str, Any]:
    """Index a nested Windows event by its leaf field names, shallowest first.

    Sysmon reaches this system in at least three shapes: flat records as
    published by OTRF/Security-Datasets, nested Event.System/Event.EventData
    from evtx conversion, and winlog.event_data from Winlogbeat. Indexing by
    leaf name reads all three without a separate adapter for each.
    """
    flat: dict[str, Any] = {}
    queue: list[Any] = [payload]
    while queue:
        current = queue.pop(0)
        if isinstance(current, dict):
            for key, value in current.items():
                name = str(key)
                if isinstance(value, (dict, list)):
                    queue.append(value)
                    # Windows XML conversion wraps scalars as {"#text": ...}.
                    if isinstance(value, dict) and "#text" in value:
                        flat.setdefault(name, value["#text"])
                else:
                    flat.setdefault(name, value)
        elif isinstance(current, list):
            queue.extend(current)
    return flat


class SysmonAdapter:
    """Windows Sysmon events.

    Sysmon is telemetry, not detection: every event is normalized with
    kind "event". The operator-assigned RuleName is carried as a tag rather
    than promoted to a rule, because a Sysmon config label is not a detection
    verdict.
    """

    source_type = "sysmon"

    def normalize(self, raw: dict[str, Any], *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        fields = _index_by_leaf(raw)

        def value(*names: str) -> Any:
            for name in names:
                if fields.get(name) not in (None, ""):
                    return fields[name]
            return None

        def text(*names: str) -> str:
            found = value(*names)
            return "" if found is None else str(found).strip()

        def port(*names: str) -> int | None:
            found = text(*names)
            try:
                number = int(found)
            except (TypeError, ValueError):
                return None
            return number if 0 <= number <= 65535 else None

        raw_event_id = value("EventID", "EventId", "event_id")
        try:
            event_id = int(str(raw_event_id).strip())
        except (TypeError, ValueError):
            event_id = 0

        timestamp = text("UtcTime", "@timestamp", "SystemTime", "TimeCreated", "timestamp")
        if not timestamp:
            raise ValueError("Sysmon event carries no usable timestamp")

        categories, action = SYSMON_EVENT_CATEGORIES.get(event_id, (["host"], f"sysmon_event_{event_id}"))

        process: dict[str, Any] = {}
        if image := text("Image"):
            process["name"] = PureWindowsPath(image).name
            process["executable"] = image
        if command_line := text("CommandLine"):
            process["command_line"] = command_line
        if pid := text("ProcessId"):
            try:
                process["pid"] = int(pid)
            except ValueError:
                pass
        if guid := text("ProcessGuid"):
            process["entity_id"] = guid
        if working_directory := text("CurrentDirectory"):
            process["working_directory"] = working_directory

        parent: dict[str, Any] = {}
        if parent_image := text("ParentImage"):
            parent["name"] = PureWindowsPath(parent_image).name
            parent["executable"] = parent_image
        if parent_command := text("ParentCommandLine"):
            parent["command_line"] = parent_command
        if parent_pid := text("ParentProcessId"):
            try:
                parent["pid"] = int(parent_pid)
            except ValueError:
                pass
        if parent_guid := text("ParentProcessGuid"):
            parent["entity_id"] = parent_guid
        if parent:
            process["parent"] = parent

        # Sysmon reports hashes on the subject of the event: the image for
        # process events, the written file for file events.
        hashes = parse_sysmon_hashes(value("Hashes", "Hash"))
        file_data: dict[str, Any] = {}
        if target := text("TargetFilename"):
            file_data["path"] = target
            file_data["name"] = PureWindowsPath(target).name
        if event_id in {11, 15, 23, 26} and hashes:
            file_data["hash"] = hashes
        elif hashes:
            process["hash"] = hashes

        source_ip = text("SourceIp")
        destination_ip = text("DestinationIp")
        network_transport = text("Protocol").lower()
        network_application = ""
        query_name = text("QueryName")
        if event_id == 22 and query_name:
            network_application = "dns"

        dns_data: dict[str, Any] = {}
        if query_name:
            dns_data["question"] = {"name": query_name}
            if results := text("QueryResults"):
                dns_data["answers"] = results
            if status := text("QueryStatus"):
                dns_data["response_code"] = status

        registry_path = text("TargetObject")
        message_parts = [action]
        if process.get("executable"):
            message_parts.append(str(process["executable"]))
        if event_id == 3 and destination_ip:
            message_parts.append(f"-> {destination_ip}:{port('DestinationPort') or ''}".rstrip(":"))
        if query_name:
            message_parts.append(query_name)
        if registry_path:
            message_parts.append(registry_path)
        if file_data.get("path"):
            message_parts.append(str(file_data["path"]))

        tags = []
        if rule_name := text("RuleName"):
            if rule_name != "-":
                tags.append(f"sysmon-rule:{rule_name}")

        return CanonicalEvent(
            id=stable_event_id(self.source_type, raw, timestamp),
            timestamp=parse_timestamp(timestamp).isoformat(),
            source_type=self.source_type,
            source_dataset=str(defaults.get("dataset") or "windows.sysmon"),
            kind="event",
            category=list(dict.fromkeys(categories)),
            severity="info",
            message=" ".join(part for part in message_parts if part).strip(),
            host_name=text("Hostname", "Computer", "ComputerName", "host_name")
            or str(defaults.get("host_name", "")),
            source_ip=source_ip,
            source_port=port("SourcePort"),
            destination_ip=destination_ip,
            destination_port=port("DestinationPort"),
            network_transport=network_transport,
            network_application=network_application,
            user_name=text("User", "SubjectUserName", "TargetUserName"),
            process=process,
            file=file_data,
            dns=dns_data,
            rule={},
            tags=tags,
            raw=raw,
            scenario_id=scenario_id,
            correlation={"registry_path": registry_path} if registry_path else {},
        )


class ECSAdapter:
    """Normalize an already ECS-like Wazuh Indexer document.

    This adapter is the bridge for the later live repository: the alert-analysis
    engine does not need to change when fixtures are replaced by Wazuh Indexer.
    """

    source_type = "ecs"

    def normalize(self, raw: dict[str, Any], *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
        destination = raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
        host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
        network = raw.get("network") if isinstance(raw.get("network"), dict) else {}
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
        timestamp = str(raw.get("@timestamp", ""))
        categories = event.get("category", [])
        if not isinstance(categories, list):
            categories = [str(categories)] if categories else []
        severity = str(event.get("severity", "medium")).lower()
        if severity.isdigit():
            severity = "high" if int(severity) >= 70 else "medium"

        return CanonicalEvent(
            id=str(event.get("id") or raw.get("_id") or stable_event_id(self.source_type, raw, timestamp)),
            timestamp=parse_timestamp(timestamp).isoformat(),
            source_type=str(event.get("provider") or raw.get("data_stream", {}).get("dataset") or self.source_type),
            source_dataset=str(raw.get("data_stream", {}).get("dataset") or event.get("dataset") or "ecs"),
            kind=str(event.get("kind", "event")),
            category=[str(value) for value in categories],
            severity=severity,
            message=str(raw.get("message", "")),
            host_name=str(host.get("name", "")),
            source_ip=str(source.get("ip", "")),
            source_port=int(source["port"]) if source.get("port") is not None else None,
            destination_ip=str(destination.get("ip", "")),
            destination_port=int(destination["port"]) if destination.get("port") is not None else None,
            network_transport=str(network.get("transport", "")),
            network_application=str(network.get("application", "")),
            user_name=str(user.get("name", "")),
            process=raw.get("process") if isinstance(raw.get("process"), dict) else {},
            file=raw.get("file") if isinstance(raw.get("file"), dict) else {},
            http=raw.get("http") if isinstance(raw.get("http"), dict) else {},
            dns=raw.get("dns") if isinstance(raw.get("dns"), dict) else {},
            outcome=str(event.get("outcome", "")),
            rule=rule,
            tags=[str(value) for value in raw.get("tags", [])] if isinstance(raw.get("tags"), list) else [],
            raw=raw.get("event", {}).get("original", raw),
            scenario_id=scenario_id,
        )
