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


class SuricataAdapter:
    source_type = "suricata"

    def normalize(self, raw: dict[str, Any], *, scenario_id: str = "", defaults: dict[str, Any] | None = None) -> CanonicalEvent:
        defaults = defaults or {}
        timestamp = str(raw.get("timestamp", ""))
        event_type = str(raw.get("event_type", "event"))
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

        message = rule.get("name") or (
            f"HTTP {http.get('request', {}).get('method', '')} "
            f"{http.get('request', {}).get('uri', '')}"
        ).strip() or f"Suricata {event_type} event"

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
    """Normalize an already ECS-like Elasticsearch document.

    This adapter is the bridge for the later live repository: the alert-analysis
    engine does not need to change when fixtures are replaced by Elasticsearch.
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
