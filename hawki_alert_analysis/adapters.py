from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
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
            rule=rule,
            tags=[str(value) for value in raw.get("tags", [])] if isinstance(raw.get("tags"), list) else [],
            raw=raw.get("event", {}).get("original", raw),
            scenario_id=scenario_id,
        )
