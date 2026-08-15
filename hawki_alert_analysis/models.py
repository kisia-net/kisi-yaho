from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

HOSTNAME_IS_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def parse_timestamp(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("timestamp is required")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Suricata commonly emits +0000 rather than +00:00.
    if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(slots=True)
class CanonicalEvent:
    id: str
    timestamp: str
    source_type: str
    source_dataset: str
    kind: str
    category: list[str] = field(default_factory=list)
    severity: str = "info"
    # ECS event.outcome. Mapped from the producer when it states one; never
    # inferred from what the event appears to mean.
    outcome: str = ""
    message: str = ""
    host_name: str = ""
    source_ip: str = ""
    source_port: int | None = None
    destination_ip: str = ""
    destination_port: int | None = None
    network_transport: str = ""
    network_application: str = ""
    user_name: str = ""
    process: dict[str, Any] = field(default_factory=dict)
    file: dict[str, Any] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    rule: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    raw: Any = None
    scenario_id: str = ""
    correlation: dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp_dt(self) -> datetime:
        return parse_timestamp(self.timestamp)

    def observables(self) -> list[dict[str, str]]:
        """Extract indicator-shaped values with the field they came from.

        Only structured fields are read. Values keep their semantic role: a URI
        is reported as a URI, never re-typed into something a lookup happens to
        accept.
        """
        found: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(observable_type: str, value: Any, field_name: str) -> None:
            text = str(value or "").strip()
            if not text:
                return
            key = (observable_type, text.lower())
            if key in seen:
                return
            seen.add(key)
            found.append({"type": observable_type, "value": text, "field": field_name})

        def add_ip(value: Any, field_name: str) -> None:
            text = str(value or "").strip()
            if not text:
                return
            add("ipv6-addr" if ":" in text else "ipv4-addr", text, field_name)

        add_ip(self.source_ip, "source.ip")
        add_ip(self.destination_ip, "destination.ip")

        request = self.http.get("request") if isinstance(self.http.get("request"), dict) else {}
        host = str(request.get("host", "")).strip()
        if host:
            # A Host header holding an address is still an address.
            if HOSTNAME_IS_IPV4.match(host):
                add_ip(host, "http.request.host")
            else:
                add("domain-name", host, "http.request.host")
        add("url", request.get("uri"), "http.request.uri")

        question = self.dns.get("question") if isinstance(self.dns.get("question"), dict) else {}
        queried = str(question.get("name") or self.dns.get("name") or "").strip()
        if queried:
            # A resolved name is an observable in its own right, whether or not
            # the lookup succeeded.
            if HOSTNAME_IS_IPV4.match(queried):
                add_ip(queried, "dns.question.name")
            else:
                add("domain-name", queried, "dns.question.name")

        for container, prefix in ((self.file, "file"), (self.process, "process")):
            if not isinstance(container, dict):
                continue
            hashes = container.get("hash") if isinstance(container.get("hash"), dict) else {}
            for algorithm in ("sha256", "sha1", "md5"):
                value = hashes.get(algorithm) or container.get(algorithm)
                add(f"file-hash-{algorithm}", value, f"{prefix}.hash.{algorithm}")

        return found

    def entity_values(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {
            "hosts": [],
            "users": [],
            "source_ips": [],
            "destination_ips": [],
            "files": [],
            "processes": [],
        }
        if self.host_name:
            result["hosts"].append(self.host_name)
        if self.user_name:
            result["users"].append(self.user_name)
        if self.source_ip:
            result["source_ips"].append(self.source_ip)
        if self.destination_ip:
            result["destination_ips"].append(self.destination_ip)
        if self.file.get("path"):
            result["files"].append(str(self.file["path"]))
        if self.process.get("name"):
            result["processes"].append(str(self.process["name"]))
        return result

    def to_dict(self, *, include_raw: bool = True) -> dict[str, Any]:
        data = {
            "id": self.id,
            "@timestamp": self.timestamp,
            "source_type": self.source_type,
            "source_dataset": self.source_dataset,
            "event": {
                key: value
                for key, value in {
                    "kind": self.kind,
                    "category": self.category,
                    "severity": self.severity,
                    "outcome": self.outcome,
                }.items()
                if value or key != "outcome"
            },
            "message": self.message,
            "host": {"name": self.host_name} if self.host_name else {},
            "source": {
                key: value
                for key, value in {"ip": self.source_ip, "port": self.source_port}.items()
                if value not in {"", None}
            },
            "destination": {
                key: value
                for key, value in {"ip": self.destination_ip, "port": self.destination_port}.items()
                if value not in {"", None}
            },
            "network": {
                key: value
                for key, value in {
                    "transport": self.network_transport,
                    "application": self.network_application,
                }.items()
                if value
            },
            "user": {"name": self.user_name} if self.user_name else {},
            "process": self.process,
            "file": self.file,
            "http": self.http,
            "dns": self.dns,
            "rule": self.rule,
            "tags": self.tags,
            "scenario_id": self.scenario_id,
            "correlation": self.correlation,
        }
        if include_raw:
            data["event.original"] = self.raw
        return data


@dataclass(slots=True)
class AlertCase:
    id: str
    scenario_id: str
    title: str
    trigger: CanonicalEvent
    related_events: list[CanonicalEvent]
    entities: dict[str, list[str]]
    time_window: dict[str, str]
    # Enrichment blocks. Typed as Any to keep models.py free of imports from the
    # asset/intel collectors, which themselves depend on CanonicalEvent.
    asset_matches: list[Any] = field(default_factory=list)
    unresolved_assets: list[str] = field(default_factory=list)
    intel_matches: list[Any] = field(default_factory=list)
    intel_stats: dict[str, Any] = field(default_factory=dict)

    @property
    def alerts(self) -> list[CanonicalEvent]:
        """The triggering alert first, then any correlated alerts."""
        return [
            self.trigger,
            *[event for event in self.related_events if event.kind == "alert"],
        ]

    @property
    def raw_events(self) -> list[CanonicalEvent]:
        """Correlated non-alert telemetry, ordered by time."""
        return sorted(
            [event for event in self.related_events if event.kind != "alert"],
            key=lambda item: item.timestamp_dt,
        )

    @property
    def timeline(self) -> list[CanonicalEvent]:
        return sorted(
            [self.trigger, *self.related_events],
            key=lambda item: item.timestamp_dt,
        )

    def to_dict(self, *, include_raw: bool = True) -> dict[str, Any]:
        return {
            "case_id": self.id,
            "scenario_id": self.scenario_id,
            "title": self.title,
            "trigger": self.trigger.to_dict(include_raw=include_raw),
            "related_events": [
                event.to_dict(include_raw=include_raw)
                for event in self.related_events
            ],
            "entities": self.entities,
            "time_window": self.time_window,
            "timeline": [
                event.to_dict(include_raw=False)
                for event in self.timeline
            ],
            "assets": [match.to_dict() for match in self.asset_matches],
            "unresolved_assets": self.unresolved_assets,
            "threat_intelligence": [match.to_dict() for match in self.intel_matches],
            "threat_intelligence_stats": self.intel_stats,
        }

    def to_llm_context(self, *, max_related: int = 30) -> dict[str, Any]:
        """Build the four-block metadata bundle handed to the LLM/SLM.

        Imported here rather than at module scope because the bundle builder
        depends on this module.
        """
        from .bundle import build_evidence_bundle

        return build_evidence_bundle(self, max_related=max_related)
