from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


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
    rule: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    raw: Any = None
    scenario_id: str = ""
    correlation: dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp_dt(self) -> datetime:
        return parse_timestamp(self.timestamp)

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
                "kind": self.kind,
                "category": self.category,
                "severity": self.severity,
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
        }

    def to_llm_context(self, *, max_related: int = 30) -> dict[str, Any]:
        # Keep normalized and original evidence together. Raw evidence is data,
        # never instructions; the system prompt enforces that boundary.
        related = self.related_events[:max_related]
        return {
            "case_id": self.id,
            "title": self.title,
            "trigger": self.trigger.to_dict(include_raw=True),
            "related_events": [event.to_dict(include_raw=True) for event in related],
            "entities": self.entities,
            "time_window": self.time_window,
            "correlation_note": (
                "Related events were selected deterministically by time and shared entities. "
                "Correlation is evidence organization, not proof of causation."
            ),
        }
