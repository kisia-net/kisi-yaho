"""Threat intelligence (위협 인텔리전스) collection and case enrichment.

This is one of the four metadata blocks delivered to the LLM/SLM. Only the feed
implementation knows where indicators come from; a MISP, OpenCTI, or OTX client
can replace the file-backed feed without touching the enrichment or bundle code.

Design rules:
- An indicator match is external context, never proof. The bundle labels it as
  such so the model does not upgrade "IP appears in a feed" to "compromise
  confirmed".
- Absence of a match is not evidence of benignity, so the number of observables
  checked without a hit is reported alongside the matches.
- Expired indicators are surfaced with an explicit flag rather than dropped;
  a stale hit is still information an analyst may want.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from .models import CanonicalEvent, parse_timestamp

VERDICT_ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3, "": 4}
UNMATCHED_SAMPLE_SIZE = 12


@dataclass(slots=True)
class ThreatIndicator:
    id: str
    type: str
    value: str
    verdict: str = "unknown"
    confidence: int = 0
    severity: str = ""
    feed: str = ""
    description: str = ""
    categories: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    valid_until: str = ""
    tlp: str = ""
    references: list[str] = field(default_factory=list)

    def is_expired(self, now: datetime | None = None) -> bool:
        if not self.valid_until:
            return False
        try:
            expiry = parse_timestamp(self.valid_until)
        except ValueError:
            return False
        return expiry < (now or datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "feed": self.feed,
            "description": self.description,
            "categories": self.categories,
            "malware_families": self.malware_families,
            "threat_actors": self.threat_actors,
            "mitre_techniques": self.mitre_techniques,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "valid_until": self.valid_until,
            "tlp": self.tlp,
            "references": self.references,
        }


@dataclass(slots=True)
class ThreatMatch:
    """One indicator resolved from an observable, with provenance."""

    indicator: ThreatIndicator
    matched_value: str
    observable_type: str
    observed_fields: list[str] = field(default_factory=list)
    observed_in: list[str] = field(default_factory=list)
    on_trigger: bool = False
    expired: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.indicator.to_dict(),
            "match": {
                "matched_value": self.matched_value,
                "observable_type": self.observable_type,
                "observed_fields": self.observed_fields,
                "observed_in_event_ids": self.observed_in,
                "on_trigger_alert": self.on_trigger,
                "indicator_expired": self.expired,
            },
        }


def indicator_from_record(record: dict[str, Any], *, feed: str = "") -> ThreatIndicator:
    def text(key: str) -> str:
        value = record.get(key, "")
        return "" if value is None else str(value)

    def string_list(key: str) -> list[str]:
        value = record.get(key, [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    value = text("value") or text("indicator")
    if not value:
        raise ValueError("threat indicator record requires a value")

    try:
        confidence = int(record.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0

    return ThreatIndicator(
        id=text("id") or f"ti-{value}",
        type=text("type") or "unknown",
        value=value,
        verdict=(text("verdict") or "unknown").lower(),
        confidence=max(0, min(confidence, 100)),
        severity=text("severity"),
        feed=text("feed") or feed,
        description=text("description"),
        categories=string_list("categories"),
        malware_families=string_list("malware_families"),
        threat_actors=string_list("threat_actors"),
        mitre_techniques=string_list("mitre_techniques"),
        first_seen=text("first_seen"),
        last_seen=text("last_seen"),
        valid_until=text("valid_until"),
        tlp=text("tlp"),
        references=string_list("references"),
    )


class ThreatIntelFeed(Protocol):
    def lookup(self, value: str) -> list[ThreatIndicator]: ...
    def all_indicators(self) -> list[ThreatIndicator]: ...


class FileThreatIntelFeed:
    """Indicator feed backed by JSON files in a directory.

    Each file is either a list of indicator records or an object with an
    `indicators` array.
    """

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self._indicators: list[ThreatIndicator] | None = None
        self._index: dict[str, list[ThreatIndicator]] = {}

    def reload(self) -> None:
        self._indicators = None
        self._index = {}

    def _load(self) -> list[ThreatIndicator]:
        if self._indicators is not None:
            return self._indicators

        indicators: list[ThreatIndicator] = []
        index: dict[str, list[ThreatIndicator]] = {}
        if self.root.exists():
            for path in sorted(self.root.glob("*.json")):
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    records, feed = payload, path.stem
                elif isinstance(payload, dict):
                    records = payload.get("indicators", [])
                    feed = str(payload.get("source", path.stem))
                else:
                    continue
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    indicator = indicator_from_record(record, feed=feed)
                    indicators.append(indicator)
                    index.setdefault(indicator.value.strip().lower(), []).append(indicator)

        self._indicators = indicators
        self._index = index
        return indicators

    def lookup(self, value: str) -> list[ThreatIndicator]:
        self._load()
        key = str(value or "").strip().lower()
        return list(self._index.get(key, [])) if key else []

    def all_indicators(self) -> list[ThreatIndicator]:
        return list(self._load())


class NullThreatIntelFeed:
    """Used when no feed is configured; keeps call sites uniform."""

    def lookup(self, value: str) -> list[ThreatIndicator]:  # noqa: ARG002
        return []

    def all_indicators(self) -> list[ThreatIndicator]:
        return []


def match_indicators(
    feed: ThreatIntelFeed,
    events: Iterable[CanonicalEvent],
    *,
    trigger_id: str = "",
    now: datetime | None = None,
) -> tuple[list[ThreatMatch], dict[str, Any]]:
    """Resolve feed indicators for every observable in the evidence.

    Returns the ordered matches plus statistics describing how much was checked,
    so the model can distinguish "no intelligence" from "not looked up".
    """
    matches: dict[tuple[str, str], ThreatMatch] = {}
    checked: set[tuple[str, str]] = set()
    unmatched: dict[str, None] = {}

    for event in events:
        for observable in event.observables():
            value = observable["value"]
            observable_type = observable["type"]
            field_name = observable["field"]
            checked.add((observable_type, value.lower()))

            hits = feed.lookup(value)
            if not hits:
                unmatched.setdefault(f"{observable_type}:{value}", None)
                continue

            for indicator in hits:
                key = (indicator.id, value.lower())
                match = matches.get(key)
                if match is None:
                    match = ThreatMatch(
                        indicator=indicator,
                        matched_value=value,
                        observable_type=observable_type,
                        expired=indicator.is_expired(now),
                    )
                    matches[key] = match
                if field_name not in match.observed_fields:
                    match.observed_fields.append(field_name)
                if event.id not in match.observed_in:
                    match.observed_in.append(event.id)
                if trigger_id and event.id == trigger_id:
                    match.on_trigger = True

    ordered = sorted(
        matches.values(),
        key=lambda item: (
            item.expired,
            VERDICT_ORDER.get(item.indicator.verdict, 4),
            -item.indicator.confidence,
            item.indicator.id,
        ),
    )
    unmatched_values = sorted(unmatched)
    stats = {
        "observables_checked": len(checked),
        "indicators_matched": len(ordered),
        "observables_without_intelligence_count": len(unmatched_values),
        # Sampled: the full list grows with every URI in the case and would
        # crowd out actual evidence in a small model's context window.
        "observables_without_intelligence": unmatched_values[:UNMATCHED_SAMPLE_SIZE],
        "feed_note": (
            "An indicator match is external context, not proof of compromise. "
            "The absence of a match is not evidence that an observable is benign."
        ),
    }
    return ordered, stats
