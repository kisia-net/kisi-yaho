from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import AlertCase, CanonicalEvent


def correlation_score(trigger: CanonicalEvent, candidate: CanonicalEvent, *, window_seconds: int) -> tuple[int, list[str]]:
    if trigger.id == candidate.id:
        return 0, []

    delta = abs((candidate.timestamp_dt - trigger.timestamp_dt).total_seconds())
    if delta > window_seconds:
        return 0, []

    score = 1  # Temporal proximity alone is weak evidence.
    reasons = [f"within {int(delta)}s"]

    if trigger.host_name and trigger.host_name == candidate.host_name:
        score += 5
        reasons.append("same host")
    if trigger.source_ip and trigger.source_ip in {candidate.source_ip, candidate.destination_ip}:
        score += 4
        reasons.append("shared trigger source IP")
    if trigger.destination_ip and trigger.destination_ip in {candidate.source_ip, candidate.destination_ip}:
        score += 4
        reasons.append("shared trigger destination IP")
    if trigger.user_name and trigger.user_name == candidate.user_name:
        score += 2
        reasons.append("same user")

    trigger_flow = trigger.correlation.get("flow_id")
    candidate_flow = candidate.correlation.get("flow_id")
    if trigger_flow and candidate_flow and trigger_flow == candidate_flow:
        score += 7
        reasons.append("same Suricata flow_id")

    if trigger.network_application and trigger.network_application == candidate.network_application:
        score += 1
        reasons.append("same application protocol")

    return score, reasons


def aggregate_entities(events: Iterable[CanonicalEvent]) -> dict[str, list[str]]:
    buckets: dict[str, set[str]] = defaultdict(set)
    for event in events:
        for key, values in event.entity_values().items():
            buckets[key].update(value for value in values if value)
    return {key: sorted(values) for key, values in buckets.items()}


def build_case(
    *,
    case_id: str,
    scenario_id: str,
    title: str,
    trigger: CanonicalEvent,
    events: list[CanonicalEvent],
    window_seconds: int = 300,
    minimum_score: int = 2,
    max_events: int = 50,
) -> AlertCase:
    ranked: list[tuple[int, CanonicalEvent, list[str]]] = []
    for candidate in events:
        score, reasons = correlation_score(trigger, candidate, window_seconds=window_seconds)
        if score >= minimum_score:
            candidate.correlation = {**candidate.correlation, "score": score, "reasons": reasons}
            ranked.append((score, candidate, reasons))

    ranked.sort(key=lambda item: (-item[0], item[1].timestamp_dt))
    selected = [item[1] for item in ranked[:max_events]]
    timeline_events = [trigger, *selected]
    start = min(event.timestamp_dt for event in timeline_events).isoformat()
    end = max(event.timestamp_dt for event in timeline_events).isoformat()

    return AlertCase(
        id=case_id,
        scenario_id=scenario_id,
        title=title,
        trigger=trigger,
        related_events=selected,
        entities=aggregate_entities(timeline_events),
        time_window={"start": start, "end": end},
    )
