"""Deterministic security-control outcome normalization."""

from __future__ import annotations

import re
from typing import Any

CONTROL_OUTCOME_SCHEMA = "hawki.control-outcome/v1"


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _lookup(data: dict[str, Any], path: str) -> Any:
    if path in data:
        return data[path]
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _http_status(data: dict[str, Any], full_log: str) -> int | None:
    try:
        status = int(data.get("id"))
        if 100 <= status <= 599:
            return status
    except (TypeError, ValueError):
        pass

    match = re.search(r"\"\s+([1-5]\d\d)\s+", full_log)
    if match:
        return int(match.group(1))

    match = re.search(
        r"\bwith\s+code\s+([1-5]\d\d)\b",
        full_log,
        flags=re.IGNORECASE,
    )
    return int(match.group(1)) if match else None


def derive_control_outcome(evidence: dict[str, Any]) -> dict[str, Any]:
    data = _mapping(evidence.get("data"))
    rule = _mapping(evidence.get("rule"))
    decoder = _mapping(evidence.get("decoder"))

    full_log = str(evidence.get("full_log") or "")
    lower_log = full_log.lower()
    location = str(evidence.get("location") or "").lower()
    decoder_name = str(decoder.get("name") or "").lower()

    raw_groups = rule.get("groups")
    groups = {
        str(v).lower() for v in raw_groups
    } if isinstance(raw_groups, list) else set()

    basis: list[str] = []
    detection_status = "UNKNOWN"
    if rule.get("id"):
        detection_status = "DETECTED"
        basis.append("wazuh_rule_present")

    http_status = _http_status(data, full_log)
    if http_status is not None:
        basis.append(f"http_status:{http_status}")

    preventive_control = None
    control_status = "UNKNOWN"

    if "modsecurity" in groups or "modsecurity:" in lower_log:
        preventive_control = "modsecurity"
        if "access denied with code" in lower_log:
            control_status = "BLOCKED"
            basis.append("modsecurity_access_denied")

    elif (
        "access forbidden by rule" in lower_log
        and ("nginx" in groups or decoder_name == "nginx-errorlog")
    ):
        preventive_control = "nginx"
        control_status = "BLOCKED"
        basis.append("nginx_access_forbidden_by_rule")

    elif "suricata" in groups or "suricata" in location:
        preventive_control = "suricata"
        action = (
            _lookup(data, "alert.action")
            or _lookup(data, "event.alert.action")
        )
        action = str(action or "").strip().lower()
        if action in {"blocked", "drop", "dropped", "reject", "rejected"}:
            control_status = "BLOCKED"
            basis.append(f"suricata_alert_action:{action}")
        elif action in {"allowed", "allow", "pass"}:
            control_status = "NOT_BLOCKED"
            basis.append(f"suricata_alert_action:{action}")

    execution_status = "UNKNOWN"
    event_id = (
        _lookup(data, "system.eventID")
        or _lookup(data, "system.eventId")
        or _lookup(data, "eventdata.eventID")
    )

    if str(event_id or "").strip() == "1":
        execution_status = "OBSERVED"
        basis.append("sysmon_process_create")

    return {
        "schema": CONTROL_OUTCOME_SCHEMA,
        "evidence_id": str(evidence.get("evidence_id") or ""),
        "observation_status": "OBSERVED",
        "detection_status": detection_status,
        "preventive_control": preventive_control,
        "control_status": control_status,
        "http_status": http_status,
        "execution_status": execution_status,
        "compromise_status": "UNKNOWN",
        "derivation": {
            "method": "deterministic",
            "basis": basis,
        },
    }
