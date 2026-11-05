"""Deterministic alert priority (자산 우선순위).

The score is computed here, in code, and never by the model. Two reasons:

1. It can be explained line by line. Every point in the score comes from a
   named factor, so an analyst (and the XAI view later) can see exactly why an
   alert ranked where it did.
2. It cannot be talked into a different answer. Text inside a log cannot raise
   or lower a number that the model never gets to write.

Inputs are the Wazuh rule level of the trigger, the inventory record of the
asset the trigger is about, and the strongest threat-intelligence match. Inventory values are business context, not a
verdict: a "critical" asset does not make the alert malicious, it makes a
mistake on that asset more expensive.
"""

from __future__ import annotations

from typing import Any

# Wazuh rule levels run 0-15. Four points per level keeps the level as the
# largest single factor (max 60) so an unknown asset never hides a level-12
# detection.
LEVEL_POINTS_PER_LEVEL = 4
LEVEL_MAX = 15

CRITICALITY_POINTS = {
    "critical": 25,
    "high": 18,
    "medium": 10,
    "low": 3,
}
# An address or host that is not in the inventory is itself worth a look:
# unmanaged machines are where attackers like to sit.
UNRESOLVED_ASSET_POINTS = 8

EXPOSURE_POINTS = {
    "internet_facing": 10,
    "dmz": 7,
    "partner_facing": 7,
    "internal": 3,
    "isolated": 0,
}

SENSITIVE_DATA_POINTS = 5
SENSITIVE_DATA_CLASSES = {"restricted", "confidential", "secret"}

# Threat intelligence. One factor, taken from the strongest live match, so a
# feed that lists the same IP three times cannot stack points. A known-bad
# address on the trigger is worth about five rule levels: a level-5 web alert
# from a high-confidence C2 address lands in P1 on an internet-facing asset.
CTI_MALICIOUS_HIGH_CONFIDENCE = 70
CTI_POINTS = {
    ("malicious", True): 20,   # confidence >= CTI_MALICIOUS_HIGH_CONFIDENCE
    ("malicious", False): 12,
    ("suspicious", True): 6,
    ("suspicious", False): 6,
}
# Seen only in the surrounding context, not on the alert itself: the link to
# this alert is weaker, so the points are halved.
CTI_CONTEXT_ONLY_DIVISOR = 2

# Upper bounds (inclusive lower edge) for each band.
PRIORITY_BANDS = (
    (70, "P1"),
    (50, "P2"),
    (30, "P3"),
    (0, "P4"),
)

# Roles that mean "the alert is about this asset", as opposed to the asset
# merely showing up as the other end of a connection.
TARGET_ROLES = {"event_host", "destination_ip"}

# Reconnaissance and error responses (출처 흐름 types "웹 스캔·정찰" and
# "웹 오류 응답"). An internet-facing asset is scanned all day, so its asset
# points would put every level-10 "multiple 400 errors" alert on web-01 in P1
# (40 + 33 = 73) and bury the alerts that matter. These alerts stop at the top
# of P3 unless a known malicious address sent them itself. The cut is a named
# factor with negative points, so the factors still add up to the score.
RECONNAISSANCE_TYPES = {"scan": "웹 스캔·정찰", "web_error": "웹 오류 응답"}
RECONNAISSANCE_CEILING_BAND = "P3"
RECONNAISSANCE_FACTOR = "reconnaissance_ceiling"


def _rule_level(trigger: dict[str, Any]) -> int:
    rule = trigger.get("rule") if isinstance(trigger.get("rule"), dict) else {}
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    return max(0, min(level, LEVEL_MAX))


def _band(score: int) -> str:
    for floor, label in PRIORITY_BANDS:
        if score >= floor:
            return label
    return PRIORITY_BANDS[-1][1]


def _target_assets(asset_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assets the trigger alert is about, most critical first."""
    targets = []
    for item in asset_matches:
        match = item.get("match") if isinstance(item.get("match"), dict) else {}
        roles = set(match.get("observed_roles") or [])
        if match.get("on_trigger_alert") and roles & TARGET_ROLES:
            targets.append(item)

    order = list(CRITICALITY_POINTS)
    return sorted(
        targets,
        key=lambda item: (
            order.index(item.get("criticality"))
            if item.get("criticality") in order
            else len(order)
        ),
    )


def _cti_factor(intel_matches: list[dict[str, Any]]) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    for item in intel_matches:
        match = item.get("match") if isinstance(item.get("match"), dict) else {}
        if match.get("indicator_expired"):
            # Reported to the model, but an expired listing does not raise
            # the priority.
            continue
        verdict = str(item.get("verdict") or "").lower()
        try:
            confidence = int(item.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0
        points = CTI_POINTS.get(
            (verdict, confidence >= CTI_MALICIOUS_HIGH_CONFIDENCE), 0
        )
        on_trigger = bool(match.get("on_trigger_alert"))
        if not on_trigger:
            points //= CTI_CONTEXT_ONLY_DIVISOR
        if points and (best is None or points > best["points"]):
            best = {
                "factor": "threat_intel_match",
                "indicator_id": item.get("id"),
                "value": f"{verdict} ({confidence}) {match.get('matched_value', '')}".strip(),
                "verdict": verdict,
                "on_trigger": on_trigger,
                "points": points,
            }
    return best


def alert_kind(trigger: dict[str, Any]) -> str:
    """The 출처 흐름 detection type of a Wazuh event or an alert-queue item."""
    from .source_flow import classify

    rule = trigger.get("rule") if isinstance(trigger.get("rule"), dict) else {}
    item = {
        "groups": trigger.get("groups") or rule.get("groups") or [],
        "rule_id": trigger.get("rule_id") or rule.get("id") or "",
        "decoder": trigger.get("decoder") or "",
    }
    return classify(item)[1]


def _malicious_sender(factors: list[dict[str, Any]]) -> bool:
    for factor in factors:
        if factor.get("factor") != "threat_intel_match" or not factor.get("on_trigger"):
            continue
        verdict = factor.get("verdict") or str(factor.get("value") or "").split(" ", 1)[0]
        if str(verdict).lower() == "malicious":
            return True
    return False


def _band_top(band: str) -> int:
    """Highest score that still falls in ``band``."""
    floors = [floor for floor, _ in PRIORITY_BANDS]
    labels = [label for _, label in PRIORITY_BANDS]
    position = labels.index(band)
    return floors[position - 1] - 1 if position else 100


def apply_reconnaissance_ceiling(factors: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    """Factors with the reconnaissance cut added when it applies.

    Also used to re-score stored reports, so an earlier cut is replaced, not
    stacked.
    """
    factors = [factor for factor in factors if factor.get("factor") != RECONNAISSANCE_FACTOR]
    if kind not in RECONNAISSANCE_TYPES or _malicious_sender(factors):
        return factors
    score = min(100, sum(int(factor.get("points") or 0) for factor in factors))
    ceiling = _band_top(RECONNAISSANCE_CEILING_BAND)
    if score <= ceiling:
        return factors
    return factors + [{
        "factor": RECONNAISSANCE_FACTOR,
        "value": f"{RECONNAISSANCE_TYPES[kind]} · {RECONNAISSANCE_CEILING_BAND} 상한",
        "kind": kind,
        "points": ceiling - score,
    }]


def score_and_band(factors: list[dict[str, Any]]) -> tuple[int, str]:
    score = max(0, min(100, sum(int(factor.get("points") or 0) for factor in factors)))
    return score, _band(score)


def compute_priority(
    trigger: dict[str, Any],
    asset_matches: list[dict[str, Any]],
    *,
    unresolved_identifiers: list[str] | None = None,
    inventory_configured: bool = True,
    intel_matches: list[dict[str, Any]] | None = None,
    intel_configured: bool = False,
) -> dict[str, Any]:
    """Return a 0-100 priority score with a factor-by-factor breakdown."""

    factors: list[dict[str, Any]] = []

    level = _rule_level(trigger)
    factors.append({
        "factor": "wazuh_rule_level",
        "value": level,
        "points": level * LEVEL_POINTS_PER_LEVEL,
    })

    targets = _target_assets(asset_matches)
    primary = targets[0] if targets else None

    if primary is not None:
        criticality = str(primary.get("criticality") or "").lower()
        factors.append({
            "factor": "asset_criticality",
            "asset_id": primary.get("id"),
            "value": criticality or "unknown",
            "points": CRITICALITY_POINTS.get(criticality, 0),
        })

        exposure = str(primary.get("exposure") or "").lower()
        factors.append({
            "factor": "asset_exposure",
            "asset_id": primary.get("id"),
            "value": exposure or "unknown",
            "points": EXPOSURE_POINTS.get(exposure, 0),
        })

        classification = str(primary.get("data_classification") or "").lower()
        if classification in SENSITIVE_DATA_CLASSES:
            factors.append({
                "factor": "asset_data_classification",
                "asset_id": primary.get("id"),
                "value": classification,
                "points": SENSITIVE_DATA_POINTS,
            })
    elif inventory_configured:
        # Only an inventory that exists can say a host is unknown. Without one,
        # every host would look "unmanaged" and the bonus would mean nothing.
        factors.append({
            "factor": "asset_not_in_inventory",
            "value": list(unresolved_identifiers or [])[:5],
            "points": UNRESOLVED_ASSET_POINTS,
        })

    cti = _cti_factor(list(intel_matches or []))
    if cti is not None:
        factors.append(cti)

    factors = apply_reconnaissance_ceiling(factors, alert_kind(trigger))
    score, band = score_and_band(factors)

    return {
        "schema": "hawki.priority/v1",
        "score": score,
        "band": band,
        "primary_asset_id": primary.get("id") if primary else None,
        "inventory_configured": inventory_configured,
        "threat_intel_configured": intel_configured,
        "factors": factors,
        "method": "deterministic: rule level + asset + threat intel, reconnaissance capped at P3; computed in code",
    }


# -- Alert queue ----------------------------------------------------------
#
# The queue needs a priority for every listed alert before anyone opens one.
# It is computed by the same code the analysis uses (asset match, CTI match,
# compute_priority) from the fields a list item carries, so the badge in the
# queue and the priority in the analysis agree for the same alert.

# Sources without a Wazuh rule level (fixture scenarios, other adapters) give
# a severity word; it is placed at the bottom of the matching Wazuh band.
SEVERITY_AS_LEVEL = {"critical": 15, "high": 12, "medium": 7, "low": 3, "info": 1, "informational": 1}


def priority_for_alert_item(
    item: dict[str, Any],
    *,
    asset_inventory: Any,
    threat_intel_feed: Any,
) -> dict[str, Any]:
    from .assets import NullAssetInventory, live_observed_values, match_live_assets
    from .threat_intel import NullThreatIntelFeed, match_live_indicators

    level = item.get("rule_level")
    derived = False
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = SEVERITY_AS_LEVEL.get(str(item.get("severity") or "").lower(), 0)
        derived = True

    host = str(item.get("host") or "")
    trigger = {
        "evidence_id": "TRIGGER",
        "rule": {"level": level, "id": str(item.get("rule_id") or ""), "groups": list(item.get("groups") or [])},
        "decoder": item.get("decoder") or item.get("source") or "",
        "agent": {"name": host, "ip": str(item.get("agent_ip") or "")},
        "data": {"srcip": str(item.get("source_ip") or "")},
    }

    inventory = asset_inventory or NullAssetInventory()
    feed = threat_intel_feed or NullThreatIntelFeed()
    inventory_configured = not isinstance(inventory, NullAssetInventory)

    asset_matches, _ = match_live_assets(inventory, [trigger])
    intel_matches, _ = match_live_indicators(feed, [trigger])
    unresolved = [
        value
        for value, role in live_observed_values(trigger)
        if role in TARGET_ROLES and inventory.lookup(value) is None
    ]
    result = compute_priority(
        trigger,
        [match.to_dict() for match in asset_matches],
        unresolved_identifiers=unresolved,
        inventory_configured=inventory_configured,
        intel_matches=[match.to_dict() for match in intel_matches],
        intel_configured=not isinstance(feed, NullThreatIntelFeed),
    )
    if derived and result["factors"]:
        result["factors"][0]["factor"] = "source_severity"
        result["factors"][0]["value"] = str(item.get("severity") or "unknown")
    return {key: result[key] for key in ("score", "band", "primary_asset_id", "factors")}
