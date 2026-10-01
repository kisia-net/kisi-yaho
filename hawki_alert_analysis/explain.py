"""Explanation of an AI judgement (판단 근거, XAI), computed in code.

The model writes claims and cites evidence ids. This module does not ask the
model to explain itself -- a model's account of its own reasoning is one more
generated text. It checks the claims against the evidence package instead:

1. every supporting / contradictory statement, with the ids it cites resolved
   to the actual record (time, host, rule, original log, why it was retrieved);
   a cited id that is not in the package is marked, never hidden;
2. how much of the package was used: cited records vs. records supplied;
3. the model's severity next to HAW-KI's deterministic priority band, and
   whether they agree -- a disagreement is shown, not resolved;
4. the priority factors, exactly as computed in priority.py;
5. what else shaped the input: the evidence agent's tool calls and the
   earlier analyst verdicts placed in the context.

So "why did HAW-KI say this?" is answered by data an analyst can check, and
"is this explanation also made up?" has a precise answer: the statements are
the model's; the links, statuses, counts and factors are not.
"""

from __future__ import annotations

from typing import Any

EXPLANATION_SCHEMA = "hawki.explanation/v1"
MAX_LOG_CHARS = 500

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
# The severities a well-calibrated analysis would usually give each band.
BAND_EXPECTED_SEVERITY = {
    "P1": ("high", "critical"),
    "P2": ("medium", "high"),
    "P3": ("low", "medium"),
    "P4": ("info", "low"),
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def evidence_records(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every citable record in the package, keyed by the id the model sees."""
    records: dict[str, dict[str, Any]] = {}
    schema = str(bundle.get("schema") or "")

    if schema.startswith("hawki.wazuh.live-evidence/"):
        trigger = _dict(bundle.get("trigger"))
        items = ([trigger] if trigger else []) + [
            item for item in bundle.get("investigation_context") or [] if isinstance(item, dict)
        ]
        for item in items:
            evidence_id = str(item.get("evidence_id") or "")
            if not evidence_id:
                continue
            rule = _dict(item.get("rule"))
            agent = _dict(item.get("agent"))
            data = _dict(item.get("data"))
            provenance = _dict(item.get("provenance"))
            retrieval = _dict(item.get("retrieval"))
            records[evidence_id] = {
                "evidence_id": evidence_id,
                "timestamp": item.get("timestamp"),
                "host": agent.get("name"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": rule.get("description"),
                "source_ip": data.get("srcip") or data.get("src_ip"),
                "log": str(item.get("full_log") or "")[:MAX_LOG_CHARS],
                "origin": "trigger" if evidence_id == "TRIGGER" else (retrieval.get("origin") or "same_agent"),
                "source_kind": provenance.get("source_kind"),
                "retrieval_reasons": list(provenance.get("retrieval_reason") or retrieval.get("relevance_reasons") or [])[:5],
            }
        return records

    # Legacy fixture bundle: alerts first (the trigger is the first), then events.
    metadata = _dict(bundle.get("metadata"))
    first = True
    for block_name in ("security_alerts", "security_events"):
        for item in _dict(metadata.get(block_name)).get("items") or []:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            host = _dict(item.get("host"))
            source = _dict(item.get("source"))
            rule = _dict(item.get("rule"))
            records[str(item["id"])] = {
                "evidence_id": str(item["id"]),
                "timestamp": item.get("@timestamp"),
                "host": host.get("name"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": item.get("message"),
                "source_ip": source.get("ip"),
                "log": str(item.get("message") or "")[:MAX_LOG_CHARS],
                "origin": "trigger" if first else ("correlated_alert" if block_name == "security_alerts" else "correlated_event"),
                "source_kind": item.get("source_type"),
                "retrieval_reasons": list(_dict(item.get("correlation")).get("reasons") or [])[:5],
            }
            first = False
    return records


def _claim_status(cited: list[str], unknown: list[str]) -> str:
    if not cited:
        return "uncited"
    if not unknown:
        return "grounded"
    if len(unknown) < len(cited):
        return "partial"
    return "ungrounded"


def severity_agreement(model_level: str, band: str) -> str:
    expected = BAND_EXPECTED_SEVERITY.get(str(band or "").upper())
    level = str(model_level or "").lower()
    if not expected or level not in SEVERITY_ORDER:
        return "unknown"
    low, high = (SEVERITY_ORDER.index(value) for value in expected)
    position = SEVERITY_ORDER.index(level)
    if position < low:
        return "model_lower"
    if position > high:
        return "model_higher"
    return "consistent"


def build_explanation(
    result: dict[str, Any],
    bundle: dict[str, Any],
    *,
    priority: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assessment = _dict(result.get("assessment"))
    records = evidence_records(bundle)
    priority = priority or _dict(bundle.get("priority"))

    claims = []
    cited_anywhere: set[str] = set()
    for kind, section in (("supporting", "supporting_evidence"), ("contradictory", "contradictory_evidence")):
        for entry in assessment.get(section) or []:
            if not isinstance(entry, dict) or not entry.get("statement"):
                continue
            cited = [str(value) for value in entry.get("event_ids") or []]
            unknown = [value for value in cited if value not in records]
            cited_anywhere.update(value for value in cited if value in records)
            claims.append({
                "kind": kind,
                "statement": str(entry["statement"])[:600],
                "event_ids": cited,
                "unknown_event_ids": unknown,
                "status": _claim_status(cited, unknown),
            })

    counts = {status: sum(1 for claim in claims if claim["status"] == status)
              for status in ("grounded", "partial", "ungrounded", "uncited")}
    severity = _dict(assessment.get("severity"))
    confidence = _dict(assessment.get("confidence"))
    band = priority.get("band")

    feedback = _dict(bundle.get("analyst_feedback"))
    agent = _dict(bundle.get("agent_retrieval"))
    profile = _dict(_dict(bundle.get("retrieval")).get("profile"))

    return {
        "schema": EXPLANATION_SCHEMA,
        "method": "deterministic: the model's cited ids are matched to the evidence package in code",
        "summary": {
            "claims": len(claims),
            **counts,
            "evidence_total": len(records),
            "evidence_cited": len(cited_anywhere),
            "observations": len(assessment.get("confirmed_observations") or []),
            "missing_sections": list(_dict(result.get("assessment_review")).get("missing_sections") or []),
        },
        "conclusion": {
            "severity": {"level": severity.get("level") or None, "rationale": str(severity.get("rationale") or "")[:600]},
            "confidence": {"level": confidence.get("level") or None, "rationale": str(confidence.get("rationale") or "")[:600]},
            "priority": {"band": band, "score": priority.get("score")},
            "agreement": severity_agreement(severity.get("level"), band),
            "expected_severity": list(BAND_EXPECTED_SEVERITY.get(str(band or "").upper(), ())),
        },
        "claims": claims,
        # Cited records first, so the page can show the trail without the rest.
        "evidence": {
            evidence_id: {**record, "cited": evidence_id in cited_anywhere}
            for evidence_id, record in sorted(records.items(), key=lambda pair: (pair[0] not in cited_anywhere, pair[0] != "TRIGGER"))
        },
        "priority_factors": list(priority.get("factors") or [])[:10],
        "inputs": {
            "correlation_profile": {key: profile.get(key) for key in ("name", "seconds_before", "seconds_after", "cross_agent") if key in profile},
            "agent_calls": len(agent.get("calls") or []),
            "agent_added_evidence": list(agent.get("added_evidence_ids") or []),
            "agent_stopped": agent.get("stopped"),
            "context_fit": {
                key: _dict(_dict(bundle.get("retrieval")).get("context_fit")).get(key)
                for key in ("dropped_evidence_ids", "shortened_fields", "original_chars", "final_chars")
            } if _dict(_dict(bundle.get("retrieval")).get("context_fit")) else None,
            "feedback": [
                {key: item.get(key) for key in ("feedback_id", "verdict", "recorded_at", "match")}
                for item in feedback.get("items") or []
                if isinstance(item, dict)
            ],
        },
    }
