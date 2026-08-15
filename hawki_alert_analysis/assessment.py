"""Structured alert assessment: the shape the model must answer in.

Prose instructions asking a model to "separate observation from inference" are
followed unevenly, especially by a small local model. This module makes the
analytical structure a schema instead: named sections, evidence entries that
cite event ids, and a validator that reports what is missing or ungrounded.

Two rules shape the design:

- Be tolerant when reading. A 20B model returns a bare string where an object
  was requested, or a single item where a list was requested. Normalization
  accepts those rather than discarding the analysis.
- Be strict when reporting. Missing sections and citations that match no event
  in the bundle are surfaced as diagnostics, never silently repaired. An
  analyst has to be able to see that the model cited evidence that does not
  exist.
"""

from __future__ import annotations

from typing import Any

CONFIDENCE_LEVELS = ("low", "medium", "high")
SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")

# Every section the analysis must contain, in presentation order.
TEXT_SECTIONS = ("interpretation", "attack_hypothesis")
LIST_SECTIONS = (
    "confirmed_observations",
    "evidence_gaps",
    "recommended_response",
)
EVIDENCE_SECTIONS = ("supporting_evidence", "contradictory_evidence")
# Sections that must carry content for the assessment to count as complete.
REQUIRED_SECTIONS = (
    "confirmed_observations",
    "interpretation",
    "attack_hypothesis",
    "confidence",
    "severity",
    "affected_entities",
    "attack_techniques",
    "supporting_evidence",
    "evidence_gaps",
    "recommended_searches",
    "recommended_response",
)
# Expected, but legitimately empty: a case can genuinely have no disconfirming
# evidence. Emptiness is reported as a note instead of counting as missing, so
# a well-formed assessment of a clean case does not trigger a correction pass.
OPTIONAL_SECTIONS = ("contradictory_evidence",)

ENTITY_KEYS = ("hosts", "users", "addresses", "processes", "files")

ASSESSMENT_CONTRACT = """The assessment object must contain these keys:
- confirmed_observations: array of strings, each a fact directly readable from the evidence
- interpretation: string, what the observations most plausibly mean
- attack_hypothesis: string, the most plausible sequence, stated as a hypothesis
- confidence: object with level (low|medium|high) and rationale
- severity: object with level (info|low|medium|high|critical) and rationale that accounts for asset criticality and exposure
- affected_entities: object with hosts, users, addresses, processes, files arrays
- attack_techniques: array of objects with id (ATT&CK technique), name, and evidence
- supporting_evidence: array of objects with statement and event_ids citing ids from the bundle
- contradictory_evidence: array of objects with statement and event_ids, empty only if genuinely none exists
- evidence_gaps: array of strings naming what is missing or unverifiable
- recommended_searches: array of objects with title, language, and value
- recommended_response: array of strings, each an approval-required next step
Cite event ids exactly as they appear in the bundle. Never invent an id."""


def _text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(item).strip() for item in value if str(item).strip())
    if isinstance(value, dict):
        # Some models wrap prose in {"text": ...} or {"summary": ...}.
        for key in ("text", "summary", "value", "description"):
            if value.get(key):
                return str(value[key]).strip()
        return ""
    return str(value or "").strip()


def _string_list(value: Any) -> list[str]:
    if value in (None, "", {}):
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        value = list(value.values())
    if not isinstance(value, list):
        return [str(value).strip()]
    items: list[str] = []
    for item in value:
        text = _text(item)
        if text:
            items.append(text)
    return items


def _leveled(value: Any, *, allowed: tuple[str, ...], fallback: str = "") -> dict[str, str]:
    """Read a {level, rationale} section, accepting a bare level string."""
    level = ""
    rationale = ""
    if isinstance(value, dict):
        level = str(value.get("level") or value.get("value") or "").strip().lower()
        rationale = _text(value.get("rationale") or value.get("reason") or value.get("justification"))
    else:
        level = _text(value).lower()

    # "high confidence", "severity: critical" and similar.
    matched = next((item for item in allowed if item in level), "")
    return {"level": matched or fallback, "rationale": rationale}


def _evidence_entries(value: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return entries

    for item in value:
        if isinstance(item, str):
            statement, ids = item.strip(), []
        elif isinstance(item, dict):
            statement = _text(
                item.get("statement") or item.get("observation") or item.get("text") or item.get("summary")
            )
            raw_ids = item.get("event_ids") or item.get("event_id") or item.get("events") or []
            if isinstance(raw_ids, str):
                raw_ids = [raw_ids]
            ids = [str(entry).strip() for entry in raw_ids if str(entry).strip()] if isinstance(raw_ids, list) else []
        else:
            continue
        if statement:
            entries.append({"statement": statement, "event_ids": ids})
    return entries


def _techniques(value: Any) -> list[dict[str, str]]:
    techniques: list[dict[str, str]] = []
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return techniques

    for item in value:
        if isinstance(item, str):
            techniques.append({"id": item.strip(), "name": "", "evidence": ""})
        elif isinstance(item, dict):
            identifier = _text(item.get("id") or item.get("technique_id") or item.get("technique"))
            techniques.append(
                {
                    "id": identifier,
                    "name": _text(item.get("name") or item.get("technique_name")),
                    "evidence": _text(item.get("evidence") or item.get("rationale")),
                }
            )
    return [item for item in techniques if item["id"] or item["name"]]


def _queries(value: Any) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return queries
    for item in value:
        if isinstance(item, str):
            queries.append({"title": "", "language": "", "value": item.strip()})
        elif isinstance(item, dict):
            queries.append(
                {
                    "title": _text(item.get("title") or item.get("name")),
                    "language": _text(item.get("language") or item.get("lang")),
                    "value": _text(item.get("value") or item.get("query")),
                }
            )
    return [item for item in queries if item["value"] or item["title"]]


def _entities(value: Any) -> dict[str, list[str]]:
    result = {key: [] for key in ENTITY_KEYS}
    if not isinstance(value, dict):
        # A flat list of entity strings cannot be typed; keep it addressable.
        flat = _string_list(value)
        if flat:
            result["hosts"] = flat
        return result

    aliases = {
        "hosts": ("hosts", "host", "hostnames", "assets"),
        "users": ("users", "user", "accounts", "usernames"),
        "addresses": ("addresses", "ips", "ip_addresses", "source_ips", "destination_ips"),
        "processes": ("processes", "process"),
        "files": ("files", "file", "paths"),
    }
    for key, names in aliases.items():
        collected: list[str] = []
        for name in names:
            for item in _string_list(value.get(name)):
                if item not in collected:
                    collected.append(item)
        result[key] = collected
    return result


def normalize_assessment(payload: Any) -> dict[str, Any]:
    """Coerce a model's assessment object into the documented shape."""
    if not isinstance(payload, dict):
        payload = {}

    return {
        "confirmed_observations": _string_list(payload.get("confirmed_observations")),
        "interpretation": _text(payload.get("interpretation")),
        "attack_hypothesis": _text(
            payload.get("attack_hypothesis") or payload.get("hypothesis") or payload.get("attack_chain")
        ),
        "confidence": _leveled(payload.get("confidence"), allowed=CONFIDENCE_LEVELS),
        "severity": _leveled(payload.get("severity"), allowed=SEVERITY_LEVELS),
        "affected_entities": _entities(payload.get("affected_entities") or payload.get("entities")),
        "attack_techniques": _techniques(
            payload.get("attack_techniques") or payload.get("mitre") or payload.get("techniques")
        ),
        "supporting_evidence": _evidence_entries(payload.get("supporting_evidence")),
        "contradictory_evidence": _evidence_entries(payload.get("contradictory_evidence")),
        "evidence_gaps": _string_list(
            payload.get("evidence_gaps") or payload.get("missing_evidence")
        ),
        "recommended_searches": _queries(
            payload.get("recommended_searches") or payload.get("next_searches")
        ),
        "recommended_response": _string_list(
            payload.get("recommended_response") or payload.get("response_options")
        ),
    }


def bundle_reference_ids(bundle: Any) -> tuple[set[str], set[str]]:
    """Event ids and indicator ids an assessment is allowed to cite."""
    event_ids: set[str] = set()
    indicator_ids: set[str] = set()
    if not isinstance(bundle, dict):
        return event_ids, indicator_ids

    metadata = bundle.get("metadata") if isinstance(bundle.get("metadata"), dict) else {}
    for block_name in ("security_alerts", "security_events"):
        block = metadata.get(block_name)
        items = block.get("items") if isinstance(block, dict) else []
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and item.get("id"):
                event_ids.add(str(item["id"]))

    intel = metadata.get("threat_intelligence")
    items = intel.get("items") if isinstance(intel, dict) else []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("id"):
            indicator_ids.add(str(item["id"]))

    return event_ids, indicator_ids


def review_assessment(assessment: dict[str, Any], bundle: Any) -> dict[str, Any]:
    """Report missing sections and citations that match nothing in the bundle.

    Nothing is rewritten. Ungrounded citations are annotated in place and
    counted here so the interface can show the analyst what did not check out.
    """
    missing = [
        section
        for section in REQUIRED_SECTIONS
        if not _section_populated(assessment.get(section))
    ]

    event_ids, _ = bundle_reference_ids(bundle)
    ungrounded: list[str] = []
    cited = 0
    for section in EVIDENCE_SECTIONS:
        for entry in assessment.get(section, []):
            unknown = [value for value in entry.get("event_ids", []) if value not in event_ids]
            cited += len(entry.get("event_ids", []))
            entry["unknown_event_ids"] = unknown
            ungrounded.extend(unknown)

    # An empty contradictory_evidence array is legitimate but worth stating,
    # because a model that never looks for disconfirming evidence and a case
    # that genuinely has none look identical in the output.
    notes: list[str] = []
    if not assessment.get("contradictory_evidence"):
        notes.append("No contradictory evidence was reported.")
    if not cited:
        notes.append("No evidence entry cited an event id.")

    return {
        "missing_sections": missing,
        "complete": not missing,
        "citations": cited,
        "ungrounded_event_ids": sorted(set(ungrounded)),
        "notes": notes,
    }


def _section_populated(value: Any) -> bool:
    if isinstance(value, dict):
        if "level" in value:
            return bool(value.get("level"))
        return any(bool(item) for item in value.values())
    return bool(value)


def assessment_markdown(assessment: dict[str, Any]) -> str:
    """Render the assessment as analyst-facing markdown.

    Used when the model returns a structured assessment but no prose answer,
    so the interface never shows an empty panel next to a populated schema.
    """
    lines: list[str] = []

    def section(title: str, body: list[str]) -> None:
        if body:
            lines.append(f"### {title}")
            lines.extend(body)
            lines.append("")

    confidence = assessment.get("confidence", {})
    severity = assessment.get("severity", {})
    header = []
    if assessment.get("interpretation"):
        header.append(assessment["interpretation"])
    if severity.get("level"):
        header.append(f"**Severity:** {severity['level']} — {severity.get('rationale', '')}".rstrip(" —"))
    if confidence.get("level"):
        header.append(f"**Confidence:** {confidence['level']} — {confidence.get('rationale', '')}".rstrip(" —"))
    section("Assessment", header)

    if assessment.get("attack_hypothesis"):
        section("Hypothesis", [assessment["attack_hypothesis"]])
    section(
        "Confirmed observations",
        [f"- {item}" for item in assessment.get("confirmed_observations", [])],
    )
    section(
        "Supporting evidence",
        [
            f"- {entry['statement']}"
            + (f" ({', '.join(entry['event_ids'])})" if entry.get("event_ids") else "")
            for entry in assessment.get("supporting_evidence", [])
        ],
    )
    section(
        "Contradictory evidence",
        [
            f"- {entry['statement']}"
            + (f" ({', '.join(entry['event_ids'])})" if entry.get("event_ids") else "")
            for entry in assessment.get("contradictory_evidence", [])
        ],
    )
    section("Evidence gaps", [f"- {item}" for item in assessment.get("evidence_gaps", [])])
    section(
        "ATT&CK techniques",
        [
            f"- {item['id']} {item.get('name', '')} {item.get('evidence', '')}".rstrip()
            for item in assessment.get("attack_techniques", [])
        ],
    )
    section(
        "Recommended searches",
        [
            f"- {item.get('title') or item.get('language') or 'Search'}: `{item['value']}`"
            for item in assessment.get("recommended_searches", [])
            if item.get("value")
        ],
    )
    section("Recommended response", [f"- {item}" for item in assessment.get("recommended_response", [])])

    return "\n".join(lines).strip()
