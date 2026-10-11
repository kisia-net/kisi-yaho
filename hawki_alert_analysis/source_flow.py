"""Where alerts come from: sensor -> detection type -> HAW-KI priority.

The dashboard's second flow view (출처 흐름). One ordered spec decides both
the indexer aggregation and the Python classification, so a level-8 alert
counted by the indexer under "웹 스캔·정찰" is the same alert the Python side
prioritises under that type. The first matching entry wins; anything
unmatched is "기타".

Matching uses Wazuh rule groups and the decoder name (and, for fixture
alerts, the adapter's source type), never free text.
"""

from __future__ import annotations

from typing import Any, Iterable

# (key, label, tags). A tag matches rule.groups or decoder.name.
SOURCES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("vulnerability", "Wazuh 취약점 탐지기", ("vulnerability-detector",)),
    ("suricata", "Suricata IDS", ("suricata", "ids")),
    ("modsecurity", "ModSecurity WAF", ("modsecurity",)),
    ("ssh", "SSH 인증 로그", ("sshd",)),
    ("web", "웹 접근 로그", ("web", "accesslog", "web-accesslog", "nginx", "apache")),
    ("system", "시스템·인증 로그", ("syslog", "pam", "authentication_success", "authentication_failed",
                                   "authlog", "sudo", "ossec", "rootcheck", "syscheck", "sca")),
)
TYPES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("cve", "취약점 (CVE)", ("vulnerability-detector",)),
    ("auth", "인증 실패·무차별 대입", ("authentication_failed", "authentication_failures", "invalid_login",
                                       "brute_force")),
    ("ids", "네트워크 IDS 탐지", ("ids", "suricata")),
    # Wazuh tags many access-log rules "attack" as well; scanning is the more
    # specific reading, so web_scan / recon is checked first.
    ("scan", "웹 스캔·정찰", ("web_scan", "recon", "scan")),
    ("web_attack", "웹 공격 시도", ("attack", "modsecurity", "sql_injection", "xss", "web_attack",
                                     "exploit_attempt")),
    ("web_other", "기타 웹 요청", ("accesslog", "web", "web-accesslog")),
    ("integrity", "무결성·설정 점검", ("syscheck", "rootcheck", "sca", "ossec")),
)
OTHER = ("other", "기타")
BANDS = ("P1", "P2", "P3", "P4")
BELOW = ("below_8", "레벨 8 미만")
UNSCORED = ("unscored", "우선순위 미계산")


def _tags(item: dict[str, Any]) -> set[str]:
    tags = {str(value).lower() for value in (item.get("groups") or []) if value}
    for key in ("decoder", "source"):
        value = item.get(key)
        if isinstance(value, dict):
            value = value.get("name")
        if value:
            tags.add(str(value).lower())
    return tags


def _first(spec: Iterable[tuple[str, str, tuple[str, ...]]], tags: set[str]) -> str:
    for key, _, wanted in spec:
        if tags & set(wanted):
            return key
    return OTHER[0]


def classify(item: dict[str, Any]) -> tuple[str, str]:
    """(source key, type key) for an alert-queue item."""
    tags = _tags(item)
    return _first(SOURCES, tags), _first(TYPES, tags)


def _matches(tags: tuple[str, ...]) -> dict[str, Any]:
    return {"bool": {"should": [{"terms": {"rule.groups": list(tags)}}, {"terms": {"decoder.name": list(tags)}}],
                     "minimum_should_match": 1}}


def exclusive_filters(spec: Iterable[tuple[str, str, tuple[str, ...]]]) -> dict[str, dict[str, Any]]:
    """Indexer filters where an alert lands in the first entry it matches."""
    filters: dict[str, dict[str, Any]] = {}
    earlier: list[dict[str, Any]] = []
    for key, _, tags in spec:
        clause = _matches(tags)
        filters[key] = {"bool": {"filter": [clause], "must_not": list(earlier)}}
        earlier.append(clause)
    filters[OTHER[0]] = {"bool": {"must_not": list(earlier)}}
    return filters


def aggregation() -> dict[str, Any]:
    """source -> type -> (level < 8 / >= 8) counts in one request."""
    return {"sources": {"filters": {"filters": exclusive_filters(SOURCES)}, "aggs": {
        "types": {"filters": {"filters": exclusive_filters(TYPES)}, "aggs": {
            "levels": {"range": {"field": "rule.level", "ranges": [{"key": "below_8", "to": 8}, {"key": "8_plus", "from": 8}]}},
        }},
    }}}


def labels() -> dict[str, dict[str, str]]:
    return {
        "sources": {**{key: label for key, label, _ in SOURCES}, OTHER[0]: OTHER[1]},
        "types": {**{key: label for key, label, _ in TYPES}, OTHER[0]: OTHER[1]},
        "targets": {**{band: band for band in BANDS}, BELOW[0]: BELOW[1], UNSCORED[0]: UNSCORED[1]},
    }


def build(
    source_type: dict[tuple[str, str], int],
    type_below: dict[str, int],
    type_band: dict[tuple[str, str], int],
    type_unscored: dict[str, int],
) -> dict[str, Any]:
    """Nodes, links and the source x type table, empty entries left out."""
    names = labels()
    source_order = [key for key, _, _ in SOURCES] + [OTHER[0]]
    type_order = [key for key, _, _ in TYPES] + [OTHER[0]]
    target_order = list(BANDS) + [UNSCORED[0], BELOW[0]]

    links: list[dict[str, Any]] = []
    for source in source_order:
        for kind in type_order:
            value = int(source_type.get((source, kind)) or 0)
            if value:
                links.append({"from": f"s:{source}", "to": f"t:{kind}", "value": value})
    for kind in type_order:
        for band in BANDS:
            value = int(type_band.get((kind, band)) or 0)
            if value:
                links.append({"from": f"t:{kind}", "to": f"p:{band}", "value": value})
        for key, counts in ((UNSCORED[0], type_unscored), (BELOW[0], type_below)):
            value = int(counts.get(kind) or 0)
            if value:
                links.append({"from": f"t:{kind}", "to": f"p:{key}", "value": value})

    used = {link["from"] for link in links} | {link["to"] for link in links}
    nodes = (
        [{"id": f"s:{key}", "column": 0, "key": key, "label": names["sources"][key]} for key in source_order if f"s:{key}" in used]
        + [{"id": f"t:{key}", "column": 1, "key": key, "label": names["types"][key]} for key in type_order if f"t:{key}" in used]
        + [{"id": f"p:{key}", "column": 2, "key": key, "label": names["targets"][key]} for key in target_order if f"p:{key}" in used]
    )
    for node in nodes:
        node["value"] = max(
            sum(link["value"] for link in links if link["from"] == node["id"]),
            sum(link["value"] for link in links if link["to"] == node["id"]),
        )

    rows = []
    for source in source_order:
        cells = {kind: int(source_type.get((source, kind)) or 0) for kind in type_order}
        if any(cells.values()):
            rows.append({"source": source, "label": names["sources"][source], "cells": cells, "total": sum(cells.values())})
    columns = [kind for kind in type_order if any(row["cells"][kind] for row in rows)]
    total = sum(row["total"] for row in rows)
    urgent = sum(int(value) for (kind, band), value in type_band.items() if band in ("P1", "P2"))
    return {
        "nodes": nodes,
        "links": links,
        "table": {
            "columns": [{"key": kind, "label": names["types"][kind]} for kind in columns],
            "rows": rows,
            "column_totals": {kind: sum(row["cells"][kind] for row in rows) for kind in columns},
        },
        "total": total,
        "urgent": urgent,
    }
