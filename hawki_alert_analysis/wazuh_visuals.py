"""Wazuh 대시보드 시각화를 HAW-KI 대시보드로 옮긴 집계.

infra/wazuh-dashboard/ 의 saved objects 와 같은 조건으로 Indexer 에 묻습니다.
그래서 Wazuh 대시보드와 HAW-KI 화면의 숫자가 같습니다.

- 02 심각도별 경보 추이: 1시간 막대를 룰 레벨 구간으로 나눕니다.
- 16 막힘/통과 판정: 출발지 IP별 WAF 탐지 · 4xx · 5xx · 2xx · 룰 31106.
- 07 MITRE 전술 × 기법.
- 14 HTTP 상태 코드 · 13 요청 URL Top.

조회 하나로 다 가져오고, 판정은 이 파일에서 규칙대로 합니다.
"""

from __future__ import annotations

from typing import Any

from .wazuh import VULNERABILITY_GROUPS

# (key, label, from, to). to 는 포함하지 않습니다.
SEVERITY_BANDS: tuple[tuple[str, str, int, int | None], ...] = (
    ("low", "낮음 L0–6", 0, 7),
    ("mid", "중간 L7–9", 7, 10),
    ("high", "높음 L10+", 10, None),
)

WEB_GROUPS = ("web", "modsecurity", "accesslog")
# 웹 공격이 성공 응답을 받았다고 Wazuh 가 직접 말하는 룰.
SUCCESS_RULE_IDS = ("31106",)

# 막힘/통과 판정에 쓰는 신호. 키 순서가 화면의 열 순서입니다.
BLOCK_PASS_SIGNALS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("waf", "WAF 탐지", {"terms": {"rule.groups": ["modsecurity"]}}),
    ("status_4xx", "4xx", {"prefix": {"data.id": "4"}}),
    ("status_5xx", "5xx", {"prefix": {"data.id": "5"}}),
    ("status_2xx", "2xx", {"prefix": {"data.id": "2"}}),
    ("success_rule", "공격 후 200", {"terms": {"rule.id": list(SUCCESS_RULE_IDS)}}),
)

VERDICTS = {
    "passed": "통과 의심",
    "blocked": "막힘",
    "observed": "관찰",
}


def _band_ranges() -> list[dict[str, Any]]:
    ranges = []
    for key, _label, low, high in SEVERITY_BANDS:
        item: dict[str, Any] = {"key": key, "from": low}
        if high is not None:
            item["to"] = high
        ranges.append(item)
    return ranges


def visuals_query(*, timestamp_field: str, since: str, until: str = "now",
                  ip_limit: int = 10) -> dict[str, Any]:
    web = {"terms": {"rule.groups": list(WEB_GROUPS)}}
    signals = {
        key: {"filter": clause}
        for key, _label, clause in BLOCK_PASS_SIGNALS
    }
    per_ip = {
        **signals,
        "last_seen": {"max": {"field": timestamp_field}},
    }
    success = {"bool": {"should": [
        {"terms": {"rule.id": list(SUCCESS_RULE_IDS)}},
        {"prefix": {"data.id": "2"}},
    ], "minimum_should_match": 1}}
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {timestamp_field: {"gte": since, "lte": until}}},
        "aggs": {
            "activity": {
                "date_histogram": {
                    "field": timestamp_field,
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since, "max": until},
                },
                "aggs": {"bands": {"range": {"field": "rule.level", "ranges": _band_ranges()}}},
            },
            "web": {
                "filter": web,
                "aggs": {
                    "by_ip": {"terms": {"field": "data.srcip", "size": ip_limit}, "aggs": per_ip},
                    # 표는 상위 IP 만 보여 주므로, 전체 IP 수는 따로 셉니다 (근삿값, cardinality).
                    "ip_count": {"cardinality": {"field": "data.srcip"}},
                    # 건수가 적어 Top 10 에 못 드는 IP 라도 성공 응답이 있으면 빠뜨리지 않습니다.
                    "success": {
                        "filter": success,
                        "aggs": {
                            "by_ip": {"terms": {"field": "data.srcip", "size": ip_limit}, "aggs": per_ip},
                            "ip_count": {"cardinality": {"field": "data.srcip"}},
                        },
                    },
                    "statuses": {"terms": {"field": "data.id", "size": 10}},
                    "urls": {
                        "terms": {"field": "data.url", "size": 10},
                        "aggs": {"sources": {"cardinality": {"field": "data.srcip"}}},
                    },
                },
            },
            "mitre": {
                "filter": {"bool": {"must_not": [{"terms": {"rule.groups": list(VULNERABILITY_GROUPS)}}]}},
                "aggs": {"tactics": {
                    "terms": {"field": "rule.mitre.tactic", "size": 10},
                    "aggs": {"techniques": {"terms": {"field": "rule.mitre.technique", "size": 8}}},
                }},
            },
        },
    }


def _count(bucket: Any, key: str) -> int:
    value = bucket.get(key) if isinstance(bucket, dict) else None
    if isinstance(value, dict):
        return int(value.get("doc_count") or 0)
    return 0


def block_pass_verdict(counts: dict[str, int]) -> str:
    """성공 응답이 있으면 통과 의심, 차단·실패만 있으면 막힘.

    2xx 는 경보 룰이 걸린 요청만 경보 인덱스에 들어오므로, 여기 잡힌 2xx 는
    공격성 요청이 성공 응답을 받은 경우입니다.
    """
    if counts.get("status_2xx") or counts.get("success_rule"):
        return "passed"
    if counts.get("waf") or counts.get("status_4xx"):
        return "blocked"
    return "observed"


def _ip_rows(buckets: list[Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for bucket in buckets:
        if not isinstance(bucket, dict) or not bucket.get("key"):
            continue
        counts = {key: _count(bucket, key) for key, _label, _clause in BLOCK_PASS_SIGNALS}
        verdict = block_pass_verdict(counts)
        rows[str(bucket["key"])] = {
            "ip": str(bucket["key"]),
            "alerts": int(bucket.get("doc_count") or 0),
            **counts,
            "last_seen": (bucket.get("last_seen") or {}).get("value_as_string"),
            "verdict": verdict,
            "verdict_label": VERDICTS[verdict],
        }
    return rows


def parse_visuals(payload: dict[str, Any], *, ip_limit: int = 10) -> dict[str, Any]:
    aggs = payload.get("aggregations") or {}

    activity = []
    for bucket in (aggs.get("activity") or {}).get("buckets") or []:
        bands = {key: 0 for key, *_rest in SEVERITY_BANDS}
        for band in ((bucket.get("bands") or {}).get("buckets") or []):
            if isinstance(band, dict) and band.get("key") in bands:
                bands[band["key"]] = int(band.get("doc_count") or 0)
        activity.append({
            "time": bucket.get("key_as_string"),
            "count": int(bucket.get("doc_count") or 0),
            "bands": bands,
        })

    web = aggs.get("web") or {}
    rows = _ip_rows((web.get("by_ip") or {}).get("buckets") or [])
    for ip, row in _ip_rows(((web.get("success") or {}).get("by_ip") or {}).get("buckets") or []).items():
        # 성공만 센 하위 집계는 그 IP 의 전체 건수가 아니므로, 이미 있는 행은 덮지 않습니다.
        rows.setdefault(ip, {**row, "partial": True})
    order = {"passed": 0, "blocked": 1, "observed": 2}
    block_pass = sorted(rows.values(), key=lambda row: (order[row["verdict"]], -row["alerts"]))[:ip_limit]

    statuses = [
        {"code": str(bucket.get("key")), "count": int(bucket.get("doc_count") or 0)}
        for bucket in (web.get("statuses") or {}).get("buckets") or []
        if isinstance(bucket, dict)
    ]
    urls = [
        {
            "url": str(bucket.get("key")),
            "count": int(bucket.get("doc_count") or 0),
            "sources": int((bucket.get("sources") or {}).get("value") or 0),
        }
        for bucket in (web.get("urls") or {}).get("buckets") or []
        if isinstance(bucket, dict)
    ]

    tactics = []
    for bucket in (((aggs.get("mitre") or {}).get("tactics") or {}).get("buckets") or []):
        if not isinstance(bucket, dict):
            continue
        tactics.append({
            "tactic": str(bucket.get("key")),
            "count": int(bucket.get("doc_count") or 0),
            "techniques": [
                {"technique": str(item.get("key")), "count": int(item.get("doc_count") or 0)}
                for item in ((bucket.get("techniques") or {}).get("buckets") or [])
                if isinstance(item, dict)
            ],
        })

    return {
        "bands": [{"key": key, "label": label} for key, label, *_rest in SEVERITY_BANDS],
        "signals": [{"key": key, "label": label} for key, label, _clause in BLOCK_PASS_SIGNALS],
        "activity": activity,
        "block_pass": block_pass,
        # Among the rows found (top IPs plus every success-signal IP up to the limit).
        "block_pass_summary": {
            verdict: sum(1 for row in rows.values() if row["verdict"] == verdict)
            for verdict in VERDICTS
        },
        "block_pass_totals": {
            "shown_ips": len(block_pass),
            "web_ips": int((web.get("ip_count") or {}).get("value") or 0),
            "passed_ips": int(((web.get("success") or {}).get("ip_count") or {}).get("value") or 0),
            "ip_limit": ip_limit,
        },
        "statuses": statuses,
        "urls": urls,
        "mitre": tactics,
    }
