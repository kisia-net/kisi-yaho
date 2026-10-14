"""Wazuh Dashboard (OpenSearch Dashboards) 가져오기용 saved objects 생성기.

    python infra/wazuh-dashboard/build_saved_objects.py

같은 폴더에 hawki_visualizations.ndjson 을 씁니다. 손으로 ndjson 을 고치지 말고
이 파일을 고친 뒤 다시 실행하세요. visState 같은 값은 JSON 을 문자열로 한 번 더
감싸야 해서 손으로 고치면 따옴표가 깨지기 쉽습니다.

인덱스 패턴은 만들지 않고 id 로만 참조합니다.
  - wazuh-alerts-*   : Wazuh 대시보드가 처음 켤 때 이 id 로 만들어 둡니다.
  - wazuh-archives-* : 없으면 가져오기 화면에서 다른 패턴으로 바꿔 연결할 수 있습니다.
"""

from __future__ import annotations

import json
from pathlib import Path

ALERTS = "wazuh-alerts-*"
ARCHIVES = "wazuh-archives-*"
TIME_FIELD = "timestamp"  # siem.py 의 timestamp_field 와 같은 값

VIS_MIGRATION = {"visualization": "7.10.0"}
DASH_MIGRATION = {"dashboard": "7.9.3"}
INDEX_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"


def search_source(query: str = "") -> str:
    return json.dumps(
        {
            "query": {"query": query, "language": "kuery"},
            "filter": [],
            "indexRefName": INDEX_REF,
        },
        ensure_ascii=False,
    )


def count(agg_id: str = "1") -> dict:
    return {"id": agg_id, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms(agg_id: str, field: str, size: int, schema: str, label: str = "") -> dict:
    params = {
        "field": field,
        "orderBy": "1",
        "order": "desc",
        "size": size,
        "otherBucket": False,
        "otherBucketLabel": "기타",
        "missingBucket": False,
        "missingBucketLabel": "없음",
    }
    if label:
        params["customLabel"] = label
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema, "params": params}


def date_histogram(agg_id: str, schema: str = "segment", interval: str = "auto") -> dict:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "date_histogram",
        "schema": schema,
        "params": {
            "field": TIME_FIELD,
            "interval": interval,
            "drop_partials": False,
            "min_doc_count": 1,
            "extended_bounds": {},
            "customLabel": "시각",
        },
    }


def xy_params(chart_type: str, mode: str, y_title: str) -> dict:
    """Vertical Bar / Area 공통 축 설정."""

    return {
        "type": chart_type,
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": y_title},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": chart_type,
                "mode": mode,
                "data": {"label": y_title, "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "interpolate": "linear",
                "showCircles": True,
            }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
        "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
    }


def heatmap_params(color_schema: str) -> dict:
    return {
        "type": "heatmap",
        "addTooltip": True,
        "addLegend": True,
        "enableHover": False,
        "legendPosition": "right",
        "times": [],
        "colorsNumber": 5,
        "colorSchema": color_schema,
        "setColorRange": False,
        "colorsRange": [],
        "invertColors": False,
        "percentageMode": False,
        "valueAxes": [
            {
                "show": False,
                "id": "ValueAxis-1",
                "type": "value",
                "scale": {"type": "linear", "defaultYExtents": False},
                "labels": {"show": True, "rotate": 0, "overwriteColor": False, "color": "black"},
            }
        ],
    }


def table_params(per_page: int = 10) -> dict:
    return {
        "perPage": per_page,
        "showPartialRows": False,
        "showMetricsAtAllLevels": False,
        "showTotal": False,
        "totalFunc": "sum",
        "percentageCol": "",
    }


def visualization(
    vis_id: str,
    title: str,
    description: str,
    vis_type: str,
    params: dict,
    aggs: list[dict],
    index: str = ALERTS,
    query: str = "",
    extra_refs: list[dict] | None = None,
) -> dict:
    vis_state = {"title": title, "type": vis_type, "aggs": aggs, "params": params}
    return {
        "id": vis_id,
        "type": "visualization",
        "migrationVersion": VIS_MIGRATION,
        "attributes": {
            "title": title,
            "description": description,
            "version": 1,
            "uiStateJSON": "{}",
            "visState": json.dumps(vis_state, ensure_ascii=False),
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": [{"name": INDEX_REF, "type": "index-pattern", "id": index}]
        + (extra_refs or []),
    }


# ── 추천 순서 1: #16 막힘 / 통과 매트릭스 ──────────────────────────────────
# 행 = 출발지 IP, 열 = 같은 IP 에서 나온 경보를 성격별로 센 값.
# "WAF 탐지" 와 "2xx" 가 같은 행에 함께 있으면 통과 = 즉시 차단 후보.
block_pass_filters = [
    ("rule.groups:modsecurity", "① WAF 탐지 (ModSecurity)"),
    ("data.id:4*", "② 4xx 응답 (실패·차단)"),
    ("data.id:5*", "③ 5xx 응답 (서버 오류)"),
    ("data.id:2*", "④ 2xx 응답 (성공)"),
    ("rule.id:31106", "⑤ 공격 후 200 (룰 31106)"),
]
v16 = visualization(
    "hawki-v16-block-pass-matrix",
    "HAW-KI 16 · 막힘/통과 매트릭스 (출발지 IP)",
    "WAF 탐지와 2xx 가 한 행에 함께 있으면 공격이 통과한 것입니다 — 즉시 차단 후보.",
    "heatmap",
    heatmap_params("Reds"),
    [
        count(),
        {
            "id": "2",
            "enabled": True,
            "type": "filters",
            "schema": "segment",
            "params": {
                "filters": [
                    {"input": {"query": q, "language": "kuery"}, "label": label}
                    for q, label in block_pass_filters
                ]
            },
        },
        terms("3", "data.srcip", 20, "group", "출발지 IP"),
    ],
    query="rule.groups:(web or modsecurity) and data.srcip:*",
)

# ── 추천 순서 2: #2 심각도별 경보 추이 ─────────────────────────────────────
v02 = visualization(
    "hawki-v02-alerts-by-severity",
    "HAW-KI 02 · 시간대별 경보 추이 (심각도별)",
    "1시간 단위 경보 수를 Wazuh 룰 레벨 구간별로 쌓아 보여 줍니다.",
    "histogram",
    xy_params("histogram", "stacked", "경보 수"),
    [
        count(),
        date_histogram("2", interval="h"),
        # range 집계의 ranges[].label 은 OpenSearch 가 거부합니다(unknown field).
        # 구간 이름을 범례에 보이려고 filters 로 나눕니다.
        {
            "id": "3",
            "enabled": True,
            "type": "filters",
            "schema": "group",
            "params": {
                "filters": [
                    {"input": {"query": q, "language": "kuery"}, "label": label}
                    for q, label in [
                        ("rule.level < 7", "낮음 L0–6"),
                        ("rule.level >= 7 and rule.level < 10", "중간 L7–9"),
                        ("rule.level >= 10", "높음 L10+"),
                    ]
                ]
            },
        },
    ],
)

# ── 추천 순서 3: #5 출발지 IP Top 10 × 룰 ──────────────────────────────────
v05 = visualization(
    "hawki-v05-top-source-ip-rule",
    "HAW-KI 05 · 출발지 IP Top 10 × 룰",
    "경보를 가장 많이 만든 출발지 IP 와 그 IP 가 걸린 룰입니다.",
    "table",
    table_params(20),
    [
        count(),
        terms("2", "data.srcip", 10, "bucket", "출발지 IP"),
        terms("3", "rule.description", 5, "bucket", "룰"),
        terms("4", "rule.id", 1, "bucket", "룰 ID"),
    ],
    query="data.srcip:*",
)

# ── 추천 순서 4: #11 필터 컨트롤 ───────────────────────────────────────────
controls = [
    ("data.srcip", "출발지 IP", "list"),
    ("agent.name", "에이전트", "list"),
    ("rule.level", "룰 레벨", "range"),
]
control_params = []
control_refs = []
for i, (field, label, ctl_type) in enumerate(controls):
    ref = f"control_{i}_index_pattern"
    options = (
        {"type": "terms", "multiselect": True, "dynamicOptions": True, "size": 10, "order": "desc"}
        if ctl_type == "list"
        else {"decimalPlaces": 0, "step": 1}
    )
    control_params.append(
        {
            "id": str(i + 1),
            "fieldName": field,
            "label": label,
            "type": ctl_type,
            "options": options,
            "parent": "",
            "indexPatternRefName": ref,
        }
    )
    control_refs.append({"name": ref, "type": "index-pattern", "id": ALERTS})

v11 = {
    "id": "hawki-v11-filter-controls",
    "type": "visualization",
    "migrationVersion": VIS_MIGRATION,
    "attributes": {
        "title": "HAW-KI 11 · 조사 필터 (출발지 IP · 에이전트 · 레벨)",
        "description": "고르고 '변경 사항 적용' 을 누르면 대시보드의 다른 패널이 함께 걸러집니다.",
        "version": 1,
        "uiStateJSON": "{}",
        "visState": json.dumps(
            {
                "title": "HAW-KI 11 · 조사 필터 (출발지 IP · 에이전트 · 레벨)",
                "type": "input_control_vis",
                "aggs": [],
                "params": {
                    "controls": control_params,
                    "updateFiltersOnChange": False,
                    "useTimeFilter": True,
                    "pinFilters": False,
                },
            },
            ensure_ascii=False,
        ),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []}
            )
        },
    },
    "references": control_refs,
}

# ── 추천 순서 5: #13 요청 URL Top ──────────────────────────────────────────
v13 = visualization(
    "hawki-v13-top-urls",
    "HAW-KI 13 · 요청 URL Top 20",
    "공격자가 두드린 경로입니다. 출발지 IP 수가 많으면 여러 곳에서 노리는 경로입니다.",
    "table",
    table_params(20),
    [
        count(),
        {
            "id": "2",
            "enabled": True,
            "type": "cardinality",
            "schema": "metric",
            "params": {"field": "data.srcip", "customLabel": "출발지 IP 수"},
        },
        terms("3", "data.url", 20, "bucket", "URL"),
    ],
    query="rule.groups:web and data.url:*",
)

# ── 추천 순서 6: #14 HTTP 상태 코드 분포 ───────────────────────────────────
v14 = visualization(
    "hawki-v14-http-status",
    "HAW-KI 14 · HTTP 상태 코드 분포",
    "웹 경보의 응답 코드 비율입니다. 200 이 보이면 통과한 요청이 있다는 뜻입니다.",
    "pie",
    {
        "type": "pie",
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "isDonut": True,
        "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
    },
    [count(), terms("2", "data.id", 10, "segment", "HTTP 상태 코드")],
    query="rule.groups:web and data.id:*",
)

# ── 추천 순서 7: #7 MITRE 전술 × 기법 ─────────────────────────────────────
v07 = visualization(
    "hawki-v07-mitre-heatmap",
    "HAW-KI 07 · MITRE ATT&CK 전술 × 기법",
    "어떤 공격 단계(전술)에서 어떤 기법이 많이 탐지됐는지 보여 줍니다.",
    "heatmap",
    heatmap_params("Blues"),
    [
        count(),
        terms("2", "rule.mitre.tactic", 10, "segment", "전술"),
        terms("3", "rule.mitre.technique", 15, "group", "기법"),
    ],
    query="rule.mitre.id:*",
)

# ── 추천 순서 8: #19 로그 출처별 수집량 (archives) ─────────────────────────
v19 = visualization(
    "hawki-v19-ingest-by-decoder",
    "HAW-KI 19 · 로그 출처별 수집량 (원시 이벤트)",
    "디코더별 원시 이벤트 수입니다. 한 줄이 갑자기 0 이 되면 그 출처의 수집이 끊긴 것입니다.",
    "area",
    xy_params("area", "stacked", "원시 이벤트 수"),
    [
        count(),
        date_histogram("2", interval="h"),
        terms("3", "decoder.name", 10, "group", "디코더"),
    ],
    index=ARCHIVES,
)


def dashboard(dash_id: str, title: str, description: str, panels: list[tuple[dict, int, int, int, int]]) -> dict:
    panels_json = []
    refs = []
    for i, (vis, x, y, w, h) in enumerate(panels):
        ref = f"panel_{i}"
        panels_json.append(
            {
                "version": "7.10.2",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                "panelIndex": str(i + 1),
                "embeddableConfig": {},
                "panelRefName": ref,
            }
        )
        refs.append({"name": ref, "type": "visualization", "id": vis["id"]})
    return {
        "id": dash_id,
        "type": "dashboard",
        "migrationVersion": DASH_MIGRATION,
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "version": 1,
            "panelsJSON": json.dumps(panels_json, ensure_ascii=False),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeFrom": "now-24h",
            "timeTo": "now",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": refs,
    }


# 그리드는 가로 48칸입니다.
overview = dashboard(
    "hawki-dashboard-overview",
    "HAW-KI · 관제 개요",
    "심각도별 추이, 출발지 IP, MITRE, 수집 상태를 한 화면에 모았습니다.",
    [
        (v02, 0, 0, 48, 14),
        (v05, 0, 14, 24, 18),
        (v07, 24, 14, 24, 18),
        (v19, 0, 32, 48, 14),
    ],
)
investigation = dashboard(
    "hawki-dashboard-ip-investigation",
    "HAW-KI · 출발지 IP 조사",
    "위쪽 필터에서 출발지 IP 를 고르면 막힘/통과 여부, 요청 경로, 응답 코드가 함께 걸러집니다.",
    [
        (v11, 0, 0, 48, 7),
        (v16, 0, 7, 48, 18),
        (v13, 0, 25, 30, 18),
        (v14, 30, 25, 18, 18),
    ],
)

OBJECTS = [v16, v02, v05, v11, v13, v14, v07, v19, overview, investigation]

if __name__ == "__main__":
    out = Path(__file__).with_name("hawki_visualizations.ndjson")
    out.write_text(
        "".join(json.dumps(obj, ensure_ascii=False) + "\n" for obj in OBJECTS),
        encoding="utf-8",
    )
    print(f"{out} — {len(OBJECTS)}개 객체")
