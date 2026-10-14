# Wazuh 대시보드 시각화 (saved objects)

`hawki_visualizations.ndjson` 하나를 가져오면 시각화 8개와 대시보드 2개가 한 번에 생깁니다.

## 가져오기

Wazuh 대시보드 → ☰ → **Dashboards Management** → **Saved objects** → **Import**
→ `hawki_visualizations.ndjson` 선택 → *Automatically overwrite conflicts* → Import

API로 가져올 때:

```bash
curl -k -u admin:<비밀번호> -XPOST "https://<대시보드>/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" --form file=@infra/wazuh-dashboard/hawki_visualizations.ndjson
```

가져오기 전에 인덱스 패턴 두 개가 있어야 합니다. 둘 다 시간 필드는 `timestamp` 입니다.

| 인덱스 패턴 id | 쓰는 곳 | 없으면 |
| --- | --- | --- |
| `wazuh-alerts-*` | 19번을 뺀 전부 | Wazuh 대시보드가 처음 켤 때 이 id로 만듭니다 |
| `wazuh-archives-*` | 19번 (수집량) | 가져오기 화면에서 다른 패턴으로 바꿔 연결하거나, 먼저 만들고 가져옵니다 |

## 만들어지는 것

| 순서 | id | 시각화 | 유형 |
| --- | --- | --- | --- |
| 1 | `hawki-v16-block-pass-matrix` | 막힘/통과 매트릭스: 출발지 IP × (WAF 탐지 / 4xx / 5xx / 2xx / 룰 31106) | Heat Map |
| 2 | `hawki-v02-alerts-by-severity` | 시간대별 경보 추이 (L0–6 / L7–9 / L10+) | Vertical Bar |
| 3 | `hawki-v05-top-source-ip-rule` | 출발지 IP Top 10 × 룰 | Data Table |
| 4 | `hawki-v11-filter-controls` | 출발지 IP · 에이전트 · 룰 레벨 필터 | Controls |
| 5 | `hawki-v13-top-urls` | 요청 URL Top 20 + URL별 출발지 IP 수 | Data Table |
| 6 | `hawki-v14-http-status` | HTTP 상태 코드 분포 (`data.id`) | Pie |
| 7 | `hawki-v07-mitre-heatmap` | MITRE 전술 × 기법 | Heat Map |
| 8 | `hawki-v19-ingest-by-decoder` | 디코더별 원시 이벤트 수 | Area |

대시보드 2개:

- **HAW-KI · 관제 개요**: 02, 05, 07, 19
- **HAW-KI · 출발지 IP 조사**: 11, 16, 13, 14. 맨 위 필터에서 IP를 고르고 *Apply changes*를 누르면 아래 패널이 함께 걸러집니다.

**16번 읽는 법:** 한 행에 ① WAF 탐지와 ④ 2xx(또는 ⑤ 31106)가 함께 있으면 공격이 통과한 것이므로 즉시 차단 후보입니다.
①과 ② 4xx만 있으면 막힌 시도이므로 위험도를 낮춥니다. 2xx 응답은 경보 룰이 걸린 요청만 `wazuh-alerts-*`에 들어오므로, 정상 200 전체를 보려면 archives가 필요합니다.

## 고치기

ndjson을 손으로 고치지 말고 생성기를 고친 뒤 다시 만드세요.

```bash
python infra/wazuh-dashboard/build_saved_objects.py
```

id가 고정이라 다시 가져오면 같은 객체를 덮어씁니다.

## 검증한 범위

- OpenSearch / OpenSearch Dashboards **2.13.0** (보안 플러그인 끔)에 가져오기: 10개 모두 성공
- Wazuh 필드 이름으로 만든 시험 문서 600건으로 8개 패널이 모두 오류 없이 그려지는 것을 확인
- 실제 Wazuh 대시보드와 실데이터로는 시험하지 않았습니다. 패널이 비어 있으면 Discover에서 해당 필드(`data.id`, `data.url`, `rule.mitre.*`, `decoder.name`)가 들어오는지 먼저 확인하세요.
