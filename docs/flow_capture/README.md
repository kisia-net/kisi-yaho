# 데이터 흐름 캡처와 대시보드 시각화

요청: 실제 들어온 데이터가 **서버별 원본 → 이벤트 → 경보 → AI 판단 → 조치**로 지나며
어떻게 모양이 바뀌는지 보여 줄 것. 이 문서는 무엇을 만들었고, 어떻게 쓰고, 시험 환경에서 무엇이 나왔는지 정리합니다.

> **이 폴더의 예시 결과(`example/`)는 시험 환경에서 만든 것입니다.**
> - Wazuh 와 같은 구조의 문서를 로컬 OpenSearch 에 넣어 만들었습니다: 원시 1,099건 / 경보 198건, 서버는 `web-01`·`ids-01`.
> - AI 단계(⑤ ⑥)는 GPU 없이 OpenAI 형식으로 답하는 **모의 모델(`mock-llm`)** 의 응답입니다.
> - 화면·API·저장 방식은 실제 시스템과 같습니다. 실제 결과는 아래 「실제 시스템에서 결과 자료 만들기」로 뽑습니다.

## 변경 전·후 비교

같은 시험 데이터로 원본(`main` 반영 시점)과 이 브랜치를 나란히 띄워 캡처했습니다.

| 비교 | 무엇이 달라졌나 |
|---|---|
| [대시보드 하단](compare/compare_c1.png) | Wazuh 시각화 4개 패널 추가 |
| [탐지 추이](compare/compare_c2.png) | 단색 막대 → 심각도별 누적 막대 |
| [경보 상세](compare/compare_c3.png) | "데이터 흐름 캡처" 버튼 추가 |
| [데이터 흐름 화면](compare/compare_c4.png) | 새 화면 (원본에는 없음) |

## 1. 대시보드: Wazuh 시각화를 HAW-KI 로 가져옴

`infra/wazuh-dashboard/` 의 Wazuh saved objects 와 **같은 조건**으로 HAW-KI 서버가 Indexer 에 직접 묻고,
HAW-KI 대시보드에 그립니다. 그래서 Wazuh 화면과 숫자가 같습니다.

- API: `GET /api/dashboard/wazuh-visuals`
  - 최근 24시간을 한 번 조회해 1분 동안 재사용합니다.
  - 집계 코드는 `hawki_alert_analysis/wazuh_visuals.py`, 조회는 `SiemService.wazuh_visuals` 입니다.

| 패널 | Wazuh 시각화 | 보여 주는 것 |
|---|---|---|
| 최근 24시간 (기존 막대 교체) | 02 | 1시간 막대를 낮음 L0–6 / 중간 L7–9 / 높음 L10+ 로 쌓음 |
| 막힘 / 통과 판정 (새 패널) | 16 | 출발지 IP별 WAF 탐지 · 4xx · 5xx · 2xx · 공격 후 200(31106) → **통과 의심 / 막힘 / 관찰** |
| MITRE ATT&CK 전술 × 기법 (새 패널) | 07 | 공격 단계별 기법 건수. 칸을 누르면 로그 검색 |
| HTTP 상태 코드 (새 패널) | 14 | 웹 공격 경보의 응답 코드 |
| 요청 URL Top 10 (새 패널) | 13 | 노린 경로와 경로별 출발지 IP 수 |

**막힘/통과 판정 규칙**
- 2xx 나 31106 이 있으면 **통과 의심**
- 그것 없이 WAF 탐지나 4xx 만 있으면 **막힘**
- 둘 다 없으면 **관찰**

통과 의심 IP 는 경보 건수가 적어 Top 10 에 들지 못해도 빠지지 않게 따로 한 번 더 셉니다.

![심각도별 추이](example/01_dashboard_severity_activity.png)
![막힘/통과 판정과 MITRE](example/02_dashboard_block_pass_mitre.png)
![상태 코드와 URL](example/03_dashboard_status_urls.png)

## 2. 단계별 캡처: 경보 하나의 흐름

- 화면: 경보 상세 → **데이터 흐름 캡처** 버튼, 또는 `/alerts/<경보 id>/flow`
  - 단계마다 한 칸이라 칸 단위로 캡처할 수 있습니다.
- API: `GET /api/alerts/<id>/flow` (JSON), `GET /api/alerts/<id>/flow.md` (결과 자료 Markdown)
- 코드: `hawki_alert_analysis/flow_capture.py`

| 단계 | 어디서 오나 | 무엇을 보여 주나 |
|---|---|---|
| ① 서버별 원본 로그 | Wazuh 문서의 `full_log` (Agent 가 보낸 원문 그대로) | 서버 → 로그 파일 → 원문 줄. 텍스트 한 줄 / JSON 한 줄 구분 |
| ② 이벤트 | `wazuh-archives-*` 의 `decoder`·`data.*` | 디코더마다 원문이 어떤 필드로 쪼개졌는지 (예: `data.srcip`, `data.url`, `data.alert.signature`) |
| ③ 경보 | `wazuh-alerts-*` 의 `rule.*` | 이벤트에 룰이 붙인 필드, 같은 증거 안의 다른 경보 룰, 룰에 걸리지 않은 이벤트 수 |
| ④ 증거 패키지 | HAW-KI `hawki.wazuh.live-evidence/v2` | TRIGGER + CTX 수 (같은 서버 / 다른 서버), 차단 판정, 우선순위, 자산, CTI, 수집 조건, 출처 연결(lineage) |
| ⑤ AI 증거 수집 | 분석 실행 때의 `agent_retrieval` | 모델이 부른 도구와 인자, 추가된 CTX, 패키지 크기 변화 (처음 → 수집 후 → 모델에 보낸 것) |
| ⑥ AI 판단 | 분석 실행 때의 결과 | 모델, 확인된 사실, 해석, 가설, 확신도·심각도, **인용한 증거와 그 원본 로그**. 없는 id 를 인용하면 표시 |
| ⑦ 조치 | AI 제안 + 승인 대기열 | 제안된 조치와 승인 상태. 승인된 수집과 새 룰이 만든 로그는 다시 ① 로 들어옴 |

**저장 방식**
- ①~④ 는 경보 id 만 있으면 언제든 같은 규칙으로 다시 만듭니다.
- ⑤ ⑥ 은 실행할 때마다 달라질 수 있어, 경보 화면에서 **LLM으로 분석을 실행한 순간**의 흐름을 저장합니다.
  - 위치: `data/flow_captures/`, 경보마다 최근 5개
  - 끄기: `FLOW_CAPTURE_ENABLED=false`
  - 보관 개수: `FLOW_CAPTURE_KEEP`
- 저장된 캡처의 ①~④ 는 **모델에 보낸 증거 기준**입니다.
  - 캡처 선택에서 「지금 다시 만들기」를 고르면, 지금 고른 전체 후보 기준으로 다시 만듭니다.
- ⑦ 의 승인 상태는 볼 때마다 승인 대기열에서 다시 읽습니다.
  - 경보 화면에서 올린 조치는 이제 `alert_id` 를 함께 저장해, 어느 경보에서 나왔는지 이어집니다.

![단계별 크기](example/11_flow_sizes.png)

## 3. 시험 환경 결과 (경보 `044599dada071c0c7803`)

시나리오는 다음과 같습니다.
1. `52.141.3.247` 이 없는 PHP 경로를 훑어 404 를 받습니다.
2. 경로 조작(`../../etc/passwd`) 요청은 ModSecurity 가 403 으로 막습니다.
3. 인코딩을 바꾼 `....//` 변형 하나가 **200** 을 받습니다. IDS 센서 `ids-01` 도 같은 요청을 탐지합니다.

트리거는 그 200 응답 경보(룰 31106)입니다.

| 단계 | 건수 | 크기(문자) | 읽는 법 |
|---|---|---|---|
| ① 원본 로그 | 20줄 | 5,197 | `web-01` 19줄 (nginx 접근 16 · 오류 3), `ids-01` 1줄 (Suricata JSON) |
| ② 이벤트 | 20건 | 11,896 | 디코더 3종 (`web-accesslog`, `nginx-errorlog`, `json`)이 원문을 필드로 쪼개며 커짐 |
| ③ 경보 | 19건 | 16,462 | 룰 5종 (31101 · 31333 · 31151 · 86601 · 31106)이 `rule.*` 를 붙임 |
| ④ 증거 패키지 | 20건 | 46,153 | 차단 판정 BLOCKED 3 · NOT_BLOCKED 1, 우선순위 P2 (57점), 자산 `web-01` (high · internet_facing) |
| ⑤ AI 증거 수집 | +3건 | 40,595 → 46,153 | `search_address(52.141.3.247)` 로 CTX-017~019 추가 후 `finish` |
| ⑥ AI 판단 | 인용 5건 | 2,320 | 인용한 TRIGGER · CTX-001~004 가 모두 실재하는 증거로 확인됨 |
| ⑦ 조치 | 2건 | — | 제안 `velociraptor_collection` 1건 → 승인 대기열 `pending_approval` 1건 |

![① 서버별 원본 로그](example/12_stage_raw.png)
![② 이벤트](example/13_stage_event.png)
![③ 경보](example/14_stage_alert.png)
![④ 증거 패키지](example/15_stage_evidence.png)
![⑤ AI 증거 수집](example/16_stage_ai_retrieval.png)
![⑥ AI 판단](example/17_stage_ai_judgment.png)
![⑦ 조치](example/18_stage_response.png)

전체 내용은 [`example/flow-example.md`](example/flow-example.md), 원본 JSON 은 [`example/flow-example.json`](example/flow-example.json) 입니다.

### 시험 중 확인된 실제 동작
- **문맥 한도와 AI 수집:** `AGENT_CONTEXT_MAX_CHARS` 기본값 24,000 에서는 처음 패키지(40,595자)가 이미 한도를 넘어, AI 증거 수집이 `no_room` 으로 건너뛰어졌습니다. 이어서 문맥 맞추기가 CTX 를 16 → 9건으로 줄였습니다. 위 결과는 한도를 64,000 으로 올려 수집 단계를 보이게 한 것입니다. 실제 시스템에서 ⑤ 단계가 비어 있으면 이 값을 먼저 확인하세요.
- **없는 증거 인용 표시:** 같은 기본값에서 모의 모델이 문맥 맞추기로 빠진 CTX id 를 인용하자, ⑥ 단계가 그 id 를 「증거에 없는 id」로 표시했습니다.
- **같은 403 이라도 판정이 다름:** 접근 로그의 403 줄은 차단 판정이 UNKNOWN 이고, 같은 요청의 nginx 오류 로그(ModSecurity 문구) 줄만 BLOCKED 입니다. 판정 규칙이 원문 문구를 근거로 하기 때문입니다.

## 실제 시스템에서 결과 자료 만들기

먼저 경보 화면에서 **LLM으로 분석**을 한 번 실행합니다. 그래야 ⑤ ⑥ 이 저장됩니다. 그다음:

```bash
HAWKI_URL=http://127.0.0.1:5000 HAWKI_ADMIN_USERNAME=analyst HAWKI_ADMIN_PASSWORD=... \
  python tools/capture_flow.py --alert <경보 id>          # 또는 --top 3 (최근 24시간 우선순위 상위)
```

`data/flow_exports/flow-<id>.json` 과 `flow-<id>.md` 가 생깁니다. 화면 캡처는 `/alerts/<id>/flow` 에서 칸별로 뜨면 됩니다.
