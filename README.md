# kisi-yaho — AI 증강 SIEM

AI보안 기술개발 교육과정 **네트워크반 1팀 '키시 야호~'** 개발 저장소입니다.

보안 로그를 수집·증강해 AI가 분석하고 대응까지 제안하는 SIEM을 만들고,
그 파이프라인이 안전한지 오픈소스 도구로 스스로 점검합니다.

| 대목표 | 내용 |
| --- | --- |
| **A. AI 증강 SIEM 구현** | 로그 수집 → 정규화 → **증강** → AI 분석 → 대응 제안 + 사람 승인 |
| **B. 파이프라인 보안성 검증** | 구축한 파이프라인을 garak · promptfoo 로 점검하고 가드레일 전후를 비교 |

---

## 빠른 시작

```powershell
git clone https://github.com/kisia-net/kisi-yaho.git
cd kisi-yaho
copy .env.example .env      # 값은 팀장에게 문의
docker compose up -d
```

→ <http://127.0.0.1:5000>

**GPU 가 없어도 화면과 증강 결과까지는 전부 볼 수 있습니다.** AI 분석 단계만 GPU 가 필요합니다.
AWS GPU 를 켜고 끄는 방법은 [`docs/RUNBOOK.md`](docs/RUNBOOK.md) 를 보세요.

> `.env` 에는 비밀번호와 API 키가 들어 있어 저장소에 올라가지 않습니다. 단톡방으로 공유하지 마세요.

---

## 문서

| 문서 | 내용 |
| --- | --- |
| [`docs/STATUS.md`](docs/STATUS.md) | **프로젝트 현황판** — 진행 상황, 한계, 향후 계획, 역할 분담, 시연 대본 |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | **재시작 런북** — 켜고 끄는 전체 절차, 오류별 대처표 |
| [`docs/MENTORING_LOG.md`](docs/MENTORING_LOG.md) | **멘토링 기록** — 회차별 지적과 그에 대한 결정 |
| [`docs/PROJECT_NOTES.md`](docs/PROJECT_NOTES.md) | 설계 결정과 근거 |
| [`docs/AWS_구축_가이드.md`](docs/AWS_구축_가이드.md) | **팀원용** — 담당 서버 접속과 설치 (Terraform 불필요) |
| [`docs/ROLES.md`](docs/ROLES.md) · [`docs/역할분담_요약.md`](docs/역할분담_요약.md) | 역할 분담 (상세 / 요약) |
| [`docs/diagrams/`](docs/diagrams/) | 네트워크 구성도 · 계층도 |
| [`docs/팀장전용_인프라_운영.md`](docs/팀장전용_인프라_운영.md) | 팀장 전용 — Terraform · GPU · 계정/키 · 비용 |
| [`infra/terraform/README.md`](infra/terraform/README.md) | 인프라 코드 사용법 |

---

## 업데이트 기록

새 항목은 **맨 위에** 추가합니다. 날짜 + 무엇이 달라졌는지 한 줄로 씁니다.

### 2026-10-13 — Wazuh 시각화 연동 · 데이터 흐름 캡처

- 대시보드에 Wazuh 시각화와 같은 집계를 연결 (`/api/dashboard/wazuh-visuals`): 심각도별 추이, 막힘/통과 판정, MITRE, 상태 코드, 요청 URL
- 경보마다 서버별 원본 → 이벤트 → 경보 → 증거 패키지 → AI 증거 수집 → AI 판단 → 조치를 보는 캡처 화면 (`/alerts/<id>/flow`) 과 결과 자료 내보내기 (`tools/capture_flow.py`)
- 설명과 시험 환경 예시: [`docs/flow_capture/README.md`](docs/flow_capture/README.md)
- 캡처에 모델에 보낸 증거 패키지 원본과 모델 응답 원문을 저장하고 감사 로그 해시와 대조 · 자동 보고서도 캡처 · 캡처 이전 분석은 마지막 분석 결과로 채움(검증 안 됨 표시) · ⑦ 은 제안·승인 상태만 (실행 결과 미연동)

### 2026-08-25 — 멘토링 피드백 반영

- `docs/MENTORING_LOG.md` 신설 — 회차별 지적과 그에 대한 결정을 기록
- 용어 통일: **SIEM (Wazuh)**, **Network IDS (Suricata)** — 역할이 앞, 제품명은 괄호
- 정규화를 **장비별로 나눠** 설명하는 절 추가 (웹 서버 / WAF / 네트워크 / 엔드포인트)
- PCAP 은 SIEM 에 직접 넣는 것이 아니라 **센서에 재생시켜 로그를 만드는 입력**임을 명시
- `STATUS.md` 에 경보 설계 방향, 공격 유형별 컨텍스트 윈도우, 「지금 결정해야 할 것」 절 추가
- 6주차 내 인프라 구축 완료를 일정에 명시

### 2026-08-24 — AWS GPU 실제 연동

- AWS `g6e.xlarge` (L40S 48GB) 에 GPT-OSS 20B 를 vLLM 으로 서빙하고, **실제 모델 추론으로 사건 판단을 받아냄**
- 모델 문맥 길이 8192 → 32768 상향 (4블록 증거 번들이 8K 를 초과)
- 분석 결과 한국어 출력 지원 (`LLM_OUTPUT_LANGUAGE`). 식별자·ATT&CK 명칭은 원문 유지
- 사건 판단을 **검증된 `assessment` 객체에서 직접 렌더링** — 화면에 보이는 것과 검증 대상이 동일해짐
- 모델이 JSON 키의 밑줄을 생략하는 문제를 관대한 파싱으로 흡수
- 좁은 화면에서 판단 패널이 3단 격자에 갇히던 문제, 긴 경로·해시가 카드 폭을 밀어내던 문제 수정
- `.gitattributes` 추가 — 줄바꿈 차이로 안 고친 파일이 modified 로 잡히던 문제 해결
- 문서 정리: `docs/STATUS.md`, `docs/RUNBOOK.md` 신설. 제출용 docx 는 노션으로 공유하고 저장소에서 제외

### 2026-08-22 — 팀 저장소 이전 및 인프라 코드화

- 개인 저장소에서 `kisia-net/kisi-yaho` 로 이력을 보존한 채 이전
- `infra/terraform/` 추가 — VPC · 보안그룹 · IAM · GPU 인스턴스 · 예산 알림을 코드로 관리
- `lab_running` 변수 하나로 GPU 인스턴스와 NAT Gateway 를 동시에 켜고 끄는 비용 통제 장치
- 보안그룹 **인바운드 규칙 0개** — 접근은 SSM 세션 매니저 터널로만
- 설계서 및 진행상황 공유 문서 작성

### 2026-08-21 — 웹 UI 한글화

- 화면 문구 전체를 한국어로 교체 (템플릿 14개, `app.py`, JS 3개)
- 제품명·필드명 등 식별자는 원문 유지

---

## 시스템 개요 — HAW-KI

의도한 LLM 보조 SOAR 구조를 그대로 구현한 Flask 기반 웹 애플리케이션입니다.

## 주요 기능

- 다중 출처 로그를 하나의 표준 이벤트 모델로 정규화
- 규칙 기반(결정적) 상관분석으로 경보 케이스 구성
- 자산 정보와 위협 인텔리전스로 증강
- 4블록 증거 번들을 로컬 LLM/SLM 에 전달
- OpenAI 호환 엔드포인트를 통한 로컬 LLM 대화
- 보안 분석가 역할이 고정된 시스템 프롬프트
- 운영 지표와 경보 발생량 시각화
- 경보 대기열과 사건 요약
- LLM · Elasticsearch · Kibana 상태 점검
- Kibana · Elasticsearch 로 가는 안전한 링크
- 선택적 읽기 전용 Elasticsearch 검색
- Elasticsearch 자격증명을 브라우저에 노출하지 않음
- 구조 개요 대화상자

## 파이프라인 — 로그가 흘러가는 길

```text
① 원본 로그              ② 어댑터              ③ 표준 이벤트         ④ 상관분석          ⑤ 케이스
Suricata eve.json  ─┐
Wazuh alerts       ─┤
Sysmon             ─┼─► 출처 판별 ─► 변환 ─► CanonicalEvent ─► 점수 매기기 ─► AlertCase
ModSecurity        ─┤                          (원본은 그대로 보존)          │
nginx / syslog     ─┘                                                        │
                                              자산 정보 ────────────────────┤
                                              위협 인텔리전스 ──────────────┤
                                                                             ▼
                                                                   4블록 증거 번들 ─► LLM/SLM
```

**실시간 스트리밍이 아니라 저장소에서 읽는 방식**입니다.
기본값(1단계)은 `data/scenarios/` 아래 파일을 읽고,
`ALERT_REPOSITORY=elasticsearch` 로 바꾸면 운영 인덱스에서 읽습니다.
그 아래 단계(상관분석 · 번들 조립 · 분석)는 어느 쪽이든 같은 코드입니다.

### 현재 수집되어 있는 것

| 시나리오 | 경보 | 로그 출처 |
| --- | --- | --- |
| `MTA-2026-02-28-NETSUPPORT` | **561건** | **실제 캡처** — malware-traffic-analysis.net PCAP 을 Suricata + ET Open 으로 재생 |
| `WEB-TRAVERSAL-001` | 6건 | 어댑터 시험용으로 작성 (nginx · ModSecurity · Suricata · Wazuh) |
| `WIN-DROPPER-001` | 2건 | 어댑터 시험용으로 작성 (Sysmon · Wazuh) |
| **합계** | **569건** | |

`mta_001` 의 `eve.json` 은 **3,854줄 / 2.9MB** 이며, 윈도우 도메인 환경의 실제 트래픽이 통째로 들어 있습니다.

| 이벤트 종류 | 건수 | | 이벤트 종류 | 건수 |
| --- | --- | --- | --- | --- |
| `dns` | 809 | | `fileinfo` | 307 |
| `flow` | 795 | | `tls` | 152 |
| **`alert`** | **561** | | `ldap` | 122 |
| `dcerpc` | 380 | | `quic` | 40 |
| `smb` | 328 | | `anomaly` | 30 |
| `http` | 308 | | `krb5` 외 | 22 |

경보 561건은 ET Open 룰셋이 실제로 발화시킨 것입니다.
반면 엔드포인트(Sysmon · Wazuh) 쪽은 아직 시험용 7줄이 전부이며, 실제 로그 확보가 남은 과제입니다.

### 정규화 — 장비마다 다르게

정규화는 **한 장비에서 나오는 로그 포맷을 표준 형태로 맞추는 일**입니다.
장비가 다르면 정규화도 다릅니다 — 웹 서버 접근 로그와 네트워크 로그는
담고 있는 것도, 표준 필드로 옮기는 방식도 서로 다릅니다.

| 구간 | 원본 | 정규화가 하는 일 |
| --- | --- | --- |
| 웹 서버 | combined access log (한 줄 텍스트) | 요청 메서드 · URI · 상태 코드 · 응답 크기 · User-Agent 를 각 필드로 분리. 상태 코드는 **응답** 속성이지 포트가 아니다 |
| WAF | ModSecurity 감사 트랜잭션 (JSON) | 발화한 CRS 룰 id 를 전부 보존하고, 요청 필드와 응답 필드를 구분 |
| 네트워크 | Suricata EVE (JSON, 이벤트 종류별 스키마) | `flow_id` · 5-tuple · 응용 프로토콜을 표준 필드로. `alert` 와 `http` · `dns` · `tls` 를 같은 이벤트로 뭉치지 않는다 |
| 엔드포인트 | Sysmon (Windows 이벤트) | 프로세스 · DNS · 네트워크 · 파일 이벤트를 종류별로 구분해 옮긴다 |

어느 경우든 **생산자 원본은 `event.original` 에 손대지 않고 그대로 남깁니다.**

### 어댑터 — 9종

| 어댑터 | 읽는 것 |
| --- | --- |
| `SuricataAdapter` | Suricata EVE JSON (네트워크 IDS) |
| `WazuhAdapter` | Wazuh 경보 (호스트 IDS) |
| `SysmonAdapter` | Windows Sysmon (프로세스 · DNS · 네트워크 · 파일) |
| `ModSecurityAdapter` | ModSecurity 감사 로그 (웹 방화벽) |
| `NginxAdapter` · `ApacheAdapter` | 웹서버 접근 로그 |
| `SyslogAdapter` · `AuthLogAdapter` | 리눅스 syslog, 인증 로그 |
| `ECSAdapter` | 범용 ECS 형식 |

### 출처 판별 — 이름 먼저, 안 되면 내용

1차는 **파일 이름**입니다 (`eve`→suricata, `sysmon`→sysmon, `modsec`→modsecurity …).
생산자 이름이 형식 이름보다 우선하므로 `apache_access.log` 는 "어떤 access log" 가 아니라 Apache 입니다.

이름으로 모르면 **첫 줄 내용**을 봅니다.

| 첫 줄에 있는 것 | 판정 |
| --- | --- |
| `event_type` 또는 `flow_id` | Suricata |
| `rule` + `agent` | Wazuh |
| `winlog` · `EventID` · 중첩된 `Event/System` | Sysmon |
| `transaction` 또는 `audit_data` | ModSecurity |
| `@timestamp` 또는 `event` | ECS |
| RFC 3164 형식 | syslog |
| `"..."` + `HTTP/` | combined access log |

**어떤 어댑터도 읽지 못한 파일은 조용히 건너뛰지 않고 이름을 밝힙니다.**
케이스에서 소리 없이 빠진 출처는, 원래 아무것도 없던 출처와 화면상 구별되지 않기 때문입니다.
개별적으로 깨진 줄(로테이션 배너, 잘린 기록)은 파일 전체를 버리지 않고
`FixtureEventRepository.skipped_lines` 에 개수로 집계합니다.

### 상관분석 — 규칙 기반 점수

AI 가 아니라 **코드가 점수를 매깁니다.** 같은 입력에 항상 같은 결과가 나와야
증강의 효과를 실험으로 측정할 수 있기 때문입니다 (`correlate.py`).

트리거 경보를 기준으로, 시간 창 안의 모든 이벤트에 점수를 매깁니다.

| 조건 | 점수 | 왜 이 가중치인가 |
| --- | --- | --- |
| 같은 Suricata `flow_id` | **+7** | 같은 TCP 연결. 가장 강한 증거 |
| 같은 호스트 | +5 | 한 장비에서 일어난 일 |
| 트리거의 출발지 IP 가 등장 | +4 | 같은 주체 |
| 트리거의 목적지 IP 가 등장 | +4 | 같은 대상 |
| 같은 사용자 계정 | +2 | 같은 행위자 |
| 같은 응용 프로토콜 | +1 | 약한 정황 |
| 시간 창 안에 있음 | +1 (기본) | **시간 근접만으로는 약한 증거** |

- 기본 시간 창 **300초**, 채택 기준 **2점 이상**
- 시나리오별로 `correlation_window_seconds`, `minimum_correlation_score` 로 조정 가능
- 점수순 → 시각순으로 정렬해 케이스에 담음

시간 근접에 주는 점수는 **1점뿐**입니다. 코드 주석에도 그렇게 적혀 있습니다 —
*"Temporal proximity alone is weak evidence."*
붙어서 일어났다는 이유만으로는 절대 채택되지 않고, 반드시 다른 근거가 하나는 더 있어야 합니다.

**왜 묶였는지가 화면에 그대로 남습니다.** 각 이벤트에 `reasons` 가 붙어
`within 8s`, `same host`, `same user`, `shared trigger destination IP` 처럼 표시되므로
분석가가 판단 근거를 되짚을 수 있습니다.

> **알려진 제약** — 한 케이스에 담는 이벤트는 `max_events=50` 으로 잘립니다.
> 현재 몇 건이 잘렸는지는 보고하지 않으므로, 이벤트가 많은 사건에서는
> "손실을 보고한다"는 원칙이 지켜지지 않습니다. 개선 예정 항목입니다.

## 로그 수집과 증거 번들

텔레메트리는 생산자의 원래 형식 그대로 수집한 뒤, 표준 이벤트 모델로 정규화하고,
결정적 규칙으로 상관분석하고, 증강한 다음에야 모델에 도달합니다.
하나의 경보 케이스는 `hawki.siem.evidence-bundle/v1` 이라는 **단일 번들**로 LLM/SLM 에 전달되며,
네 개의 메타데이터 블록을 담습니다.

| 블록 | | 담는 것 |
| --- | --- | --- |
| `security_alerts` | 보안경보 | 트리거가 된 탐지(`role: "trigger"`)와 상관된 탐지들 |
| `security_events` | 보안이벤트 | 상관된 원본 텔레메트리. 정규화하되 생산자 원본은 `event.original` 에 손대지 않고 보존 |
| `assets` | 자산정보 | 증거에 등장한 호스트와 주소의 자산대장 기록 |
| `threat_intelligence` | 위협 인텔리전스 | 증거에서 발견된 관측값의 지표 매칭 결과 |

블록끼리는 서로 참조합니다. 모든 경보와 이벤트가 `links` 필드로 자신이 건드린 자산·지표 id 를 명시하므로,
모델이 네 개의 독립된 목록을 스스로 다시 이어붙일 필요가 없습니다.

**각 블록은 자신의 증거 무게를 스스로 밝힙니다.** 탐지는 생산자의 의견이고,
자산의 업무중요도는 가능성이 아니라 영향도에 대한 정보이며, 지표 매칭은 의심을 높일 뿐 침해를 증명하지 않습니다.
자산대장에 없는 호스트와 위협정보가 없는 관측값은 **명시적으로 보고**됩니다.
정보가 없다는 것은 안전하다는 증거가 아니기 때문입니다.

```text
ModSecurity ─┐
Suricata ────┤
Wazuh ───────┼─► adapters ─► canonical events ─► correlation ─► AlertCase
Sysmon ──────┤                                                     │
Nginx/syslog ┘                                                     │
                                    asset inventory ────────────┤
                                    threat intel feed ──────────┤
                                                                ▼
                                                       evidence bundle ─► LLM/SLM
```

수집 출처는 인터페이스 뒤에서 교체할 수 있습니다.
`FixtureEventRepository` 는 환경변수 하나로 `ElasticsearchEventRepository` 로 바뀌고,
`FileAssetInventory` 와 `FileThreatIntelFeed` 는 CMDB 나 MISP/OpenCTI 로 교체할 수 있습니다.
상관분석·번들 조립·에이전트 코드는 한 줄도 바꾸지 않습니다.

관련 엔드포인트:

```text
GET  /api/alerts                    자산·위협정보 미리보기가 붙은 분류 대기열
GET  /api/alerts/{id}               케이스 전체
GET  /api/alerts/{id}/context       모델에 실제로 보낸 번들 그대로
GET  /api/alerts/{id}/evidence      트리거와 상관된 증거
GET  /api/alerts/{id}/timeline      시간순 정렬
POST /api/alerts/{id}/analyze       번들을 로컬 모델에 넣어 분석 실행
GET  /api/assets                    자산 정보
GET  /api/threat-intel              지표 피드
```

수집 경로는 `ALERT_FIXTURE_ROOT`, `ASSET_INVENTORY_ROOT`, `THREAT_INTEL_ROOT` 로 지정합니다.
지정한 경로가 없으면 `hawki_alert_analysis/fixtures/` 에 동봉된 자료로 대체됩니다.
컨테이너에서 `/app/data` 위에 볼륨이 마운트될 때 실제로 이 경로가 쓰입니다.

`AGENT_CONTEXT_MAX_CHARS` 는 직렬화된 문맥의 상한입니다.
번들이 이를 넘으면 **잃는 것이 적은 순서로** 증거를 줄입니다 —
반복되는 상용구 → 생산자 원본 기록 → 상관 이벤트 → 요약본 순이며,
**무엇을 덜어냈는지 payload 에 명시**합니다. 네 블록은 어느 단계에서도 사라지지 않고,
결과는 항상 유효한 JSON 입니다.

## 실제 로그 수집하기

Suricata EVE, Wazuh 경보, ModSecurity 감사 로그, Windows Sysmon,
Nginx · Apache combined 접근 로그, Linux syslog, `auth.log` 용 어댑터가 있으며
범용 ECS 리더도 있습니다. 이들이 이해하는 형식이라면 코드를 짜지 않고 그대로 넣을 수 있습니다.

### 수집한 로그 디렉터리에서

```bash
python -m hawki_alert_analysis.ingest /path/to/logs \
    --out data/scenarios/my_case --host web-01 --year 2026 --dry-run
```

출처 종류는 파일명으로 먼저 판별하고, 그다음 내용으로 판별합니다.
**무엇을 분류했고 무엇을 분류하지 못했는지 모두 보고**합니다.
어떤 어댑터도 읽지 못한 파일은 조용히 건너뛰지 않고 이름을 밝힙니다.
케이스에서 소리 없이 빠진 출처는, 원래 아무것도 없던 출처와 화면상 구별이 안 되기 때문입니다.
개별적으로 해석되지 않는 줄(로테이션 배너, 잘린 기록)은 파일 전체를 버리지 않고
`FixtureEventRepository.skipped_lines` 에 개수로 집계합니다.

syslog 에는 연도가 없으므로 `--year` 를 주세요. 없으면 현재 연도로 가정하고
해당 이벤트에 `assumed-year` 표시를 붙입니다.
ingest 는 로그 디렉터리에 절대 쓰지 않으므로 읽기 전용 자료도 그대로 쓸 수 있습니다.

### PCAP 에서

로컬에 Suricata 가 설치되어 있다면:

```bash
python tools/collect_pcap.py capture.pcap --out data/scenarios/replay_case
```

설치 없이 Compose 로:

```bash
cp ~/Downloads/traffic.pcap capture/pcap/capture.pcap

docker compose run --rm suricata-update      # 최초 1회: ET Open 룰셋 내려받기
docker compose run --rm suricata             # 재생 -> capture/out/eve.json

python -m hawki_alert_analysis.ingest capture/out \
    --out data/scenarios/real_001 --host web-01
```

Network IDS (Suricata) 가 캡처를 읽어 자신의 `eve.json` 을 씁니다.
**실제 센서가 만드는 것과 같은 형식**이라 뒷단에서는 차이를 알 수 없습니다.
이렇게 만들어진 이벤트에는 합성된 부분이 없습니다.

> **오해하기 쉬운 지점** — PCAP 을 SIEM 에 직접 넣는 것이 아닙니다.
> PCAP 을 SIEM 으로 가져와 처리하는 방식은 실무에서 일반적이지 않습니다.
> 여기서 PCAP 은 **센서에 재생시켜 로그를 만들어내기 위한 입력**일 뿐이고,
> 수집되는 것은 어디까지나 센서가 생성한 `eve.json` 입니다.
> 운영 환경에서는 이 자리에 라이브 센서가 들어갑니다.

`suricata-update` 를 먼저 실행하세요. 룰셋이 없으면 Suricata 는 `http`, `dns`, `tls`, `flow`
이벤트는 남기지만 **경보를 만들지 않고**, 경보가 없는 케이스에는 트리거가 없습니다.

`tools/collect_pcap.py` 는 Suricata 를 포함하지 않습니다.
없으면 설치 안내를 출력하고 종료합니다 — 일어나지 않은 수집을 성공한 것처럼 보고하지 않기 위해서입니다.

### 정답 데이터 (ground truth)

`--labels labels.json` 으로 정답을 붙이고 트리거를 명시합니다.

```json
{
  "id": "COLLECTED-001",
  "trigger": {"source_type": "suricata", "kind": "alert", "rule_id": "2100001"},
  "correlation_window_seconds": 240,
  "expected": {
    "attack_techniques": ["T1190", "T1059.004"],
    "affected_hosts": ["web-01"],
    "indicators": ["203.0.113.45"],
    "answers": [{"question": "Which account executed the shell?", "expect": ["www-data"]}]
  }
}
```

실제 로그로 옮겨간 뒤에도 시나리오는 여전히 필요하지만 역할이 달라집니다.
**매니페스트는 데이터가 아니라 정답지 층**이 됩니다.
재구성이 *맞았는지* 평가하려면 답을 알고 있어야 하기 때문입니다.

### 데이터셋

흐름 특징(flow feature) 데이터셋 — CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, KDD'99 — 은
이 시스템에 맞지 않습니다. 원본 생산자 기록이 아니라 흐름당 파생 통계를 담고 있어서,
특징 벡터로부터 재구성할 사건 자체가 없습니다.

아래는 맞습니다.

| 데이터셋 | 담는 것 | 쓰임 |
| --- | --- | --- |
| AIT Log Data Set (AIT-LDS) | Apache, auth, syslog, audit, DNS, Suricata EVE, v2 에는 Wazuh 까지. 다중 호스트, 공격 단계 라벨 | 기존 어댑터와 가장 잘 맞음. 주 평가 자료. 버전별 정확한 출처 목록은 Zenodo 기록 확인 |
| OTRF Security-Datasets (구 Mordor) | ATT&CK 기법별 JSON, Sysmon 과 Windows Security | 기법 단위 평가. Sysmon 어댑터가 바로 읽음 |
| Splunk `attack_data` | 기법별 원본 로그, 여러 생산자 | 개별 데이터셋을 골라 사용 |
| Splunk BOTS v1~v3 | 정답 문답이 딸린 완결된 사건 | 문답을 `expected.answers` 에 넣어 평가 세트로 활용 |
| malware-traffic-analysis.net | PCAP 과 공개된 분석 글 | `collect_pcap.py` 로 재생. 분석 글이 정답 역할 |
| EVTX-ATTACK-SAMPLES | 기법별 Windows EVTX | JSON 으로 변환(evtx_dump, Chainsaw) 후 Sysmon 으로 수집 |

자료 모음은 **저장소 밖에 두세요.** 용량과 라이선스 모두 커밋하지 않을 이유가 됩니다.
`ALERT_FIXTURE_ROOT` 가 그쪽을 가리키게 하면 됩니다.

## 분석 결과 평가

```bash
python tools/evaluate.py             # 전체 시나리오, 결정적 데모 경로
python tools/evaluate.py --live      # 설정된 LLM 에 실제로 붙여서
python tools/evaluate.py --json report.json
```

### 증강 전후 비교

```bash
python tools/evaluate.py --compare --live --markdown comparison.md
```

경보마다 두 번 분석해 두 결과를 비교합니다.
**"전"** 은 트리거 경보 하나만 — 증강 없는 SIEM 이 분석가에게 건네는 그대로이며,
상관 이벤트도 자산 정보도 위협 인텔리전스도 없습니다.
**"후"** 는 4블록 번들 전체입니다.
**모델에게 던지는 질문은 양쪽이 완전히 동일**하므로, 답의 차이는 프롬프트가 아니라 증거에서 온 것입니다.

경계 양쪽에서 무엇이 달라졌는지 보고합니다 — 들어간 증거의 양과 나온 결과
(지목한 대상, ATT&CK 기법, 확인된 관찰, 인용한 이벤트, 채워진 스키마 항목, 선언된 정답 재현율).
`--markdown` 은 두 답변 전문을 나란히 기록합니다.

세 가지를 측정하며, **객관적으로 판정 가능한 순서**대로입니다 —
스키마 충족도, 인용 근거성, 선언된 정답 재현.
앞의 둘은 라벨이 필요 없어서 합성 자료에 대한 회귀 검사로도 쓰입니다.
`--live` 실행은 판단이 불완전하거나 번들에 없는 이벤트 id 를 인용하면
**0 이 아닌 종료 코드**를 반환하므로, 프롬프트와 번들 변경을 자동으로 막는 관문이 됩니다.

정답 대조는 **일부러 얕게** 만들었습니다 — 판단문에서 기대 문자열을 찾는 수준입니다.
빠뜨린 기법이나 호스트는 잡아냅니다. 다만 **추론이 타당한지는 판정하지 않으며,
그것을 자동으로 판정하는 검사는 없습니다.**

## 구조화된 사건 판단

`alert_summary` 모드에서 모델은 산문만이 아니라 `assessment` 객체를 반드시 반환해야 합니다.
그 구조를 산문으로 부탁하면 작은 로컬 모델은 들쭉날쭉하게 따르므로, **스키마로 강제**합니다 —
확인된 관찰, 해석, 공격 가설, 신뢰도, 심각도, 영향받는 대상, ATT&CK 기법,
이벤트 id 를 인용한 뒷받침 증거와 모순 증거, 증거 공백, 권장 검색, 권장 대응.

**읽기는 관대하게, 보고는 엄격하게.**
정규화 단계는 객체 자리에 문자열이 와도, 키 이름이 조금 달라도 받아들입니다.
형식이 살짝 어긋났다고 쓸 만한 분석을 버리지 않기 위해서입니다.
그다음 검토 단계가 **무엇이 빠졌는지, 인용한 이벤트 id 중 번들에 없는 것이 무엇인지** 보고합니다.
그런 인용은 표시될 뿐 조용히 삭제되지 않습니다 —
모델이 존재하지 않는 증거를 인용한 순간을 분석가가 볼 수 있어야 하기 때문입니다.
불완전한 판단에는 보정 요청이 **한 번** 나가며(`ASSESSMENT_REPAIR_ENABLED`, 기본 켜짐),
보정 결과는 원본보다 더 많이 채웠을 때만 채택됩니다.

`contradictory_evidence` 는 정당하게 비어 있을 수 있습니다.
그래서 누락 항목으로 세지 않고 안내 문구로 보고합니다.
깨끗한 사건이 의미 없는 보정 왕복을 유발하지 않도록 하기 위해서입니다.

## 디렉터리 구조

```text
kisi-yaho/
├── app.py
├── .env.example
├── requirements.txt
├── README.md
├── hawki_alert_analysis/     수집 · 상관분석 · 증강 · 번들 조립
│   ├── adapters.py           생산자 원본 형식 -> 표준 이벤트
│   ├── ingest.py             수집한 로그 디렉터리 -> 시나리오 매니페스트
│   ├── correlate.py          시간 · 대상 기반 결정적 상관분석
│   ├── assets.py             자산 정보 수집과 매칭
│   ├── threat_intel.py       지표 피드 수집과 매칭
│   ├── bundle.py             4블록 증거 번들
│   ├── elastic.py            2단계: Elasticsearch 기반 저장소
│   ├── assessment.py         구조화된 판단 스키마와 검토
│   └── repository.py         출처에 무관한 이벤트 저장소
├── data/
│   ├── scenarios/            생산자 원본 형식 텔레메트리 자료
│   ├── assets/               자산 정보
│   └── threat_intel/         지표 피드
├── infra/terraform/          AWS 인프라 (GPU 서버, 네트워크, 예산)
├── tools/
│   ├── collect_pcap.py       PCAP -> Suricata -> 시나리오
│   └── evaluate.py           스키마 · 근거성 · 정답 채점
├── docs/                     프로젝트 문서
├── tests/
├── templates/
└── static/
```

## 테스트

```bash
python -m unittest discover -s tests
```

## 실행

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**환경변수 두 가지가 반드시 필요**하며, 없으면 서버가 시작을 거부합니다.

```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export HAWKI_ADMIN_USERNAME=analyst
export HAWKI_ADMIN_PASSWORD='choose-a-strong-password'
python app.py
```

<http://127.0.0.1:5000> 을 열고 로그인합니다.
경보 대기열은 `/alerts` 이고, 각 행은 `/alerts/<id>` 로 연결되며
거기서 **「LLM으로 분석하기」** 가 증거 번들을 설정된 모델로 보냅니다.

모델에 닿지 못하면 번들로부터 만든 결정적 요약으로 대체되며, **그렇다고 화면에 표시**됩니다.
실제 모델을 쓰려면 `LLM_API_URL` 과 `LLM_MODEL` 이 OpenAI 호환 엔드포인트
(vLLM, Ollama, llama.cpp 등)를 가리키게 하세요.

```bash
export LLM_API_URL=http://127.0.0.1:8000/v1/chat/completions
export LLM_MODEL=hawki-local
export DEMO_MODE=false        # 조용히 대체하지 말고 실패를 드러내기
```

### Compose 로 실행

```bash
cp .env.example .env                  # 필수: compose 가 env_file 로 읽습니다
docker compose up -d                  # 웹 앱만, 약 300MB, GPU 불필요
docker compose --profile llm up -d    # vLLM 추가 (GPU 필요)
```

서비스는 프로필 뒤에 두어 로컬 단계가 가볍게 유지됩니다.
웹 앱은 vLLM 에 의존하지 않습니다 — 실행을 거부하는 대신 **모델에 닿지 못한다고 보고**합니다.

호스트에서 수집한 시나리오로 작업하려면 마운트해서 띄웁니다.

```bash
docker compose -f compose.yaml -f compose.dev.yaml up
```

화면의 마크다운 렌더링에는 브라우저 라이브러리 세 개를 **이 출처에서 직접** 제공합니다.
한 번만 설치하면 됩니다 — Content Security Policy 가 `'self'` 스크립트만 허용하고,
배포 계획상 웹 계층은 CDN 으로 나가는 경로가 없는 서브넷에 놓이기 때문입니다.

```bash
python tools/vendor_assets.py            # static/vendor/ 에 설치
python tools/vendor_assets.py --verify   # 잠금 파일과 대조
```

없어도 앱은 동작하며, 마크다운은 이스케이프된 평문으로 표시됩니다.

브라우저 없이 전체를 검증하려면:

```bash
python -m unittest discover -s tests    # 테스트 101개, 네트워크·모델 불필요
python tools/evaluate.py                # 동봉된 시나리오 채점
```

## 데이터 출처

기본값은 1단계입니다 — 경보와 이벤트가 `data/scenarios/` 아래 시나리오 파일에서 옵니다.
저장소에는 리눅스 웹 침해 케이스(ModSecurity, Suricata, Nginx, Wazuh),
윈도우 드로퍼 케이스(Sysmon, Wazuh), 그리고 실제 캡처를 Suricata 로 재생한
NetSupport RAT 케이스가 들어 있습니다.

| 변수 | 기본값 | 용도 |
| --- | --- | --- |
| `ALERT_REPOSITORY` | `fixture` | `fixture` 또는 `elasticsearch` |
| `ALERT_FIXTURE_ROOT` | `data/scenarios` | 시나리오 디렉터리 |
| `ASSET_INVENTORY_ROOT` | `data/assets` | 자산 정보 JSON |
| `THREAT_INTEL_ROOT` | `data/threat_intel` | 지표 피드 JSON |
| `AGENT_CONTEXT_MAX_CHARS` | `24000` | 직렬화된 문맥 예산 |
| `ASSESSMENT_REPAIR_ENABLED` | `true` | 불완전한 판단에 대한 1회 보정 |

각 경로는 지정된 위치가 없으면 `hawki_alert_analysis/fixtures/` 에 동봉된 자료로 대체됩니다.
컨테이너에서 `/app/data` 위에 볼륨이 마운트될 때가 그 경우입니다.

### 2단계: Elasticsearch 에서 읽기

```bash
export ALERT_REPOSITORY=elasticsearch
export ELASTICSEARCH_URL=https://es.internal:9200
export ELASTICSEARCH_API_KEY=...                       # 또는 _USERNAME/_PASSWORD
export ELASTICSEARCH_ALERT_INDEX='wazuh-alerts-*,logs-*'
export ELASTICSEARCH_EVENT_INDEX='logs-*,winlogbeat-*,packetbeat-*'
export ELASTICSEARCH_WINDOW_SECONDS=300
python app.py
```

저장소 경계 아래로는 아무것도 바뀌지 않습니다.
Elasticsearch 는 시간과 대상으로 후보를 고르기만 하고,
순위 매김과 케이스 조립은 `correlate.build_case` 에 그대로 남습니다.
그래서 **운영 인덱스에서 만든 케이스와 파일에서 만든 케이스가 같은 규칙으로 조립되고 서로 비교 가능**합니다.
문서는 ECS 로도, 생산자 원본 형태로도 읽습니다 —
Suricata · Wazuh · Sysmon 기록이 그대로 실려 왔다면 각자의 어댑터가 정규화하므로
클러스터 전체에 하나의 관례를 강제할 필요가 없습니다. 문서 `_id` 가 이벤트 id 가 됩니다.

발행하는 요청은 `_search` 뿐이고 인덱스 패턴은 URL 에 닿기 전에 검증되므로,
이 저장소는 **구조적으로 읽기 전용**입니다. 대상 인덱스로 제한된 읽기 전용 API 키를 쓰세요.

클러스터에 닿지 못하면 모든 페이지에서 오류를 내는 대신 빈 경보 목록을 반환합니다.
`/api/config` 가 `alert_repository.reachable` 과 `last_error` 를 보고하므로
**왜 비어 있는지가 스스로 설명**됩니다.

`ENABLE_ES_SEARCH` 는 별개이며 `/logs` 의 분석가용 로그 검색을 제어합니다.
기본값은 `false` 이고, 이 상태에서는 질의 대신 Kibana 링크를 준비합니다.
실제 운영에 쓰기 전에는 전용 정책 게이트웨이가 이 엔드포인트를 대체해야 합니다.

## 운영 배포 시 유의사항

- Flask 서비스를 Nginx 나 Caddy 뒤에 둘 것
- 신뢰된 실습망 밖으로 노출하기 전에 인증을 추가할 것
- vLLM 과 Elasticsearch 는 신뢰되지 않은 클라이언트에서 접근 불가하게 유지할 것
- HTTPS 를 쓸 것
- CSRF 방어, 영속 세션, RBAC, 감사 로깅, 요청 제한을 추가할 것
- **LLM 이 제안한 모든 질의와 대응 조치는 검증 전까지 신뢰하지 않을 것**
