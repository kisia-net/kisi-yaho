# 역할 분담 — 2026-08-25 멘토링 Action Items 기준

작성 2026-08-27 · 기준 문서 `docs/MENTORING_LOG.md`, 「이글루코퍼레이션 답사 멘토링 (8/24)」

원칙 세 가지입니다.

1. **한 사람이 서버 한 대를 온전히 책임진다.** 그래야 "그 서버는 누구한테 물어보면 되냐" 가 성립합니다.
2. **팀장은 빈 서버를 접속 가능한 상태까지만 만들어 넘긴다.** 그 안에 오픈소스를 깔고 설정하는 것은 담당자의 몫입니다.
3. **모든 항목은 "무엇이 나오면 끝인가" 를 적는다.** 완료 판정이 없는 일은 끝나지 않습니다.

Action Item 15개와, 멘토링 본문에만 있고 체크리스트에는 빠진 4개를 합쳐 19개를 나눴습니다.

---

## ① 아키텍처·구성도 — 민석형

**담당 서버** SIEM (Wazuh Manager · Indexer · Dashboard) · `t3.large` 이상
**Action Item** 1, 2, 3, 4, 13

### 1. 구성도 검수 — 제가 그린 것을 그대로 쓰지 마십시오

`docs/diagrams/키시야호_구성도_1_네트워크.png` 와 `_2_계층도.png` 를 열고, 아래 여섯 개를 하나씩 확인합니다.

| 확인할 것 | 맞으면 | 틀리면 |
|---|---|---|
| Wazuh Agent 가 웹 서버·네트워크 센서·엔드포인트 **세 상자 안에** 각각 들어 있는가 | 통과 | 위치 지정해 알려주기 |
| Network IDS 상자 위로 「트래픽 미러링 (SPAN/TAP)」 화살표가 들어오는가 | 통과 | 방향 지정 |
| 장비 상자마다 회색 글씨로 그 장비가 내보내는 로그 이름이 붙어 있는가 | 통과 | 빠진 장비 지정 |
| 「SIEM (Wazuh)」 · 「Network IDS (Suricata)」 표기로 되어 있는가 | 통과 | 위치 지정 |
| 공격 유입선(① HTTPS 443)이 IGW→웹 서버로만 들어오는가 | 통과 | — |
| C2 아웃바운드(②)가 NAT GW 를 거쳐 나가는가 | 통과 | — |

**완료 판정** — 여섯 항목 전부에 O 를 치거나, 고칠 곳을 좌표로 지정해서 팀장에게 전달.

### 2. 표기 수정을 그림 밖으로 확대 (Action Item 4)

그림은 고쳤지만 **문서와 코드에는 아직 옛 표기가 남아 있습니다.**

```bash
cd kisi-yaho
grep -rn "Wazuh SIEM" --include="*.md" --include="*.py" --include="*.json" .
grep -rn "^Suricata\|· Suricata\|Suricata를\|Suricata가" --include="*.md" docs README.md
```

나온 줄을 `SIEM (Wazuh)` · `Network IDS (Suricata)` 로 고칩니다. 단 **다음은 고치지 않습니다** — `source_type: "suricata"`, `suricata.eve`, `SuricataAdapter`, 파일 경로. 이건 제품명이 아니라 식별자라 바꾸면 코드가 깨집니다.

**완료 판정** — 위 `grep` 두 줄이 아무것도 출력하지 않음 (식별자 제외).

### 3. 로그 전송 에이전트 명칭 재확인 (Action Item 13)

멘토링 기록에 "※ 멘토링 중 언급된 에이전트 명칭은 재확인 필요" 라고 남아 있습니다. 후보는 세 가지입니다.

- **Wazuh Agent** — 우리가 지금 그림에 쓴 이름
- **Filebeat / Elastic Agent** — Wazuh 가 내부적으로 쓰는 전송 컴포넌트
- **Fluent Bit / Logstash** — 일반적인 로그 수집 에이전트

멘토님께 "저희가 그림에 Wazuh Agent 라고 적었는데, 말씀하신 에이전트가 이것 맞습니까" 를 확인하고, 다른 이름이면 그림·표 1·`README.md` 세 곳을 함께 고칩니다.

**완료 판정** — `docs/MENTORING_LOG.md` 에 확정된 명칭과 확인 날짜가 기록됨.

### 4. 발표 아키텍처 파트 담당

멘토님 지적의 핵심은 그림이 아니라 이 문장입니다 — *"개발을 처음부터 한 사람조차 자기 아키텍처가 어떻게 구현됐는지 놓친다"*, *"사고 대응에는 네트워크 구성도를 도메인 지식으로 가진 사람이 반드시 포함된다"*.

발표 때 다음 세 질문에 그림만 보고 답할 수 있어야 합니다.

1. 공격이 어디로 들어와서 어디로 나갔습니까
2. 이 판단의 근거가 된 로그는 어느 장비에서 왔습니까
3. 왜 프라이빗 서브넷에 인바운드 규칙이 하나도 없습니까

**완료 판정** — 팀 회의에서 그림 두 장만 띄워놓고 3분 안에 설명 완주.

---

## ② 인프라·AWS + 파이프라인 코드 — 세현 (팀장)

**담당 서버** VM 7대 생성 전체 · LLM (`g6e.xlarge`, 구축 완료)
**Action Item** 14 + 멘토링 §6 · §9

### 1. 6주차 내 인프라 구축 일정 (Action Item 14)

`infra/terraform/` 에 VM 6대를 추가합니다. 지금은 `llm.tf` 하나만 있습니다.

| 순서 | 파일 | 인스턴스 | 이유 |
|---|---|---|---|
| 1 | `siem.tf` | `t3.large` | 나머지가 전부 여기로 로그를 보내므로 제일 먼저 |
| 2 | `web.tf` | `t3.small` | nginx + ModSecurity. 공격 대상 |
| 3 | `sensor.tf` | `t3.medium` | Suricata + 트래픽 미러링 타겟 |
| 4 | `endpoint.tf` | `t3.small` (Windows) | Sysmon |
| 5 | `dfir.tf` | `t3.small` | Velociraptor Server |
| 6 | `attacker.tf` | `t3.micro` | 7주차 |

각 VM 은 `lab_running` 변수로 함께 껐다 켜지도록 `count = var.lab_running ? 1 : 0` 를 답니다.

**완료 판정** — `terraform plan` 이 "6 to add" 를 출력하고, `terraform apply` 후 여섯 대 모두 SSM 세션 매니저로 접속됨. 각 담당자에게 인스턴스 ID 전달.

**넘기는 경계** — 저는 여기까지입니다. 그 안에 Suricata·nginx·Sysmon 을 깔고 설정하는 것은 각 담당자가 합니다.

### 2. 증강 소스를 SIEM 기준으로 재정리 (멘토링 §6)

멘토님 답변: *"사실상 모든 정보는 SIEM 안에 담겨 있다. 증강 소스를 SIEM 기준으로 정리할 것."*

지금 4블록 번들의 출처입니다.

| 블록 | 현재 출처 | SIEM 기준이면 |
|---|---|---|
| `security_alerts` | `data/scenarios/*/` 파일 | Wazuh 경보 인덱스 |
| `security_events` | 같음 | Wazuh 이벤트 인덱스 |
| `assets` | `data/assets/inventory.json` | Wazuh agent 목록 + syscollector |
| `threat_intelligence` | `data/threat_intel/indicators.json` | 외부 유지 (SIEM 밖이 맞음) |

`assets` 를 Wazuh syscollector 로 옮기면 자산 정보가 사람 손으로 유지되지 않고 자동으로 최신이 됩니다. 이게 멘토님이 말한 "SIEM 안에 다 있다" 의 실물입니다.

**완료 판정** — `hawki_alert_analysis/assets.py` 가 Wazuh API 를 읽는 경로를 갖고, 파일 경로는 폴백으로 남음.

### 3. 확장성 질문 대응 1장 (멘토링 §9)

*"하루 100억 건, 5TB 를 유실 없이 처리하는 SIEM 을 만들 수 있는가?"* — 예상 질문입니다. 정직하게 답해야 합니다.

준비할 숫자: 우리 실측 규모(`mta_001` = 3,854 이벤트 / 2.9MB), 상관분석 윈도우 300초, `correlate.py` 의 `max_events=50` 제약, 100억 건 환산 시 무엇이 먼저 터지는가.

**완료 판정** — 「우리 규모 / 실제 규모 / 격차 / 격차를 메우려면」 4단 슬라이드 1장.

### 4. 파이프라인 코드 유지보수 (상시)

`app.py` · `correlate.py` · `bundle.py` · `assessment.py` · `adapters.py` 의 소유자입니다. 알려진 결함 세 가지를 처리합니다.

1. `correlate.py` `max_events=50` — 조용히 잘라냅니다. 설계 원칙 「손실 보고」 위반이라 잘린 건수를 번들에 실어야 합니다.
2. `models.py:20` `fromisoformat` — Python 3.10(Ubuntu 22.04)에서 깨집니다. SIEM VM 이 서면 바로 문제가 됩니다.
3. `tests/test_alert_analysis.py` 2건 실패 — `python -m pytest tests -q` 로 재현.

---

## ③ 네트워크·로그 수집

**담당 서버** 네트워크 센서 (Suricata) · `t3.medium`
**Action Item** 5, 6

### 1. payload 를 켠다 (Action Item 5) — 첫 작업

**확인은 이미 끝났습니다. 지금 payload 가 0건입니다.**

```
mta_001/eve.json  3,854줄 전수 조사
  payload             0건
  payload_printable   0건
  http_request_body   0건
```

Suricata 기본 설정이 payload 를 안 찍습니다. 센서 VM 에서 `/etc/suricata/suricata.yaml` 의 `outputs:` → `eve-log:` → `types:` → `alert:` 아래를 이렇게 고칩니다.

```yaml
- alert:
    payload: yes              # 원본 바이트 (base64)
    payload-printable: yes    # 사람이 읽을 수 있는 형태  ← 발표에 쓸 것
    payload-buffer-size: 4kb
    http-body: yes            # HTTP 요청 본문
    http-body-printable: yes
    metadata: yes
```

적용 후 재시작하고 PCAP 을 다시 재생합니다.

```bash
sudo systemctl restart suricata
sudo suricata -r capture.pcap -l /var/log/suricata/
python3 -c "import json;print(sum('payload_printable' in json.loads(l) for l in open('/var/log/suricata/eve.json')))"
```

0 이 아닌 숫자가 나오면 성공입니다. 그다음 path traversal 경보 하나를 골라 `payload_printable` 이 보이도록 캡처합니다.

**완료 판정** — `GET /../../etc/passwd` 같은 실제 요청 문자열이 보이는 스크린샷 1장. 이게 있어야 발표에서 "탐지됐습니다" 를 넘어 **"뭐가 들어왔는지"** 를 보여줄 수 있습니다.

**주의** — payload 를 켜면 로그 용량이 크게 늘어납니다. 재생 후 `du -h eve.json` 로 증가폭을 재서 팀장에게 알려주십시오. §9 확장성 답변에 그 숫자가 들어갑니다.

### 2. 웹/네트워크 정규화 분리 정리 (Action Item 6)

초안은 이미 노션에 있습니다. 이걸 **발표 슬라이드 한 장**으로 만드는 것이 남은 일입니다.

읽을 코드: `hawki_alert_analysis/adapters.py`
- `NginxAdapter` `:228-273` / `ApacheAdapter` `:277-291`
- `SuricataAdapter` `:62-227`

슬라이드에 반드시 들어가야 할 대비 세 가지입니다.

| | 웹 서버 로그 | 네트워크 로그 |
|---|---|---|
| 입력 | 문자열 한 줄 → 정규식 파싱 | JSON dict, `event_type` 마다 스키마가 다름 |
| 5-tuple | `source_port` 없음, `destination_*` 는 시나리오 기본값 | 원본에서 직접 |
| 없는 필드 | `rule` · `dns` · `tls` · `correlation` 전부 빔 | `http` 블록이 빔 |

그리고 마지막 한 줄이 핵심입니다 — **같은 `flow_id` 의 `alert` 와 `http` 는 별도 레코드로 정규화되고, 상관분석에서 +7점으로 다시 묶인다** (`correlate.py:36`). 「왜 뭉치지 않고 나눴다가 다시 묶느냐」가 나올 질문이고, 답은 "원본 보존" 입니다.

**완료 판정** — 좌우 대비표 + 실제 로그 한 줄 → 정규화 결과 JSON 을 보여주는 슬라이드 1장.

---

## ④ 경보 설계

**담당 서버** 웹 서버 (nginx + ModSecurity) `t3.small` · 공격자 `t3.micro`(7주차)
**Action Item** 7, 10 + 멘토링 §7

### 1. 경보 룰 3종 정의 (Action Item 7)

멘토님이 방향을 세 개로 주셨습니다. 각각에 대해 「무엇을 보고 · 언제 울리고 · 위험도를 어떻게 매기는가」를 씁니다.

| # | 룰 | 보는 것 | 발동 조건 | 위험도 |
|---|---|---|---|---|
| 1 | SQLi 문자열 탐지 | ModSecurity 경보 | SQLi 룰 ID 매칭 | 중 |
| 2 | IP 기반 | 출발지 IP | 위협 인텔 매칭 또는 임계 초과 | 인텔 confidence 를 따름 |
| 3 | **WAF + 웹서버 200 상관분석** | ModSecurity 경보 + nginx 응답코드 | 같은 IP·URI 가 300초 내 양쪽에 등장 | **200 → 높음 / 403·404 → 낮음** |

3번이 핵심입니다. 멘토님 말씀 그대로 — *WAF 에서 탐지됐고 웹 서버를 통과했다면 위험, 통과 못 했다면 위험도 하향.* 단일 장비 경보로는 절대 못 하는 판단이고, **우리가 상관분석을 하는 이유 그 자체**입니다.

**완료 판정** — 세 룰의 정의서(위 표를 채운 것) + 3번에 해당하는 실제 사례를 `web_path_traversal` 시나리오에서 찾아 캡처.

### 2. 공격 유형별 시간 윈도우 (Action Item 10)

지금 `scenario.json` 은 전부 `"correlation_window_seconds": 300` 으로 고정입니다. 멘토님 지적은 **공격 유형마다 달라야 한다**는 것이었습니다.

| 공격 유형 | 윈도우 | 근거 |
|---|---|---|
| Brute force | 60~300초 | 짧은 시간에 몰림 |
| 회피형 brute force | 3일 | "5분에 한 번씩 때리는 놈" |
| 정찰 → 침투 → C2 | 1주 | 잘 만들어진 SIEM 의 범위 |
| Path traversal 단발 | 300초 | 현행 유지 |

**완료 판정** — 위 표 + `scenario.json` 의 `correlation_window_seconds` 를 시나리오별로 다르게 설정하고 결과가 달라지는지 확인.

**주의** — 윈도우를 넓히면 상관분석에 걸리는 이벤트가 늘어나는데, `correlate.py` 의 `max_events=50` 에서 잘립니다. 1주 윈도우를 쓰려면 이 값을 함께 손봐야 하니 팀장에게 알려주십시오.

### 3. Brute force 시나리오 신규 제작 (멘토링 §7)

멘토님이 §7 전체를 brute force 로 설명하셨는데 **우리 시나리오 3개에 brute force 가 없습니다.** 예시로 드신 걸 우리가 못 보여주는 상태입니다.

`data/scenarios/brute_force/` 를 새로 만듭니다. 기존 시나리오와 같은 구조입니다.

```
data/scenarios/brute_force/
  scenario.json
  nginx_access.log        ← /portal/login 에 대한 POST 다수, 401 → 200
  modsec_audit.json       ← WAF 경보
  wazuh_alerts.jsonl      ← 인증 실패 반복 경보
```

`scenario.json` 은 `web_path_traversal/scenario.json` 을 복사해서 `id`, `trigger`, `sources`, `correlation_window_seconds` 만 고칩니다.

로그 내용은 멘토님이 알려주신 **판단 순서**가 데이터로 재현되도록 만듭니다.

1. 같은 출발지 IP 에서 `/portal/login` 으로 POST 반복
2. 응답 코드가 계속 401 이다가 **한 번 200 이 나온다**
3. 200 이 나온 요청은 앞의 실패들과 **패킷 사이즈가 다르다**
4. 200 이후 다른 페이지로 이동한 흔적

이 네 개가 로그에 있으면, 분석 화면이 "성공했는가" 에 답할 수 있고 발표에서 멘토님 질문 순서 그대로 따라갈 수 있습니다.

**완료 판정** — 화면에 새 시나리오가 뜨고, 「LLM으로 분석하기」 결과에 "인증 시도 다수 중 1건 성공" 이 나옴.

---

## ⑤ LLM 분석·대응

**담당 서버** DFIR (Velociraptor Server) · `t3.small`
**Action Item** 8, 9, 11

### 1. Suricata 룰 제안 목적 확정 (Action Item 9) — 이번 주 최우선

멘토링 기록에서 **「⚠️ 예상 질문」이라고 직접 표시된 유일한 항목**입니다.

> "이미 Suricata NIDS 로 탐지가 됐는데, 여기서 또 Suricata 룰을 제안하는 건 이상하지 않나?"

둘 중 하나를 고릅니다. 고르고 나면 평가 지표가 자동으로 정해집니다.

| | (A) 미탐(FN) 감소 | (B) 탐지 범위 확대 |
|---|---|---|
| 주장 | NIDS 탐지가 부정확할 수 있으니 정확도를 높인다 | 우회 시도를 잡으려 scope 를 넓힌다 |
| 대가 | 룰이 좁아져 놓치는 게 생길 수 있음 | **오탐(FP)이 올라감** |
| 측정 지표 | 기존 룰이 놓친 이벤트를 새 룰이 몇 건 잡는가 | 새 룰이 추가로 잡은 건수 중 실제 위협 비율 |
| 우리 데이터로 측정 가능한가 | 561건 경보 + 3,293건 비경보 이벤트로 가능 | 가능하나 정답 라벨이 없어 수작업 판정 필요 |

**완료 판정** — 「우리는 (A/B) 를 목적으로 한다. 근거는 ~. 따라서 지표는 ~ 이다」 세 문장이 담긴 1장. 이 한 장이 룰을 만드는 것보다 먼저입니다.

### 2. LLM 에 구성 컨텍스트 주입 → Sigma 룰 생성 (Action Item 8)

멘토님이 넣을 것 네 가지를 짚어주셨습니다 — 어떤 로그를 수집하는가 / 어떤 장비를 쓰는가 / 로그 출처 / 어떤 form 으로 SIEM 에 전달하는가.

`app.py` 의 `BASE_SYSTEM_PROMPT` 아래에 구성 컨텍스트 블록을 붙이고, `docs/diagrams/` 의 표 1·표 2 내용을 텍스트로 넣습니다.

여기에 멘토님이 §2 끝에 덧붙이신 활용 포인트가 있습니다 — *"구성도를 인식시키면, 원래 어디에서 로그를 가져왔어야 하는지 판단하고 엉뚱한 곳에서 수집 중이면 지적해 줄 수 있다."* 이건 Sigma 생성보다 **더 좋은 데모 소재**입니다. 일부러 없는 장비의 로그를 요구하는 질문을 던져서 모델이 지적하는지 봅니다.

**완료 판정** — 생성된 Sigma 룰 3건 + 그중 우리 로그에 실제로 매칭되는 것이 있는지 확인한 결과.

### 3. 검증 에이전트 비식별 처리 로직 (Action Item 11)

예상 질문 대비입니다 — *"기밀 정보는 어떻게 처리하나?"*

번들에서 마스킹할 대상을 정합니다: 내부 IP(`192.168.*`, `10.*`) → 자산 별칭, 사용자명(`j.lee`) → 역할 라벨, 호스트명 → 자산 ID, 파일 경로 중 사용자 폴더.

**마스킹하면 안 되는 것**: 외부 IP(위협 인텔 매칭에 필요), 파일 해시, 도메인, 룰 ID. 이걸 가리면 분석 자체가 불가능해집니다.

**완료 판정** — 마스킹 전/후 번들을 나란히 보여주는 예시 + "왜 이건 가리고 저건 안 가리는가" 한 문단.

---

## ⑥ 엔드포인트·데이터 신뢰성·문서

**담당 서버** 엔드포인트 (Windows) · `t3.small`
**Action Item** 12, 15 + 멘토링 §3

이 트랙이 **우리 데모의 신뢰도를 가장 크게 올릴 수 있는 자리**입니다. 이유는 아래 1번에 있습니다.

### 1. 실제 엔드포인트 로그 확보 (멘토링 §3) — 최우선

멘토링 기록 §3 에 이 문장이 있습니다.

> **"윈도우 시스템에서 들어오는 로그가 보였다 → 왜?"**
> "로그 기록만 봐도 실제 데이터인지 가상(합성) 데이터인지 알 수 있다."

**멘토님이 우리 화면을 보고 물으신 겁니다.** 우리 `data/scenarios/windows_dropper/sysmon.jsonl` 은 손으로 쓴 5줄입니다. 이미 들켰고, 다음에 또 물으실 항목입니다.

할 일 순서입니다.

1. 팀장에게 Windows 엔드포인트 VM 인스턴스 ID 를 받는다
2. Sysmon 설치 — SwiftOnSecurity 설정 파일을 쓰면 소음이 줄어듭니다
   ```
   sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
3. Wazuh Agent 설치 후 SIEM 서버에 등록. `ossec.conf` 에 Sysmon 채널을 추가합니다
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
4. `windows_dropper` 시나리오를 **실제로 재현** — Office 문서에서 PowerShell 이 뜨고, 임시 폴더에 파일을 쓰고, 그걸 실행하는 흐름
5. 나온 Sysmon 이벤트를 `data/scenarios/windows_dropper_real/sysmon.jsonl` 로 저장

**완료 판정** — Event ID 1(프로세스 생성) · 3(네트워크) · 11(파일 생성) · 22(DNS) 가 실제 타임스탬프와 실제 SHA256 을 달고 들어옴. 합성 5줄과 나란히 놓으면 차이가 한눈에 보입니다.

### 2. 실제/합성 구분표 (멘토링 §3)

멘토님 말씀 — *"가상 데이터를 쓴다면 그 사실을 인지하고 설명할 수 있어야 한다."* 숨기지 말고 표로 만들어 발표에 넣습니다.

| 데이터 | 출처 | 실제/합성 | 규모 |
|---|---|---|---|
| `mta_001` 네트워크 | 공개 PCAP 재생 | **실제** | 3,854 이벤트 / 561 경보 |
| `web_path_traversal` | 손으로 작성 | 합성 | 6 경보 |
| `windows_dropper` | 손으로 작성 | 합성 | 2 경보 · Sysmon 5줄 |
| 위협 인텔 `indicators.json` | 손으로 작성 | **합성** | — |
| 자산 `inventory.json` | 손으로 작성 | 합성 | — |

이 표를 만들면서 반드시 짚어야 할 것이 하나 있습니다. **`mta_001` 의 실제 C2 IP `45.131.214.85` 가 우리 `indicators.json` 에 없습니다.** 지금 위협 인텔이 잡아내는 건 우리가 직접 심어둔 `203.0.113.45` 뿐입니다. 즉 **우리가 심어둔 답을 우리가 찾아내고 있는** 상태고, 이건 발표에서 반드시 나올 질문입니다.

**완료 판정** — 위 표 + 「합성인 부분을 어떻게 실제로 바꿀 것인가」 한 문단(abuse.ch URLhaus/ThreatFox 연동 계획).

### 3. Suricata 룰 오류 → 수정 이력 문서화 (Action Item 12)

멘토님 조언 — *"오류 발견부터 수정까지의 과정을 기록해 두고 발표 때 히스토리로 풀면 좋다. 팀원이 이미 고쳐 놓은 부분을 다른 사람이 원복했을 때도 추적이 가능해진다."*

`docs/ISSUE_LOG.md` 를 만들고 형식을 고정합니다.

| 날짜 | 증상 | 원인 | 조치 | 커밋 |
|---|---|---|---|---|

이미 채울 수 있는 항목이 여러 건 있습니다 — LLM 400 에러(컨텍스트 8192 초과 → 32768), JSON 잘림(출력 토큰 2200 → 12000), 미작성 항목 11개(모델이 키에서 밑줄을 뺌 → `_restore_separators()`), 영어 출력(언어 지시가 영어 계약서 앞에 있었음 → 마지막으로 이동).

**완료 판정** — `docs/ISSUE_LOG.md` 에 최소 5건. 각 행에 커밋 해시가 붙어 있을 것.

### 4. 이슈 5가지 취합 (Action Item 15)

멘토님 요구 — *"모일 때마다 이슈 5가지를 뽑아 올 것."* 6명이 각자 1개씩 내면 채워집니다. 회의 전날 취합해서 `docs/MENTORING_LOG.md` 에 올립니다.

---

## 전원 공통

**Zero-Trust 자세** (멘토링 §10) — *"플랫폼을 만들었으면 하나하나 직접 확인하고 체크해야 한다."* 자기 담당 서버는 남이 만들어준 걸 믿지 말고 직접 열어보십시오. 제가 그린 구성도도 마찬가지입니다.

**커밋 규칙** — 이력 추적이 되려면 커밋 메시지가 「무엇을 왜」를 담아야 합니다. `fix`, `update` 한 단어짜리 커밋은 나중에 원복 추적이 안 됩니다.

**AWS 비용** — GPU 는 하루 약 7만원입니다. `terraform apply -var lab_running=false` 로 끄되, 끄기 전에 다른 사람이 쓰고 있는지 확인하십시오. `setup.ps1` 은 절대 실행하지 마십시오(서버가 한 벌 더 생깁니다).
