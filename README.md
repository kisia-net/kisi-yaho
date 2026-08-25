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
| [`docs/PROJECT_NOTES.md`](docs/PROJECT_NOTES.md) | 설계 결정과 근거 |
| [`docs/AWS_구축_가이드.md`](docs/AWS_구축_가이드.md) | AWS 환경 구축 1~6단계 (처음 쓰는 사람 기준) |
| [`infra/terraform/README.md`](infra/terraform/README.md) | 인프라 코드 사용법 |
| [`docs/submissions/`](docs/submissions/) | 제출용 문서 원본 (HWP 붙여넣기용 docx) |

---

## 업데이트 기록

새 항목은 **맨 위에** 추가합니다. 날짜 + 무엇이 달라졌는지 한 줄로 씁니다.

### 2026-08-24 — AWS GPU 실제 연동

- AWS `g6e.xlarge` (L40S 48GB) 에 GPT-OSS 20B 를 vLLM 으로 서빙하고, **실제 모델 추론으로 사건 판단을 받아냄**
- 모델 문맥 길이 8192 → 32768 상향 (4블록 증거 번들이 8K 를 초과)
- 분석 결과 한국어 출력 지원 (`LLM_OUTPUT_LANGUAGE`). 식별자·ATT&CK 명칭은 원문 유지
- 사건 판단을 **검증된 `assessment` 객체에서 직접 렌더링** — 화면에 보이는 것과 검증 대상이 동일해짐
- 모델이 JSON 키의 밑줄을 생략하는 문제를 관대한 파싱으로 흡수
- 좁은 화면에서 판단 패널이 3단 격자에 갇히던 문제, 긴 경로·해시가 카드 폭을 밀어내던 문제 수정
- `.gitattributes` 추가 — 줄바꿈 차이로 안 고친 파일이 modified 로 잡히던 문제 해결
- 문서 정리: `docs/STATUS.md`, `docs/RUNBOOK.md` 신설, 제출용 docx 는 `docs/submissions/` 로 이동

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

A minimal Flask-based front end that represents the intended LLM-assisted SOAR architecture.

## Included features

- Multi-source log collection normalized into a canonical event model
- Deterministic correlation into alert cases
- Asset inventory and threat-intelligence enrichment
- A four-block evidence bundle delivered to the local LLM/SLM
- Local LLM chat through an OpenAI-compatible endpoint
- Fixed security-analyst system prompt
- Operational metrics and alert-volume visualization
- Alert queue and incident summary
- Service-health checks for the LLM, Elasticsearch, and Kibana
- Safe links to Kibana and Elasticsearch
- Optional read-only Elasticsearch search
- No Elasticsearch credentials exposed to the browser
- Architecture overview dialog

## Log collection and the evidence bundle

Telemetry is collected in native producer formats, normalized to a canonical
event model, correlated deterministically, and enriched before anything reaches
the model. One alert case is delivered to the LLM/SLM as a single bundle
(`hawki.siem.evidence-bundle/v1`) holding four metadata blocks:

| Block | | Contents |
| --- | --- | --- |
| `security_alerts` | 보안경보 | The triggering detection (`role: "trigger"`) plus correlated detections |
| `security_events` | 보안이벤트 | Correlated raw telemetry, normalized, with the untouched producer record under `event.original` |
| `assets` | 자산정보 | Inventory records for hosts and addresses seen in the evidence |
| `threat_intelligence` | 위협 인텔리전스 | Indicator matches for observables found in the evidence |

Blocks are cross-referenced: every alert and event carries a `links` field
naming the asset and indicator ids it touches, so the model does not have to
re-join four independent lists.

Each block states its own evidential weight. A detection is a producer's
opinion, asset criticality informs impact rather than likelihood, and an
indicator match raises suspicion without proving compromise. Hosts with no
inventory record and observables with no intelligence coverage are reported
explicitly, because absence of data is not evidence of safety.

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

Collection sources are swappable behind their interfaces. `FixtureEventRepository`
is replaced by `ElasticsearchEventRepository` with one environment variable, and
`FileAssetInventory` and `FileThreatIntelFeed` can be replaced by a CMDB and
MISP/OpenCTI, without changing correlation, bundling, or the agent.

Relevant endpoints:

```text
GET  /api/alerts                    triage queue with asset/intel previews
GET  /api/alerts/{id}               full case
GET  /api/alerts/{id}/context       the exact bundle sent to the model
GET  /api/alerts/{id}/evidence      trigger and correlated evidence
GET  /api/alerts/{id}/timeline      ordered sequence
POST /api/alerts/{id}/analyze       run the local model over the bundle
GET  /api/assets                    asset inventory
GET  /api/threat-intel              indicator feed
```

Collection roots are configurable with `ALERT_FIXTURE_ROOT`,
`ASSET_INVENTORY_ROOT`, and `THREAT_INTEL_ROOT`. Each falls back to the fixtures
packaged in `hawki_alert_analysis/fixtures/` when the configured path is absent,
which is what happens in the container, where a volume is mounted over `/app/data`.

`AGENT_CONTEXT_MAX_CHARS` bounds the serialized context. When a bundle exceeds
it, evidence is reduced in order of cheapest loss — repeated boilerplate, then
original producer records, then correlated events, then a digest — and what was
removed is stated in the payload. The four blocks survive every step, and the
result is always valid JSON.

## Collecting real logs

Adapters exist for Suricata EVE, Wazuh alerts, ModSecurity audit logs, Windows
Sysmon, Nginx and Apache combined access logs, Linux syslog, and `auth.log`,
plus a generic ECS reader. Anything those
understand can be ingested without writing code.

### From a directory of collected logs

```bash
python -m hawki_alert_analysis.ingest /path/to/logs \
    --out data/scenarios/my_case --host web-01 --year 2026 --dry-run
```

Source types are identified by filename, then by content. Detection reports
what it classified and what it could not — a file no adapter reads is named
rather than skipped quietly, because a source silently missing from a case looks
exactly like a source that had nothing in it. Individual unparsable lines
(rotation banners, truncated writes) are counted in
`FixtureEventRepository.skipped_lines` instead of discarding the whole file.

Syslog carries no year, so pass `--year`; without it the current year is assumed
and the events are tagged `assumed-year`. Ingest never writes into the log
directory, so read-only corpora work as-is.

### From a PCAP

With Suricata installed locally:

```bash
python tools/collect_pcap.py capture.pcap --out data/scenarios/replay_case
```

Or through Compose, with no local install:

```bash
cp ~/Downloads/traffic.pcap capture/pcap/capture.pcap

docker compose run --rm suricata-update      # once: fetch ET Open rules
docker compose run --rm suricata             # replay -> capture/out/eve.json

python -m hawki_alert_analysis.ingest capture/out \
    --out data/scenarios/real_001 --host web-01
```

Suricata reads the capture and writes its own `eve.json` — the same format a
live sensor produces, so nothing downstream can tell the difference. Nothing
about the resulting events is synthetic.

Run `suricata-update` first. Without a ruleset Suricata still logs `http`,
`dns`, `tls` and `flow` events, but raises no alerts, and a case with no alert
has no trigger.

`tools/collect_pcap.py` does not bundle Suricata; if it is missing the script
prints installation instructions and exits rather than reporting a collection
that did not happen.

### Ground truth

`--labels labels.json` attaches ground truth and names the trigger explicitly:

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

Scenarios remain necessary after switching to real logs, but their role changes:
the manifest is the label layer, not the data. Evaluating whether a
reconstruction is *correct* requires knowing the answer.

### Datasets

Flow-feature datasets — CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, KDD'99 — do not
fit this system. They ship derived statistics per flow rather than raw producer
records, and there is no incident to reconstruct from a feature vector.

These do fit:

| Dataset | Contents | Use |
| --- | --- | --- |
| AIT Log Data Set (AIT-LDS) | Apache, auth, syslog, audit, DNS, Suricata EVE, and Wazuh in v2; multi-host, labeled attack phases | Closest match to the existing adapters; primary evaluation corpus. Check the Zenodo record for the exact per-version source list |
| OTRF Security-Datasets (ex-Mordor) | Per-ATT&CK-technique JSON, Sysmon and Windows Security | Technique-level evaluation; read directly by the Sysmon adapter |
| Splunk `attack_data` | Per-technique raw logs across many producers | Pick individual datasets |
| Splunk BOTS v1–v3 | A full incident with ground-truth Q&A | Feed the Q&A into `expected.answers` as an evaluation set |
| malware-traffic-analysis.net | PCAP plus a published write-up | Replay through `collect_pcap.py`; the write-up is the ground truth |
| EVTX-ATTACK-SAMPLES | Per-technique Windows EVTX | Convert to JSON (evtx_dump, Chainsaw) and ingest as Sysmon |

Keep corpora outside the repository — size and licensing both argue against
committing them — and point `ALERT_FIXTURE_ROOT` at them.

## Evaluating the analysis

```bash
python tools/evaluate.py             # every scenario, deterministic demo path
python tools/evaluate.py --live      # against the configured LLM
python tools/evaluate.py --json report.json
```

### Before and after enrichment

```bash
python tools/evaluate.py --compare --live --markdown comparison.md
```

Analyzes each alert twice and diffs the two runs. The "before" side is the
triggering alert alone — what an un-enriched SIEM hands an analyst, with no
correlated events, no asset context, and no threat intelligence. The "after"
side is the full four-block bundle. The question put to the model is identical
both times, so any difference in the answer is attributable to the evidence
rather than to prompting.

It reports what changed on both sides of the boundary: how much evidence went
in, and what came back out — entities named, ATT&CK techniques, confirmed
observations, cited events, schema sections filled, and recovery of any declared
ground truth. `--markdown` writes both full answers side by side.

Three things are measured, in decreasing order of how objectively they can be
judged: schema coverage, citation grounding, and recovery of any declared ground
truth. The first two need no labels, so this doubles as a regression check on
the synthetic fixture. A `--live` run exits non-zero when an assessment is
incomplete or cites an event id that is not in the bundle, so it can gate prompt
and bundle changes.

Ground-truth matching is deliberately shallow — it looks for expected strings in
the assessment. That catches a missed technique or host. It does not judge
whether the reasoning is sound, and no automatic check does.

## Structured assessment

For `alert_summary`, the model must return an `assessment` object rather than
prose alone. Asking for that structure in prose is followed unevenly by a small
local model, so it is enforced as a schema: confirmed observations,
interpretation, attack hypothesis, confidence, severity, affected entities,
ATT&CK techniques, supporting and contradictory evidence with cited event ids,
evidence gaps, recommended searches, and recommended response.

Reading is tolerant and reporting is strict. Normalization accepts a bare
string where an object was requested and alternate key names, so a usable
analysis is never discarded on a formatting slip. Review then reports what is
missing and which cited event ids match nothing in the bundle — those are
annotated, never quietly dropped, so an analyst can see when the model cited
evidence that does not exist. An incomplete assessment triggers one correction
pass (`ASSESSMENT_REPAIR_ENABLED`, default on), and the correction is kept only
if it covers more than the original.

`contradictory_evidence` may legitimately be empty; that is reported as a note
rather than counted as a missing section, so a clean case does not trigger a
pointless correction round trip.

## Directory structure

```text
soar_frontend/
├── app.py
├── .env.example
├── requirements.txt
├── README.md
├── hawki_alert_analysis/     collection, correlation, enrichment, bundling
│   ├── adapters.py           native producer formats -> canonical events
│   ├── ingest.py             collected log directory -> scenario manifest
│   ├── correlate.py          deterministic time/entity correlation
│   ├── assets.py             asset inventory collection and matching
│   ├── threat_intel.py       indicator feed collection and matching
│   ├── bundle.py             the four-block evidence bundle
│   ├── elastic.py           Phase 2: Elasticsearch-backed repository
│   ├── assessment.py         structured analysis schema and review
│   └── repository.py         source-agnostic event repository
├── data/
│   ├── scenarios/            native-format telemetry fixtures
│   ├── assets/               asset inventory
│   └── threat_intel/         indicator feed
├── tools/
│   ├── collect_pcap.py       PCAP -> Suricata -> scenario
│   └── evaluate.py           schema, grounding, and ground-truth scoring
├── tests/
├── templates/
└── static/
```

## Tests

```bash
python -m unittest discover -s tests
```

## Run

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Two environment variables are required, and the server refuses to start without
them:

```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export HAWKI_ADMIN_USERNAME=analyst
export HAWKI_ADMIN_PASSWORD='choose-a-strong-password'
python app.py
```

Open <http://127.0.0.1:5000> and sign in. The alert queue is at `/alerts`; each
row links to `/alerts/<id>`, where **Analyze with LLM** sends the evidence
bundle to the configured model.

Without a reachable model the analysis falls back to a deterministic summary
built from the bundle, labelled as such. To use a real one, point `LLM_API_URL`
and `LLM_MODEL` at any OpenAI-compatible endpoint (vLLM, Ollama, llama.cpp):

```bash
export LLM_API_URL=http://127.0.0.1:8000/v1/chat/completions
export LLM_MODEL=hawki-local
export DEMO_MODE=false        # fail loudly instead of falling back
```

### With Compose

```bash
cp .env.example .env                  # required: compose reads it through env_file
docker compose up -d                  # web app only, ~300 MB, no GPU
docker compose --profile llm up -d    # add vLLM (needs a GPU)
```

Services sit behind profiles so the local stage stays light. The web app does
not depend on vLLM — it runs and reports the model as unreachable rather than
refusing to start.

To work against scenarios you ingested on the host, mount them in:

```bash
docker compose -f compose.yaml -f compose.dev.yaml up
```

The interface renders Markdown with three browser libraries served from this
origin. Install them once — the Content Security Policy allows scripts from
`'self'` only, and the deployment plan puts the web tier on a subnet with no
route to a CDN:

```bash
python tools/vendor_assets.py            # install into static/vendor/
python tools/vendor_assets.py --verify   # check against the lock file
```

Without them the app still runs; Markdown falls back to escaped plain text.

Verify everything without a browser:

```bash
python -m unittest discover -s tests    # 101 tests, no network or model needed
python tools/evaluate.py                # score the bundled scenarios
```

## Data sources

The default is Phase 1: alerts and events come from scenario files under
`data/scenarios/`. Two scenarios ship with the repository — a Linux web
exploitation case (ModSecurity, Suricata, Nginx, Wazuh) and a Windows dropper
case (Sysmon, Wazuh).

| Variable | Default | Purpose |
| --- | --- | --- |
| `ALERT_REPOSITORY` | `fixture` | `fixture` or `elasticsearch` |
| `ALERT_FIXTURE_ROOT` | `data/scenarios` | Scenario directory |
| `ASSET_INVENTORY_ROOT` | `data/assets` | Asset inventory JSON |
| `THREAT_INTEL_ROOT` | `data/threat_intel` | Indicator feed JSON |
| `AGENT_CONTEXT_MAX_CHARS` | `24000` | Serialized context budget |
| `ASSESSMENT_REPAIR_ENABLED` | `true` | One correction pass for incomplete assessments |

Each root falls back to the fixtures packaged in
`hawki_alert_analysis/fixtures/` when the configured path is absent, which is
what happens in the container, where a volume is mounted over `/app/data`.

### Phase 2: reading from Elasticsearch

```bash
export ALERT_REPOSITORY=elasticsearch
export ELASTICSEARCH_URL=https://es.internal:9200
export ELASTICSEARCH_API_KEY=...                       # or _USERNAME/_PASSWORD
export ELASTICSEARCH_ALERT_INDEX='wazuh-alerts-*,logs-*'
export ELASTICSEARCH_EVENT_INDEX='logs-*,winlogbeat-*,packetbeat-*'
export ELASTICSEARCH_WINDOW_SECONDS=300
python app.py
```

Nothing below the repository boundary changes. Elasticsearch selects candidates
by time and entity; ranking and case assembly stay in `correlate.build_case`, so
a case built from a live index is assembled by the same rules as one built from
a fixture and remains comparable to it. Documents are read either as ECS or in
their native producer shape — a Suricata, Wazuh, or Sysmon record shipped
verbatim is normalized by its own adapter rather than requiring one convention
across the cluster. Document `_id` becomes the event id.

Only `_search` is ever issued and index patterns are validated before reaching a
URL, so the repository is read-only by construction. Use a read-only API key
restricted to the intended indices.

An unreachable cluster yields an empty alert list rather than an error on every
page; `/api/config` reports `alert_repository.reachable` and `last_error` so the
emptiness explains itself.

`ENABLE_ES_SEARCH` is separate and governs the analyst-facing log search on
`/logs`. It stays `false` by default, where the UI prepares a Kibana link
instead of querying. A dedicated policy gateway should replace that endpoint
before production use.

## Production notes

- Put the Flask service behind Nginx or Caddy.
- Add authentication before exposing it beyond a trusted lab network.
- Keep vLLM and Elasticsearch inaccessible from untrusted clients.
- Use HTTPS.
- Add CSRF protection, persistent sessions, RBAC, audit logging, and rate limiting.
- Treat all LLM-proposed queries and response actions as untrusted until validated.
