# HAW-KI Front-End Prototype

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
Suricata ─┐
Nginx ────┼─► adapters ─► canonical events ─► correlation ─► AlertCase
Wazuh ────┘                                                     │
                                    asset inventory ────────────┤
                                    threat intel feed ──────────┤
                                                                ▼
                                                       evidence bundle ─► LLM/SLM
```

Collection sources are swappable behind their interfaces: `FixtureEventRepository`,
`FileAssetInventory`, and `FileThreatIntelFeed` can be replaced by Elasticsearch,
a CMDB, and MISP/OpenCTI without changing correlation, bundling, or the agent.

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

Adapters exist for Suricata EVE, Wazuh alerts, Nginx and Apache combined access
logs, Linux syslog, and `auth.log`, plus a generic ECS reader. Anything those
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

```bash
python tools/collect_pcap.py capture.pcap --out data/scenarios/replay_case
```

Suricata reads the capture and writes its own `eve.json`; nothing about the
resulting events is synthetic. Suricata is not bundled — if it is missing, the
script prints installation instructions and exits rather than reporting a
collection that did not happen.

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
| OTRF Security-Datasets (ex-Mordor) | Per-ATT&CK-technique JSON, Sysmon and Windows Security | Technique-level evaluation; needs a Sysmon adapter |
| Splunk `attack_data` | Per-technique raw logs across many producers | Pick individual datasets |
| Splunk BOTS v1–v3 | A full incident with ground-truth Q&A | Feed the Q&A into `expected.answers` as an evaluation set |
| malware-traffic-analysis.net | PCAP plus a published write-up | Replay through `collect_pcap.py`; the write-up is the ground truth |
| EVTX-ATTACK-SAMPLES | Per-technique Windows EVTX | Windows coverage |

Keep corpora outside the repository — size and licensing both argue against
committing them — and point `ALERT_FIXTURE_ROOT` at them.

## Evaluating the analysis

```bash
python tools/evaluate.py             # every scenario, deterministic demo path
python tools/evaluate.py --live      # against the configured LLM
python tools/evaluate.py --json report.json
```

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
cd soar_frontend
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`, then start the server:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Elasticsearch mode

The default is `ENABLE_ES_SEARCH=false`. In that mode, the UI generates an investigation link but does not execute a search.

To enable direct search:

1. Create a read-only Elasticsearch API key.
2. Restrict it to the intended log indices.
3. Put the API key in `.env`.
4. Set `ENABLE_ES_SEARCH=true`.

The backend enforces a result limit and returns selected fields only. A dedicated policy gateway should replace this simple search endpoint before production use.

## Production notes

- Put the Flask service behind Nginx or Caddy.
- Add authentication before exposing it beyond a trusted lab network.
- Keep vLLM and Elasticsearch inaccessible from untrusted clients.
- Use HTTPS.
- Add CSRF protection, persistent sessions, RBAC, audit logging, and rate limiting.
- Treat all LLM-proposed queries and response actions as untrusted until validated.
