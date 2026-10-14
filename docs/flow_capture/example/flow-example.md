# 데이터 흐름 캡처 · 경보 64d5a7dde3b1ad6e5a95

- 캡처 시각: 2026-10-14T16:27:09.303217+00:00
- 방식: 분석 실행 시점 저장
- 기준: 모델에 보낸 증거 기준 (분석 실행 시점 저장)

| 단계 | 저장 위치 | 건수 | 크기(문자) |
|---|---|---|---|
| ① 서버별 원본 로그 | 각 서버의 로그 파일 → Wazuh Agent 가 그대로 전송 (full_log) | 20 | 5197 |
| ② 이벤트 (디코딩) | wazuh-archives-* · Manager 디코더가 data.* 로 쪼갬 | 20 | 11896 |
| ③ 경보 | wazuh-alerts-* · 룰에 걸린 이벤트에 rule.* 가 붙음 | 19 | 16462 |
| ④ 증거 패키지 | HAW-KI · 요청 때마다 같은 규칙으로 생성 (저장 안 함) | 20 | 46153 |
| ⑤ AI 증거 수집 | HAW-KI · 모델이 읽기 전용 도구로 증거를 더 가져옴 | 3 | — |
| ⑥ AI 판단 | HAW-KI · 모델 응답을 검증된 assessment 로 정리 | 5 | 2320 |
| ⑦ 조치 제안 · 승인 상태 | HAW-KI 승인 대기열 · 실행 결과(수집·룰)는 아직 이 흐름에 연결되지 않음 | 2 | — |

## ① 서버별 원본 로그

### web-01 (10.0.1.201) · 19줄
- **nginx 접근 로그** `/var/log/nginx/access.log` · 텍스트 한 줄 · 16줄
  - `TRIGGER` 2026-10-14T14:28:15.008+0000

```
52.141.3.247 - - [14/Oct/2026:23:28:15 +0900] "GET /portal/index.php?page=....//....//....//etc/passwd HTTP/1.1" 200 2845 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
  - `CTX-001` 2026-10-14T14:26:45.000+0000

```
52.141.3.247 - - [14/Oct/2026:23:26:45 +0900] "GET /wp-freya.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
  - `CTX-002` 2026-10-14T14:26:47.000+0000

```
52.141.3.247 - - [14/Oct/2026:23:26:47 +0900] "GET /x7.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
- **nginx 오류 로그 (ModSecurity 차단 포함)** `/var/log/nginx/error.log` · 텍스트 한 줄 · 3줄
  - `CTX-013` 2026-10-14T14:27:39.150+0000

```
2026/10/14 23:27:39 [error] 2014#2014: *4756 [client 52.141.3.247] ModSecurity: Access denied with code 403 (phase 2). [file "/etc/nginx/modsec/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [id "930100"] [msg "Path Traversal Attack (/../)"] [severity "CRITICAL"] [hostname "10.0.1.201"] [uri "/portal/index.php"], client: 52.141.3.247, server: portal, request: "GET /portal/index.php?page=../../../../etc/passwd HTTP/1.1", host: "10.0.1.201"
```
  - `CTX-015` 2026-10-14T14:27:43.150+0000

```
2026/10/14 23:27:43 [error] 2014#2014: *3806 [client 52.141.3.247] ModSecurity: Access denied with code 403 (phase 2). [file "/etc/nginx/modsec/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [id "930100"] [msg "Path Traversal Attack (/../)"] [severity "CRITICAL"] [hostname "10.0.1.201"] [uri "/portal/index.php"], client: 52.141.3.247, server: portal, request: "GET /portal/index.php?page=../../../../etc/passwd HTTP/1.1", host: "10.0.1.201"
```
  - `CTX-019` 2026-10-14T14:27:35.150+0000

```
2026/10/14 23:27:35 [error] 2014#2014: *4455 [client 52.141.3.247] ModSecurity: Access denied with code 403 (phase 2). [file "/etc/nginx/modsec/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [id "930100"] [msg "Path Traversal Attack (/../)"] [severity "CRITICAL"] [hostname "10.0.1.201"] [uri "/portal/index.php"], client: 52.141.3.247, server: portal, request: "GET /portal/index.php?page=../../../../etc/passwd HTTP/1.1", host: "10.0.1.201"
```

### ids-01 (10.0.1.50) · 1줄
- **Suricata eve.json** `/var/log/suricata/eve.json` · JSON 한 줄 · 1줄
  - `CTX-016` 2026-10-14T14:28:15.040+0000

```
{"timestamp": "2026-10-14T23:28:15.040000+09:00", "flow_id": 577381452783689, "in_iface": "ens5", "event_type": "alert", "src_ip": "52.141.3.247", "src_port": 52886, "dest_ip": "10.0.1.201", "dest_port": 80, "proto": "TCP", "alert": {"action": "allowed", "gid": 1, "signature_id": 2049416, "rev": 3, "signature": "ET WEB_SERVER /etc/passwd Detected in URI", "category": "Web Application Attack", "severity": 1}, "http": {"hostname": "10.0.1.201", "url": "/portal/index.php?page=....//....//....//etc/passwd", "http_method": "GET", "status": 200}}
```

## ② 이벤트 (디코딩)

### web-01 · 디코더 `web-accesslog` · 16건
쪼개진 필드: `data.id`, `data.protocol`, `data.srcip`, `data.url`

```json
{
  "evidence_id": "TRIGGER",
  "timestamp": "2026-10-14T14:28:15.008+0000",
  "agent": {
    "ip": "10.0.1.201",
    "name": "web-01",
    "id": "001"
  },
  "decoder": {
    "name": "web-accesslog"
  },
  "location": "/var/log/nginx/access.log",
  "data": {
    "srcip": "52.141.3.247",
    "protocol": "GET",
    "id": "200",
    "url": "/portal/index.php?page=....//....//....//etc/passwd"
  }
}
```

### web-01 · 디코더 `nginx-errorlog` · 3건
쪼개진 필드: `data.srcip`, `data.url`

```json
{
  "evidence_id": "CTX-013",
  "timestamp": "2026-10-14T14:27:39.150+0000",
  "agent": {
    "ip": "10.0.1.201",
    "name": "web-01",
    "id": "001"
  },
  "decoder": {
    "name": "nginx-errorlog"
  },
  "location": "/var/log/nginx/error.log",
  "data": {
    "srcip": "52.141.3.247",
    "url": "/portal/index.php?page=../../../../etc/passwd"
  }
}
```

### ids-01 · 디코더 `json` · 1건
쪼개진 필드: `data.alert.action`, `data.alert.category`, `data.alert.gid`, `data.alert.rev`, `data.alert.severity`, `data.alert.signature`, `data.alert.signature_id`, `data.dest_ip`, `data.dest_port`, `data.event_type`, `data.flow_id`, `data.http.hostname`, `data.http.http_method`, `data.http.status`, `data.http.url`, `data.in_iface`, `data.proto`, `data.src_ip`, `data.src_port`, `data.timestamp`

```json
{
  "evidence_id": "CTX-016",
  "timestamp": "2026-10-14T14:28:15.040+0000",
  "agent": {
    "ip": "10.0.1.50",
    "name": "ids-01",
    "id": "002"
  },
  "decoder": {
    "name": "json"
  },
  "location": "/var/log/suricata/eve.json",
  "data": {
    "in_iface": "ens5",
    "src_ip": "52.141.3.247",
    "src_port": 52886,
    "event_type": "alert",
    "alert": {
      "severity": 1,
      "signature_id": 2049416,
      "rev": 3,
      "gid": 1,
      "signature": "ET WEB_SERVER /etc/passwd Detected in URI",
      "action": "allowed",
      "category": "Web Application Attack"
    },
    "flow_id": 577381452783689,
    "dest_ip": "10.0.1.201",
    "proto": "TCP",
    "http": {
      "hostname": "10.0.1.201",
      "http_method": "GET",
      "url": "/portal/index.php?page=....//....//....//etc/passwd",
      "status": 200
    },
    "dest_port": 80,
    "timestamp": "2026-10-14T23:28:15.040000+09:00"
  }
}
```

## ③ 경보

트리거 경보의 룰 정보 (이벤트에 붙은 부분):

```json
{
  "firedtimes": 1,
  "mail": false,
  "level": 6,
  "description": "A web attack returned code 200 (success).",
  "groups": [
    "web",
    "accesslog",
    "attack"
  ],
  "mitre": {
    "technique": [
      "Exploit Public-Facing Application"
    ],
    "id": [
      "T1190"
    ],
    "tactic": [
      "Initial Access"
    ]
  },
  "id": "31106"
}
```

같은 증거 안의 다른 경보:

| 룰 | 레벨 | 설명 | 건수 |
|---|---|---|---|
| 31101 | 5 | Web server 400 error code. | 12 |
| 31333 | 7 | ModSecurity rejected a query | 3 |
| 31151 | 10 | Multiple web server 400 error codes from same source ip. | 1 |
| 86601 | 10 | Suricata: Alert - ET WEB_SERVER /etc/passwd Detected in URI | 1 |
| 31106 | 6 | A web attack returned code 200 (success). | 1 |

룰에 걸리지 않은 원시 이벤트: 1건

## ④ 증거 패키지

- 스키마 `hawki.wazuh.live-evidence/v2` · 블록 `agent_retrieval`, `alert_id`, `assembled_at`, `assets`, `control_outcomes`, `investigation_context`, `lineage`, `priority`, `retrieval`, `schema`, `threat_intelligence`, `trigger`
- TRIGGER 1 + CTX 19건 · 출처별 {"same_agent": 15, "cross_agent": 1, "agent_search": 3}
- 차단 판정 {"UNKNOWN": 16, "BLOCKED": 3, "NOT_BLOCKED": 1} · 우선순위 {"band": "P2", "score": 57, "primary_asset_id": "asset-web"}
- 출처 연결(lineage) 34개 · 수집 조건 {"profile": {"name": "web_attack", "seconds_before": 600, "seconds_after": 300, "cross_agent": true}, "window_seconds": 600, "candidate_count": 28, "selected_count": 19, "suppressed_routine_count": 0}

## ⑤ AI 증거 수집

- `search_address` {"address": "52.141.3.247", "hours": 2} → 추가 ['CTX-017', 'CTX-018', 'CTX-019']
- `finish` {} → 추가 []
- 추가된 증거 ['CTX-017', 'CTX-018', 'CTX-019'] · 멈춘 이유 `finish`
- 크기 변화: 처음 {'context_count': 16, 'size_chars': 40595} → 수집 후 {'context_count': 19, 'size_chars': 46153} → 모델에 보낸 것 {'context_count': 19, 'size_chars': 46153}

## ⑥ AI 판단

- 모델 `mock-llm` · 분석 id `4ead32dc79394d0db86a64f132700c14`
- 응답 요약: 스캔 뒤 경로 조작 우회 1건이 200 으로 응답됐습니다. 확신도 중간 · 다음 조치: 출발지 차단 승인과 web-01 증거 수집.

인용한 증거와 그 원본:

- `TRIGGER` · web-01

```
52.141.3.247 - - [14/Oct/2026:23:28:15 +0900] "GET /portal/index.php?page=....//....//....//etc/passwd HTTP/1.1" 200 2845 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
- `CTX-001` · web-01

```
52.141.3.247 - - [14/Oct/2026:23:26:45 +0900] "GET /wp-freya.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
- `CTX-002` · web-01

```
52.141.3.247 - - [14/Oct/2026:23:26:47 +0900] "GET /x7.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
- `CTX-003` · web-01

```
52.141.3.247 - - [14/Oct/2026:23:26:49 +0900] "GET /ok.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```
- `CTX-004` · web-01

```
52.141.3.247 - - [14/Oct/2026:23:26:51 +0900] "GET /z.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

assessment:

```json
{
  "confirmed_observations": [
    "52.141.3.247 이 web-01 에 존재하지 않는 PHP 경로를 연속 요청해 404 를 받았습니다 (TRIGGER).",
    "같은 출발지의 경로 조작 요청을 ModSecurity 가 403 으로 차단했습니다.",
    "인코딩을 바꾼 경로 조작 요청 하나는 HTTP 200 으로 응답됐고, IDS 센서(ids-01)도 같은 요청을 탐지했습니다."
  ],
  "interpretation": "자동화된 스캔 뒤 경로 조작(LFI) 시도로 이어졌고, 우회 변형 1건이 WAF 를 통과해 응답을 받았습니다.",
  "attack_hypothesis": "취약 PHP 경로 탐색 → 경로 조작 시도 → WAF 차단 → 인코딩 변형으로 우회 → /etc/passwd 노출 가능성 (가설).",
  "confidence": {
    "level": "medium",
    "rationale": "200 응답은 확인되지만 응답 본문은 증거에 없습니다."
  },
  "severity": {
    "level": "high",
    "rationale": "인터넷 노출 웹 서버에서 우회 성공 응답이 관찰됐습니다."
  },
  "affected_entities": {
    "hosts": [
      "web-01"
    ],
    "users": [],
    "addresses": [
      "52.141.3.247",
      "10.0.1.201"
    ],
    "processes": [],
    "files": [
      "/etc/passwd"
    ]
  },
  "attack_techniques": [
    {
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "evidence": "CTX-001 CTX-002"
    }
  ],
  "supporting_evidence": [
    {
      "statement": "스캔과 차단, 우회 성공이 같은 출발지에서 이어집니다.",
      "event_ids": [
        "TRIGGER",
        "CTX-001",
        "CTX-002",
        "CTX-003",
        "CTX-004"
      ],
      "unknown_event_ids": []
    }
  ],
  "contradictory_evidence": [],
  "evidence_gaps": [
    "200 응답의 본문 크기 외 내용",
    "웹 서버 프로세스 실행 기록"
  ],
  "recommended_searches": [
    {
      "title": "같은 출발지 전체 요청",
      "language": "wazuh",
      "value": "data.srcip:\"52.141.3.247\"",
      "index": "archives"
    }
  ],
  "recommended_response": [
    "52.141.3.247 차단 (승인 필요)",
    "web-01 의 /portal/index.php page 파라미터 입력 검증 확인"
  ]
}
```

### 모델 응답 원문

- `alert_summary:answer` · 1599자

```
{"answer": "스캔 뒤 경로 조작 우회 1건이 200 으로 응답됐습니다. 확신도 중간 · 다음 조치: 출발지 차단 승인과 web-01 증거 수집.", "assessment": {"confirmed_observations": ["52.141.3.247 이 web-01 에 존재하지 않는 PHP 경로를 연속 요청해 404 를 받았습니다 (TRIGGER).", "같은 출발지의 경로 조작 요청을 ModSecurity 가 403 으로 차단했습니다.", "인코딩을 바꾼 경로 조작 요청 하나는 HTTP 200 으로 응답됐고, IDS 센서(ids-01)도 같은 요청을 탐지했습니다."], "interpretation": "자동화된 스캔 뒤 경로 조작(LFI) 시도로 이어졌고, 우회 변형 1건이 WAF 를 통과해 응답을 받았습니다.", "attack_hypothesis": "취약 PHP 경로 탐색 → 경로 조작 시도 → WAF 차단 → 인코딩 변형으로 우회 → /etc/passwd 노출 가능성 (가설).", "confidence": {"level": "medium", "rationale": "200 응답은 확인되지만 응답 본문은 증거에 없습니다."}, "severity": {"level": "high", "rationale": "인터넷 노출 웹 서버에서 우회 성공 응답이 관찰됐습니다."}, "affected_entities": {"hosts": ["web-01"], "users": [], "addresses": ["52.141.3.247", "10.0.1.201"], "processes": [], "files": ["/etc/passwd"]}, "attack_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application", "evidence": ["CTX-001", "CTX-002"]}], "supporting_evidence": [{"statement": "스캔과 차단, 우회 성공이 같은 출발지에서 이어집니다.", "event_ids": ["TRIGGER", "CTX-001", "CTX-002", "CTX-003", "CTX-004"]}], "contradictory_evidence": [], "evidence_gaps": ["200 응답의 본문 크기 외 내용", "웹 서버 프로세스 실행 기록"], "recommended_searches": [{"title": "같은 출발지 전체 요청", "language": "wazuh", "index": "archives", "value": "data.srcip:\"52.141.3.247\""}], "recommended_response": ["52.141.3.247 차단 (승인 필요)", "web-01 의 /portal/index.php page 파라미터 입력 검증 확인"]}, "evidence": [], "queries": [], "actions": [{"type": "velociraptor_collection", "title": "web-01 웹 서버 증거 수집", "target": "web-01", "artifact": "Linux.Sys.Pslist", "reason": "우회 성공 뒤 실행 흔적 확인"}]}
```


### 검증 (감사 로그 대조)

- 분석 id `4ead32dc79394d0db86a64f132700c14` · 경로 `manual`
- 저장된 증거 패키지를 다시 계산한 해시 `a3778f5c5233c8a8636572f829af46b387c75d9165f7df3877f1e5a606832dc0`
- 캡처에 기록된 해시와 일치: 예
- 감사 로그 `alert_analysis_completed` (2026-10-14T16:27:09.302028+00:00) 의 해시와 일치: 예

## ⑦ 조치 제안 · 승인 상태

실행 결과(Velociraptor 수집, Suricata 룰)는 아직 이 흐름에 연결되지 않았습니다. 제안과 승인 상태만 보여 줍니다.

- 제안: `velociraptor_collection` web-01 웹 서버 증거 수집 → web-01
- 대기열: `ACT-20261014-E3FCD3` `velociraptor_collection` 상태 `pending_approval`
