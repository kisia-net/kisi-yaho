# 재시작 런북

노트북을 껐다 켠 뒤 AI 증강 SIEM을 처음부터 다시 띄우는 절차입니다.
위에서 아래로 따라가면 되고, 단계마다 **무엇이 보여야 다음으로 넘어가는지**를 적어두었습니다.

> **가장 중요한 규칙** — 7단계(GPU 끄기)를 빠뜨리면 아무도 쓰지 않는 동안에도 AWS 요금이 계속 나갑니다.
> 작업이 끝나면 반드시 마지막 단계까지 실행하세요.

경로는 팀장 노트북 기준입니다. 각자 환경에 맞게 바꿔서 쓰세요.

---

## 전체 그림 — 무엇을 켜는 것인가

시스템은 컴퓨터 두 대에 나뉘어 있습니다. 재시작이란 이 둘을 각각 켜고 사이의 길을 다시 잇는 일입니다.

| 구분 | 어디에 | 무엇을 하는가 | 켜는 방법 |
| --- | --- | --- | --- |
| `hawki-web` | 내 노트북 (Docker Desktop) | 화면 · 로그 수집 · 상관분석 · 4블록 증강 · 답변 검증 · 감사 기록 | `docker compose` |
| `hawki-vllm` | AWS 서울 (g6e.xlarge, GPU) | GPT-OSS 20B 모델 추론만 담당 | `terraform` + 자동 재시작 |
| SSM 터널 | 둘 사이 | 암호화된 통로. AWS 쪽에는 열린 포트가 하나도 없음 | `terraform output` |

무거운 계산(모델)만 AWS에 있고 **프로젝트의 알맹이는 노트북에 있습니다.**
그래서 모델을 끄고도 화면 작업은 계속할 수 있습니다.

소요 시간: 1~2단계 5분 · 3~5단계 5분 · 모델 로딩 대기 포함 총 10분 내외

---

## 0단계 — 시작 전 30초 점검

1. Docker Desktop 실행 → 작업표시줄 고래 아이콘이 안정될 때까지 대기
2. **크롬 자동 번역 끄기** — 켜져 있으면 Suricata가 "미어캣", HAW-KI가 "호키"로 바뀝니다
3. PowerShell 두 개 열기 — 하나는 명령용, 하나는 터널 전용

> 포트 5000을 다른 프로그램이 쓰고 있으면 웹 화면이 안 뜹니다.
> 예전에 `python app.py`를 직접 실행해두고 잊은 적이 있었습니다.
> 의심되면 [오류별 대처](#오류별-대처)의 "포트 5000" 항목을 보세요.

---

## 1단계 — 노트북 웹 앱 켜기

```powershell
cd C:\Users\KSH\Desktop\KISIA\깃허브\security
docker compose up -d --build
```

코드를 안 고쳤다면 `--build`는 빼도 됩니다.

### 확인

```powershell
docker compose ps
```

PORTS 칸에 `0.0.0.0:5000->5000/tcp` 가 보여야 합니다.
`5000/tcp` 만 보이면 포트가 실제로 열리지 않은 것입니다.

```powershell
curl.exe -i http://127.0.0.1:5000/healthz
```

`HTTP/1.1 200 OK` 와 **`Server: gunicorn`** 이 나와야 정상입니다.
`Server: Werkzeug` 라면 컨테이너가 아니라 다른 파이썬 프로세스가 응답하고 있는 것입니다.

### 브라우저 접속

<http://127.0.0.1:5000>

| 항목 | 값 |
| --- | --- |
| 아이디 | `analyst` |
| 비밀번호 | `.env` 의 `HAWKI_ADMIN_PASSWORD` (팀장에게 문의) |
| 권한 | admin |

> 이 계정은 계정 DB가 비어 있을 때 `.env` 값으로 **최초 1회만** 생성됩니다.
> 지금 `.env` 의 비밀번호를 바꿔도 이미 만들어진 계정은 바뀌지 않습니다.

**여기까지는 GPU 없이 동작합니다.** 화면 작업이나 문서 작업만 할 거라면 2단계 이후는 건너뛰세요.
AI 분석을 실제로 돌릴 때만 GPU를 켭니다.

---

## 2단계 — AWS GPU 켜기

```powershell
cd C:\Users\KSH\Desktop\KISIA\깃허브\security\infra\terraform
terraform apply -var lab_running=true
```

변경 계획이 출력되고 `Enter a value:` 에서 멈춥니다. **`yes`** 를 정확히 입력하세요. `y` 나 `Y` 는 받지 않습니다.

> 3~5분 걸립니다. **오래 걸린다고 Ctrl+C 로 끊지 마세요.**
> 중간에 끊으면 절반만 만들어진 상태로 남아 다음 실행이 더 복잡해집니다.

### 확인

```powershell
terraform output llm_state
```

`running` 이면 인스턴스가 켜진 것입니다.

---

## 3단계 — 인스턴스에 들어가 모델 확인

인스턴스 ID는 켤 때마다 바뀌므로 직접 타이핑하지 말고 출력받아 씁니다.

```powershell
terraform output -raw step_4_connect
```

출력된 명령을 그대로 복사해 실행하면 인스턴스 안으로 들어갑니다.

### 도커를 쓸 수 있는 계정으로 전환

SSM 으로 들어가면 `ssm-user` 계정이라 도커 권한이 없습니다 (`permission denied`).

```bash
sudo su - ubuntu
```

### 모델 서버 상태 확인

```bash
docker ps -a
```

`hawki-vllm` 이 `Up` 이면 그대로 두면 됩니다. 재시작 정책이 걸려 있어 인스턴스가 켜지면 대개 자동으로 올라옵니다.
`Exited` 라면:

```bash
docker start hawki-vllm
```

### 모델이 다 올라왔는지 확인

컨테이너가 떠 있는 것과 모델이 GPU 메모리에 다 올라온 것은 다릅니다. 2~3분 기다린 뒤:

```bash
curl -H "Authorization: Bearer <API_KEY>" localhost:8000/v1/models
```

`"id":"hawki-local"` 과 `"max_model_len":32768` 이 보이면 준비 완료입니다.
`{"error":"Unauthorized"}` 는 키를 안 붙였다는 뜻이고, **서버 자체는 살아 있다는 신호**입니다.

### 컨테이너가 아예 없어졌다면

모델 파일은 `/opt/hawki/models` 에 남아 있어 다시 내려받지 않습니다.

```bash
docker run -d --name hawki-vllm --restart unless-stopped --gpus all --ipc=host \
  -p 8000:8000 -v /opt/hawki/models:/root/.cache/huggingface \
  vllm/vllm-openai:latest \
  --model openai/gpt-oss-20b --served-model-name hawki-local \
  --api-key <API_KEY> --max-model-len 32768 --gpu-memory-utilization 0.90
```

> 이미지 진입점에 이미 `serve` 가 들어 있으므로 명령에 `serve` 를 넣으면 안 됩니다.
> 넣으면 `unrecognized arguments: serve` 오류가 납니다.

---

## 4단계 — 터널 열기

새 PowerShell 창에서:

```powershell
cd C:\Users\KSH\Desktop\KISIA\깃허브\security\infra\terraform
terraform output -raw step_5_tunnel
```

출력된 명령을 실행하면 노트북의 8000번 포트가 AWS 모델 서버로 연결됩니다.

> **이 창은 닫지 마세요.** 닫으면 터널이 끊기고, 분석을 누를 때 연결 오류가 납니다.

cmd 창에서는 작은따옴표가 깨집니다. cmd 를 쓸 때는 이 형식으로:

```
aws ssm start-session --target <INSTANCE_ID> --document-name AWS-StartPortForwardingSession --parameters portNumber=8000,localPortNumber=8000
```

### 확인 (또 다른 창)

```powershell
curl.exe -H "Authorization: Bearer <API_KEY>" http://127.0.0.1:8000/v1/models
```

컨테이너에서도 닿는지 확인합니다. **이 한 줄이 최종 판정입니다.**

```powershell
docker exec hawki-web python -c "import urllib.request as u; r=u.urlopen(u.Request('http://host.docker.internal:8000/v1/models', headers={'Authorization':'Bearer <API_KEY>'})); print(r.status)"
```

`200` 이 찍히면 성공입니다.

---

## 5단계 — 앱을 모델에 붙이기

```powershell
cd C:\Users\KSH\Desktop\KISIA\깃허브\security
docker compose restart hawki-web
```

| 무엇을 고쳤나 | 필요한 명령 |
| --- | --- |
| 아무것도 안 고침 | `docker compose restart hawki-web` |
| `.env` 수정 | `docker compose up -d --force-recreate hawki-web` |
| `app.py` · `static/` 등 코드 수정 | `docker compose up -d --build hawki-web` |

---

## 6단계 — 화면에서 최종 확인

1. 브라우저에서 **Ctrl+F5** 강제 새로고침 (CSS 캐시 때문에 필수)
2. 보안 경보 → 사건 하나 선택 → **「LLM으로 분석하기」**
3. 결과 확인

- 머리글에 `hawki-local` 과 전달한 증거 건수가 표시됨
- 판단 요약 · 공격 가설 · 확인된 관찰 · 뒷받침 증거 · 영향받는 대상 · ATT&CK 기법 · 증거 공백 · 권장 검색 · 권장 대응이 한국어로 표시됨
- 하단에 **`필수 항목 모두 채움`** 과 **`증거 인용 N건`** 배지
- `demo fallback` 이나 `llm_transport_error` 가 **보이지 않음**

첫 분석은 20~40초 걸립니다.

---

## 7단계 — 반드시 끄기

```powershell
cd C:\Users\KSH\Desktop\KISIA\깃허브\security\infra\terraform
terraform apply -var lab_running=false
```

`yes` 입력. NAT Gateway 와 고정 IP 가 삭제되고 인스턴스가 정지합니다.
3~4분 걸리는 것은 정상이며, GPU 인스턴스는 원래 종료가 느립니다.

```powershell
terraform output llm_state
```

`stopped` 이면 완료입니다. 디스크 요금만 남고 시간당 GPU 요금은 멈춥니다.

| 상황 | 하루 비용 (추정) |
| --- | --- |
| 2시간 쓰고 끔 | 약 7,000원 |
| **끄는 걸 잊고 24시간 방치** | **약 7만 원** |

---

## 한 장 요약

### 켤 때

```powershell
cd <repo>
docker compose up -d
cd infra\terraform
terraform apply -var lab_running=true
terraform output -raw step_4_connect   # 접속 → sudo su - ubuntu → docker ps -a
terraform output -raw step_5_tunnel    # 새 창에서 실행, 닫지 말 것
cd <repo>
docker compose restart hawki-web
```

### 끌 때

```powershell
cd <repo>\infra\terraform
terraform apply -var lab_running=false
```

---

## 현재 설정값 (.env)

| 설정 | 값 | 이유 |
| --- | --- | --- |
| `LLM_MAX_TOKENS` | 12000 | 답변이 중간에 잘려 JSON 파싱이 실패하던 문제 해결 |
| `LLM_REQUEST_TIMEOUT` | 300 | 긴 답변은 80초 이상 걸려 기본 120초로는 부족 |
| `AGENT_CONTEXT_MAX_CHARS` | 24000 | 4블록 증거 번들의 최대 크기 |
| `LLM_OUTPUT_LANGUAGE` | `ko` | 분석 문장만 한국어. `en` 으로 바꾸면 영어 결과와 비교 가능 |
| `DEMO_MODE` | `false` | 실제 모델을 쓰도록 강제 |
| `--max-model-len` | 32768 | 번들 + 프롬프트 + 답변이 8192를 넘겨서 상향 |

> `.env` 에는 비밀번호와 API 키가 평문으로 들어 있습니다. 저장소에 올라가지 않으며,
> 단톡방으로 공유하지 마세요. 팀원 배포용으로는 `.env.example` 을 주고 각자 채우게 합니다.

---

## 오류별 대처

실제로 겪었던 문제들입니다.

### 노트북 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| 브라우저에 Flask `Not Found`, `Server: Werkzeug` | 예전에 띄운 `python app.py` 가 5000번 점유 | `Get-Process -Id (Get-NetTCPConnection -LocalPort 5000 -State Listen).OwningProcess` 로 확인 후 `Stop-Process` |
| `docker port` 가 비어 있음 / `port is already allocated` | 위와 같은 원인. 도커가 포트를 못 잡음 | 점유 프로세스 종료 후 `docker compose up -d` |
| `dockerDesktopLinuxEngine ... 파일을 찾을 수 없습니다` | Docker Desktop 미실행 | Docker Desktop 실행 후 대기 |
| `Docker Desktop distro installation failed` / `ConfigureGpu` | WSL 커널이 오래됨 | Docker Desktop 종료 → `wsl --update` → 재실행 → 필요시 Recover WSL distro |
| CSS 수정이 화면에 반영 안 됨 | 브라우저 캐시 | Ctrl+F5 |

### AWS 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| `permission denied ... docker.sock` | SSM 기본 계정 `ssm-user` 에 도커 권한 없음 | `sudo su - ubuntu` (또는 매번 `sudo`) |
| `{"error":"Unauthorized"}` | API 키 미첨부. 서버는 정상 | `-H "Authorization: Bearer <키>"` 추가 |
| `unrecognized arguments: serve` | 이미지 진입점에 이미 `serve` 포함 | `docker run` 명령에서 `serve` 제거 |
| `Invalid target ID format` | 예시 인스턴스 ID를 그대로 사용 | `terraform output -raw step_4_connect` 로 실제 명령 출력 |
| `egress.0.description doesn't comply` | 보안 그룹 설명에 한글 사용 | AWS 설명 필드는 ASCII 만 허용 |
| `Error parsing parameter '--parameters'` | cmd 창에서 작은따옴표 JSON 사용 | PowerShell 을 쓰거나 `portNumber=8000,localPortNumber=8000` 형식 사용 |

### 분석 결과 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| `400 Bad Request` (chat/completions) | 번들+프롬프트+답변이 모델 문맥 한계 초과 | `--max-model-len` 32768 로 상향 |
| 화면에 JSON 원문이 그대로 노출 | 답변이 중간에 잘려 파싱 실패 | `LLM_MAX_TOKENS` 상향 후 재생성 |
| 미작성 항목 11개 / 증거 인용 0건 | 모델이 JSON 키의 밑줄을 생략 | 코드에서 정규화 처리됨 (`assessment.py`) |
| 분석 결과가 영어로 나옴 | 언어 지시가 영어 스키마 설명보다 앞에 있었음 | 프롬프트 최후미로 이동 (`system_message`) |
| 연결된 서비스 4개 중 0개 | Kibana/ES/Velociraptor 미기동 | 정상. 파일 기반 시나리오로 분석은 동작 |

### 깃 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| 안 고친 파일 수십 개가 modified 로 표시 | 줄바꿈(CRLF/LF) 차이 | `.gitattributes` 적용됨. 최초 1회 `git add --renormalize .` |
| `unable to stat 'docs/~$....docx'` | 워드 임시 파일이 추적 중인데 디스크에 없음 | `git add -A docs` 로 삭제 반영 |
| 여러 줄 커밋 메시지가 깨짐 | cmd 는 여러 줄 따옴표 미지원 | `-m` 을 여러 번 사용 |
