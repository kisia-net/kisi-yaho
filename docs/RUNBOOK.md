# 재시작 런북 — 팀원용

> 노트북에서 앱을 켜고, AI 분석까지 붙이고, 담당 서버에 들어가기까지의 절차입니다.
> 막혔을 때 볼 「오류별 대처」가 맨 아래에 있습니다.
>
> **Terraform 은 설치하지 않으셔도 됩니다.** 서버를 만들고 켜고 끄는 것은 팀장이 합니다.
> 서버가 꺼져 있으면 팀장에게 켜달라고 요청하세요.
>
> 처음 접속하시는 분은 [`AWS_구축_가이드.md`](AWS_구축_가이드.md) 를 먼저 보세요.

---

## 저장소를 처음 받았을 때

```powershell
git clone <저장소 주소>
cd security
```

**`.env` 파일을 만들어야 합니다.** 저장소에 올라가지 않는 파일이라 따로 받으셔야 해요. 팀장에게 요청하시면 개인 DM 으로 내용을 보내드립니다.

메모장으로 만드실 경우 **파일 형식을 「모든 파일(*.*)」로 바꿔야** 합니다. 안 그러면 `.env.txt` 로 저장돼서 안 먹힙니다. 인코딩은 UTF-8.

```powershell
dir .env        # 파일이 보이면 정상
ren .env.txt .env   # .env.txt 로 저장됐다면
```

준비물은 이 정도입니다.

| 필요한 것 | 확인 |
| --- | --- |
| Docker Desktop | 실행 중이어야 함 |
| `.env` | `app.py` 가 있는 폴더 안에 |
| AWS CLI + Session Manager 플러그인 | 서버에 들어갈 때만 필요 |

---

## 전체 그림

```
  내 노트북                              AWS
 ┌──────────────┐                 ┌────────────────┐
 │ HAW-KI 웹앱  │ ──SSM 터널──▶  │ GPU 서버       │
 │ (도커)       │                 │ vLLM + 모델    │
 └──────────────┘                 └────────────────┘
        ↑                          ┌────────────────┐
   브라우저 5000                    │ siem/web/vm    │ ← SSM 접속
                                   └────────────────┘
```

**AWS 쪽에는 인터넷에 열린 포트가 없습니다.** 전부 AWS 내부 통로(SSM)로만 들어갑니다.

---

## 0단계 — 시작 전 30초 점검

```powershell
docker version          # Docker Desktop 이 떠 있는가
dir .env                # .env 가 있는가
```

---

## 1단계 — 노트북 웹 앱 켜기

```powershell
cd C:\경로\security
docker compose up -d --build
```

코드를 안 고쳤다면 `--build` 는 빼도 됩니다.

### 확인

```powershell
docker compose ps
```

PORTS 칸에 `0.0.0.0:5000->5000/tcp` 가 보여야 합니다. `5000/tcp` 만 보이면 포트가 실제로 열리지 않은 것입니다.

```powershell
curl.exe -i http://127.0.0.1:5000/healthz
```

`HTTP/1.1 200 OK` 와 **`Server: gunicorn`** 이 나와야 정상입니다. `Server: Werkzeug` 라면 컨테이너가 아니라 다른 파이썬 프로세스가 응답하고 있는 것입니다.

### 브라우저 접속

<http://127.0.0.1:5000>

| 항목 | 값 |
| --- | --- |
| 아이디 | `analyst` |
| 비밀번호 | `.env` 의 `HAWKI_ADMIN_PASSWORD` |

> 이 계정은 계정 DB 가 비어 있을 때 `.env` 값으로 **최초 1회만** 생성됩니다. 나중에 `.env` 의 비밀번호를 바꿔도 이미 만들어진 계정은 안 바뀝니다. 바꾸려면 `data/hawki_accounts.sqlite3` 를 지우고 다시 실행하세요.

> ※ **크롬 자동 번역을 꺼주세요.** Suricata 가 "미어캣" 으로 번역돼 화면이 이상해집니다.
> ※ 화면 왼쪽 아래 빨간 점은 아직 안 띄운 서비스들이라 정상입니다.

**여기까지는 GPU 없이 동작합니다.** 경보 목록, 상관분석 결과, 증거 번들, 타임라인은 다 보입니다. 화면 작업이나 문서 작업만 하실 거면 여기서 끝입니다.

---

## 2단계 — AI 분석까지 쓰려면

「LLM 으로 분석하기」를 누르려면 **GPU 서버가 켜져 있어야** 합니다.

### 2-1. 팀장에게 요청

> "GPU 좀 켜주세요"

켜지면 팀장이 **터널 명령을 채팅에 통째로 올려드립니다.** GPU 는 하루 7만원짜리라 필요할 때만 켭니다.

### 2-2. 터널 열기

받은 명령을 **새 PowerShell 창**에 붙여넣고, **그 창은 열어둔 채로** 두세요.

```powershell
aws ssm start-session --target <인스턴스 ID> --document-name AWS-StartPortForwardingSession --parameters portNumber=8000,localPortNumber=8000
```

> **이 창을 닫으면 터널이 끊깁니다.** 분석을 누를 때 연결 오류가 납니다.
> cmd 는 따옴표가 깨지니 PowerShell 을 쓰거나 위 `key=value` 형식을 쓰세요.

### 2-3. 확인 (또 다른 창)

```powershell
curl.exe -H "Authorization: Bearer <LLM_API_KEY>" http://127.0.0.1:8000/v1/models
```

모델 정보가 나오면 연결된 것입니다. 컨테이너에서도 닿는지가 **최종 판정**입니다.

```powershell
docker exec hawki-web python -c "import urllib.request as u; r=u.urlopen(u.Request('http://host.docker.internal:8000/v1/models', headers={'Authorization':'Bearer <LLM_API_KEY>'})); print(r.status)"
```

`200` 이 찍히면 성공입니다.

### 2-4. 앱을 모델에 붙이기

```powershell
docker compose restart hawki-web
```

| 무엇을 고쳤나 | 필요한 명령 |
| --- | --- |
| 아무것도 안 고침 | `docker compose restart hawki-web` |
| `.env` 수정 | `docker compose up -d --force-recreate hawki-web` |
| `app.py` · `static/` 등 코드 수정 | `docker compose up -d --build hawki-web` |

### 2-5. 화면에서 확인

1. 브라우저에서 **Ctrl+F5** 강제 새로고침 (CSS 캐시 때문에 필수)
2. 보안 경보 → 사건 하나 선택 → **「LLM 으로 분석하기」**

정상이면 이렇게 나옵니다.

- 머리글에 `hawki-local` 과 전달한 증거 건수
- 판단 요약 · 공격 가설 · 확인된 관찰 · 뒷받침 증거 · 영향받는 대상 · ATT&CK 기법 · 증거 공백 · 권장 검색 · 권장 대응이 **한국어로** 표시
- 하단에 **`필수 항목 모두 채움`** 과 **`증거 인용 N건`** 배지
- `demo fallback` 이나 `llm_transport_error` 가 **보이지 않음**

첫 분석은 20~40초 걸립니다. 로딩이 도는 게 정상이에요.

### 2-6. 다 쓰면 팀장에게 알려주세요

터널 창을 닫으시고 카톡에 남겨주세요. 마지막 분이 끝나면 팀장이 GPU 를 끕니다.

---

## 서버 목록

| 서버 | 인스턴스 ID | 사설 IP | 담당 | 올라갈 것 |
| --- | --- | --- | --- | --- |
| `siem` | `i-0d3f61f22252b1fbb` | `10.0.10.123` | 권민석 · 이효찬 | Wazuh Manager · Indexer · Dashboard · Velociraptor Server |
| `web` | `i-0629c84bb40895441` | `10.0.1.201` | 하서휘 | nginx · ModSecurity · Wazuh Agent |
| `vm` | `i-00cee9b7e43c531d1` | `10.0.10.235` | 엄수현 | Suricata · Sysmon for Linux · Wazuh Agent |
| `llm` | `i-0a8d4b62ea1de7699` | — | 이승섭 (테스트) | vLLM · GPT-OSS 20B (구축 완료) |

**Wazuh Manager 주소는 `10.0.10.123`** — Agent 설치할 때 이 값을 넣습니다.

### 들어가는 법 (셋 다 동일)

```powershell
aws ssm start-session --target <인스턴스 ID>
```

```bash
sudo su - ubuntu
```

> SSM 은 `ssm-user` 로 붙습니다. 이 계정은 docker 권한이 없어서 기본 계정으로 바꿔야 합니다.

### Wazuh 대시보드 (권민석 · 이효찬)

터널을 열고 브라우저에서 `https://127.0.0.1:8443` — 인증서 경고는 넘기시면 됩니다.

```powershell
aws ssm start-session --target i-0d3f61f22252b1fbb --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443
```

### 지금 어떤 서버가 켜져 있나

```powershell
aws ssm describe-instance-information --query "InstanceInformationList[].{ID:InstanceId,Ping:PingStatus}" --output table
```

`Online` 이 안 보이면 꺼져 있는 것입니다. 팀장에게 요청하세요.

### 웹 서버 공인 IP 는 매번 바뀝니다

껐다 켜면 다른 주소가 배정됩니다. 문서나 시나리오에 IP 를 적어두지 마시고, 필요할 때 확인하세요.

```powershell
aws ec2 describe-instances --instance-ids i-0629c84bb40895441 --query "Reservations[].Instances[].PublicIpAddress" --output text
```

---

## 작업 규칙

**서버 작업 전에 카톡에 한 줄 남겨주세요.**

> "web 서버에서 nginx 설치합니다"

지금 팀 공용 AWS 계정이라 **기록에 이름이 안 남습니다.** 문제가 생겼을 때 카톡이 유일한 단서입니다.

**작업이 끝나면 카톡에 알려주세요.** 켜두면 하루 1만 3천원이 나갑니다.

---

## 한 장 요약

### 화면만 볼 때

```powershell
docker compose up -d
# http://127.0.0.1:5000
```

### AI 분석까지

```
1. 팀장에게 "GPU 켜주세요" 요청
2. 받은 터널 명령을 새 창에 붙여넣고 그 창은 열어둠
3. docker compose restart hawki-web
4. 브라우저 Ctrl+F5 → 경보 클릭 → 「LLM 으로 분석하기」
5. 끝나면 터널 창 닫고 카톡에 알림
```

### 서버 작업

```
1. 팀장에게 "서버 켜주세요" 요청
2. aws ssm start-session --target <내 서버 ID>
3. sudo su - ubuntu
4. 작업 → 끝나면 카톡에 알림
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

> `DEMO_MODE` 를 `true` 로 두면 **모델에 못 닿을 때 조용히 가짜 요약으로 대체됩니다.** GPU 가 꺼져 있어도 그럴듯한 결과가 뜨니 반드시 `false` 로 두세요.

> `.env` 에는 비밀번호와 API 키가 평문으로 들어 있습니다. 저장소에 올라가지 않으며, **단톡방으로 공유하지 마세요.**

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
| `.env` 를 만들었는데 안 먹힘 | `.env.txt` 로 저장됨 | `ren .env.txt .env` |

### AWS 접속 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| `Unable to locate credentials` | `aws configure` 미실행 | 팀장에게 받은 키로 `aws configure` |
| `plugin was not found` | Session Manager 플러그인 미설치 | `AWS_구축_가이드.md` 1-② 참고 |
| `TargetNotConnected` | 서버가 꺼져 있음 | 팀장에게 켜달라고 요청 |
| 켠 직후 접속 실패 | 부팅 + SSM 등록에 1~2분 | 기다렸다 다시 시도 |
| `permission denied ... docker.sock` | SSM 기본 계정 `ssm-user` 에 도커 권한 없음 | `sudo su - ubuntu` |
| `{"error":"Unauthorized"}` | API 키 미첨부. **서버는 정상** | `-H "Authorization: Bearer <키>"` 추가 |
| `Error parsing parameter '--parameters'` | cmd 창에서 작은따옴표 JSON 사용 | PowerShell 을 쓰거나 `portNumber=8000,localPortNumber=8000` 형식 |

### 분석 결과 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| `400 Bad Request` (chat/completions) | 번들+프롬프트+답변이 모델 문맥 한계 초과 | 팀장에게 문의 (`--max-model-len` 조정 필요) |
| 화면에 JSON 원문이 그대로 노출 | 답변이 중간에 잘려 파싱 실패 | `.env` 의 `LLM_MAX_TOKENS` 확인 후 재생성 |
| 미작성 항목 11개 / 증거 인용 0건 | 모델이 JSON 키의 밑줄을 생략 | 코드에서 정규화 처리됨 (`assessment.py`) |
| 분석 결과가 영어로 나옴 | `LLM_OUTPUT_LANGUAGE` 미설정 | `.env` 에 `LLM_OUTPUT_LANGUAGE=ko` |
| `demo fallback` 이 뜸 | 모델에 못 닿아 가짜 요약으로 대체됨 | 터널이 살아 있는지 확인. `DEMO_MODE=false` 확인 |
| 연결된 서비스 4개 중 0개 | Kibana/ES/Velociraptor 미기동 | **정상.** 파일 기반 시나리오로 분석은 동작 |

### 깃 쪽

| 증상 | 원인 | 대처 |
| --- | --- | --- |
| 안 고친 파일 수십 개가 modified 로 표시 | 줄바꿈(CRLF/LF) 차이 | `.gitattributes` 적용됨. 최초 1회 `git add --renormalize .` |
| `unable to stat 'docs/~$....docx'` | 워드 임시 파일이 추적 중인데 디스크에 없음 | `git add -A docs` 로 삭제 반영 |
| 여러 줄 커밋 메시지가 깨짐 | cmd 는 여러 줄 따옴표 미지원 | `-m` 을 여러 번 사용 |

---

## 관련 문서

| 문서 | 내용 |
| --- | --- |
| [`AWS_구축_가이드.md`](AWS_구축_가이드.md) | 처음 접속 설정, 담당 서버별 설치 |
| [`ROLES.md`](ROLES.md) | 역할 분담 상세 |
| [`STATUS.md`](STATUS.md) | 프로젝트 현황 |
| [`diagrams/`](diagrams/) | 네트워크 구성도 · 계층도 |
