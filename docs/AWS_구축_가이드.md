# AWS 구축 가이드 — LLM 서버 1대로 "실모델 측정"까지

> **2026-08-24 갱신** — 이 문서는 AWS 를 **처음 구축할 때** 보는 안내서입니다.
> 이미 구축이 끝났다면 매일 켜고 끄는 절차는 [`RUNBOOK.md`](RUNBOOK.md) 를 보세요.
> 아래 값들은 실제 구축 결과 확인된 내용으로 정정했습니다.
>
> | 문서의 원래 안내 | 확인된 값 |
> | --- | --- |
> | `--max-model-len` 은 8192 로 시작해 올려본다 | **32768 이 정상 동작**한다 (L40S 48GB). 8192 로는 증거 번들이 들어가지 않아 400 오류가 난다 |
> | 터널 명령의 JSON 따옴표 | PowerShell 에서는 그대로 동작. **cmd 에서는 `--parameters portNumber=8000,localPortNumber=8000`** 형식을 쓸 것 |
> | `docker run ... serve --model ...` | 이미지 진입점에 `serve` 가 포함되어 있어 **`serve` 를 넣으면 안 된다** |


> 네트워크반 1팀 (키시 야호~) · AWS를 처음 쓰는 사람을 위한 단계별 안내
>
> **목표:** 이 문서를 끝까지 따라가면 `comparison.md` 파일에 **진짜 모델이 낸 증강 전/후 수치**가 찍힙니다.
> 지금 문서에 있는 "데모 경로 값"이라는 단서를 뗄 수 있게 됩니다.

---

## 0. 시작 전에 — 단어 여섯 개만 알면 됩니다

AWS 문서가 어려운 이유는 낯선 단어가 한꺼번에 쏟아져서입니다. 우리한테 필요한 건 여섯 개뿐이에요.

| 단어 | 쉽게 말하면 | 우리 경우 |
|---|---|---|
| **리전 (Region)** | 데이터센터가 있는 지역 | 서울 (`ap-northeast-2`) |
| **VPC** | 우리만 쓰는 가상 사설망 | 건물 한 채를 통째로 빌린 것 |
| **서브넷 (Subnet)** | VPC 안의 구역 | 건물 안의 층. 1층=바깥과 통함, 지하=안 통함 |
| **EC2** | 서버 한 대 | GPU 서버 |
| **IAM Role** | 서버에게 주는 신분증 | "이 서버는 SSM으로 접속해도 된다" |
| **보안 그룹 (SG)** | 서버 앞에 붙은 방화벽 | 우리는 **들어오는 문을 0개** 만듭니다 |

### 우리가 만들 그림

```
┌──────── VPC (10.0.0.0/16) — 우리 건물 ────────┐
│                                                │
│  퍼블릭 서브넷 (10.0.1.0/24) — 1층            │
│    └ NAT Gateway (밖으로 나가기만 하는 통로)   │
│                    ↑                           │
│  프라이빗 서브넷 (10.0.10.0/24) — 지하         │
│    └ [GPU 서버] g6e.xlarge                     │
│         · vLLM + GPT-OSS 20B                   │
│         · 들어오는 포트: 0개                    │
│         · 접속: SSM (AWS 내부 통로)             │
└────────────────────────────────────────────────┘
                     ↕ SSM 터널
             내 PC (Windows) — HAW-KI 웹앱
```

**핵심 아이디어:** GPU 서버는 인터넷에서 아예 안 보입니다. 우리는 AWS 내부 통로(SSM)로 들어가고, 그 통로에 **터널**을 뚫어서 내 PC의 8000번 포트를 서버의 8000번 포트에 연결합니다. 그러면 내 컴퓨터에서 도는 웹앱이 "옆방에 모델이 있다"고 착각하게 됩니다.

---

## 0-1. 준비물 — 내 PC에 세 가지 설치 (30분)

셋 다 설치하고 **PowerShell을 새로 열어야** 합니다. (환경변수가 반영되려면 필요해요.)

### ① AWS CLI

```powershell
winget install --id Amazon.AWSCLI -e
```

winget이 안 되면 <https://awscli.amazonaws.com/AWSCLIV2.msi> 를 받아서 설치 (그냥 다음-다음 누르면 됩니다).

확인 (**새 PowerShell 창**에서):
```powershell
aws --version
# aws-cli/2.x.x ... 이렇게 나오면 성공
```

### ② Session Manager 플러그인 ★ 이게 없으면 터널이 안 뚫립니다

<https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html> 에서 Windows용 설치 파일.

확인:
```powershell
session-manager-plugin
# "The Session Manager plugin is installed successfully" 나오면 성공
```

> 이 플러그인은 AWS CLI와 **별개**입니다. 대부분 여기서 막혀요. 꼭 따로 설치하세요.

### ③ Terraform

**권장 — winget으로 한 줄.** Windows 10/11에 기본으로 들어 있는 설치 도구입니다. 압축 풀 필요도, Path 건드릴 필요도 없습니다.

```powershell
winget install --id Hashicorp.Terraform -e
```

설치가 끝나면 **PowerShell 창을 닫고 새로 여세요.** (Path가 새 창에만 반영됩니다.)

확인:
```powershell
terraform -version
# Terraform v1.x.x 나오면 성공
```

<details>
<summary><b>winget이 없거나 실패할 때 — 수동 설치</b></summary>

1. <https://developer.hashicorp.com/terraform/install> 에서 **Windows / AMD64** zip 다운로드
2. 압축을 풀면 `terraform.exe` 파일 하나가 나옵니다
3. `C:\terraform\` 폴더를 만들고 그 안에 `terraform.exe`를 넣습니다
4. 시작 메뉴에서 **"시스템 환경 변수 편집"** 검색 → 실행
5. 오른쪽 아래 **환경 변수(N)...** 버튼
6. 아래쪽 **시스템 변수** 목록에서 **Path** 선택 → **편집(I)...**
7. **새로 만들기(N)** → `C:\terraform` 입력 (파일명 말고 **폴더 경로**)
8. **확인**을 세 번 눌러 창을 모두 닫기
9. **PowerShell을 닫고 새로 열기** ← 안 하면 계속 "인식할 수 없는 명령"이 뜹니다

</details>

> 💡 **다른 프로그램도 같은 방법으로 찾을 수 있습니다.**
> ```powershell
> winget search terraform
> winget search "aws cli"
> ```
> 나온 ID를 `winget install --id <ID> -e` 에 넣으면 됩니다.

### ④ AWS 계정 연결 — 액세스 키 만들기

> **받은 게 "아이디 + 비밀번호"뿐인가요?** 정상입니다.
> 그건 **웹 콘솔 로그인용**이고, CLI가 쓰는 **액세스 키는 본인이 직접 만드는 것**입니다.
> 담당자가 안 준 게 아니라, 원래 각자 만드는 겁니다.

| 받은 것 | 쓰는 곳 |
|---|---|
| 아이디 + 비밀번호 | **웹 브라우저**에서 AWS 콘솔 로그인 |
| 액세스 키 ID + 시크릿 키 | **터미널**에서 `aws` / `terraform` 명령 |

#### 1) 콘솔에 로그인

<https://console.aws.amazon.com/> 접속 → **IAM 사용자** 탭 선택 (루트 사용자 아님)

- **계정 ID 또는 계정 별칭**: 담당자에게 받은 12자리 숫자 또는 별칭
- 사용자 이름 / 비밀번호: 받은 값

첫 로그인에서 비밀번호 변경을 요구할 수 있습니다. 바꾸고 진행하세요.


#### 2) 액세스 키 만들기

1. 우측 상단 **계정 이름** 클릭 → **보안 자격 증명 (Security credentials)**
2. 아래로 스크롤 → **액세스 키** 구역 → **액세스 키 만들기**
3. 사용 사례에서 **명령줄 인터페이스(CLI)** 선택
4. 아래 확인 체크박스에 동의 → **다음**
5. 설명 태그(선택): `kisia-net1-cli-본인이름` 처럼 적어두면 나중에 누구 키인지 알 수 있습니다
6. **액세스 키 만들기**

#### 3) ⚠️ 시크릿 키는 이 화면에서만 보입니다

**창을 닫으면 다시는 볼 수 없습니다.** (액세스 키 ID는 나중에도 보이지만 시크릿은 안 보입니다.)

- **.csv 파일 다운로드** 버튼을 눌러 저장하거나
- 바로 다음 단계(`aws configure`)까지 마치고 창을 닫으세요

잃어버리면 키를 삭제하고 새로 만드는 수밖에 없습니다.

#### 4) CLI에 등록

```powershell
aws configure
```

```
AWS Access Key ID     : AKIA... (방금 만든 값)
AWS Secret Access Key : (방금 만든 값)
Default region name   : ap-northeast-2
Default output format : json
```

#### 5) 확인

```powershell
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/본인아이디"
}
```

`Arn`에 본인 아이디가 보이면 성공입니다.

---

#### 🚨 액세스 키 보안 — 이건 농담이 아닙니다

**액세스 키를 GitHub에 올리면 몇 분 안에 도둑맞습니다.** 봇이 공개 저장소를 실시간으로 훑고 있고, 훔친 키로 최상위 GPU 인스턴스를 잔뜩 띄워 암호화폐를 캡니다. 학생 프로젝트에서 수천 달러가 청구되는 사고가 매년 반복됩니다.

지켜야 할 것:

- `aws configure`로 넣으면 `C:\Users\<이름>\.aws\credentials`에 저장됩니다. **저장소 밖**이라 안전합니다
- **코드나 `.env`에 키를 직접 적지 마세요.** Terraform도 `aws configure`로 넣은 값을 알아서 씁니다
- `.gitignore`에 `.env`, `*.tfvars`, `*.tfstate` 가 있는지 확인
- 커밋 전에 습관적으로: `git diff --cached | Select-String "AKIA"`
- **키는 팀원끼리 공유하지 마세요.** 각자 만들어 쓰세요 — 사고가 나도 그 사람 키만 폐기하면 되고, 감사 기록에 누가 뭘 했는지 남습니다

혹시 실수로 올렸다면: **즉시 콘솔에서 그 키를 비활성화·삭제**하고 새로 만드세요. 커밋을 되돌리는 것만으로는 부족합니다. 이미 노출된 겁니다.

---

<details>
<summary><b>"AWS 액세스 포털 URL"을 같이 받았다면 (IAM Identity Center / SSO)</b></summary>

담당자가 `https://d-xxxx.awsapps.com/start` 같은 주소를 줬다면 SSO 방식이라 액세스 키를 만들지 않습니다. 대신:

```powershell
aws configure sso
```

- SSO start URL: 받은 주소
- SSO Region: `ap-northeast-2`
- 브라우저가 열리면 승인 → 계정·역할 선택
- 프로필 이름을 정하면 이후 `aws --profile <이름>` 으로 씁니다

이 방식은 키가 자동 만료돼서 더 안전합니다. 다만 세션이 끊기면 `aws sso login`을 다시 해야 합니다.

</details>

---

## 1단계. GPU 쿼터 증설 요청 (5분) ★ 지금 당장

**이걸 제일 먼저 하는 이유:** 승인에 몇 시간~며칠 걸립니다. 나중에 알면 주말을 통째로 날립니다.

신규 AWS 계정은 **GPU 인스턴스 한도가 0**인 경우가 많습니다. 이 상태로 서버를 띄우면 이렇게 막혀요.

```
You have requested more vCPU capacity than your current vCPU limit of 0
```

### 하는 법

1. AWS 콘솔 로그인 → 오른쪽 위 **리전을 "아시아 태평양(서울)"로** 바꾸기 (중요!)
2. 검색창에 `Service Quotas` 입력 → 들어가기
3. 왼쪽 메뉴 **AWS 서비스** → 검색창에 `EC2` → **Amazon Elastic Compute Cloud (Amazon EC2)** 클릭
4. 쿼터 검색창에 `G and VT` 입력
5. **Running On-Demand G and VT instances** 클릭
6. 오른쪽 위 **계정 수준에서 증가 요청** 버튼
7. 값에 **`8`** 입력 → 요청

### 왜 8인가

`g6e.xlarge`는 vCPU가 4개입니다. 4만 신청하면 딱 한 대만 되고, 나중에 다른 크기를 시험하려면 다시 신청해야 해요. 8이면 여유가 있고, 그렇다고 과하지도 않아서 승인이 잘 납니다.

### 승인 확인

같은 화면의 **할당량 요청 기록** 탭에서 상태를 봅니다.

- `Pending` → 대기 중
- `Approved` / 적용된 계정 할당량 값이 8 → **완료**

> 승인 기다리는 동안 **2단계와 3단계를 진행하세요.** 대기 시간이 낭비가 되지 않습니다.

---

## 2단계. 비용 알람 걸기 (10분) — 이거 안 하면 크레딧 날아갑니다

GPU 서버는 시간당 과금입니다. 켜두고 잊으면 조용히 계속 나가요. **사람은 반드시 잊습니다.**

### ① 결제 알림 켜기 (선행 작업)

1. 콘솔 오른쪽 위 계정 이름 → **결제 및 비용 관리**
2. 왼쪽 아래 **결제 기본 설정**
3. **알림 기본 설정** → **CloudWatch 결제 알림 수신** 체크 → 저장

### ② 예산(Budget) 만들기

1. 같은 화면 왼쪽 메뉴에서 **예산**
2. **예산 생성** → **맞춤형 예산** 선택
3. 예산 유형: **비용 예산**
4. 이름: `kisia-net1-monthly`
5. 기간: **월별**, 예산 금액: 팀에 배정된 크레딧에 맞춰 설정 (예: `$200`)
6. **경보 임계값 추가**를 눌러 최소 **세 개**를 만드세요

| 임계값 | 언제 울리나 | 뜻 |
|---|---|---|
| 50% | 절반 썼을 때 | "속도를 보자" |
| 80% | 대부분 썼을 때 | "이제 아껴야 함" |
| 100% (예측 기준) | 이대로 가면 초과 예상 | **"지금 멈춰라"** |

7. 알림 받을 **이메일 주소**에 팀장 + 인프라 담당 최소 2명 등록

> 100% 항목은 **"예측(Forecasted)"** 기준으로 잡으세요. 실제로 다 쓴 다음에 알려주면 이미 늦습니다.

### ③ 습관 하나

매일 작업 끝날 때 콘솔에서 **비용 탐색기**를 30초만 보세요. 어제 얼마 나갔는지 숫자로 보면 감이 생깁니다.

---

## 3단계. Terraform으로 환경 만들기

### 3-0. 준비 스크립트 한 줄 (자동)

명령을 하나씩 손으로 칠 필요 없습니다. `infra/terraform/setup.ps1` 이 준비 작업을 대신합니다.

```powershell
cd infra\terraform
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

> `-ExecutionPolicy Bypass` 는 윈도우가 기본으로 `.ps1` 실행을 막기 때문에 붙입니다.
> 이 한 줄로 실행하면 시스템 설정을 바꾸지 않고 이번 실행만 허용합니다.

이 스크립트가 하는 일:

| 단계 | 내용 |
|---|---|
| 1 | AWS CLI · Terraform 설치 확인, 계정 연결 확인 |
| 2 | **버킷 이름을 직접 입력** — 규칙 검사, 이미 쓰이는 이름이면 다시 물어봄 |
| 3 | S3 버킷 생성 + 버전 관리 + 기본 암호화 + 공개 접근 전면 차단 |
| 4 | `backend.tf` 에 버킷 이름 자동 반영 |
| 5 | `terraform.tfvars` 생성 후 메모장 열어 이메일 입력 |

중간에 멈추면 **어디서 왜 멈췄는지 한글로 알려줍니다.** 고치고 다시 실행하면 됩니다.
이미 끝난 단계는 건너뛰므로 몇 번을 다시 돌려도 안전합니다.

#### 버킷 이름은 직접 정합니다

2단계에서 이렇게 물어봅니다.

```
    쓸 이름을 입력하세요 (그냥 엔터 = kisia-net1-tfstate):
```

원하는 이름을 넣거나, 그냥 엔터를 치면 기본값을 씁니다.

| 규칙 | 내용 |
|---|---|
| 길이 | 3~63 자 |
| 쓸 수 있는 글자 | 소문자 · 숫자 · 하이픈(`-`) |
| 쓸 수 없는 것 | 대문자, 밑줄(`_`), 공백, 한글 |
| 유일성 | **전 세계에서 유일**해야 함 |

규칙에 안 맞으면 그 자리에서 알려주고 다시 물어봅니다.
남이 이미 쓰는 이름이면 이렇게 나오고 다시 물어봅니다.

```
    !!  그 이름은 다른 계정이 이미 쓰고 있습니다. 다른 이름을 넣어 주세요.
        예) kisia-net1-tfstate-net1 , kisia-net1-tfstate-2026 , kisia-yaho-tfstate
```

> 이름에 팀명이나 프로젝트명이 드러나도 괜찮습니다. 공개 접근을 전면 차단하기 때문에
> 이름을 안다고 내용을 볼 수 있는 게 아닙니다. 다만 **비밀값을 이름에 넣지는 마세요.**

#### ⚠️ 스크립트가 끝나면 `backend.tf` 를 커밋하세요

버킷 이름이 바뀌었기 때문에, **팀원 전부가 같은 이름을 봐야** 같은 state 를 공유합니다.

```powershell
git add backend.tf
git commit -m "Set the Terraform state bucket name"
```

<details>
<summary><b>스크립트 없이 손으로 하려면</b></summary>

각 줄이 한 줄짜리라 그대로 붙여넣을 수 있습니다. `BUCKET` 값만 유일한 이름으로 바꾸세요.

```powershell
$BUCKET = "kisia-net1-tfstate-1a2b3c4d"
aws s3api create-bucket --bucket $BUCKET --region ap-northeast-2 --create-bucket-configuration LocationConstraint=ap-northeast-2
aws s3api put-bucket-versioning --bucket $BUCKET --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket $BUCKET --server-side-encryption-configuration "Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256}}]"
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

그다음 `backend.tf` 의 `bucket` 값을 같은 이름으로 고치고,
`terraform.tfvars.example` 을 `terraform.tfvars` 로 복사해 이메일을 채우세요.

</details>

> **왜 S3에 두나:** state 는 "지금 AWS에 뭐가 만들어져 있는지" 기록입니다.
> 각자 노트북에 두면 팀원 A가 만든 걸 B가 모르고 또 만드는 사고가 납니다.
> 이 버킷 하나만 Terraform 이전에 있어야 합니다. (닭과 달걀 문제)

### 3-1. 파일은 이미 만들어져 있습니다

저장소의 `infra/terraform/` 폴더를 열어 보세요. 다음 파일들이 들어 있습니다.

| 파일 | 하는 일 |
|---|---|
| `backend.tf` | Terraform 설정, S3 state 연결, AWS 프로바이더 |
| `variables.tf` | 바꿔 쓰는 값들 — **`lab_running` 이 핵심** |
| `network.tf` | VPC, 퍼블릭·프라이빗 서브넷, IGW, NAT, 라우팅 |
| `iam.tf` | SSM 접속용 IAM Role (SSH 키 없이 들어가는 열쇠) |
| `security.tf` | 보안 그룹 — **인바운드 규칙 0개** ★ |
| `llm.tf` | GPU 인스턴스, 부트스트랩, 정지/실행 제어 |
| `budget.tf` | 비용 알람 (50% / 80% / 100% 예측) |
| `outputs.tf` | 인스턴스 ID와 SSM 명령을 화면에 찍어 줌 |
| `.gitignore` | state·비밀값이 GitHub 에 올라가지 않게 |
| `terraform.tfvars.example` | 이메일 등 직접 채울 값의 견본 |
| `README.md` | 이 폴더만 보고도 쓸 수 있게 정리한 사용법 |

각 파일에 왜 그렇게 썼는지 한글 주석이 달려 있으니 열어서 읽어 보세요.
**코드를 이해하고 발표에서 설명할 수 있는 것까지가 이 단계의 목표입니다.**

### 3-2. 내 환경에 맞게 두 군데만 고치기

#### ① 이메일 주소 채우기

```powershell
cd infra\terraform
copy terraform.tfvars.example terraform.tfvars
notepad terraform.tfvars
```

```hcl
budget_emails = ["팀장@example.com", "인프라담당@example.com"]
```

`terraform.tfvars` 는 `.gitignore` 에 있어 GitHub 에 올라가지 않습니다.

> 이 변수는 일부러 기본값을 비워 뒀습니다. 안 적으면 `apply` 할 때 물어봅니다.
> 주소를 안 넣으면 비용 알람이 **아무 데도 안 가기** 때문입니다.

#### ② S3 버킷 이름이 다르다면

3-0 에서 만든 버킷 이름이 `kisia-net1-tfstate` 가 아니라면,
`backend.tf` 의 `bucket` 값을 그 이름으로 고치세요.

### 3-3. 실행

```powershell
cd infra\terraform

# ① 초기화 — 플러그인 받고 S3 백엔드 연결 (처음 한 번만)
terraform init

# ② 무엇이 만들어질지 미리 보기 ★ 반드시 눈으로 확인
terraform plan -var lab_running=true

# ③ 실제로 만들기
terraform apply -var lab_running=true
```

`plan` 결과의 **"Plan: N to add"** 숫자와 목록을 꼭 확인하세요.
실수로 비싼 걸 만드는 사고를 여기서 막습니다. `apply` 는 `yes` 를 입력해야 진행됩니다.

#### ⚠️ 첫 실행은 왜 `lab_running=true` 인가

GPU 서버가 부팅하면서 도커 이미지를 받아야 하는데, 그러려면 **NAT Gateway가 있어야** 합니다.
`false` 로 만들면 서버가 인터넷 없이 부팅했다가 곧바로 정지되어, 준비 작업이 실패합니다.

그래서 **처음 만들 때는 `true`** 로 시작하고, 4단계 모델 다운로드까지 끝낸 뒤에 `false` 로 내리세요.
`apply` 가 끝나는 순간부터 요금이 나가므로, 바로 4단계로 이어서 진행하시는 게 좋습니다.

#### apply 가 끝나면 화면에 이런 게 찍힙니다

```
llm_instance_id = "i-0abc123def456"
llm_state       = "running (요금 발생 중)"
step_4_connect  = "aws ssm start-session --target i-0abc123def456"
step_5_tunnel   = "aws ssm start-session --target i-0abc123def456 --document-name ..."
```

**이 값들을 메모해 두세요.** 4단계와 5단계에서 그대로 복사해 씁니다.
잊어버리면 `terraform output` 을 다시 치면 됩니다.

---

## 4단계. vLLM 띄우고 모델 받기

### 4-1. 실험 켜기

```powershell
terraform apply -var lab_running=true
```

이러면 NAT이 생기고 GPU 서버가 켜집니다. **여기서부터 시간당 과금이 시작됩니다.**

서버가 SSM에 등록되는 데 1~2분 걸립니다. 확인:

```powershell
aws ssm describe-instance-information --query "InstanceInformationList[].{Id:InstanceId,Ping:PingStatus}"
# PingStatus 가 Online 이면 준비 완료
```

### 4-2. 서버 안으로 들어가기

```powershell
# 인스턴스 ID는 terraform output 으로 확인
terraform output llm_instance_id

aws ssm start-session --target i-0abc123def456
```

들어가면 리눅스 셸이 나옵니다. **SSH 키도, 22번 포트도 없이** 들어온 겁니다.

```bash
# 기본 계정으로 전환
sudo su - ubuntu

# GPU가 보이는지 확인 ★ 여기서 실패하면 아래로 진행하지 마세요
nvidia-smi
```

`NVIDIA L40S`와 메모리 `46068MiB` 같은 게 보이면 성공입니다.

### 4-3. vLLM 실행 — 왜 손으로 하는가

> **첫 시도는 거의 항상 실패합니다.** 이미지 태그, 메모리 설정, 모델 이름… 실패를 Terraform으로 디버깅하면 서버를 부수고 다시 만드느라 **모델 40GB를 매번 다시 받게 됩니다.** 손으로 되는 조합을 먼저 찾고, 그다음에 코드에 박는 게 훨씬 빠릅니다.

```bash
docker run -d --name hawki-vllm \
  --gpus all --ipc=host --restart unless-stopped \
  -p 8000:8000 \
  -v /opt/hawki/models:/root/.cache/huggingface \
  vllm/vllm-openai:latest \
  --model openai/gpt-oss-20b \
  --served-model-name hawki-local \
  --api-key CHANGE-ME-TO-A-LONG-RANDOM-STRING \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.90
```

#### 각 옵션이 왜 있는지

| 옵션 | 이유 |
|---|---|
| `--gpus all` | 컨테이너가 GPU를 쓰게 함. 없으면 CPU로 돌다가 실패 |
| `-v /opt/hawki/models:...` | **모델을 디스크에 저장.** 이거 없으면 재시작마다 40GB 재다운로드 |
| `--served-model-name hawki-local` | 우리 `.env`의 `LLM_MODEL` 값과 **정확히 같아야** 함 |
| `--api-key` | 터널 안이라도 인증은 걸어둡니다. `.env`의 `LLM_API_KEY`와 같아야 함 |
| `--max-model-len 32768` | 증거 번들 + 프롬프트 + 답변이 8192 를 넘는다. L40S 48GB 에서 32768 확인 |

#### ⚠️ `--max-model-len`을 8192로 시작하는 이유

GPT-OSS 20B는 MXFP4라는 압축 형식으로 배포되는데, **이 압축을 하드웨어에서 그대로 처리하는 건 H100·B200 계열**입니다. `g6e`의 L40S(Ada Lovelace)에서는 vLLM이 압축을 풀어서(bf16) 올릴 수 있어요. 그러면 13GB가 아니라 **40GB 가까이** 씁니다.

L40S는 48GB라서 **들어가긴 합니다.** 설계 문서에서 "예산 여유가 있으니 48GB로 안전하게 간다"고 하신 판단이 결과적으로 정확했어요. 24GB짜리를 골랐으면 여기서 막혔습니다.

다만 남는 공간이 빠듯해서, 문맥 길이를 처음부터 32768로 잡으면 **KV 캐시가 넘쳐 OOM**이 납니다. 그래서:

```
8192 로 시작 → 뜨면 16384 시도 → 되면 32768 시도  (2026-08-24 확인: 32768 정상 동작)
```

되는 최대값을 찾아서 기록해 두세요. 그게 여러분의 "긴 로그 한 번에 넣기" 실험의 실제 상한입니다. **이 숫자 자체가 발표 자료가 됩니다.**

### 4-4. 뜰 때까지 지켜보기

```bash
docker logs -f hawki-vllm
```

모델 다운로드에 **20분~1시간** 걸립니다. 로그가 안 움직이는 것처럼 보여도 받는 중이에요.

**성공 신호:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

`Ctrl+C`로 로그 보기를 빠져나온 뒤 (컨테이너는 계속 돕니다) 서버 안에서 직접 확인:

```bash
curl -s http://localhost:8000/v1/models -H "Authorization: Bearer CHANGE-ME-TO-A-LONG-RANDOM-STRING"
# {"data":[{"id":"hawki-local", ...}]} 가 나오면 완성
```

`hawki-local` 이라는 이름이 보이면 4단계 끝입니다.

### 4-5. 되는 조합을 코드에 박기

여기까지 성공한 `docker run` 명령을 그대로 `llm.tf`의 `user_data`에 옮겨 적으세요. 다음에 서버를 새로 만들면 자동으로 뜹니다. **되는 걸 확인한 뒤에 코드화** — 이 순서가 핵심입니다.

---

## 5단계. SSM 터널 → 내 PC 앱 연결

### 5-1. 터널 뚫기

**새 PowerShell 창**을 열고 (이 창은 계속 켜둬야 합니다):

```powershell
aws ssm start-session `
  --target i-0abc123def456 `
  --document-name AWS-StartPortForwardingSession `
  --parameters '{\"portNumber\":[\"8000\"],\"localPortNumber\":[\"8000\"]}'
```

```
Starting session with SessionId: ...
Port 8000 opened for sessionId ...
Waiting for connections...
```

이 창을 **닫으면 터널이 끊깁니다.** 작업하는 동안 그대로 두세요.

> PowerShell에서 따옴표 이스케이프가 까다롭습니다. 위 명령이 안 되면 JSON을 파일로 저장해서 `--parameters file://params.json` 으로 넘기세요.

### 5-2. `.env` 고치기 — ★ 여기가 제일 많이 막히는 지점

저장소 루트의 `.env` 파일에 추가/수정합니다.

```bash
LLM_API_URL=http://host.docker.internal:8000/v1/chat/completions
LLM_MODEL=hawki-local
LLM_API_KEY=CHANGE-ME-TO-A-LONG-RANDOM-STRING
DEMO_MODE=false
```

#### 왜 `127.0.0.1`이 아니라 `host.docker.internal`인가

웹앱(Flask)은 **도커 컨테이너 안에서** 돕니다. 컨테이너 입장에서 `127.0.0.1`은 자기 자신이에요. 터널은 **윈도우 호스트**에 뚫려 있고요.

`host.docker.internal`은 "나를 실행한 그 컴퓨터"를 가리키는 특별한 이름입니다. 다행히 `compose.yaml`에 이미 준비돼 있습니다:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

이걸 모르고 `127.0.0.1`을 넣으면 계속 `llm_transport_error`가 뜨는데 원인을 못 찾습니다. **한 시간씩 날리는 지점이에요.**

#### `DEMO_MODE=false`로 두는 이유

`true`면 모델이 안 될 때 조용히 데모 답변으로 넘어갑니다. 지금은 **연결이 진짜 됐는지 확인하는 게 목적**이라, 실패하면 실패했다고 말하게 두는 게 낫습니다. 측정이 끝나면 다시 `true`로 돌려도 됩니다.

### 5-3. 앱 다시 띄우고 확인

```powershell
docker compose down
docker compose up -d
```

<http://127.0.0.1:5000> → 경보 하나 클릭 → **LLM으로 분석하기**

**성공 판별:**

| 위치 | 실패 (지금) | 성공 |
|---|---|---|
| 오른쪽 위 작은 글씨 | `soar-local · demo fallback` | **`hawki-local`** (demo fallback 없음) |
| Confidence | `low — the local model was unreachable` | 모델이 실제로 매긴 값 |
| 답변 내용 | 항상 똑같은 고정 문장 | 매번 조금씩 다른 문장 |
| 응답 시간 | 즉시 | **몇 초~수십 초** (모델이 생각하는 시간) |

**"demo fallback" 다섯 글자가 사라지는 순간이 이 프로젝트의 분기점입니다.**

---

## 6단계. 실모델로 증강 전/후 측정 ★ 이게 진짜 목표

### 6-1. 명령 — ⚠️ 주소가 5단계와 다릅니다

`evaluate.py`는 도커 밖에서, 윈도우에서 직접 돕니다. 그래서 `host.docker.internal`이 아니라 **`127.0.0.1`**이어야 해요.

```powershell
# 이 창에서만 임시로 주소를 덮어씁니다 (.env 파일은 그대로 둡니다)
$env:LLM_API_URL = "http://127.0.0.1:8000/v1/chat/completions"
$env:LLM_MODEL   = "hawki-local"
$env:LLM_API_KEY = "CHANGE-ME-TO-A-LONG-RANDOM-STRING"

python tools\evaluate.py --compare --live --markdown comparison.md
```

> **한 줄로 붙여 쓰지 마세요.** `docker compose ... --compare` 처럼 이어 붙이면 `unknown flag: --compare` 오류가 나면서 `evaluate.py`가 실행조차 되지 않습니다. (문서 8절에 이미 적혀 있는 함정입니다.)

### 6-2. 결과 확인 — 머리글부터 보세요

출력 맨 위에 이렇게 찍힙니다.

```
증강 전/후 비교  (live LLM)
```

**`(live LLM)`이어야 합니다.** `(demo path)`라고 나오면 아직 모델에 안 붙은 겁니다. 5단계로 돌아가세요.

### 6-3. 문서 갱신

`comparison.md`에 나온 값으로 `docs/PROJECT_NOTES.md` 4절의 표를 교체합니다.

그리고 이 문장을 **지우세요.**

> ~~이 숫자는 `--live` 없이 데모 경로에서 나온 값이다. 실제 sLM이 낸 답이 아니다.~~

대신 이렇게 적습니다.

> 이 값은 AWS `g6e.xlarge`(L40S 48GB)에서 vLLM으로 서빙한 GPT-OSS 20B 실측값이다.
> 측정일: 2026-__-__ / 문맥 길이: ____ / 커밋: ______

**측정 조건을 같이 적는 게 중요합니다.** 나중에 "그거 어떤 조건에서 잰 거예요?"라는 질문에 바로 답할 수 있어야 해요.

### 6-4. 백업

```powershell
git add comparison.md docs\PROJECT_NOTES.md
git commit -m "Replace demo-path figures with live model measurements"
```

**측정 결과는 다시 얻기 비쌉니다** (GPU 시간이 듭니다). 바로 커밋하세요.

---

## 매일 하는 일 — 켜고 끄기

```powershell
# 작업 시작
terraform apply -var lab_running=true
# → 2분 기다렸다가 SSM 터널 열고 작업

# 작업 끝 ★ 반드시
terraform apply -var lab_running=false
```

끄면 이렇게 됩니다.

| 항목 | 켰을 때 | 껐을 때 |
|---|---|---|
| GPU 서버 | 실행 중 (시간당 과금) | **정지 (요금 0)** |
| NAT Gateway | 있음 (시간당 과금) | **삭제됨** |
| 디스크 (모델 40GB) | 유지 | **유지** ← 다시 안 받아도 됨 |
| VPC / IAM / 보안그룹 | 유지 | 유지 (원래 무료) |

**퇴근 전 `lab_running=false`.** 이걸 팀 규칙으로 정하고, 슬랙이나 단톡방에 매일 확인하는 사람을 정해두세요.

> 발표에서 이렇게 말할 수 있습니다.
> **"GPU 비용은 사람이 기억해서 끄는 게 아니라, 변수 하나로 통제됩니다."**
> 서비스를 많이 쓰는 것보다 이런 게 설계 점수를 법니다.

---

## 막혔을 때 — 증상별 대처

| 증상 | 원인 | 해결 |
|---|---|---|
| `vCPU limit of 0` | GPU 쿼터 미승인 | 1단계. 승인 기다리기 |
| `Insufficient capacity` | 그 가용영역에 재고 없음 | `availability_zone`을 `c`나 `b`로 바꿔서 재시도 |
| `session-manager-plugin not found` | 플러그인 미설치 | 0-1 ②. **CLI와 별개입니다** |
| SSM에 서버가 안 보임 | NAT 없음 / IAM Role 없음 | `lab_running=true`인지, 2분 기다렸는지 확인 |
| `nvidia-smi` 실패 | AMI가 잘못 잡힘 | `data.aws_ami` 필터 확인. 아래 명령으로 이름 조회 |
| vLLM 컨테이너가 죽음 (OOM) | 문맥 길이 과다 | `--max-model-len`을 8192 → 4096으로 |
| 웹 UI가 계속 `demo fallback` | `.env` 주소 오류 | **`host.docker.internal`** 맞는지. `docker compose down && up -d` 했는지 |
| `evaluate.py`가 연결 실패 | 주소 오류 | 여기선 **`127.0.0.1`**. 6-1 참고 |
| 출력이 `(demo path)` | 모델 미연결 | 5단계 성공 판별표로 먼저 확인 |
| `terraform apply` 잠김 | 다른 팀원이 작업 중 | 기다리기. **`force-unlock`은 함부로 쓰지 마세요** |

### AMI 이름을 못 찾을 때

```powershell
aws ec2 describe-images --owners amazon `
  --filters "Name=name,Values=Deep Learning*Ubuntu 22.04*" `
  --query "reverse(sort_by(Images,&CreationDate))[:5].[Name,ImageId]" `
  --output table
```

나온 이름을 보고 `llm.tf`의 `values` 패턴을 맞추세요.

---

## 비용 감각 — 무엇이 돈을 먹나

| 항목 | 언제 과금 | 대처 |
|---|---|---|
| **GPU 인스턴스** | 실행 중일 때만 | 정지하면 0 |
| **NAT Gateway** | 존재하는 내내 + 데이터 처리량 | `lab_running=false`로 삭제 |
| **EBS 디스크 200GB** | 인스턴스를 정지해도 계속 | 프로젝트 끝날 때까지는 유지 (모델 보관용) |
| **데이터 전송** | 모델 다운로드 시 1회성 | 캐시 볼륨으로 재다운로드 방지 |
| VPC / 서브넷 / IAM / 보안그룹 | 무료 | — |

정확한 단가는 변동되므로 **[AWS 요금 계산기](https://calculator.aws/)**에서 `ap-northeast-2` 기준으로 직접 확인하세요. 실측 요금은 **비용 탐색기**에서 하루 뒤에 보입니다.

---

## 진행 체크리스트

```
[ ] 0-1  AWS CLI / Session Manager 플러그인 / Terraform 설치
[ ] 0-1  aws configure → get-caller-identity 성공
[ ] 1    GPU 쿼터 증설 요청 (G and VT → 8)          ← 오늘 당장
[ ] 1    승인 확인
[ ] 2    결제 알림 켜기 + 예산 3단계 알람
[ ] 3-0  state용 S3 버킷 생성 (+ 버전 관리)
[ ] 3-2  Terraform 파일 8개 작성
[ ] 3-3  terraform init → plan(눈으로 확인) → apply
[ ] 4-1  lab_running=true → SSM Online 확인
[ ] 4-2  SSM 접속 → nvidia-smi 성공
[ ] 4-3  vLLM 컨테이너 실행
[ ] 4-4  /v1/models 에서 hawki-local 확인
[ ] 4-3  되는 max-model-len 최대값 찾아서 기록
[ ] 4-5  성공한 명령을 user_data 에 반영
[ ] 5-1  SSM 터널 열기
[ ] 5-2  .env 수정 (host.docker.internal!)
[ ] 5-3  웹 UI에서 "demo fallback" 사라짐 확인   ★ 분기점
[ ] 6-1  evaluate.py --compare --live 실행 (127.0.0.1!)
[ ] 6-2  머리글이 (live LLM) 인지 확인
[ ] 6-3  PROJECT_NOTES.md 표 교체 + 측정 조건 기록
[ ] 6-4  커밋
[ ] 매일 lab_running=false 로 끄기
```

---

## 이 문서 이후에 할 일

여기까지 끝나면 **대목표 A의 가장 약한 고리가 사라집니다.** 그다음 순서는 이렇습니다.

1. **위협 인텔 실제 피드 연동** (URLhaus / ThreatFox) — GPU 불필요, 오늘도 가능
2. **나머지 서버 3대** (공격표면 / SIEM / Agent) — 지금 Terraform을 모듈로 확장
3. **대목표 B** — `guardrails/`, `redteam/` (garak · promptfoo)

`infra/terraform/`을 이미 코드로 만들어 뒀으니, 서버 3대를 붙이는 건 파일 몇 개를 더하는 일입니다. **처음부터 코드로 간 게 여기서 값을 합니다.**
