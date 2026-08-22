# infra/terraform — AI 증강 SIEM 인프라

AWS 환경을 코드로 관리합니다. 콘솔에서 마우스로 만들지 않습니다.

## 지금 만드는 것

LLM 서버 **1대**와 그 서버가 살 네트워크입니다.
나머지 3대(공격표면 / SIEM / Agent)는 실모델 측정이 끝난 뒤에 이 코드를 확장해서 붙입니다.

```
VPC 10.0.0.0/16
├── 퍼블릭 서브넷 10.0.1.0/24   → NAT Gateway
└── 프라이빗 서브넷 10.0.10.0/24 → GPU 서버 (g6e.xlarge)
                                    · 들어오는 포트 0개
                                    · 접속은 SSM 으로만
```

## 처음 한 번만 — 스크립트 한 줄

```powershell
cd infra\terraform
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

이 스크립트가 도구 확인 → state 버킷 생성(이름 중복 없음) → 보안 설정 →
`backend.tf` 반영 → `terraform.tfvars` 준비까지 해 줍니다.
이미 끝난 단계는 건너뛰므로 여러 번 돌려도 안전합니다.

끝나면 **`backend.tf` 를 반드시 커밋하세요.** 팀원 전부 같은 버킷을 봐야 합니다.

```powershell
terraform init
```

## 매일 쓰는 명령

```powershell
# 작업 시작 — GPU 서버 켜기 + NAT 생성
terraform apply -var lab_running=true

# 작업 끝 ★ 반드시 — GPU 정지 + NAT 삭제 (모델 디스크는 유지)
terraform apply -var lab_running=false

# 지금 무엇이 만들어질/사라질지 미리 보기
terraform plan -var lab_running=true
```

`apply` 가 끝나면 SSM 접속 명령과 터널 명령이 화면에 찍힙니다.

## 첫 apply 는 `lab_running=true` 로

GPU 서버가 부팅하면서 도커 이미지를 받아야 하는데, 그러려면 NAT 이 있어야 합니다.
그래서 **처음 만들 때는 `-var lab_running=true`** 로 시작하고, 4단계 모델 다운로드까지
끝낸 뒤에 `false` 로 내리세요.

## 파일 구성

| 파일 | 내용 |
|---|---|
| `backend.tf` | Terraform 설정, S3 state, AWS 연결 |
| `variables.tf` | 바꿔 쓰는 값들 (`lab_running` 이 핵심) |
| `network.tf` | VPC, 서브넷, IGW, NAT, 라우팅 |
| `iam.tf` | SSM 접속용 IAM Role |
| `security.tf` | 보안 그룹 — **인바운드 규칙 0개** |
| `llm.tf` | GPU 인스턴스, 부트스트랩, 정지/실행 제어 |
| `budget.tf` | 비용 알람 (50% / 80% / 100% 예측) |
| `outputs.tf` | 인스턴스 ID, SSM 명령 |

## 팀 규칙

1. **`terraform apply` 전에 반드시 `terraform plan` 을 눈으로 확인**한다.
   `Plan: N to add, M to change, K to destroy` 의 숫자와 목록을 본다.
2. **퇴근 전 `lab_running=false`.** 매일 확인하는 사람을 정한다.
3. **콘솔에서 손으로 자원을 만들지 않는다.** 코드에 없는 자원은 아무도 모른다.
4. `terraform force-unlock` 은 함부로 쓰지 않는다. 잠겨 있으면 누가 작업 중인 것이다.
5. state 파일과 `terraform.tfvars` 는 절대 커밋하지 않는다. (`.gitignore` 확인)

## 자세한 절차

`docs/AWS_구축_가이드.md` 의 3단계~6단계를 보세요.
