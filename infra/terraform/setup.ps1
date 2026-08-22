# =============================================================================
#  setup.ps1 - Terraform 사전 준비 자동화
# =============================================================================
#  하는 일:
#    1) AWS CLI / Terraform 설치 확인
#    2) state 저장용 S3 버킷 이름을 직접 정하고 생성
#    3) 버전 관리 / 암호화 / 공개 차단 설정
#    4) backend.tf 에 버킷 이름 반영
#    5) terraform.tfvars 준비
#
#  실행 방법 (infra\terraform 폴더에서):
#    powershell -ExecutionPolicy Bypass -File .\setup.ps1
#
#  여러 번 실행해도 안전합니다. 이미 끝난 단계는 건너뜁니다.
# =============================================================================

# 네이티브 명령(aws)의 종료 코드를 직접 확인하므로 Stop 을 쓰지 않습니다.
$ErrorActionPreference = "Continue"
$REGION = "ap-northeast-2"

function Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Ok($msg)       { Write-Host "    OK  $msg" -ForegroundColor Green }
function Warn($msg)     { Write-Host "    !!  $msg" -ForegroundColor Yellow }
function Info($msg)     { Write-Host "        $msg" -ForegroundColor Gray }
function Die($msg)      { Write-Host "`n[중단] $msg" -ForegroundColor Red; exit 1 }

# --- 1. 도구 확인 -------------------------------------------------------------
Step 1 "도구 확인"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Die "AWS CLI 가 없습니다.`n       winget install --id Amazon.AWSCLI -e`n       설치 후 PowerShell 을 새로 여세요."
}
Ok "AWS CLI"

if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
    Die "Terraform 이 없습니다.`n       winget install --id Hashicorp.Terraform -e`n       설치 후 PowerShell 을 새로 여세요."
}
Ok "Terraform"

$identityJson = aws sts get-caller-identity --output json 2>$null
if ($LASTEXITCODE -ne 0) { Die "AWS 계정 연결이 안 됩니다.  aws configure  를 먼저 실행하세요." }
$identity = $identityJson | ConvertFrom-Json
Ok "AWS 계정 연결됨 ($($identity.Arn))"

# --- 2. 버킷 이름 직접 정하기 -------------------------------------------------
Step 2 "state 저장용 S3 버킷 이름 정하기"

$backendPath = Join-Path $PSScriptRoot "backend.tf"
if (-not (Test-Path $backendPath)) { Die "backend.tf 를 찾을 수 없습니다. infra\terraform 폴더에서 실행하세요." }

$backend = Get-Content $backendPath -Raw -Encoding UTF8
if ($backend -match 'bucket\s*=\s*"([^"]+)"') { $current = $Matches[1] }
else { Die "backend.tf 에서 bucket 값을 찾지 못했습니다." }

Info "backend.tf 에 지금 적힌 이름 : $current"
Write-Host ""
Info "S3 버킷 이름 규칙"
Info "  - 3~63 자"
Info "  - 소문자 / 숫자 / 하이픈(-) 만 사용"
Info "  - 대문자, 밑줄(_), 공백, 한글 불가"
Info "  - 전 세계에서 유일해야 함 (남이 쓰고 있으면 못 씀)"
Write-Host ""

$bucket = $null
while ($true) {

    $answer = Read-Host "    쓸 이름을 입력하세요 (그냥 엔터 = $current)"
    if ([string]::IsNullOrWhiteSpace($answer)) { $candidate = $current }
    else { $candidate = $answer.Trim().ToLower() }

    # --- 이름 규칙 검사 (AWS 에 물어보기 전에 걸러냅니다) ---
    if ($candidate.Length -lt 3 -or $candidate.Length -gt 63) {
        Warn "3~63 자여야 합니다. 지금 $($candidate.Length) 자."; continue
    }
    if ($candidate -cmatch '[A-Z]') { Warn "대문자는 쓸 수 없습니다."; continue }
    if ($candidate -match '_')      { Warn "밑줄(_) 은 쓸 수 없습니다. 하이픈(-) 을 쓰세요."; continue }
    if ($candidate -notmatch '^[a-z0-9][a-z0-9.-]*[a-z0-9]$') {
        Warn "소문자/숫자/하이픈만 되고, 처음과 끝은 문자나 숫자여야 합니다."; continue
    }
    if ($candidate -match '\.\.') { Warn "점을 연속으로 쓸 수 없습니다."; continue }
    if ($candidate -match '^\d+\.\d+\.\d+\.\d+$') { Warn "IP 주소 모양은 쓸 수 없습니다."; continue }

    # --- 이미 내 계정에 있는가 ---
    aws s3api head-bucket --bucket $candidate 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Ok "이미 내 계정에 있는 버킷입니다. 그대로 씁니다: $candidate"
        $bucket = $candidate; break
    }

    # --- 만들어 보기 ---
    $out = aws s3api create-bucket --bucket $candidate --region $REGION `
             --create-bucket-configuration LocationConstraint=$REGION 2>&1
    if ($LASTEXITCODE -eq 0) {
        Ok "생성됨: $candidate"
        $bucket = $candidate; break
    }

    $text = "$out"
    if ($text -match 'BucketAlreadyOwnedByYou') {
        Ok "이미 내 계정에 있는 버킷입니다: $candidate"
        $bucket = $candidate; break
    }
    if ($text -match 'BucketAlreadyExists') {
        Warn "그 이름은 다른 계정이 이미 쓰고 있습니다. 다른 이름을 넣어 주세요."
        Info "예) $candidate-net1 , $candidate-2026 , kisia-yaho-tfstate"
        Write-Host ""
        continue
    }
    if ($text -match 'InvalidBucketName') {
        Warn "AWS 가 이름 형식을 거부했습니다. 다시 입력해 주세요."
        Write-Host ""
        continue
    }
    Die "버킷 생성에 실패했습니다.`n$text"
}

# --- 3. 버킷 보안 설정 --------------------------------------------------------
Step 3 "버킷 보안 설정"

# 실수로 지우거나 덮어써도 되돌릴 수 있게
aws s3api put-bucket-versioning --bucket $bucket `
    --versioning-configuration Status=Enabled | Out-Null
if ($LASTEXITCODE -eq 0) { Ok "버전 관리 켜짐" } else { Warn "버전 관리 설정 실패 (권한 확인 필요)" }

# state 에는 자원 정보와 때로는 비밀값이 들어갑니다.
aws s3api put-bucket-encryption --bucket $bucket `
    --server-side-encryption-configuration "Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256}}]" | Out-Null
if ($LASTEXITCODE -eq 0) { Ok "기본 암호화 켜짐" } else { Warn "암호화 설정 실패 (권한 확인 필요)" }

# 공개된 Terraform state 는 실제 침해 사고에서 자주 나오는 경로입니다.
aws s3api put-public-access-block --bucket $bucket `
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" | Out-Null
if ($LASTEXITCODE -eq 0) { Ok "공개 접근 전면 차단" } else { Warn "공개 차단 설정 실패 (권한 확인 필요)" }

# --- 4. backend.tf 반영 -------------------------------------------------------
Step 4 "backend.tf 에 버킷 이름 반영"

$new = $backend -replace '(bucket\s*=\s*)"[^"]+"', "`$1`"$bucket`""
if ($new -ne $backend) {
    Set-Content -Path $backendPath -Value $new -Encoding UTF8 -NoNewline
    Ok "반영 완료 ($current -> $bucket)"
    Warn "이 변경은 반드시 커밋하세요. 팀원 전부 같은 버킷을 봐야 합니다."
    Info "git add backend.tf"
    Info "git commit -m `"Set the Terraform state bucket name`""
} else {
    Ok "이미 맞게 되어 있음"
}

# --- 5. terraform.tfvars 준비 -------------------------------------------------
Step 5 "terraform.tfvars 준비"

$tfvars  = Join-Path $PSScriptRoot "terraform.tfvars"
$example = Join-Path $PSScriptRoot "terraform.tfvars.example"

if (Test-Path $tfvars) {
    Ok "이미 있습니다"
} else {
    Copy-Item $example $tfvars
    Ok "terraform.tfvars 를 만들었습니다"
    Warn "메모장이 열립니다. budget_emails 에 실제 이메일 주소를 넣고 저장하세요."
    Start-Process notepad.exe $tfvars -Wait
}

# --- 끝 -----------------------------------------------------------------------
Write-Host "`n=====================================================" -ForegroundColor Green
Write-Host " 준비 완료.  버킷: $bucket" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  terraform init"
Write-Host "  terraform plan -var lab_running=true"
Write-Host "  terraform apply -var lab_running=true"
Write-Host ""
Write-Host " plan 결과의 'Plan: N to add' 목록을 꼭 눈으로 확인하세요." -ForegroundColor Yellow
Write-Host ""
