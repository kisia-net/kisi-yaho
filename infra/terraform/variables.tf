# =============================================================================
# variables.tf — 바꿔 쓸 수 있는 값들
# =============================================================================

variable "region" {
  type        = string
  default     = "ap-northeast-2" # 서울
  description = "모든 자원이 만들어질 리전"
}

variable "az_suffix" {
  type        = string
  default     = "a"
  description = <<-DESC
    가용영역 접미사. ap-northeast-2a 의 마지막 글자.
    GPU 인스턴스 생성 시 'Insufficient capacity' 오류가 나면
    "c" 또는 "b" 로 바꿔서 다시 시도하세요.
  DESC
}

# ★★★ 가장 중요한 변수 ★★★
# 이 값 하나로 "돈 나가는 것들"을 통째로 껐다 켭니다.
#
#   true  → GPU 서버 실행 + NAT Gateway 생성   (요금 발생)
#   false → GPU 서버 정지 + NAT Gateway 삭제   (디스크 값만)
#
# 디스크는 지워지지 않으므로 받아둔 모델 40GB 는 그대로 남습니다.
variable "lab_running" {
  type        = bool
  default     = false
  description = "실험할 때만 true. 작업 끝나면 반드시 false."
}

variable "instance_type" {
  type        = string
  default     = "g6e.xlarge" # NVIDIA L40S 48GB / 4 vCPU
  description = "GPU 인스턴스 종류. 쿼터가 8 vCPU 이므로 4 vCPU 짜리 한 대."
}

variable "root_volume_gb" {
  type        = number
  default     = 200
  description = "모델 40GB + 도커 이미지 15GB + OS + 여유"
}

variable "monthly_budget_usd" {
  type        = number
  default     = 200
  description = "월 예산. 팀 크레딧에 맞춰 조정하세요."
}

# ⚠ 기본값이 없습니다. terraform.tfvars 에 적거나, 없으면 apply 할 때 물어봅니다.
#   일부러 이렇게 뒀습니다 — 주소를 안 적으면 비용 알람이 아무 데도 안 갑니다.
variable "budget_emails" {
  type        = list(string)
  description = "비용 알람을 받을 이메일. 최소 2명 (팀장 + 인프라 담당)"
}

variable "team_name" {
  type        = string
  default     = "kisi-yaho"
  description = "모든 자원에 자동으로 붙는 Team 태그 값"
}

variable "project_prefix" {
  type        = string
  default     = "siem"
  description = "자원 이름 앞에 붙는 말"
}

# =============================================================================
# 서버 3대 (SIEM · 웹 · 센서 VM) — servers.tf 에서 씁니다
# =============================================================================

# ★ 두 번째로 중요한 변수 ★
#   lab_running 은 GPU 만, 이건 나머지 서버들만 켜고 끕니다.
#   따로 둔 이유: SIEM 만 만지는 날에 GPU까지 켜지면 돈이 아깝습니다.
variable "siem_running" {
  type        = bool
  default     = false
  description = "SIEM · 웹 · 센서 VM 을 켤지. 작업 끝나면 false."
}

variable "siem_instance_type" {
  type        = string
  default     = "t3.xlarge" # 4 vCPU / 16GB — Indexer 가 JVM 힙을 크게 먹습니다
  description = "SIEM 서버 크기. t3.large 로 내리면 인덱싱 중 죽을 수 있습니다."
}

variable "web_instance_type" {
  type        = string
  default     = "t3.small"
  description = "웹 서버 크기. nginx + ModSecurity 면 충분합니다."
}

variable "vm_instance_type" {
  type        = string
  default     = "t3.large" # Suricata 가 ET Open 룰만 1.5GB 가까이 씁니다
  description = "센서 VM 크기."
}

variable "siem_volume_gb" {
  type        = number
  default     = 100
  description = "SIEM 디스크. 로그가 쌓이는 곳이라 넉넉히."
}

variable "vm_volume_gb" {
  type        = number
  default     = 50
  description = "센서 VM 디스크. eve.json 이 쌓입니다."
}

# ⚠ 트래픽 미러링은 맨 마지막에 켜세요.
#   서버 셋이 다 서고 SIEM 에 로그가 올라오는 걸 확인한 뒤에 true 로.
variable "mirroring_enabled" {
  type        = bool
  default     = false
  description = "웹 서버 트래픽을 센서 VM 으로 복사할지."
}

# 웹 서버를 인터넷 전체에 열지, 우리 IP 만 열지.
#   true  → 실제 봇 스캔이 들어옵니다. 진짜 공격 로그가 쌓이지만 관리가 필요합니다.
#   false → team_ip_cidrs 에 적은 주소만. 안전하지만 우리가 만든 로그뿐입니다.
variable "web_open_to_internet" {
  type        = bool
  default     = true
  description = "웹 서버를 0.0.0.0/0 에 열지 여부."
}

variable "team_ip_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/32"] # 일부러 아무것도 아닌 값. tfvars 에서 채우세요.
  description = "web_open_to_internet=false 일 때 허용할 팀원 IP. 예: [\"1.2.3.4/32\"]"
}
