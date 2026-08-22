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
