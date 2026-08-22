# =============================================================================
# backend.tf — Terraform 자체 설정과 AWS 연결
# =============================================================================

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # 팀 전체가 같은 state 파일을 봅니다.
  # state = "지금 AWS에 뭐가 만들어져 있는지" 기록.
  # 각자 노트북에 두면 A가 만든 걸 B가 모르고 또 만드는 사고가 납니다.
  #
  # use_lockfile : 두 사람이 동시에 apply 하는 것을 막습니다.
  #                (Terraform 1.10부터 DynamoDB 없이 S3 자체 잠금 지원)
  #
  # ⚠ 아래 bucket 이름은 전 세계에서 유일해야 합니다.
  #    이미 누가 쓰고 있으면 뒤에 숫자를 붙이세요. (예: kisia-net1-tfstate-01)
  #    그리고 이 버킷은 terraform init 전에 미리 만들어져 있어야 합니다.
  backend "s3" {
    bucket       = "kisia-net1-s3"
    key          = "llm/terraform.tfstate"
    region       = "ap-northeast-2"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  # 여기서 만든 모든 자원에 자동으로 붙는 꼬리표.
  # 나중에 "이거 누가 왜 만든 거지?" 를 막아 줍니다.
  default_tags {
    tags = {
      Project   = "kisia-net-1"
      Team      = var.team_name
      ManagedBy = "terraform"
    }
  }
}
