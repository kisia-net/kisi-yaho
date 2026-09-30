# =============================================================================
# redteam.tf — 레드팀 전용 스테이징 서버 (HAW-KI 복제본 + promptfoo/garak)
# =============================================================================
#
#  운영 프론트엔드를 건드리지 않고, 수정한 HAW-KI 를 여기서 먼저 공격·검증합니다.
#  vLLM(8000) 과 Wazuh Indexer(9200) 는 이미 VPC 대역 전체에 열려 있어서
#  이 서버를 프라이빗 서브넷에 두기만 하면 추가 규칙 없이 닿습니다.
#
#      노트북 ──SSM 터널(5001)──▶ redteam:5000 (HAW-KI 스테이징)
#                                     │
#                                     ├──▶ LLM 8000       (운영과 공유)
#                                     └──▶ Indexer 9200   (실제 경보 E2E 때만)
#
#  ★ 인바운드 규칙이 하나도 없습니다. 접속은 SSM 으로만 합니다.
#  ★ 기본값 false — 이 파일이 있어도 켜기 전까지는 아무것도 만들지 않습니다.
#
#  켜기  : terraform.tfvars 에 redteam_enabled = true  → terraform apply
#  잠시 끄기 : redteam_running = false → apply (디스크·설치물 유지)
#  완전 삭제 : redteam_enabled = false → apply (디스크까지 삭제, 비용 0)

variable "redteam_enabled" {
  type        = bool
  default     = false
  description = "레드팀 스테이징 서버를 만들지. 프로젝트 끝나면 false 로 지웁니다."
}

variable "redteam_running" {
  type        = bool
  default     = true
  description = "만들어진 레드팀 서버를 켜둘지. 안 쓰는 날은 false."
}

variable "redteam_instance_type" {
  type        = string
  default     = "t3.medium" # HAW-KI 빌드 + promptfoo(node) + garak 컨테이너 동시 실행
  description = "레드팀 스테이징 서버 크기."
}

resource "aws_security_group" "redteam" {
  count       = var.redteam_enabled ? 1 : 0
  name        = "${var.project_prefix}-sg-redteam"
  description = "Red team staging. No inbound; operators use SSM only."
  vpc_id      = aws_vpc.main.id

  # HAW-KI backend (frontend host) -> red team runner, for automatic evaluation
  # of live analysis results (REDTEAM_RUNNER_URL, port 8091). Only the frontend
  # security group may connect; nothing else reaches the runner.
  # The group description above still says "No inbound": changing a security
  # group's description replaces the whole group, so it is left as it is.
  ingress {
    from_port       = 8091
    to_port         = 8091
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend.id]
    description     = "HAW-KI backend to red team runner (auto evaluation)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound for package install, SSM messaging, git clone, LLM and SIEM calls"
  }

  tags = { Name = "${var.project_prefix}-sg-redteam" }
}

resource "aws_instance" "redteam" {
  count                  = var.redteam_enabled ? 1 : 0
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.redteam_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.redteam[0].id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name # 기존 프로필 재사용 — 새 IAM 없음

  root_block_device {
    volume_size           = 40 # 도커 이미지(HAW-KI, promptfoo, garak) 여유분
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data = <<-BOOTSTRAP
    #!/bin/bash
    set -eux
    apt-get update -qq
    apt-get install -y ca-certificates curl gnupg git
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    usermod -aG docker ubuntu
    fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    mkdir -p /opt/hawki-redteam
    chown -R ubuntu:ubuntu /opt/hawki-redteam
    echo "bootstrap done" > /opt/hawki-redteam/READY
  BOOTSTRAP

  tags = {
    Name    = "${var.project_prefix}-redteam"
    Purpose = "redteam-staging"
  }

  lifecycle {
    ignore_changes = [user_data, ami]
  }
}

resource "aws_ec2_instance_state" "redteam" {
  count       = var.redteam_enabled ? 1 : 0
  instance_id = aws_instance.redteam[0].id
  state       = var.redteam_running ? "running" : "stopped"
}

output "tunnel_redteam" {
  description = "레드팀 스테이징 HAW-KI 접속 터널 (로컬 5001 — 운영 터널 5000/8080 과 안 겹치게)"
  value = var.redteam_enabled ? "aws ssm start-session --region ap-northeast-2 --target ${aws_instance.redteam[0].id} --document-name AWS-StartPortForwardingSession --parameters portNumber=5000,localPortNumber=5001" : "redteam_enabled = false"
}

output "redteam_instance_id" {
  value = var.redteam_enabled ? aws_instance.redteam[0].id : null
}
