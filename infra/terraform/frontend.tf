# =============================================================================
# frontend.tf — HAW-KI 웹 앱(프론트엔드) 서버
# =============================================================================
#
#  지금까지 노트북 도커에서 돌리던 화면을 서버로 올립니다.
#  계층도에서 「사람 승인」과 분석 결과를 보는 자리이고,
#  SIEM · LLM 과 VPC 안에서 직접 통신합니다.
#
#      브라우저 ──SSM 터널──▶ frontend:5000
#                                  │
#                                  ├──▶ SIEM Indexer 9200   (경보 조회)
#                                  └──▶ LLM 8000            (분석 요청)
#
#  ★ 프라이빗 서브넷입니다. 인터넷에서 들어오는 포트가 없습니다.
#    관리자 화면이라 밖에 열지 않았습니다. 볼 때는 터널을 씁니다.

resource "aws_instance" "frontend" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.frontend_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.frontend.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # 도커만 미리 깔아둡니다. 앱 배포는 SSM 으로 손으로 합니다.
  # (llm.tf 와 같은 이유 — 첫 배포는 거의 항상 한 번에 안 됩니다)
  user_data = <<-BOOTSTRAP
    #!/bin/bash
    set -eux
    apt-get update -qq
    apt-get install -y ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    usermod -aG docker ubuntu
    mkdir -p /opt/hawki
    chown -R ubuntu:ubuntu /opt/hawki
    echo "bootstrap done" > /opt/hawki/READY
  BOOTSTRAP

  tags = { Name = "${var.project_prefix}-frontend" }

  lifecycle {
    # 다시 만들면 올려둔 .env 와 데이터가 날아갑니다.
    ignore_changes = [user_data, ami]
  }
}

resource "aws_ec2_instance_state" "frontend" {
  instance_id = aws_instance.frontend.id
  state       = var.siem_running ? "running" : "stopped"
}
