# =============================================================================
# llm.tf — GPU 서버
# =============================================================================

# GPU 드라이버와 CUDA 가 미리 깔린 이미지를 씁니다.
# 이걸 안 쓰면 드라이버 설치로 하루를 날립니다.
#
# ⚠ AMI 이름 패턴이 안 맞아 오류가 나면 아래 명령으로 실제 이름을 확인하세요:
#   aws ec2 describe-images --owners amazon `
#     --filters "Name=name,Values=Deep Learning*Ubuntu 22.04*" `
#     --query "reverse(sort_by(Images,&CreationDate))[:5].[Name,ImageId]" --output table
data "aws_ami" "dlami" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Deep Learning OSS Nvidia Driver AMI GPU PyTorch*Ubuntu 22.04*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_instance" "llm" {
  ami                    = data.aws_ami.dlami.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.llm.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # 여기서는 "준비"까지만 합니다.
  # 모델 다운로드와 vLLM 기동은 4단계에서 SSM 으로 들어가 손으로 한 번 해 봅니다.
  #
  # 왜 자동화하지 않나:
  #   첫 시도는 거의 항상 실패합니다(이미지 태그, 메모리 설정, 모델 이름 …).
  #   실패를 Terraform 사이클로 디버깅하면 서버를 부수고 다시 만드느라
  #   매번 모델 40GB 를 다시 받게 됩니다.
  #   되는 조합을 먼저 찾고, 그 다음에 이 자리에 옮겨 적으세요.
  user_data = <<-BOOTSTRAP
    #!/bin/bash
    set -eux
    mkdir -p /opt/hawki/models
    chown -R ubuntu:ubuntu /opt/hawki
    # NAT 이 아직 준비 중일 수 있으니 실패해도 부팅은 계속합니다.
    docker pull vllm/vllm-openai:latest || true
    echo "bootstrap done" > /opt/hawki/READY
  BOOTSTRAP

  tags = { Name = "${var.project_prefix}-llm" }

  lifecycle {
    # user_data 나 AMI 가 바뀌어도 서버를 다시 만들지 않습니다.
    # 다시 만들면 받아둔 모델 40GB 가 통째로 날아갑니다.
    ignore_changes = [user_data, ami]
  }
}

# ★ 서버를 "지우지" 않고 "정지"만 시킵니다.
#   정지 상태 = GPU 요금 0, 디스크(모델)는 그대로 유지.
resource "aws_ec2_instance_state" "llm" {
  instance_id = aws_instance.llm.id
  state       = var.lab_running ? "running" : "stopped"
}
