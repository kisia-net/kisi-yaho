# =============================================================================
# servers.tf — SIEM · 웹 서버 · 센서 VM
# =============================================================================
#
#  계층도(docs/diagrams/키시야호_계층도_rev4.png)를 그대로 옮긴 것입니다.
#
#    web   퍼블릭  nginx + ModSecurity + Wazuh Agent      ← 공격받는 쪽
#    vm    프라이빗 Suricata + Sysmon for Linux + Agent    ← 관측하는 쪽
#    siem  프라이빗 Wazuh 일체 + Velociraptor Server       ← 모으는 쪽
#
#  llm.tf 와 같은 원칙을 씁니다.
#    · 서버를 "지우지" 않고 "정지"만 시킨다 (디스크 = 쌓인 로그를 지키려고)
#    · 안에 무엇을 설치할지는 여기 적지 않는다 (SSM 으로 손으로)

locals {
  # 프라이빗 서버가 패키지를 받으려면 NAT 이 있어야 합니다.
  # GPU 를 안 켜도 SIEM 만 켜면 NAT 이 올라오도록 조건을 넓힙니다.
  nat_needed = var.lab_running || var.siem_running || (var.redteam_enabled && var.redteam_running)
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
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

# --- SIEM ---------------------------------------------------------------------
# t3.xlarge 인 이유: Wazuh Indexer 가 OpenSearch 라서 JVM 힙을 크게 먹습니다.
# 8GB 로도 뜨긴 하는데 로그가 몰리면 인덱싱 중에 죽습니다.

resource "aws_instance" "siem" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.siem_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.siem.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  root_block_device {
    volume_size           = var.siem_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # Indexer 가 요구하는 커널 설정만 미리 넣습니다.
  # 이걸 안 하면 설치 도중 max_map_count 오류로 멈춥니다.
  user_data = <<-BOOTSTRAP
    #!/bin/bash
    set -eux
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    sysctl -p
  BOOTSTRAP

  tags = { Name = "${var.project_prefix}-siem" }

  lifecycle {
    # 다시 만들면 쌓인 로그가 통째로 날아갑니다.
    ignore_changes = [user_data, ami]
  }
}

resource "aws_ec2_instance_state" "siem" {
  instance_id = aws_instance.siem.id
  state       = var.siem_running ? "running" : "stopped"
}

# --- 웹 서버 -------------------------------------------------------------------
# 유일하게 퍼블릭 서브넷에 있습니다. 공격받는 게 역할이니까요.

resource "aws_instance" "web" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.web_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "${var.project_prefix}-web" }

  lifecycle {
    ignore_changes = [user_data, ami]
  }
}

resource "aws_ec2_instance_state" "web" {
  instance_id = aws_instance.web.id
  state       = var.siem_running ? "running" : "stopped"
}

# --- 센서 VM -------------------------------------------------------------------
# t3.large 인 이유: Suricata 가 ET Open 룰 3만 개를 메모리에 올립니다.
# 그것만 1.5GB 가까이 먹어서 4GB 로는 빠듯합니다.

resource "aws_instance" "vm" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.vm_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.vm.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  # 미러링된 트래픽을 받으려면 원본 IP 검사를 꺼야 합니다.
  # 이걸 안 끄면 AWS 가 "네 것이 아닌 패킷" 이라며 버립니다.
  source_dest_check = false

  root_block_device {
    volume_size           = var.vm_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "${var.project_prefix}-vm" }

  lifecycle {
    ignore_changes = [user_data, ami]
  }
}

resource "aws_ec2_instance_state" "vm" {
  instance_id = aws_instance.vm.id
  state       = var.siem_running ? "running" : "stopped"
}
