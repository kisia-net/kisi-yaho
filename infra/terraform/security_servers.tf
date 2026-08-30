# =============================================================================
# security_servers.tf — 방화벽 (SIEM · 웹 · 센서)
# =============================================================================
#
#  security.tf 의 원칙을 그대로 이어갑니다.
#  인터넷에서 들어올 수 있는 곳은 웹 서버의 80/443 뿐입니다.
#  관리 접속은 전부 SSM 세션 매니저 — SSH 키를 나눠 가질 일이 없습니다.
#
#  ⚠ AWS 는 보안 그룹 description 에 ASCII 만 받습니다. 한글을 쓰면 apply 가 거부됩니다.

# --- SIEM ---------------------------------------------------------------------
# 인터넷 인바운드 0개. Agent 가 VPC 안에서 보내는 것만 받습니다.
# 대시보드(443)도 열지 않습니다 — SSM 포트 포워딩으로 봅니다.

resource "aws_security_group" "siem" {
  name        = "${var.project_prefix}-sg-siem"
  description = "Wazuh manager. Inbound only from hosts inside the VPC."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Wazuh agent log transport (1514) and enrollment (1515)"
  }

  ingress {
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Wazuh API"
  }

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Velociraptor client to server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound for package install and SSM messaging"
  }

  tags = { Name = "${var.project_prefix}-sg-siem" }
}

# --- 웹 서버 -------------------------------------------------------------------
# 여기만 인터넷에 열립니다. 공격 대상이 되는 것이 역할입니다.
#
#  var.web_open_to_internet = false 로 두면 우리 IP 만 들어옵니다.
#  true 로 하면 실제 봇 스캔이 들어와서 진짜 공격 로그가 쌓입니다 — 대신 관리 필요.

resource "aws_security_group" "web" {
  name        = "${var.project_prefix}-sg-web"
  description = "Public web server. This host is meant to be attacked."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.web_open_to_internet ? ["0.0.0.0/0"] : var.team_ip_cidrs
    description = "HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.web_open_to_internet ? ["0.0.0.0/0"] : var.team_ip_cidrs
    description = "HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound for package install and SSM messaging"
  }

  tags = { Name = "${var.project_prefix}-sg-web" }
}

# --- 센서 VM -------------------------------------------------------------------
# 인터넷 인바운드 0개.
# 웹 서버에서 복사돼 오는 미러링 트래픽(VXLAN 4789)만 받습니다.

resource "aws_security_group" "vm" {
  name        = "${var.project_prefix}-sg-vm"
  description = "Sensor host. Receives mirrored traffic only. No internet inbound."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 4789
    to_port         = 4789
    protocol        = "udp"
    security_groups = [aws_security_group.web.id]
    description     = "VXLAN encapsulated mirrored traffic from the web server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound for package install and SSM messaging"
  }

  tags = { Name = "${var.project_prefix}-sg-vm" }
}
