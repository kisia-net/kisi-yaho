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
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Wazuh Dashboard HTTPS, called from inside the VPC"
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

  # 프론트엔드가 경보를 조회하는 통로. Wazuh Indexer(OpenSearch) 는
  # 기본이 HTTPS + 자체 서명 인증서입니다.
  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Wazuh Indexer, queried by the frontend app"
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
#  현재 0.0.0.0/0 전체 개방입니다 (web_open_to_internet = true).
#
#  ★ 이건 의도된 설정입니다 ★
#    SIEM 프로젝트에서 "공격받는 웹 서버" 가 있어야 실제 공격 로그가 생깁니다.
#    다만 교육용 AWS 계정 지침상 전체 개방은 사전 확인 대상이므로,
#    담당자께 알린 뒤 사용합니다.
#
#  전체 개방을 유지하는 조건 네 가지 — 하나라도 못 지키면 team_ip_cidrs 로 되돌리세요.
#    1. 작업할 때만 켠다 (siem_running=false 가 기본)
#    2. ModSecurity + OWASP CRS 를 nginx 와 함께 올린다
#    3. 이 서버에는 실제 개인정보나 팀 비밀값을 두지 않는다
#    4. 이 서버의 IAM 권한은 SSM 통신 하나뿐으로 유지한다
#       (털려도 새 인스턴스를 못 만들게 하는 마지막 방어선)

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

  # 프론트엔드 → 센서 VM 8787. 콘솔에서 직접 추가돼 코드에 없던 규칙을 2026-09-21 코드로 옮김.
  # description 이 없는 상태로 AWS 에 존재하므로 일부러 비워둡니다(값을 넣으면 규칙이 재생성됨).
  # 용도: 확인 필요 (Suricata 룰 적재·검증 게이트웨이로 추정) — 확인되면 이 주석을 갱신하세요.
  ingress {
    from_port       = 8787
    to_port         = 8787
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend.id]
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

# --- 프론트엔드 ---------------------------------------------------------------
# 인터넷 인바운드 0개. 브라우저는 SSM 포트 포워딩으로 붙습니다.
# 5000 은 VPC 안에서만 열어, SIEM 서버가 API 로 호출할 수 있게 합니다.

resource "aws_security_group" "frontend" {
  name        = "${var.project_prefix}-sg-frontend"
  description = "HAW-KI web app. Reachable inside the VPC only; browsers use SSM tunneling."
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "Web app, from inside the VPC only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound for package install, SSM messaging, SIEM and LLM calls"
  }

  tags = { Name = "${var.project_prefix}-sg-frontend" }
}
