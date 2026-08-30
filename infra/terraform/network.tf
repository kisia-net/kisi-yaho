# =============================================================================
# network.tf — VPC (우리만 쓰는 가상 사설망)
# =============================================================================
#
#  ┌──────── VPC 10.0.0.0/16 ────────────────────────────┐
#  │  퍼블릭 서브넷 10.0.1.0/24  — 1층, 인터넷과 통함     │
#  │     └ NAT Gateway (나가기만 하는 통로)              │
#  │                    ↑                                │
#  │  프라이빗 서브넷 10.0.10.0/24 — 지하, 직접 접근 불가 │
#  │     └ GPU 서버                                      │
#  └─────────────────────────────────────────────────────┘

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_prefix}-vpc" }
}

# --- 1층: 인터넷과 통하는 구역 ------------------------------------------------

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}${var.az_suffix}"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_prefix}-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.project_prefix}-rt-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- 지하: GPU 서버가 사는 구역 -----------------------------------------------

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "${var.region}${var.az_suffix}"

  tags = { Name = "${var.project_prefix}-private" }
}

# --- NAT Gateway: lab_running=true 일 때만 존재 -------------------------------
# 프라이빗 서버가 "밖으로 나가기만" 할 수 있게 해 줍니다.
# (모델 다운로드와 SSM 통신에 필요)
# 시간당 과금이라 안 쓸 때는 통째로 지웁니다.

resource "aws_eip" "nat" {
  count  = local.nat_needed ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${var.project_prefix}-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  count         = local.nat_needed ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public.id
  depends_on    = [aws_internet_gateway.igw]

  tags = { Name = "${var.project_prefix}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # NAT 이 있을 때만 바깥으로 나가는 길이 생깁니다.
  # NAT 이 없으면 이 서브넷은 완전히 고립됩니다.
  dynamic "route" {
    for_each = local.nat_needed ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.nat[0].id
    }
  }

  tags = { Name = "${var.project_prefix}-rt-private" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}
