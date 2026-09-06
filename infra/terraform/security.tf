# =============================================================================
# security.tf — 방화벽
# =============================================================================
#
#  ★ 발표에서 말할 부분 ★
#
#  인터넷에서 이 서버로 들어올 수 있는 포트는 0개입니다.
#
#    · SSH(22)    — 열지 않음. SSM Session Manager 로 접속합니다.
#    · vLLM(8000) — 인터넷에는 닫혀 있고, VPC 안에서만 열립니다.
#                   프론트엔드 서버(10.0.10.176)가 모델을 호출해야 하기 때문입니다.
#                   노트북에서 볼 때는 여전히 SSM 터널을 씁니다.
#
#  "우리 LLM 서버는 인터넷에서 접근 가능한 포트가 하나도 없습니다."

resource "aws_security_group" "llm" {
  name        = "${var.project_prefix}-sg-llm"
  description = "LLM server. No inbound rules at all - access is via SSM only."
  vpc_id      = aws_vpc.main.id

  # 인터넷에서 오는 인바운드는 여전히 0개입니다.
  # 아래는 VPC 내부(10.0.0.0/16)에서만 허용되는 규칙입니다.
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "vLLM OpenAI API, called by the frontend app inside the VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    # AWS 의 보안 그룹 description 은 ASCII 만 받습니다. 한글을 쓰면 apply 가 거부됩니다.
    # 설명이 필요하면 이렇게 주석으로 답니다 - 주석은 AWS 로 가지 않습니다.
    #   (아웃바운드: 모델 다운로드와 SSM 통신에 필요)
    description = "Outbound for model download and SSM messaging"
  }

  tags = { Name = "${var.project_prefix}-sg-llm" }
}
