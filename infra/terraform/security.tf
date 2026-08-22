# =============================================================================
# security.tf — 방화벽
# =============================================================================
#
#  ★ 발표에서 말할 부분 ★
#
#  이 보안 그룹에는 ingress(들어오는 규칙) 블록이 하나도 없습니다.
#  인터넷에서 이 서버로 들어올 수 있는 포트는 0개입니다.
#
#    · SSH(22)   — 열지 않음. SSM Session Manager 로 접속합니다.
#    · vLLM(8000) — 열지 않음. SSM 포트 포워딩으로 터널을 뚫습니다.
#
#  "우리 LLM 서버는 인터넷에서 접근 가능한 포트가 하나도 없습니다."

resource "aws_security_group" "llm" {
  name        = "${var.project_prefix}-sg-llm"
  description = "LLM server. No inbound rules at all - access is via SSM only."
  vpc_id      = aws_vpc.main.id

  # ingress 없음 (의도적)

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
