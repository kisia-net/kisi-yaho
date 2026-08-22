# =============================================================================
# iam.tf — 서버에게 "SSM 써도 된다"는 신분증 주기
# =============================================================================
# 이게 있어야 SSH 키 없이, 22번 포트 없이 서버에 들어갈 수 있습니다.

resource "aws_iam_role" "ssm" {
  name = "${var.project_prefix}-llm-ssm-role"

  # "EC2 라는 서비스가 이 역할을 빌려 쓸 수 있다"는 선언
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project_prefix}-llm-ssm-role" }
}

# AWS 가 미리 만들어 둔 표준 정책.
# 우리가 권한을 직접 쓰지 않는 편이 안전합니다.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# EC2 에 실제로 붙이는 형태
resource "aws_iam_instance_profile" "ssm" {
  name = "${var.project_prefix}-llm-ssm-profile"
  role = aws_iam_role.ssm.name
}
