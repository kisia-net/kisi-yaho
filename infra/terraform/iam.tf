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

# =============================================================================
# 웹 서버가 설치 파일을 S3 에서 받아오게 하는 최소 권한 (읽기 전용)
# =============================================================================
#
#  web 서버는 빈 Ubuntu 로 떠서, infra/web 의 setup.sh·설정 파일을 받아야
#  nginx + ModSecurity 를 올릴 수 있습니다. 저장소가 비공개라 서버에서
#  git clone 이 안 되므로, 팀 S3 버킷의 web/ 경로를 경유합니다.
#
#    내 PC:  aws s3 cp infra\web s3://<버킷>/web/ --recursive
#    서버:   sudo aws s3 cp s3://<버킷>/web/ /opt/kisiyaho-web/ --recursive
#
#  범위를 web/ 경로의 GetObject 와, 그 경로를 나열하는 ListBucket 으로만
#  좁혔습니다. 이 역할은 SIEM·센서·GPU 서버도 함께 씁니다(iam.tf 위쪽의
#  단일 ssm 역할). 그 서버들도 같은 버킷 읽기가 생기지만, 읽기 전용이고
#  대상이 설치 파일뿐이라 위험은 낮습니다. 작업이 끝나면 이 블록을 지워도
#  됩니다 — 지우고 apply 하면 권한이 회수됩니다.
resource "aws_iam_role_policy" "web_artifact_read" {
  name = "${var.project_prefix}-web-artifact-read"
  role = aws_iam_role.ssm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListBucketWebPrefix"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = ["arn:aws:s3:::${var.web_artifact_bucket}"]
        Condition = {
          StringLike = { "s3:prefix" = ["web/*"] }
        }
      },
      {
        Sid      = "GetWebObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::${var.web_artifact_bucket}/web/*"]
      }
    ]
  })
}
