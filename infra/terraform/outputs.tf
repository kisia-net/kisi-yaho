# =============================================================================
# outputs.tf — apply 가 끝나면 화면에 찍히는 값들
# =============================================================================

output "llm_instance_id" {
  value       = aws_instance.llm.id
  description = "SSM 접속·터널 명령에 넣을 값"
}

output "llm_state" {
  value       = var.lab_running ? "running (요금 발생 중)" : "stopped (GPU 요금 없음)"
  description = "지금 GPU 서버 상태"
}

output "step_4_connect" {
  description = "4단계 — 서버 안으로 들어가기"
  value       = "aws ssm start-session --target ${aws_instance.llm.id}"
}

output "step_5_tunnel" {
  description = "5단계 — 내 PC 8000번 → 서버 8000번 터널 (새 창에서 계속 켜두기)"
  value       = "aws ssm start-session --target ${aws_instance.llm.id} --document-name AWS-StartPortForwardingSession --parameters '{\\\"portNumber\\\":[\\\"8000\\\"],\\\"localPortNumber\\\":[\\\"8000\\\"]}'"
}
