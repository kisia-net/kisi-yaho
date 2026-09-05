# =============================================================================
# outputs_servers.tf — 팀원에게 넘겨줄 값들
# =============================================================================

output "server_ids" {
  description = "각 담당자에게 전달할 인스턴스 ID"
  value = {
    siem = aws_instance.siem.id
    web  = aws_instance.web.id
    vm   = aws_instance.vm.id
    llm      = aws_instance.llm.id
    frontend = aws_instance.frontend.id
  }
}

output "server_private_ips" {
  description = "Agent 설정에 넣을 SIEM 주소 등"
  value = {
    siem = aws_instance.siem.private_ip
    web  = aws_instance.web.private_ip
    vm       = aws_instance.vm.private_ip
    frontend = aws_instance.frontend.private_ip
  }
}

output "web_public_ip" {
  description = "브라우저로 접속하거나 공격을 날릴 주소"
  value       = aws_instance.web.public_ip
}

output "servers_state" {
  value = var.siem_running ? "running (요금 발생 중)" : "stopped (디스크 값만)"
}

output "connect_siem" {
  description = "SIEM 서버 안으로 들어가기"
  value       = "aws ssm start-session --target ${aws_instance.siem.id}"
}

output "tunnel_wazuh_dashboard" {
  description = "Wazuh 대시보드 터널 — 열고 나서 https://127.0.0.1:8443"
  value       = "aws ssm start-session --target ${aws_instance.siem.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443"
}

output "tunnel_frontend" {
  description = "프론트엔드 터널 — 열고 나서 http://127.0.0.1:5000"
  value       = "aws ssm start-session --target ${aws_instance.frontend.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=5000,localPortNumber=5000"
}
