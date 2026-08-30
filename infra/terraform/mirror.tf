# =============================================================================
# mirror.tf — 트래픽 미러링 (웹 서버 → 센서 VM)
# =============================================================================
#
#  웹 서버와 센서가 다른 기계이므로, 센서는 웹 트래픽을 볼 방법이 없습니다.
#  AWS 가 패킷을 복사해서 센서로 보내주는 것이 트래픽 미러링입니다.
#
#      web 의 랜카드 ──(복사 · VXLAN 4789)──▶ vm 의 랜카드 ──▶ Suricata
#
#  ★ 맨 마지막에 켜세요. var.mirroring_enabled = false 로 시작합니다.
#    앞의 세 대가 다 서고 SIEM 에 로그가 올라오는 걸 확인한 뒤에 true 로 바꾸세요.
#    같이 하면 안 될 때 원인이 Agent 인지 미러링인지 구분이 안 됩니다.
#
#  ※ t3 는 Nitro 계열이라 미러링을 지원합니다. t2 였다면 불가능합니다.

resource "aws_ec2_traffic_mirror_target" "sensor" {
  count                = var.mirroring_enabled ? 1 : 0
  description          = "Suricata sensor"
  network_interface_id = aws_instance.vm.primary_network_interface_id

  tags = { Name = "${var.project_prefix}-mirror-target" }
}

# 무엇을 복사할지. 지금은 들어오고 나가는 것 전부입니다.
# 나중에 노이즈가 심하면 여기서 포트를 좁히면 됩니다.
resource "aws_ec2_traffic_mirror_filter" "all" {
  count       = var.mirroring_enabled ? 1 : 0
  description = "Mirror all inbound and outbound traffic"

  tags = { Name = "${var.project_prefix}-mirror-filter" }
}

resource "aws_ec2_traffic_mirror_filter_rule" "ingress" {
  count                    = var.mirroring_enabled ? 1 : 0
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.all[0].id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_number              = 100
  rule_action              = "accept"
  traffic_direction        = "ingress"
  description              = "All inbound"
}

resource "aws_ec2_traffic_mirror_filter_rule" "egress" {
  count                    = var.mirroring_enabled ? 1 : 0
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.all[0].id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_number              = 100
  rule_action              = "accept"
  traffic_direction        = "egress"
  description              = "All outbound"
}

resource "aws_ec2_traffic_mirror_session" "web_to_sensor" {
  count                    = var.mirroring_enabled ? 1 : 0
  description              = "Copy web server traffic to the Suricata sensor"
  network_interface_id     = aws_instance.web.primary_network_interface_id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.sensor[0].id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.all[0].id
  session_number           = 1

  tags = { Name = "${var.project_prefix}-mirror-session" }
}
