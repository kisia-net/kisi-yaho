#!/usr/bin/env bash
# =============================================================================
# install-agent.sh — 웹 서버에 Wazuh Agent 설치 (Ubuntu 22.04)
# =============================================================================
#
#  Manager 주소는 계층도 2번 칸의 SIEM 입니다. 사설 IP 로 붙습니다.
#  docs/RUNBOOK.md 의 서버 목록에서 값이 바뀌면 여기도 같이 고치십시오.
set -euo pipefail

MANAGER="${WAZUH_MANAGER:-10.0.10.123}"
AGENT_NAME="${WAZUH_AGENT_NAME:-web-01}"

echo "== Wazuh Agent 설치 (manager=${MANAGER}, name=${AGENT_NAME})"

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list

apt-get update -qq
WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
  apt-get install -y wazuh-agent

# 로그 수집 대상 등록. 이미 들어 있으면 다시 넣지 않습니다.
if ! grep -q "modsec_audit.json" /var/ossec/etc/ossec.conf; then
  python3 - <<'PY'
import re, pathlib
conf = pathlib.Path("/var/ossec/etc/ossec.conf")
text = conf.read_text()
block = pathlib.Path("/opt/kisiyaho-web/wazuh/localfile.xml").read_text()
# 주석 머리말을 걷어내고 <localfile> 블록만 남깁니다.
block = block[block.index("<localfile>"):]
text = text.replace("</ossec_config>", block + "\n</ossec_config>", 1)
conf.write_text(text)
print("ossec.conf 에 localfile 블록 3개를 넣었습니다.")
PY
else
  echo "localfile 블록이 이미 있습니다. 건너뜁니다."
fi

# Agent 가 root 로 읽어야 하는 파일들입니다.
chmod 0644 /var/log/modsec_audit.json 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl restart wazuh-agent
sleep 3
systemctl --no-pager --lines=10 status wazuh-agent || true

echo
echo "== 확인"
echo "  tail -f /var/ossec/logs/ossec.log        ← 'Connected to the server' 가 나와야 합니다"
echo "  Manager 쪽에서: /var/ossec/bin/agent_control -l"
