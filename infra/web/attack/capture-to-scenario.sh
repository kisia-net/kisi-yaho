#!/usr/bin/env bash
# =============================================================================
# capture-to-scenario.sh — 서버가 받은 진짜 로그를 시나리오로 넘긴다
# =============================================================================
#
#  replay.sh 로 만든 실제 로그를 파이프라인이 읽는 scenario 폴더로 옮깁니다.
#  이렇게 하면 fixtures(합성)가 아니라 진짜 캡처가 분석 화면에 뜹니다.
#  (docs/STATUS.md 의 "실제/합성 데이터 구분표" 에서 '실제' 쪽으로 들어갑니다.)
#
#      bash capture-to-scenario.sh web_real_capture
set -euo pipefail

NAME="${1:-web_real_capture}"
STAGE="$(mktemp -d)"

# 웹 서버(이 호스트)에서 나오는 원본 두 개. 이건 여기서 바로 뜹니다.
cp /var/log/nginx/access.log   "$STAGE/nginx_access.log"
cp /var/log/modsec_audit.json  "$STAGE/modsec_audit.json"

# ※ Wazuh 경보(wazuh_alerts.jsonl)는 여기 없습니다.
#   경보는 Agent 가 아니라 Manager 가 디코더·룰을 돌려 만듭니다(계층도 2번 칸).
#   그래서 SIEM 서버(10.0.10.123)의 /var/ossec/logs/alerts/alerts.json 에서
#   같은 시간대·같은 IP 로 걸러 받아 이 폴더에 wazuh_alerts.jsonl 로 넣으십시오.
#   (민석형/효찬에게 요청) 없으면 없는 대로 nginx+modsec 두 소스만으로도 돕니다.

echo "수집 원본을 $STAGE 에 모았습니다:"
ls -la "$STAGE"

echo
echo "이제 파이프라인 있는 곳(노트북/컨테이너)에서 아래를 실행하세요:"
echo "  scp 또는 aws ssm 으로 $STAGE 를 내려받은 뒤"
echo "  python -m hawki_alert_analysis.ingest <내려받은폴더> \\"
echo "    --out data/scenarios/$NAME --id WEB-REAL-001 --host web-01"
echo
echo "ingest 가 payload 0건이라고 하면 modsec overrides.conf 의 SecAuditLogParts 에"
echo "C 가 들어있는지, SecRequestBodyAccess On 인지 다시 보세요."
