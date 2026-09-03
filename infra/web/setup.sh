#!/usr/bin/env bash
# =============================================================================
# setup.sh — 웹 서버(web / 10.0.1.201)에 nginx + ModSecurity 한 번에 올리기
# =============================================================================
#
#  대상: Ubuntu 22.04 (계층도 rev.4 의 web, 퍼블릭 서브넷)
#  접속: aws ssm start-session --target i-0629c84bb40895441 → sudo su - ubuntu
#
#  이 스크립트가 하는 일 (계층도 1번 칸 "웹 서버 + 웹 방화벽"):
#    1. nginx 를 소스로 빌드 (ModSecurity-nginx connector 를 붙이려면 필요)
#    2. libmodsecurity(v3) 빌드
#    3. OWASP CRS 4.x 배치
#    4. 우리 설정 파일 배치 (이 저장소의 것)
#    5. 취약 포털 앱 + 미끼 트리 + 더미 DB
#
#  ★ nginx 는 apt 판에 ModSecurity 를 못 붙입니다 (동적모듈 미제공).
#    그래서 소스 빌드입니다. 15~25분 걸립니다. t3.small 이면 스왑을 켜세요.
#
#  멱등하게 짰습니다. 중간에 끊기면 다시 돌려도 됩니다.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/kisiyaho-web}"   # 이 저장소 infra/web 을 여기로 복사해 둔다고 가정
NGINX_VER="${NGINX_VER:-1.24.0}"
MODSEC_BRANCH="v3/master"
CRS_VER="${CRS_VER:-v4.7.0}"

need_root() { [ "$(id -u)" = 0 ] || { echo "sudo 로 실행하세요"; exit 1; }; }
need_root

echo "== 0. 스왑 (t3.small 메모리로 빌드가 OOM 나는 것 방지)"
if ! swapon --show | grep -q .; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

echo "== 1. 빌드 의존성"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y git build-essential libpcre3-dev zlib1g-dev libssl-dev \
  libtool automake autoconf libxml2-dev libyajl-dev pkgconf libcurl4-openssl-dev \
  liblmdb-dev libgeoip-dev php8.1-fpm php8.1-sqlite3 sqlite3 curl gnupg

echo "== 2. libmodsecurity (v3)"
if [ ! -f /usr/local/modsecurity/lib/libmodsecurity.so ]; then
  cd /usr/local/src
  rm -rf ModSecurity
  git clone --depth 1 -b "$MODSEC_BRANCH" https://github.com/owasp-modsecurity/ModSecurity
  cd ModSecurity
  git submodule update --init --recursive
  ./build.sh && ./configure && make -j"$(nproc)" && make install
fi

echo "== 3. ModSecurity-nginx connector + nginx 소스"
cd /usr/local/src
[ -d ModSecurity-nginx ] || git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx
[ -f "nginx-${NGINX_VER}.tar.gz" ] || curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz"
rm -rf "nginx-${NGINX_VER}"
tar xf "nginx-${NGINX_VER}.tar.gz"
cd "nginx-${NGINX_VER}"
./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log \
  --pid-path=/run/nginx.pid --with-compat --with-http_ssl_module \
  --add-dynamic-module=../ModSecurity-nginx
make -j"$(nproc)" modules
make -j"$(nproc)"
make install
install -d /usr/lib/nginx/modules
install -m0644 objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

echo "== 4. OWASP CRS ${CRS_VER}"
install -d /etc/nginx/modsec/coreruleset
if [ ! -f /etc/nginx/modsec/coreruleset/crs-setup.conf ]; then
  cd /etc/nginx/modsec
  rm -rf coreruleset
  git clone --depth 1 -b "$CRS_VER" https://github.com/coreruleset/coreruleset
  cp coreruleset/crs-setup.conf.example coreruleset/crs-setup.conf
fi
# 업스트림 권장 modsecurity.conf (우리는 overrides.conf 로만 덮습니다)
[ -f /etc/nginx/modsec/modsecurity.conf ] || \
  cp /usr/local/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/ 2>/dev/null || true

echo "== 5. 우리 설정 파일 배치 (이 저장소)"
install -m0644 "$REPO_DIR/modsec/main.conf"      /etc/nginx/modsec/main.conf
install -m0644 "$REPO_DIR/modsec/overrides.conf" /etc/nginx/modsec/overrides.conf
install -m0644 "$REPO_DIR/nginx/log_format.conf" /etc/nginx/conf.d/log_format.conf
install -d /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets
install -m0644 "$REPO_DIR/nginx/portal.conf"     /etc/nginx/sites-available/portal
ln -sf /etc/nginx/sites-available/portal /etc/nginx/sites-enabled/portal
rm -f /etc/nginx/sites-enabled/default

# nginx.conf 에 modsec 모듈 load 와 sites-enabled include 가 없으면 넣습니다.
grep -q "ngx_http_modsecurity_module.so" /etc/nginx/nginx.conf || \
  sed -i '1i load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf
grep -q "sites-enabled" /etc/nginx/nginx.conf || \
  sed -i '/http {/a \    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf

: > /var/log/modsec_audit.json
chmod 0640 /var/log/modsec_audit.json

echo "== 6. 취약 포털 앱 + 미끼 + 더미 DB"
install -d /var/www/kisiyaho/pages
cp -r "$REPO_DIR/app/portal/." /var/www/kisiyaho/
install -d /var/www/kisiyaho-decoy/etc
cp "$REPO_DIR/decoy/etc/passwd" /var/www/kisiyaho-decoy/etc/passwd
chown -R www-data:www-data /var/www/kisiyaho /var/www/kisiyaho-decoy
install -m0644 "$REPO_DIR/app/portal.pool.conf" /etc/php/8.1/fpm/pool.d/portal.conf
bash "$REPO_DIR/app/seed.sh"

echo "== 7. systemd 유닛"
cat > /etc/systemd/system/nginx.service <<'UNIT'
[Unit]
Description=nginx (source build with ModSecurity)
After=network.target
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now php8.1-fpm
nginx -t
systemctl enable --now nginx
systemctl restart nginx

echo
echo "== 완료. 확인:"
echo "  curl -s localhost/portal/index.php?page=about | head"
echo "  curl -s 'localhost/../../../../etc/passwd'                 # WAF 가 잡는지"
echo "  tail -n1 /var/log/modsec_audit.json | python3 -m json.tool | head"
echo "  tail -n1 /var/log/nginx/access.log"
echo
echo "  그다음 Wazuh Agent: sudo bash $REPO_DIR/wazuh/install-agent.sh"
