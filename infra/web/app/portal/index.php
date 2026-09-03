<?php
/* =============================================================================
 * index.php — 일부러 취약하게 만든 포털 (실습 전용)
 * =============================================================================
 *
 *  ★ 이 파일은 의도적으로 취약합니다 ★
 *    LFI(로컬 파일 포함) 취약점을 일부러 남겨두었습니다. 공격이 성공해야
 *    "WAF 가 탐지했는데 웹서버가 200 을 돌려줬다" 는 사례가 만들어지고,
 *    그게 경보 룰 3번이 존재하는 이유이기 때문입니다.
 *
 *    대신 봉쇄는 PHP-FPM 풀의 open_basedir 로 겁니다(infra/web/app/portal.pool.conf).
 *    허용 경로 밖으로 나가는 traversal 은 404 가 되고, 안쪽의 미끼 트리
 *    (/var/www/kisiyaho-decoy)로 가는 traversal 만 200 이 됩니다.
 *    즉 공격은 "성공한 것처럼" 보이지만 실제로 새는 것은 가짜 파일뿐입니다.
 *
 *    이 서버에 진짜 개인정보나 팀 비밀값을 두지 마십시오.
 *    (infra/terraform/security_servers.tf 의 전체개방 조건 3번)
 */

$page = isset($_GET['page']) ? (string) $_GET['page'] : 'home';
$path = __DIR__ . '/pages/' . $page;   // ← 취약: 사용자 입력을 경로에 그대로 붙임

header('Content-Type: text/html; charset=utf-8');
echo "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">";
echo "<title>Kisiyaho Portal</title></head><body>";
echo "<h1>Kisiyaho Portal</h1>";
echo "<nav><a href=\"/portal/index.php?page=home\">home</a> · ";
echo "<a href=\"/portal/index.php?page=about\">about</a> · ";
echo "<a href=\"/portal/index.php?page=notice\">notice</a> · ";
echo "<a href=\"/portal/login\">login</a></nav><hr>";

if (!is_file($path) || !is_readable($path)) {
    http_response_code(404);
    echo "<p>page not found: " . htmlspecialchars($page, ENT_QUOTES) . "</p>";
} else {
    echo "<pre>";
    readfile($path);
    echo "</pre>";
}

echo "</body></html>";
