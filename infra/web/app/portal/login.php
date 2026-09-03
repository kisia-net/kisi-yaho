<?php
/* =============================================================================
 * login.php — 일부러 취약하게 만든 로그인 (실습 전용)
 * =============================================================================
 *
 *  ★ SQL 문자열 결합을 일부러 남겨두었습니다 ★
 *    ' OR '1'='1' -- 로 인증이 통과합니다.
 *
 *  계정은 전부 가짜입니다(seed.sh). 실제 비밀번호를 절대 넣지 마십시오.
 *  DB 는 SQLite 파일 하나라, 망가지면 seed.sh 를 다시 돌리면 됩니다.
 *
 *  응답 코드가 중요합니다 — 상관분석이 보는 값이기 때문입니다.
 *    로그인 실패 401 · 성공 200 · GET(폼) 200
 *  brute force 시나리오의 "401 이 반복되다 한 번 200" 이 여기서 나옵니다.
 */

const DB_PATH = '/var/www/kisiyaho-data/portal.db';

header('Content-Type: text/html; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo '<!doctype html><meta charset="utf-8"><title>login</title>';
    echo '<h1>Portal Login</h1><form method="post" action="/portal/login">';
    echo '<input name="user" placeholder="user"> ';
    echo '<input name="pass" type="password" placeholder="password"> ';
    echo '<button>sign in</button></form>';
    exit;
}

$user = isset($_POST['user']) ? (string) $_POST['user'] : '';
$pass = isset($_POST['pass']) ? (string) $_POST['pass'] : '';

// ← 취약: 파라미터를 그대로 SQL 에 이어붙임
$sql = "SELECT id, name, role FROM users WHERE name = '$user' AND pass = '$pass'";

try {
    $db  = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    // 문법이 깨진 인젝션도 500 이 아니라 401 로 떨어뜨립니다.
    // 500 이 섞이면 "막힌 것" 인지 "터진 것" 인지 로그에서 구분이 안 됩니다.
    $row = false;
}

if ($row) {
    http_response_code(200);
    echo '<!doctype html><meta charset="utf-8"><title>welcome</title>';
    echo '<h1>signed in</h1><p>welcome, ' . htmlspecialchars((string) $row['name'], ENT_QUOTES) . '</p>';
    echo '<p>role: ' . htmlspecialchars((string) $row['role'], ENT_QUOTES) . '</p>';
} else {
    http_response_code(401);
    echo '<!doctype html><meta charset="utf-8"><title>denied</title>';
    echo '<h1>authentication failed</h1>';
}
