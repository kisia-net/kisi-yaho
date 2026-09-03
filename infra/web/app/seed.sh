#!/usr/bin/env bash
# 더미 계정 DB 를 만듭니다. 전부 가짜입니다. 실제 계정 정보 금지.
set -euo pipefail

DB=/var/www/kisiyaho-data/portal.db
install -d -o www-data -g www-data -m 0750 /var/www/kisiyaho-data
rm -f "$DB"

sqlite3 "$DB" <<'SQL'
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, pass TEXT, role TEXT);
INSERT INTO users (name, pass, role) VALUES
  ('admin',   'Portal!admin2026', 'administrator'),
  ('jhkim',   'spring-2026-a',    'staff'),
  ('sylee',   'autumn-2026-b',    'staff'),
  ('guest',   'guest',            'read-only');
SQL

chown www-data:www-data "$DB"
chmod 0640 "$DB"
echo "seeded $DB"
sqlite3 "$DB" 'SELECT name, role FROM users;'
