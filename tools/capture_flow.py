#!/usr/bin/env python3
"""경보의 데이터 흐름 캡처를 결과 자료로 내려받습니다 (JSON + Markdown).

HAW-KI 에 로그인해 /api/alerts/<id>/flow 와 /flow.md 를 받습니다. 화면과 같은
내용이고, 실제 시스템에서 돌리면 실제 데이터로 결과 자료가 만들어집니다.

    # 경보 id 를 직접 지정
    python tools/capture_flow.py --alert 044599dada071c0c7803

    # 최근 24시간 공격 경보 중 우선순위가 높은 3건
    python tools/capture_flow.py --top 3

    # 분석을 실행한 캡처가 아니라 지금 다시 만든 흐름 (AI 단계 제외)
    python tools/capture_flow.py --alert <id> --view live

접속 정보는 환경 변수로 받습니다: HAWKI_URL (기본 http://127.0.0.1:5000),
HAWKI_ADMIN_USERNAME, HAWKI_ADMIN_PASSWORD. 결과는 --out (기본
data/flow_exports/) 아래 경보마다 flow-<id>.json, flow-<id>.md 로 남습니다.
AI 단계(⑤ ⑥)는 그 경보를 화면에서 "LLM으로 분석"한 적이 있어야 채워집니다.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests


def login(base: str, username: str, password: str, verify: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify
    page = session.get(f"{base}/login", timeout=20)
    page.raise_for_status()
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    if not match:
        raise SystemExit("로그인 화면에서 CSRF 토큰을 찾지 못했습니다. HAWKI_URL 을 확인하세요.")
    response = session.post(
        f"{base}/login",
        data={"username": username, "password": password, "csrf_token": match.group(1)},
        timeout=20,
    )
    response.raise_for_status()
    if session.get(f"{base}/api/auth/me", timeout=20).status_code != 200:
        raise SystemExit("로그인하지 못했습니다. HAWKI_ADMIN_USERNAME / HAWKI_ADMIN_PASSWORD 를 확인하세요.")
    return session


def top_alerts(session: requests.Session, base: str, count: int) -> list[str]:
    response = session.get(f"{base}/api/alerts", params={"category": "attack", "range": "24h", "sort": "priority"}, timeout=60)
    response.raise_for_status()
    body = response.json()
    items = body.get("alerts") if isinstance(body, dict) else body
    return [str(item.get("id")) for item in (items or []) if item.get("id")][:count]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--alert", action="append", default=[], help="경보 id (여러 번 지정 가능)")
    parser.add_argument("--top", type=int, default=0, help="최근 24시간 우선순위 상위 N건")
    parser.add_argument("--view", default="", help="live 또는 캡처 id. 비우면 가장 최근 캡처")
    parser.add_argument("--out", default="data/flow_exports", help="결과를 쓸 폴더")
    parser.add_argument("--insecure", action="store_true", help="HTTPS 인증서를 확인하지 않음 (자체 서명 인증서)")
    args = parser.parse_args()

    base = os.getenv("HAWKI_URL", "http://127.0.0.1:5000").rstrip("/")
    username = os.getenv("HAWKI_ADMIN_USERNAME", "")
    password = os.getenv("HAWKI_ADMIN_PASSWORD", "")
    if not username or not password:
        print("HAWKI_ADMIN_USERNAME 과 HAWKI_ADMIN_PASSWORD 가 필요합니다.", file=sys.stderr)
        return 2
    session = login(base, username, password, verify=not args.insecure)

    alert_ids = list(args.alert)
    if args.top:
        alert_ids += [alert_id for alert_id in top_alerts(session, base, args.top) if alert_id not in alert_ids]
    if not alert_ids:
        print("--alert 또는 --top 을 지정하세요.", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    params = {"view": args.view} if args.view else {}
    failed = 0
    for alert_id in alert_ids:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", alert_id)[:60]
        response = session.get(f"{base}/api/alerts/{alert_id}/flow", params=params, timeout=120)
        if response.status_code != 200:
            failed += 1
            print(f"{alert_id}: 실패 {response.status_code} {response.text[:200]}", file=sys.stderr)
            continue
        doc = response.json()
        (out / f"flow-{safe}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        markdown = session.get(f"{base}/api/alerts/{alert_id}/flow.md", params=params, timeout=120)
        markdown.raise_for_status()
        (out / f"flow-{safe}.md").write_text(markdown.text, encoding="utf-8")
        counts = doc.get("counts") or {}
        print(f"{alert_id}: {doc.get('mode')} · 원본 {counts.get('raw')}줄 → 경보 {counts.get('alert')}건 → "
              f"증거 {counts.get('evidence')}건 → AI 인용 {counts.get('ai_judgment') if counts.get('ai_judgment') is not None else '없음'}"
              f" · {out / f'flow-{safe}.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
