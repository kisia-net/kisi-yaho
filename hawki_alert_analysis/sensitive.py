"""Sensitive-target categories for searching alerts and reports (10주차 멘토링 5번).

An analyst searching for "credential" found nothing: attack logs say
"GET /.aws/credentials" or "GET /etc/passwd", and an LLM report says what it
says in its own words. Neither carries the analyst's category word.

Two things fix that, both deterministic and both outside the model:
- the alert search box knows each category's words, so "credential" or
  "자격증명" searches for the paths and file names that mean it;
- every automatic report keeps `facets`, a small structured record taken
  from the evidence package (requested paths and the categories they hit).
  That is the store people search; the model's free text is not parsed for
  it, and the model never reads it (search data and AI context kept apart,
  as the mentor suggested).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# key: (label, words an analyst may type, substrings that mean it in a path or log)
SENSITIVE_CATEGORIES: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "credential": (
        "자격증명·계정 정보",
        ("credential", "credentials", "password", "passwd", "자격증명", "비밀번호", "계정정보", "계정 정보"),
        ("passwd", "/etc/shadow", "credentials", "id_rsa", "id_ed25519", ".htpasswd", ".git-credentials",
         ".netrc", "password", ".pgpass", ".ssh/"),
    ),
    "secret_config": (
        "설정·비밀 파일",
        ("secret", "secrets", "config", ".env", "env", "설정파일", "설정 파일", "환경변수", "비밀키"),
        (".env", "wp-config", "config.php", "configuration.php", "settings.py", ".git/config", "docker-compose",
         ".npmrc", "application.properties", "appsettings.json", "secrets", ".aws/config", "web.config",
         "debug.log", ".amplifyrc"),
    ),
    "backup": (
        "백업·덤프 파일",
        ("backup", "dump", "백업", "덤프"),
        (".bak", ".backup", ".old", ".sql", ".tar.gz", ".tgz", ".zip", "dump", ".swp"),
    ),
    "admin_login": (
        "관리자·로그인 페이지",
        ("login", "admin", "wp-login", "로그인", "관리자"),
        ("wp-login", "/wp-admin", "/admin", "phpmyadmin", "/login", "xmlrpc.php", "/manager/html", "/user/login"),
    ),
    "traversal": (
        "경로 조작",
        ("traversal", "path traversal", "lfi", "경로조작", "경로 조작", "디렉터리 탐색"),
        ("../", "..%2f", "%2e%2e", "..\\", "/etc/passwd", "/proc/self"),
    ),
}

MAX_PATHS = 40
MAX_EXAMPLES = 5
_PATH = re.compile(r"(?:GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+(\S+)", re.IGNORECASE)


def category_for_query(text: str) -> str | None:
    """The category an analyst means by a search word, if any."""
    needle = str(text or "").strip().lower()
    if not needle:
        return None
    for key, (_, aliases, _) in SENSITIVE_CATEGORIES.items():
        if needle == key or needle in aliases:
            return key
    return None


def category_patterns(key: str) -> tuple[str, ...]:
    return SENSITIVE_CATEGORIES[key][2] if key in SENSITIVE_CATEGORIES else ()


def classify(values: Iterable[str]) -> dict[str, list[str]]:
    """Which categories these paths or log lines hit, with a few examples."""
    hits: dict[str, list[str]] = {}
    for value in values:
        text = str(value or "")
        lower = text.lower()
        if not lower:
            continue
        for key, (_, _, patterns) in SENSITIVE_CATEGORIES.items():
            if any(pattern in lower for pattern in patterns):
                examples = hits.setdefault(key, [])
                if text[:200] not in examples and len(examples) < MAX_EXAMPLES:
                    examples.append(text[:200])
    return hits


def _paths(items: Iterable[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        candidates = [data.get("url"), (data.get("http") or {}).get("url") if isinstance(data.get("http"), dict) else None]
        candidates += _PATH.findall(str(item.get("full_log") or ""))
        for value in candidates:
            value = str(value or "").strip()
            if value and value not in paths and len(paths) < MAX_PATHS:
                paths.append(value[:300])
    return paths


def report_facets(bundle: dict[str, Any] | None, alert: dict[str, Any] | None = None) -> dict[str, Any]:
    """The searchable record of a report, from its evidence package."""
    bundle = bundle if isinstance(bundle, dict) else {}
    items = [bundle.get("trigger") or {}, *(bundle.get("investigation_context") or [])]
    paths = _paths(items)
    texts = paths + [str((item or {}).get("full_log") or "")[:500] for item in items if isinstance(item, dict)]
    if alert:
        texts.append(str(alert.get("summary") or ""))
    sensitive = classify(texts)
    return {
        "schema": "hawki.report-facets/v1",
        "source": "evidence" if paths or bundle else "alert",
        "paths": paths,
        "sensitive": sensitive,
    }


def facets_from_alert(alert: dict[str, Any] | None) -> dict[str, Any]:
    """For reports made before facets existed: the alert's own summary only."""
    alert = alert if isinstance(alert, dict) else {}
    summary = str(alert.get("summary") or "")
    return {
        "schema": "hawki.report-facets/v1",
        "source": "alert",
        "paths": _PATH.findall(summary)[:MAX_PATHS],
        "sensitive": classify([summary, str(alert.get("title") or "")]),
    }
