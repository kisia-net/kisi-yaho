"""Forward live analysis results to the red team runner (siem-redteam).

Flow when REDTEAM_AUTO_EVAL_ENABLED=true:

    LLM 분석 button -> /api/alerts/<id>/analyze (this backend)
      -> the same result, its evidence package and the hashes of both
         are posted to REDTEAM_RUNNER_URL + JOBS_PATH, in the background
      -> the runner stores it and starts the tools in REDTEAM_AUTO_TOOLS
      -> /api/redteam/jobs/<analysis_id> reads the job status back

Rules this module enforces, whatever the caller does:
- Only live Wazuh analyses are sent. Fixture and demo results never are.
- Nothing is sent without a token (REDTEAM_RUNNER_TOKEN); an empty token
  means "not connected yet", not "connect without authentication".
- A request that came from the runner itself (X-HAWKI-Redteam-Eval header)
  is never forwarded again, so an evaluation cannot trigger evaluations.
  The header can only suppress forwarding, never grant anything.
- Sending happens on a background thread with REDTEAM_RUNNER_TIMEOUT: the
  analyst's answer is never delayed or failed by the runner.
- Only tools in ALLOWED_TOOLS may be requested (promptfoo, garak).

Runner contract (confirm with the red team side; change JOBS_PATH here if it
differs):
    POST {REDTEAM_RUNNER_URL}/api/jobs          Authorization: Bearer <token>
         body: build_job_payload(...)            -> 2xx {"job_id": ...}
    GET  {REDTEAM_RUNNER_URL}/api/jobs/<analysis_id>
                                                 -> 200 {status, results...}
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import requests

JOBS_PATH = "/api/jobs"
RECURSION_HEADER = "X-HAWKI-Redteam-Eval"
ALLOWED_TOOLS = ("promptfoo", "garak")
ANALYSIS_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
LIVE_SCHEMAS = {"hawki.wazuh.live-evidence/v1", "hawki.wazuh.live-evidence/v2"}


def new_analysis_id() -> str:
    return uuid.uuid4().hex


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))


def parse_tools(raw: str) -> list[str]:
    tools = []
    for item in str(raw or "").split(","):
        name = item.strip().lower()
        if name in ALLOWED_TOOLS and name not in tools:
            tools.append(name)
    return tools


def forwarding_decision(
    *,
    enabled: bool,
    runner_url: str,
    token: str,
    tools: list[str],
    bundle_schema: str,
    demo: bool,
    from_runner: bool,
) -> str:
    """'send' or the reason it is not sent (recorded in the audit log)."""
    if not enabled:
        return "disabled"
    if from_runner:
        return "skipped_recursive_request"
    if bundle_schema not in LIVE_SCHEMAS:
        return "skipped_not_live"
    if demo:
        return "skipped_demo_result"
    if not runner_url:
        return "skipped_no_runner_url"
    if not token:
        return "skipped_no_token"
    if not tools:
        return "skipped_no_tools"
    return "send"


def build_job_payload(
    *,
    analysis_id: str,
    alert_id: str,
    request_text: str,
    prompt_sha256: str,
    bundle_sha256: str,
    bundle: dict[str, Any],
    result: dict[str, Any],
    tools: list[str],
) -> dict[str, Any]:
    return {
        "schema": "hawki.redteam-job/v1",
        "analysis_id": analysis_id,
        "alert_id": alert_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tools": tools,
        "model": result.get("model"),
        "request": request_text,
        "hashes": {"prompt_sha256": prompt_sha256, "bundle_sha256": bundle_sha256},
        "evidence_bundle": bundle,
        "result": {
            key: result.get(key)
            for key in ("answer", "assessment", "assessment_review", "evidence", "queries", "actions", "generation")
        },
    }


def dispatch_in_background(
    *,
    runner_url: str,
    token: str,
    timeout: float,
    payload: dict[str, Any],
    on_done: Callable[[dict[str, Any]], None],
    start_thread: Callable[[threading.Thread], None] = lambda thread: thread.start(),
) -> None:
    """POST the job without holding up the analyst's response."""

    def run() -> None:
        outcome: dict[str, Any] = {"analysis_id": payload.get("analysis_id")}
        try:
            response = requests.post(
                runner_url.rstrip("/") + JOBS_PATH,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
                timeout=timeout,
            )
            outcome["status_code"] = response.status_code
            outcome["dispatched"] = 200 <= response.status_code < 300
            try:
                body = response.json()
                if isinstance(body, dict) and body.get("job_id"):
                    outcome["job_id"] = str(body["job_id"])[:128]
            except ValueError:
                pass
        except requests.RequestException as exc:
            outcome["dispatched"] = False
            outcome["error"] = str(exc)[:300]
        on_done(outcome)

    start_thread(threading.Thread(target=run, name="hawki-redteam-dispatch", daemon=True))


def fetch_job_status(*, runner_url: str, token: str, timeout: float, analysis_id: str) -> tuple[int, dict[str, Any]]:
    response = requests.get(
        f"{runner_url.rstrip('/')}{JOBS_PATH}/{analysis_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text[:500]}
    return response.status_code, body if isinstance(body, dict) else {"data": body}
