"""Forward live analysis results to the red team runner (siem-redteam).

Flow when REDTEAM_AUTO_EVAL_ENABLED=true:

    LLM 분석 button -> /api/alerts/<id>/analyze (this backend)
      -> the same result, its evidence package and the hashes of both
         are posted to REDTEAM_RUNNER_URL + REDTEAM_JOBS_PATH, in the background
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

Runner contract, as the siem-redteam runner implements it (2026-10-01):
    GET  {REDTEAM_RUNNER_URL}/healthz            no token     -> 200
    POST {REDTEAM_RUNNER_URL}/v1/jobs            Bearer token -> 202 + the job
         body: build_job_payload(...); the runner requires all ten fields,
         request/hashes/evidence_bundle/result as objects, a 32-hex
         analysis_id, a live bundle and result.demo == false (4 MB limit).
         202 means accepted, not passed. The 24-character job id comes back
         as job_id, id, job.job_id and job.id.
    GET  {REDTEAM_RUNNER_URL}/v1/jobs/<job_id>   Bearer token -> status, results
The path is REDTEAM_JOBS_PATH (default /v1/jobs). The runner names jobs by its
own 24-character id, so the job id it returns is kept per analysis_id
(RedteamJobIndex) and /api/redteam/jobs/<analysis_id> looks it up.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows development
    fcntl = None  # type: ignore[assignment]

import requests

DEFAULT_JOBS_PATH = "/v1/jobs"
HEALTH_PATH = "/healthz"
JOBS_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9/_.-]{1,64}$")
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
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


def payload_problem(payload: dict[str, Any]) -> str | None:
    """What the runner would refuse, checked before the request is made."""
    if not ANALYSIS_ID_PATTERN.fullmatch(str(payload.get("analysis_id") or "")):
        return "analysis_id_not_32_hex"
    if not str(payload.get("alert_id") or "").strip():
        return "missing_alert_id"
    for key in ("request", "hashes", "evidence_bundle", "result"):
        if not isinstance(payload.get(key), dict):
            return f"{key}_not_object"
    if str(payload["evidence_bundle"].get("schema") or "") not in LIVE_SCHEMAS:
        return "bundle_not_live"
    if payload["result"].get("demo") is not False:
        return "demo_result"
    return None


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
    # The runner (2026-10-01) requires all ten fields; request, hashes,
    # evidence_bundle and result must be objects, result.demo must be false,
    # and analysis_id / alert_id / bundle_schema inside result must match.
    return {
        "schema": "hawki.redteam-job/v1",
        "analysis_id": analysis_id,
        "alert_id": alert_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tools": tools,
        "model": result.get("model"),
        "request": {"kind": "alert_analysis", "text": request_text},
        "hashes": {"prompt_sha256": prompt_sha256, "bundle_sha256": bundle_sha256},
        "evidence_bundle": bundle,
        "result": {
            **{
                key: result.get(key)
                for key in ("answer", "assessment", "assessment_review", "evidence", "queries", "actions", "generation")
            },
            "analysis_id": analysis_id,
            "alert_id": alert_id,
            "bundle_schema": str(bundle.get("schema") or ""),
            "demo": bool(result.get("demo")),
        },
    }


def jobs_path_or_default(value: str) -> str:
    path = str(value or "").strip().rstrip("/")
    return path if JOBS_PATH_PATTERN.fullmatch(path or "-") else DEFAULT_JOBS_PATH


def extract_job_id(body: Any) -> str | None:
    """The runner's id for a new job, from the shapes a 202 body tends to take."""
    if not isinstance(body, dict):
        return None
    candidates = [body.get("job_id"), body.get("id")]
    job = body.get("job")
    if isinstance(job, dict):
        candidates += [job.get("job_id"), job.get("id")]
    elif isinstance(job, str):
        candidates.append(job)
    for value in candidates:
        if isinstance(value, (str, int)) and JOB_ID_PATTERN.fullmatch(str(value)):
            return str(value)
    return None


class RedteamJobIndex:
    """analysis_id -> runner job_id, appended as jobs are accepted."""

    def __init__(self, path: Path):
        self.path = Path(path)

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fcntl is None:
            yield
            return
        with open(self.path.with_suffix(".lock"), "a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def record(self, *, analysis_id: str, job_id: str, alert_id: str = "") -> None:
        entry = {
            "analysis_id": str(analysis_id),
            "job_id": str(job_id),
            "alert_id": str(alert_id or "")[:200],
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock():
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def job_for(self, analysis_id: str) -> str | None:
        if not self.path.exists():
            return None
        found = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict) and entry.get("analysis_id") == analysis_id:
                    found = entry.get("job_id")
        return str(found) if found else None


def dispatch_in_background(
    *,
    runner_url: str,
    token: str,
    timeout: float,
    payload: dict[str, Any],
    on_done: Callable[[dict[str, Any]], None],
    jobs_path: str = DEFAULT_JOBS_PATH,
    start_thread: Callable[[threading.Thread], None] = lambda thread: thread.start(),
) -> None:
    """POST the job without holding up the analyst's response."""

    def run() -> None:
        outcome: dict[str, Any] = {"analysis_id": payload.get("analysis_id")}
        problem = payload_problem(payload)
        if problem:
            outcome.update(dispatched=False, error=f"not sent: {problem}")
            on_done(outcome)
            return
        try:
            response = requests.post(
                runner_url.rstrip("/") + jobs_path_or_default(jobs_path),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
                timeout=timeout,
            )
            outcome["status_code"] = response.status_code
            outcome["dispatched"] = 200 <= response.status_code < 300
            try:
                job_id = extract_job_id(response.json())
                if job_id:
                    outcome["job_id"] = job_id
            except ValueError:
                pass
        except requests.RequestException as exc:
            outcome["dispatched"] = False
            outcome["error"] = str(exc)[:300]
        on_done(outcome)

    start_thread(threading.Thread(target=run, name="hawki-redteam-dispatch", daemon=True))


def fetch_job_status(
    *,
    runner_url: str,
    token: str,
    timeout: float,
    job_id: str,
    jobs_path: str = DEFAULT_JOBS_PATH,
) -> tuple[int, dict[str, Any]]:
    if not JOB_ID_PATTERN.fullmatch(str(job_id or "")):
        raise ValueError("Job ID is invalid.")
    response = requests.get(
        f"{runner_url.rstrip('/')}{jobs_path_or_default(jobs_path)}/{job_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text[:500]}
    return response.status_code, body if isinstance(body, dict) else {"data": body}


# The runner's tool states that count as a pass, and the job states that
# mean the runner has finished (same reading as static/redteam.js overall()).
TOOL_PASS_STATES = {"passed", "pass", "ok", "success", "succeeded", "completed", "complete", "done", "finished"}
TOOL_ERROR_STATES = {"error", "errored", "timeout"}
TOOL_RUNNING_STATES = {"running", "queued", "pending", "in_progress", "started"}


def runner_verdict(body: Any) -> str | None:
    """"passed", "failed" or "error" once the runner has a verdict, else None."""
    if not isinstance(body, dict):
        return None
    job = body.get("job") if isinstance(body.get("job"), dict) else body
    tools = job.get("tool_results") if isinstance(job.get("tool_results"), dict) else {}
    states = [str((value or {}).get("status") or "").lower() for value in tools.values() if isinstance(value, dict)]
    if not states:
        return None
    if "failed" in states:
        return "failed"
    if any(state in TOOL_ERROR_STATES for state in states):
        return "error"
    if any(state in TOOL_RUNNING_STATES or not state for state in states):
        return None
    if all(state in TOOL_PASS_STATES or state == "skipped" for state in states):
        return "passed"
    return None
