"""Small Frontend proxy for separately launched, authenticated deep scans.

Registration reuses HAW-KI's analyst decorator and global CSRF middleware.
No runner token is exposed to browser JavaScript or response JSON.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import requests
from flask import jsonify, request

SCAN_ID = re.compile(r"^[a-f0-9]{24}$")
ALERT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
FIXTURE_ID = re.compile(r"^evt-[a-f0-9]{16}$", re.IGNORECASE)
STATES = {"queued", "running", "completed", "blocked", "error"}
RUNNER_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{32,200}$")


def safe_counter(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("Invalid scan counts.")
    return value


def public_probes(rows, tool, counts):
    """Standalone Frontend whitelist: no runner imports or raw response data."""
    if not isinstance(rows, list) or len(rows) > 5000:
        raise ValueError("Invalid scan probe list.")
    result = []
    for row in rows:
        if not isinstance(row, dict) or row.get("tool", tool) != tool:
            raise ValueError("Invalid scan probe tool.")
        name = row.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("Invalid scan probe name.")
        counters = {key: safe_counter(row.get(key, 0)) for key in ("passed", "total", "unscored")}
        counters["hits"] = safe_counter(row.get("hits", counters["total"] - counters["passed"]))
        if counters["passed"] + counters["hits"] != counters["total"]:
            raise ValueError("Inconsistent scan probe counts.")
        status = "failed" if counters["hits"] else "unscored" if counters["unscored"] or not counters["total"] else "passed"
        if row.get("status") == "error" and not counters["total"] and counters["unscored"]:
            status = "error"
        elif "status" in row and row["status"] != status:
            raise ValueError("Inconsistent scan probe status.")
        probe = {"tool": tool, "name": name, **counters, "status": status}
        if "detector" in row:
            detector = row["detector"]
            if not isinstance(detector, str) or not detector.strip() or len(detector) > 120:
                raise ValueError("Invalid scan detector name.")
            probe["detector"] = detector
        result.append(probe)
    for key in ("passed", "total", "hits", "unscored"):
        actual = sum(row[key] for row in result)
        if (actual > counts[key] if key == "unscored" else actual != counts[key]):
            raise ValueError("Scan probe list disagrees with tool counts.")
    return result


def public_security_metrics(value):
    """Forward aggregates only; recompute rates from validated denominators."""
    if not isinstance(value, dict):
        raise ValueError("Invalid security metrics.")
    result = {key: safe_counter(value.get(key, 0)) for key in (
        "attack_attempted", "attack_evaluated", "attack_goal_hits",
        "control_evaluated", "control_failures",
    )}
    if (result["attack_goal_hits"] > result["attack_evaluated"]
            or result["attack_evaluated"] > result["attack_attempted"]
            or result["control_failures"] > result["control_evaluated"]):
        raise ValueError("Inconsistent security denominators.")
    counts = value.get("counts") or {}
    result["counts"] = {key: safe_counter(counts.get(key, 0)) for key in (
        "passed", "attack_goal_hit", "quality_failure", "diagnostic_warning", "error", "unscored",
    )}
    for key, numerator, denominator in (
        ("attack_goal_hit_rate", "attack_goal_hits", "attack_evaluated"),
        ("attack_evaluation_coverage", "attack_evaluated", "attack_attempted"),
        ("control_failure_rate", "control_failures", "control_evaluated"),
    ):
        result[key] = result[numerator] / result[denominator] if result[denominator] else None
    result["basis"] = "deterministic_assertions_not_human_adjudication"
    return result


def runner_configuration(config) -> tuple[str, str]:
    """Read the snapshot's existing CONFIG without changing automatic tools.

    The snapshot already stores redteam_auto_tools as a list. Deep scans use
    their own fixed tools and must not rewrite that per-analysis setting.
    """
    url = str(config.get("redteam_runner_url") or "").strip().rstrip("/")
    token = str(config.get("redteam_runner_token") or "").strip()
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in url)
    ):
        raise ValueError("Invalid runner base URL.")
    # Reading port also rejects malformed/out-of-range configured ports.
    parsed.port
    if not RUNNER_TOKEN.fullmatch(token):
        raise ValueError("Invalid runner token.")
    return url, token


def public_scan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != "hawki.deep-scan/v1":
        raise ValueError("Invalid scan schema.")
    if not SCAN_ID.fullmatch(str(value.get("scan_id") or "")):
        raise ValueError("Invalid scan ID.")
    if value.get("status") not in STATES:
        raise ValueError("Invalid scan status.")
    if not ALERT_ID.fullmatch(str(value.get("alert_id") or "")) or FIXTURE_ID.fullmatch(value["alert_id"]):
        raise ValueError("Invalid live alert ID.")
    result = {key: value.get(key) for key in (
        "schema", "scan_id", "status", "alert_id", "tool", "created_at",
        "started_at", "finished_at", "model",
    )}
    result["summary"] = str(value.get("summary") or "")[:1000]
    if value.get("validation_scope") == "restart_subset":
        result["validation_scope"] = "restart_subset"
    result["tools"] = {}
    result["probes"] = []
    for tool in ("promptfoo", "garak"):
        item = (value.get("tools") or {}).get(tool)
        if not isinstance(item, dict):
            continue
        counts = item.get("counts") or {}
        safe_counts = {}
        for key in ("passed", "total", "hits", "errors", "unscored"):
            count = counts.get(key, 0)
            safe_counts[key] = safe_counter(count)
        if safe_counts["passed"] + safe_counts["hits"] != safe_counts["total"]:
            raise ValueError("Inconsistent scan counts.")
        result["tools"][tool] = {
            "status": str(item.get("status") or "pending")[:30],
            "counts": safe_counts,
            "failure_summary": str(item.get("failure_summary") or "")[:600],
            "error_summary": str(item.get("error_summary") or "")[:600],
        }
        public = result["tools"][tool]
        rows = item.get("probes")
        if "probes" not in item:
            legacy = value.get("probes", [])
            if not isinstance(legacy, list):
                raise ValueError("Invalid scan probe list.")
            rows = [row for row in legacy if isinstance(row, dict) and row.get("tool") == tool]
        if rows or "probes" in item:
            public["probes"] = public_probes(rows, tool, safe_counts)
            result["probes"].extend(public["probes"])
        if item.get("grading_source") == "offline_replay_of_original_received_responses":
            public["grading_source"] = "offline_replay_of_original_received_responses"
        if isinstance(item.get("process_exit_verified"), bool):
            public["process_exit_verified"] = item["process_exit_verified"]
        if item.get("count_unit") in {"test_cases", "probe_detector_evaluations"}:
            public["count_unit"] = item["count_unit"]
        if item.get("evaluation_coverage") == "not_evaluated":
            public["evaluation_coverage"] = "not_evaluated"
        if tool == "promptfoo" and "security_evaluation" in item:
            public["security_evaluation"] = public_security_metrics(item["security_evaluation"])
        if tool == "garak" and isinstance(item.get("response_audit"), dict):
            audit = {key: safe_counter(item["response_audit"].get(key, 0))
                     for key in ("received", "structured", "malformed_or_missing")}
            if audit["structured"] + audit["malformed_or_missing"] != audit["received"]:
                raise ValueError("Inconsistent response audit.")
            public["response_audit"] = audit
        if tool == "promptfoo" and isinstance(item.get("request_audit"), dict):
            source = item["request_audit"]
            if source.get("status") in {"not_available", "invalid"}:
                public["request_audit"] = {"status": source["status"]}
            else:
                audit = {key: safe_counter(source.get(key, 0))
                         for key in ("sent", "received", "skipped", "retries")}
                if audit["received"] > audit["sent"] or audit["retries"] != 0:
                    raise ValueError("Inconsistent bounded request audit.")
                public["request_audit"] = audit
    # Raw prompts, model responses, cookies, headers and filesystem paths are
    # intentionally not forwarded even if an upstream includes them.
    return result


def register_redteam_scan_routes(app, *, configuration, role_required, live_enabled, audit=None):
    def proxy(method: str, suffix: str, payload=None, expected_id=None):
        try:
            url, token = configuration()
            response = requests.request(
                method, url + suffix,
                headers={"Authorization": "Bearer " + token},
                json=payload if method == "POST" else None,
                timeout=5,
                allow_redirects=False,
            )
            if response.status_code == 404:
                # Old runners return 404 for the whole scans API. Do not turn
                # that into 'no results' and enable a model-affecting button.
                body = response.json()
                known_absent = {"No deep scan is available.", "Deep scan not found."}
                if method == "GET" and isinstance(body, dict) and body.get("error") in known_absent:
                    return jsonify({"error": "No deep scan result is available."}), 404
                return jsonify({"error": "The runner's deep-scan API is unavailable. Update the runner before retrying."}), 502
            if response.status_code == 409:
                body = response.json()
                conflict = {"error": "Another deep scan is active; wait for it to finish."}
                if isinstance(body, dict) and body.get("scan"):
                    conflict["scan"] = public_scan(body["scan"])
                return jsonify(conflict), 409
            if response.status_code not in (200, 202):
                return jsonify({"error": "The deep-scan runner could not accept or serve this request."}), 502
            scan = public_scan(response.json())
            if expected_id and scan["scan_id"] != expected_id:
                raise ValueError("Scan ID mismatch.")
            if method == "POST" and (response.status_code != 202 or scan["alert_id"] != payload["alert_id"]):
                raise ValueError("Scan submission mismatch.")
            reply = jsonify(scan)
            reply.headers["Cache-Control"] = "no-store"
            return reply, response.status_code
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            # Do not echo requests exceptions: they may contain secret headers
            # or an upstream response with credentials.
            return jsonify({"error": "The deep-scan runner is unavailable or returned an invalid result."}), 502

    @app.post("/api/redteam/scans")
    @role_required("analyst")
    def api_redteam_scan_start():
        if not live_enabled():
            return jsonify({"error": "Deep scans require live Wazuh mode with demo mode disabled."}), 409
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {"alert_id", "tools"}:
            return jsonify({"error": "Only alert_id and the fixed tools are accepted."}), 400
        alert_id = payload.get("alert_id")
        if not isinstance(alert_id, str) or not ALERT_ID.fullmatch(alert_id) or FIXTURE_ID.fullmatch(alert_id):
            return jsonify({"error": "Select a real Wazuh alert ID."}), 400
        if payload.get("tools", ["promptfoo", "garak"]) != ["promptfoo", "garak"]:
            return jsonify({"error": "This button runs the fixed Promptfoo and garak scan."}), 400
        reply, status = proxy("POST", "/v1/scans", {"alert_id": alert_id, "tools": ["promptfoo", "garak"]})
        if audit is not None:
            # A deep scan calls the model through HAW-KI's analysis API, so who
            # launched it, on which alert, and what the runner answered is
            # recorded like any other model-affecting request.
            body = reply.get_json(silent=True) or {}
            audit("redteam_deep_scan_requested", {
                "alert_id": alert_id,
                "status_code": status,
                "scan_id": body.get("scan_id") if status == 202 else None,
                "tools": ["promptfoo", "garak"],
            })
        return reply, status

    @app.get("/api/redteam/scans/latest")
    @role_required("analyst")
    def api_redteam_scan_latest():
        return proxy("GET", "/v1/scans/latest")

    @app.get("/api/redteam/scans/<scan_id>")
    @role_required("analyst")
    def api_redteam_scan_status(scan_id):
        if not SCAN_ID.fullmatch(scan_id):
            return jsonify({"error": "Invalid scan ID."}), 400
        return proxy("GET", "/v1/scans/" + scan_id, expected_id=scan_id)
