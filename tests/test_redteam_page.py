"""레드팀 검증 화면 and LLM analysis as a background job."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

_WORKDIR = tempfile.mkdtemp(prefix="hawki-tests-")
os.environ.setdefault("FLASK_SECRET_KEY", "t" * 48)
os.environ.setdefault("AUTH_DATABASE_PATH", str(Path(_WORKDIR) / "auth.db"))
os.environ.setdefault("ACTION_QUEUE_PATH", str(Path(_WORKDIR) / "actions.jsonl"))
os.environ.setdefault("AUDIT_LOG_PATH", str(Path(_WORKDIR) / "audit.jsonl"))
os.environ.setdefault("HAWKI_ADMIN_USERNAME", "analyst")
os.environ.setdefault("HAWKI_ADMIN_PASSWORD", "Str0ng-Passw0rd-Value!")
os.environ.setdefault("WAZUH_API_URL", "https://127.0.0.1:55000")
os.environ.setdefault("WAZUH_API_USERNAME", "test")
os.environ.setdefault("WAZUH_API_PASSWORD", "test")

import app  # noqa: E402
from hawki_alert_analysis.redteam_bridge import runner_summary  # noqa: E402


class SignedIn(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.audit = Path(self.dir.name) / "audit.jsonl"
        for target, value in (("AUDIT_LOG_PATH", self.audit),
                              ("ANALYSIS_JOB_ROOT", Path(self.dir.name) / "jobs"),
                              ("LAST_ANALYSIS_ROOT", Path(self.dir.name) / "last")):
            patcher = mock.patch.object(app, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(app.REDTEAM_VERDICTS, {}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"

    def write_audit(self, *records):
        now = datetime.now(timezone.utc)
        with self.audit.open("a", encoding="utf-8") as handle:
            for minutes_ago, kind, detail, actor in records:
                record = {"timestamp": (now - timedelta(minutes=minutes_ago)).isoformat(), "event_type": kind, "detail": detail}
                if actor:
                    record["actor"] = {"username": actor}
                handle.write(json.dumps(record) + "\n")


class EvaluationListTests(SignedIn):
    def setUp(self):
        super().setUp()
        self.a, self.b, self.c, self.d = ("a" * 32, "b" * 32, "c" * 32, "d" * 32)
        self.write_audit(
            (50, "alert_analysis_completed", {"analysis_id": self.a, "alert_id": "al-1", "redteam": "send",
                                              "served_model": "/models/hub/models--Qwen--Qwen3.5-27B-FP8/x"}, "analyst"),
            (49, "redteam_eval_dispatched", {"analysis_id": self.a, "dispatched": True, "job_id": "1" * 24}, None),
            (40, "auto_report_analyzed", {"analysis_id": self.b, "alert_id": "al-2", "report_id": "AR-20261011-abcdef",
                                          "redteam": "send"}, "hawki-auto"),
            (39, "redteam_eval_dispatched", {"analysis_id": self.b, "dispatched": True, "job_id": "2" * 24}, None),
            (30, "auto_report_analyzed", {"analysis_id": self.c, "alert_id": "al-3", "redteam": "not_sent"}, "hawki-auto"),
            (20, "alert_analysis_completed", {"analysis_id": self.d, "alert_id": "al-4",
                                              "redteam": "skipped_recursive_request"}, "analyst"),
        )
        app.remember_redteam_verdict(self.a, runner_summary({"job": {"tool_results": {"promptfoo": {
            "status": "failed", "failures": [{"assertion": "EvidenceIdsInBundle", "reason": "x"}]}}}}))

    def get(self, **params):
        with mock.patch.dict(app.CONFIG, {"redteam_runner_url": "", "redteam_runner_token": ""}):
            response = self.client.get("/api/redteam/evaluations", query_string=params)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_rows_link_to_alert_and_report_with_their_outcome(self):
        data = self.get(range="24h")
        rows = {row["analysis_id"]: row for row in data["evaluations"]}
        self.assertEqual([row["analysis_id"] for row in data["evaluations"]], [self.d, self.c, self.b, self.a])
        self.assertEqual(rows[self.a]["status"], "failed")
        self.assertEqual(rows[self.a]["failed_checks"], ["EvidenceIdsInBundle"])
        self.assertEqual(rows[self.a]["kind"], "manual")
        self.assertEqual(rows[self.b]["status"], "checking")
        self.assertEqual(rows[self.b]["report_id"], "AR-20261011-abcdef")
        self.assertEqual(rows[self.c]["status"], "not_sent")
        self.assertEqual(rows[self.d]["kind"], "deep")

    def test_summary_leaves_out_deep_scan_analyses(self):
        data = self.get(range="24h")
        self.assertEqual(data["summary"]["total"], 3)
        self.assertEqual(data["summary"]["failed"], 1)
        self.assertEqual(data["failing_checks"], [["EvidenceIdsInBundle", 1]])

    def test_filters(self):
        self.assertEqual([row["analysis_id"] for row in self.get(status="failed")["evaluations"]], [self.a])
        self.assertEqual({row["kind"] for row in self.get(kind="auto")["evaluations"]}, {"auto"})
        self.assertEqual(self.client.get("/api/redteam/evaluations?status=nope").status_code, 400)

    def test_page_and_menu(self):
        page = self.client.get("/redteam")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn("data-rt-list", html)
        self.assertIn("data-redteam-scan-card", html)  # deep scan lives here now
        dashboard = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("data-redteam-scan-card", dashboard)
        self.assertIn('href="/redteam"', dashboard)

    def test_dashboard_recent_list_carries_the_verdict(self):
        with mock.patch.dict(app.CONFIG, {"redteam_runner_url": "", "redteam_runner_token": ""}):
            items = self.client.get("/api/redteam/recent").get_json()["items"]
        verdicts = {item["analysis_id"]: item["verdict"] for item in items}
        self.assertEqual(verdicts[self.a], "failed")
        self.assertIsNone(verdicts[self.b])


class Immediate:
    """threading.Thread stand-in that runs the target at start()."""

    def __init__(self, target=None, args=(), kwargs=None, **_):
        self.target, self.args, self.kwargs = target, args, kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)


class AnalysisJobTests(SignedIn):
    def post(self, url):
        return self.client.post(url, json={}, headers={"X-CSRF-Token": "test-token"})

    def alert_id(self):
        return app.ALERT_ANALYSIS.list_alerts()[0]["id"]

    def test_a_job_runs_and_its_answer_is_kept_for_the_alert(self):
        alert_id = self.alert_id()
        reply = {"answer": "판단", "model": "hawki-local", "demo": False, "evidence": [], "queries": [], "actions": []}
        with mock.patch.object(app, "call_llm", return_value=reply), \
             mock.patch.object(app.threading, "Thread", Immediate):
            started = self.post(f"/api/alerts/{alert_id}/analysis-jobs")
        self.assertEqual(started.status_code, 202)
        job = self.client.get(f"/api/analysis-jobs/{started.get_json()['id']}").get_json()
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"]["answer"], "판단")
        last = self.client.get(f"/api/alerts/{alert_id}/last-analysis").get_json()
        self.assertEqual(last["result"]["analysis_id"], job["result"]["analysis_id"])
        self.assertIsNone(last["running"])

    def test_a_second_click_joins_the_running_job(self):
        alert_id = self.alert_id()
        with mock.patch.object(app.threading, "Thread") as thread:
            first = self.post(f"/api/alerts/{alert_id}/analysis-jobs").get_json()
            second = self.post(f"/api/alerts/{alert_id}/analysis-jobs").get_json()
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(thread.call_count, 1)
        self.assertEqual(self.client.get(f"/api/alerts/{alert_id}/last-analysis").get_json()["running"]["id"], first["id"])

    def test_a_failed_analysis_is_reported_not_lost(self):
        alert_id = self.alert_id()
        with mock.patch.object(app, "call_llm", side_effect=ValueError("bad json")), \
             mock.patch.object(app.threading, "Thread", Immediate):
            started = self.post(f"/api/alerts/{alert_id}/analysis-jobs").get_json()
        job = self.client.get(f"/api/analysis-jobs/{started['id']}").get_json()
        self.assertEqual(job["status"], "error")
        self.assertIn("error", job["error"])

    def test_unknown_and_malformed_job_ids(self):
        self.assertEqual(self.client.get("/api/analysis-jobs/" + "f" * 24).status_code, 404)
        self.assertEqual(self.client.get("/api/analysis-jobs/../../etc").status_code, 404)

    def test_a_job_whose_worker_died_is_reported_as_stopped(self):
        app.ANALYSIS_JOB_ROOT.mkdir(parents=True, exist_ok=True)
        old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        (app.ANALYSIS_JOB_ROOT / ("e" * 24 + ".json")).write_text(json.dumps(
            {"id": "e" * 24, "alert_id": "x", "status": "running", "started_at": old}))
        self.assertEqual(self.client.get("/api/analysis-jobs/" + "e" * 24).get_json()["status"], "error")


if __name__ == "__main__":
    unittest.main()
