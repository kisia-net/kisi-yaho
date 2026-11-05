"""처리 흐름: collection to analyst, counted over the last 24 hours."""

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
from hawki_alert_analysis.feedback import FeedbackStore  # noqa: E402
from hawki_alert_analysis.redteam_bridge import runner_verdict  # noqa: E402
from hawki_alert_analysis.wazuh import WazuhEventRepository  # noqa: E402


def job(*states):
    return {"job": {"status": "completed", "tool_results": {f"t{i}": {"status": s} for i, s in enumerate(states)}}}


class VerdictTests(unittest.TestCase):
    def test_runner_states_read_like_the_red_team_panel(self):
        self.assertEqual(runner_verdict(job("passed")), "passed")
        self.assertEqual(runner_verdict(job("passed", "failed")), "failed")
        self.assertEqual(runner_verdict(job("passed", "error")), "error")
        self.assertIsNone(runner_verdict(job("passed", "running")))
        self.assertIsNone(runner_verdict({"job_id": "x", "status": "running"}))
        self.assertEqual(runner_verdict({"tool_results": {"promptfoo": {"status": "passed"}}}), "passed")


class FlowCountTests(unittest.TestCase):
    def test_one_exact_window_and_a_minute_histogram(self):
        bodies = []

        class Client:
            def search(self, index, body):
                bodies.append((index, body))
                if body.get("aggs"):
                    return {"aggregations": {"per_minute": {"buckets": [
                        {"key_as_string": "2026-10-11T03:00:00Z", "doc_count": 4},
                        {"key_as_string": "2026-10-11T03:01:00Z", "doc_count": 9}]}}}
                return {"hits": {"total": {"value": 12, "relation": "eq"}}}

        end = datetime(2026, 10, 11, 3, 2, tzinfo=timezone.utc)
        counts = WazuhEventRepository(Client()).flow_counts(start=end - timedelta(hours=24), end=end)
        self.assertEqual((counts["raw_events"], counts["alerts"], counts["level_8_plus"]), (12, 12, 12))
        self.assertEqual([point["count"] for point in counts["per_minute"]], [4, 9])
        histogram = next(body for _, body in bodies if body.get("aggs"))
        self.assertEqual(histogram["aggs"]["per_minute"]["date_histogram"]["fixed_interval"], "1m")
        self.assertTrue(all("now-" not in json.dumps(body) for _, body in bodies))


class FlowRouteTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.audit = Path(self.dir.name) / "audit.jsonl"
        self.store = FeedbackStore(Path(self.dir.name) / "feedback.jsonl")
        for target, value in (("AUDIT_LOG_PATH", self.audit), ("FEEDBACK_STORE", self.store)):
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

    def write_audit(self, *records):
        now = datetime.now(timezone.utc)
        with self.audit.open("a", encoding="utf-8") as handle:
            for minutes_ago, kind, detail in records:
                handle.write(json.dumps({"timestamp": (now - timedelta(minutes=minutes_ago)).isoformat(),
                                         "event_type": kind, "detail": detail}) + "\n")

    def flow(self):
        with mock.patch.dict(app.CONFIG, {"redteam_runner_url": "", "redteam_runner_token": ""}):
            response = self.client.get("/api/dashboard/flow")
        self.assertEqual(response.status_code, 200)
        return {stage["id"]: stage for stage in response.get_json()["stages"]}

    def test_stages_are_in_order_and_link_to_their_lists(self):
        response = self.client.get("/api/dashboard/flow").get_json()
        self.assertEqual([stage["id"] for stage in response["stages"]],
                         ["raw", "alerts", "level8", "selected", "analysis", "redteam", "handled"])
        start = datetime.fromisoformat(response["window"]["start"])
        end = datetime.fromisoformat(response["window"]["end"])
        self.assertEqual(end - start, timedelta(hours=24))

    def test_analyses_and_red_team_outcomes_are_counted_from_the_audit_log(self):
        a, b, c, d = ("a" * 32, "b" * 32, "c" * 32, "d" * 32)
        self.write_audit(
            (30, "alert_analysis_completed", {"analysis_id": a, "redteam": "send"}),
            (29, "redteam_eval_dispatched", {"analysis_id": a, "dispatched": True, "job_id": "1" * 24}),
            (20, "auto_report_analyzed", {"analysis_id": b, "redteam": "send"}),
            (19, "redteam_eval_dispatched", {"analysis_id": b, "dispatched": False, "status_code": 400}),
            (10, "auto_report_analyzed", {"analysis_id": c, "redteam": "not_sent"}),
            (5, "alert_analysis_completed", {"analysis_id": d, "redteam": "skipped_recursive_request"}),
            (60 * 30, "alert_analysis_completed", {"analysis_id": "e" * 32, "redteam": "send"}),  # older than 24 h
        )
        app.REDTEAM_VERDICTS[a] = "passed"
        stages = self.flow()
        self.assertEqual(stages["analysis"]["count"], 3)
        self.assertEqual(stages["analysis"]["extra"]["deep_scan_calls"], 1)
        self.assertEqual(stages["redteam"]["count"], 2)
        self.assertEqual(stages["redteam"]["verdicts"]["passed"], 1)
        self.assertEqual(stages["redteam"]["verdicts"]["refused"], 1)
        self.assertEqual(stages["redteam"]["drop"]["reasons"], {"not_sent": 1})

    def test_settled_verdicts_count_as_handled(self):
        now = datetime.now(timezone.utc)
        for alert_id, verdict in (("x1", "false_positive"), ("x2", "confirmed"), ("x3", "investigating")):
            self.store.record(alert_id=alert_id, alert={}, verdict=verdict, note="", reviewer="analyst",
                              source="alert_analysis", now=now)
        stage = self.flow()["handled"]
        self.assertEqual(stage["count"], 2)
        self.assertIn("추가 조사 1건", stage["detail"])

    def test_unknown_verdicts_are_fetched_in_the_background_and_kept(self):
        calls = []

        def fetch(**kwargs):
            calls.append(kwargs["job_id"])
            return 200, job("failed")

        with mock.patch.object(app, "fetch_job_status", side_effect=fetch):
            app.refresh_redteam_verdicts([("f" * 32, "2" * 24)])
        self.assertEqual(calls, ["2" * 24])
        self.assertEqual(app.cached_verdict("f" * 32), "failed")


if __name__ == "__main__":
    unittest.main()
