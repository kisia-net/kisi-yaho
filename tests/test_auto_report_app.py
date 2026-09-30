"""자동 보고서 routes: reading, reviewing, exporting, and who may do what."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
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
from hawki_alert_analysis.auto_report import AutoReportSettings, ReportStore  # noqa: E402


class AutoReportRouteTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.store = ReportStore(Path(self.dir.name))
        patches = [
            mock.patch.object(app, "AUTO_REPORT_STORE", self.store),
            mock.patch.object(app, "AUTO_REPORT_SETTINGS", AutoReportSettings(enabled=True, lookback_seconds=7 * 86400)),
            mock.patch.dict(app.CONFIG, {"llm_base_url": "http://127.0.0.1:9/v1",
                                         "llm_api_url": "http://127.0.0.1:9/v1/chat/completions"}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

        # Fixture alerts are from August; read them all, with the model off.
        reporter = app.build_auto_reporter()
        reporter.run_cycle(lookback_seconds=365 * 86400)
        self.reports = self.store.all()

        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"

    def post(self, url, body):
        return self.client.post(url, json=body, headers={"X-CSRF-Token": "test-token"})

    def test_fixture_run_writes_reports_that_wait_for_the_model(self):
        self.assertTrue(self.reports)
        for report in self.reports:
            self.assertIn(report["priority"]["band"], ("P1", "P2"))
            self.assertEqual(report["ai"]["status"], "pending")
            self.assertEqual(report["ai"]["waiting_reason"], "model_unavailable")

    def test_list_and_counts(self):
        body = self.client.get("/api/auto-reports").get_json()
        self.assertEqual(body["counts"]["total"], len(self.reports))
        self.assertEqual(body["counts"]["unreviewed"], len(self.reports))
        self.assertTrue(body["settings"]["enabled"])
        self.assertTrue(body["worker"]["running"])
        only_p2 = self.client.get("/api/auto-reports?band=P2").get_json()["reports"]
        self.assertTrue(all(item["priority"]["band"] == "P2" for item in only_p2))

    def test_detail_and_unknown_ids(self):
        report_id = self.reports[0]["id"]
        self.assertEqual(self.client.get(f"/api/auto-reports/{report_id}").get_json()["report"]["id"], report_id)
        missing = self.client.get("/api/auto-reports/AR-20260101-abcdef")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.get_json()["error"], "보고서를 찾을 수 없습니다.")
        self.assertEqual(self.client.get("/api/auto-reports/..%2F..%2Fstate").status_code, 404)

    def test_review_is_saved_and_audited(self):
        report_id = self.reports[0]["id"]
        response = self.post(f"/api/auto-reports/{report_id}/review", {"status": "confirmed", "note": "IP 차단 필요"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.get(report_id)["review"]["status"], "confirmed")
        self.assertEqual(self.store.get(report_id)["review"]["reviewer"], os.environ["HAWKI_ADMIN_USERNAME"])
        audit = [json.loads(line) for line in Path(os.environ["AUDIT_LOG_PATH"]).read_text(encoding="utf-8").splitlines()]
        self.assertIn("auto_report_reviewed", [record["event_type"] for record in audit])
        self.assertIn("auto_report_created", [record["event_type"] for record in audit])
        created = next(record for record in audit if record["event_type"] == "auto_report_created")
        self.assertEqual(created["actor"]["username"], "hawki-auto")

    def test_review_rejects_unknown_status_and_missing_csrf(self):
        report_id = self.reports[0]["id"]
        bad = self.post(f"/api/auto-reports/{report_id}/review", {"status": "deleted"})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()["error"], "검토 상태 값이 올바르지 않습니다.")
        no_token = self.client.post(f"/api/auto-reports/{report_id}/review", json={"status": "confirmed"})
        self.assertEqual(no_token.status_code, 400)
        self.assertIn("CSRF", no_token.get_json()["error"])

    def test_markdown_download(self):
        report_id = self.reports[0]["id"]
        response = self.client.get(f"/api/auto-reports/{report_id}/markdown")
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'filename="{report_id}.md"', response.headers["Content-Disposition"])
        self.assertIn("AI 초안 · 분석가 검토 필요", response.get_data(as_text=True))

    def test_run_now_is_refused_while_disabled(self):
        with mock.patch.object(app, "AUTO_REPORT_SETTINGS", AutoReportSettings(enabled=False)):
            response = self.post("/api/auto-reports/run", {})
        self.assertEqual(response.status_code, 409)

    def test_page_and_login(self):
        page = self.client.get("/auto-reports")
        self.assertEqual(page.status_code, 200)
        self.assertIn("auto_reports.js", page.get_data(as_text=True))
        anonymous = app.app.test_client()
        self.assertEqual(anonymous.get("/api/auto-reports").status_code, 401)

    def test_model_errors_are_sorted_by_cause(self):
        import requests
        from hawki_alert_analysis.auto_report import ModelUnavailable

        bundle = {"schema": "hawki.wazuh.live-evidence/v2"}

        def http_error(status):
            response = requests.Response()
            response.status_code = status
            return requests.HTTPError(f"{status}", response=response)

        with mock.patch.object(app, "call_llm", side_effect=requests.ConnectionError("refused")):
            with self.assertRaises(ModelUnavailable):
                app.auto_analyze(bundle, {"id": "a1"})
        with mock.patch.object(app, "call_llm", side_effect=http_error(503)):
            with self.assertRaises(ModelUnavailable):
                app.auto_analyze(bundle, {"id": "a1"})
        # Over the context length: this report's problem, not the model's.
        with mock.patch.object(app, "call_llm", side_effect=http_error(400)):
            with self.assertRaises(requests.HTTPError):
                app.auto_analyze(bundle, {"id": "a1"})

    def test_no_action_was_queued(self):
        queue = Path(os.environ["ACTION_QUEUE_PATH"])
        records = queue.read_text(encoding="utf-8").splitlines() if queue.exists() else []
        self.assertFalse([line for line in records if "auto_report" in line])


if __name__ == "__main__":
    unittest.main()
