"""Feedback and explanation through the application routes."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections import defaultdict
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
from hawki_alert_analysis.feedback import FeedbackStore  # noqa: E402


def twin_alerts():
    """Two fixture alerts of the same rule on the same host."""
    groups = defaultdict(list)
    for item in app.ALERT_ANALYSIS.list_alerts():
        groups[(item.get("title"), item.get("host"))].append(item["id"])
    return next(ids for ids in groups.values() if len(ids) >= 2)[:2]


class FeedbackRouteTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.store = FeedbackStore(Path(self.dir.name) / "feedback.jsonl")
        patch = mock.patch.object(app, "FEEDBACK_STORE", self.store)
        patch.start()
        self.addCleanup(patch.stop)

        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.first, self.second = twin_alerts()

    def post(self, url, body):
        return self.client.post(url, json=body, headers={"X-CSRF-Token": "test-token"})

    def model_reply(self):
        captured = {}

        def call_llm(mode, message, history, context):
            captured["context"] = context
            return {
                "answer": "판단", "model": "hawki-local", "demo": False, "evidence": [], "queries": [], "actions": [],
                "assessment": {
                    "severity": {"level": "high", "rationale": "x"},
                    "supporting_evidence": [{"statement": "trigger", "event_ids": [self.second]}],
                },
                "assessment_review": {"missing_sections": []},
            }

        return captured, call_llm

    def analyze(self, alert_id, *, feedback_on):
        captured, fake = self.model_reply()
        with mock.patch.dict(app.CONFIG, {"analyst_feedback_context_enabled": feedback_on}), \
             mock.patch.object(app, "call_llm", side_effect=fake):
            body = self.post(f"/api/alerts/{alert_id}/analyze", {}).get_json()
        return captured["context"], body

    def test_a_verdict_is_recorded_and_audited(self):
        response = self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "false_positive", "note": "점검 스캐너"})
        self.assertEqual(response.status_code, 201)
        (entry,) = self.store.all()
        self.assertEqual((entry["alert_id"], entry["verdict"], entry["source"]), (self.first, "false_positive", "alert_analysis"))
        self.assertTrue(entry["rule_id"] and entry["host"])
        audit = Path(os.environ["AUDIT_LOG_PATH"]).read_text(encoding="utf-8")
        self.assertIn("analyst_feedback_recorded", audit)

    def test_bad_input(self):
        self.assertEqual(self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "withdrawn"}).status_code, 400)
        bad = self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "benign"})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()["error"], "판정 값이 올바르지 않습니다.")
        self.assertEqual(self.post("/api/alerts/evt-none/feedback", {"verdict": "confirmed"}).status_code, 404)

    def test_similar_verdicts_reach_the_next_analysis_only_when_enabled(self):
        self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "false_positive", "note": "점검 스캐너"})

        context, body = self.analyze(self.second, feedback_on=True)
        block = context["alert_case"]["analyst_feedback"]
        self.assertEqual(block["items"][0]["verdict"], "false_positive")
        self.assertEqual(block["items"][0]["note"], "점검 스캐너")
        self.assertEqual(body["feedback_context"], 1)
        self.assertEqual(body["explanation"]["inputs"]["feedback"][0]["feedback_id"], "FB-1")

        context, body = self.analyze(self.second, feedback_on=False)
        self.assertNotIn("analyst_feedback", context["alert_case"])
        self.assertEqual(body["feedback_context"], 0)

    def test_an_alert_is_not_its_own_precedent(self):
        self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "confirmed"})
        context, _ = self.analyze(self.first, feedback_on=True)
        self.assertNotIn("analyst_feedback", context["alert_case"])

    def test_every_analysis_carries_an_explanation(self):
        _, body = self.analyze(self.second, feedback_on=False)
        explanation = body["explanation"]
        self.assertEqual(explanation["schema"], "hawki.explanation/v1")
        self.assertEqual(explanation["claims"][0]["status"], "grounded")
        self.assertIn(explanation["conclusion"]["priority"]["band"], ("P1", "P2"))
        self.assertIn(self.second, explanation["evidence"])

    def test_the_prompt_states_how_feedback_may_be_used(self):
        self.assertIn("never cite an FB id as evidence", app.BASE_SYSTEM_PROMPT)
        self.assertIn("never lower severity or confidence on precedent alone", app.BASE_SYSTEM_PROMPT)

    def test_list_endpoint(self):
        self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "false_positive"})
        body = self.client.get(f"/api/alerts/{self.second}/feedback").get_json()
        self.assertEqual(len(body["similar"]), 1)
        self.assertEqual(body["for_alert"], [])
        mine = self.client.get(f"/api/alerts/{self.first}/feedback").get_json()
        self.assertEqual(mine["for_alert"][0]["verdict"], "false_positive")

    def test_feedback_never_pushes_the_evidence_out(self):
        self.post(f"/api/alerts/{self.first}/feedback", {"verdict": "false_positive", "note": "x" * 900})
        real = app.serialize_agent_context

        def tight(context):
            if "analyst_feedback" in (context.get("alert_case") or {}):
                raise ValueError("over the limit")
            return real(context)

        with mock.patch.object(app, "serialize_agent_context", side_effect=tight):
            context, body = self.analyze_with_patch(self.second)
        self.assertNotIn("analyst_feedback", context["alert_case"])
        self.assertEqual(body["feedback_context"], 0)

    def analyze_with_patch(self, alert_id):
        captured, fake = self.model_reply()
        with mock.patch.dict(app.CONFIG, {"analyst_feedback_context_enabled": True}), \
             mock.patch.object(app, "call_llm", side_effect=fake):
            body = self.post(f"/api/alerts/{alert_id}/analyze", {}).get_json()
        return captured["context"], body

    def test_live_identity_reads_like_the_alert_queue(self):
        record = {"rule": {"id": "60122"}, "agent": {"ip": "10.0.10.5"},
                  "data": {"eventdata": {"sourceIp": "45.95.11.22"}}}
        self.assertEqual(app.identity_from_record(record),
                         {"rule_id": "60122", "host": "10.0.10.5", "source_ip": "45.95.11.22"})

    def test_a_note_on_an_unjudged_report_withdraws_nothing(self):
        reports = ReportStore(Path(self.dir.name) / "reports2")
        with mock.patch.object(app, "AUTO_REPORT_STORE", reports), \
             mock.patch.object(app, "AUTO_REPORT_SETTINGS", AutoReportSettings(enabled=True)), \
             mock.patch.dict(app.CONFIG, {"llm_base_url": "http://127.0.0.1:9/v1"}):
            app.build_auto_reporter().run_cycle(lookback_seconds=365 * 86400)
            report = reports.all()[0]
            alert_id = report["alert"]["id"]
            self.post(f"/api/alerts/{alert_id}/feedback", {"verdict": "confirmed"})
            self.post(f"/api/auto-reports/{report['id']}/review", {"status": "unreviewed", "note": "나중에 볼 것"})
        self.assertEqual([r["verdict"] for r in self.store.all()], ["confirmed"])

    def test_an_automatic_report_review_is_feedback_too(self):
        reports = ReportStore(Path(self.dir.name) / "reports")
        with mock.patch.object(app, "AUTO_REPORT_STORE", reports), \
             mock.patch.object(app, "AUTO_REPORT_SETTINGS", AutoReportSettings(enabled=True)), \
             mock.patch.dict(app.CONFIG, {"llm_base_url": "http://127.0.0.1:9/v1"}):
            app.build_auto_reporter().run_cycle(lookback_seconds=365 * 86400)
            report = reports.all()[0]
            self.post(f"/api/auto-reports/{report['id']}/review", {"status": "confirmed", "note": "차단함"})
            self.post(f"/api/auto-reports/{report['id']}/review", {"status": "unreviewed"})
        records = self.store.all()
        self.assertEqual([(r["source"], r["verdict"], r["report_id"]) for r in records],
                         [("auto_report", "confirmed", report["id"]), ("auto_report", "withdrawn", report["id"])])
        # Set back to unreviewed: the confirmation no longer counts.
        alert = {"rule_id": records[0]["rule_id"], "host": records[0]["host"], "source_ip": records[0]["source_ip"]}
        self.assertEqual(self.store.similar(alert, exclude_alert_id="other", now=app.datetime.now(app.timezone.utc)), [])


if __name__ == "__main__":
    unittest.main()
