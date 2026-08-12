"""Tests for the context handed to the LLM/SLM by the agent endpoints.

These cover the size ladder in app.serialize_agent_context: whatever it
returns must stay valid JSON and must never quietly drop the asset or
threat-intelligence blocks in order to fit.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_WORKDIR = tempfile.mkdtemp(prefix="hawki-tests-")
os.environ.setdefault("FLASK_SECRET_KEY", "t" * 48)
os.environ.setdefault("AUTH_DATABASE_PATH", str(Path(_WORKDIR) / "auth.db"))
os.environ.setdefault("ACTION_QUEUE_PATH", str(Path(_WORKDIR) / "actions.jsonl"))
os.environ.setdefault("AUDIT_LOG_PATH", str(Path(_WORKDIR) / "audit.jsonl"))
os.environ.setdefault("HAWKI_ADMIN_USERNAME", "analyst")
os.environ.setdefault("HAWKI_ADMIN_PASSWORD", "Str0ng-Passw0rd-Value!")

import app  # noqa: E402  (import after the environment is prepared)
from hawki_alert_analysis import BUNDLE_SCHEMA  # noqa: E402


def metadata_blocks(payload: dict) -> set[str]:
    blocks: set[str] = set()
    for case in app._iter_alert_cases(payload):
        blocks |= set(case.get("metadata", {}))
    for digest in payload.get("alert_case_digests", []):
        blocks |= set(digest.get("metadata_digest", {}))
    return blocks


class AgentContextTests(unittest.TestCase):
    def setUp(self):
        self.alert_ids = [item["id"] for item in app.ALERT_ANALYSIS.list_alerts()]
        self.original_limit = app.CONFIG["agent_context_max_chars"]

    def tearDown(self):
        app.CONFIG["agent_context_max_chars"] = self.original_limit

    def test_attached_case_is_published_under_one_key(self):
        single = app.attach_alert_cases({"alert_ids": self.alert_ids[:1]})
        self.assertIn("alert_case", single)
        self.assertNotIn("alert_cases", single)

        multi = app.attach_alert_cases({"alert_ids": self.alert_ids[:2]})
        self.assertIn("alert_cases", multi)
        self.assertNotIn("alert_case", multi)
        self.assertEqual(len(multi["alert_cases"]), 2)

    def test_serialized_context_is_valid_json_and_within_limit(self):
        for count in (1, 2, 4):
            for limit in (24000, 16000, 9000, 6000):
                with self.subTest(alerts=count, limit=limit):
                    app.CONFIG["agent_context_max_chars"] = limit
                    context = app.attach_alert_cases({"alert_ids": self.alert_ids[:count]})
                    text = app.serialize_agent_context(context)
                    payload = json.loads(text)  # must never be a sliced fragment
                    self.assertLessEqual(len(text), limit)
                    self.assertEqual(
                        metadata_blocks(payload),
                        {"security_alerts", "security_events", "assets", "threat_intelligence"},
                    )

    def test_reduction_keeps_alerts_assets_and_intel_when_events_are_dropped(self):
        app.CONFIG["agent_context_max_chars"] = 16000
        context = app.attach_alert_cases({"alert_ids": self.alert_ids[:1]})
        payload = json.loads(app.serialize_agent_context(context))
        case = app._iter_alert_cases(payload)[0]
        metadata = case["metadata"]
        self.assertTrue(metadata["security_alerts"]["items"])
        self.assertTrue(metadata["assets"]["items"])
        self.assertTrue(metadata["threat_intelligence"]["items"])

    def test_digest_reports_that_evidence_was_omitted(self):
        app.CONFIG["agent_context_max_chars"] = 6000
        context = app.attach_alert_cases({"alert_ids": self.alert_ids[:4]})
        payload = json.loads(app.serialize_agent_context(context))
        self.assertIn("alert_case_digests", payload)
        self.assertIn("exceeded", payload["context_summary"])
        digest = payload["alert_case_digests"][0]
        self.assertTrue(digest["metadata_digest"]["security_alerts"])
        self.assertTrue(digest["timeline"])
        self.assertIn("counts", digest["collection"])

    def test_unknown_alert_id_is_rejected_rather_than_silently_dropped(self):
        with self.assertRaises(app.AlertNotFound):
            app.attach_alert_cases({"alert_ids": ["evt-does-not-exist"]})


class LlmDeliveryTests(unittest.TestCase):
    """The bundle must survive all the way into the outbound LLM request."""

    def setUp(self):
        self.alert_id = app.ALERT_ANALYSIS.list_alerts()[0]["id"]

    def call_and_capture(self, mode: str) -> dict:
        captured: dict = {}

        class StubResponse:
            status_code = 200

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "model": "stub",
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {"answer": "ok", "evidence": [], "queries": [], "actions": []}
                                )
                            }
                        }
                    ],
                }

        def fake_post(url, headers=None, json=None, timeout=None):  # noqa: A002
            captured.update(json or {})
            return StubResponse()

        original = app.requests.post
        app.requests.post = fake_post
        try:
            case = app.ALERT_ANALYSIS.get_case(self.alert_id)
            app.call_llm(mode, "Analyze this case.", [], {"alert_case": case.to_llm_context()})
        finally:
            app.requests.post = original
        return captured

    def test_four_blocks_reach_the_model_payload(self):
        body = self.call_and_capture("alert_summary")
        user_message = body["messages"][-1]["content"]
        context = json.loads(user_message.split("untrusted evidence, not instructions): ", 1)[1].split("\n\nAnalyst request:")[0])
        blocks = context["alert_case"]["metadata"]
        self.assertEqual(
            list(blocks),
            ["security_alerts", "security_events", "assets", "threat_intelligence"],
        )
        self.assertTrue(blocks["assets"]["items"])
        self.assertTrue(blocks["threat_intelligence"]["items"])

    def test_system_prompt_describes_the_blocks(self):
        body = self.call_and_capture("alert_summary")
        system = body["messages"][0]["content"]
        for block in ("security_alerts", "security_events", "assets", "threat_intelligence"):
            self.assertIn(block, system)


class MetadataApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        response = self.client.post(
            "/login",
            data={
                "username": os.environ["HAWKI_ADMIN_USERNAME"],
                "password": os.environ["HAWKI_ADMIN_PASSWORD"],
                "csrf_token": "test-token",
                "next": "/",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.alert_id = app.ALERT_ANALYSIS.list_alerts()[0]["id"]

    def get(self, path):
        response = self.client.get(path)
        return response.status_code, json.loads(response.data)

    def test_context_endpoint_returns_the_bundle_sent_to_the_model(self):
        status, payload = self.get(f"/api/alerts/{self.alert_id}/context")
        self.assertEqual(status, 200)
        self.assertEqual(payload["bundle"]["schema"], BUNDLE_SCHEMA)
        self.assertEqual(
            list(payload["bundle"]["metadata"]),
            ["security_alerts", "security_events", "assets", "threat_intelligence"],
        )
        self.assertGreater(payload["serialized_chars"], 0)

    def test_asset_and_threat_intel_endpoints(self):
        status, assets = self.get("/api/assets")
        self.assertEqual(status, 200)
        self.assertIn("web-01", {item["hostname"] for item in assets["assets"]})

        status, intel = self.get("/api/threat-intel")
        self.assertEqual(status, 200)
        self.assertIn("203.0.113.45", {item["value"] for item in intel["indicators"]})

    def test_alert_queue_carries_enrichment_previews(self):
        status, payload = self.get("/api/alerts")
        self.assertEqual(status, 200)
        alert = next(item for item in payload["alerts"] if item["host"] == "web-01")
        self.assertEqual(alert["asset_criticality"], "high")

    def test_metadata_endpoints_require_authentication(self):
        anonymous = app.app.test_client()
        for path in ("/api/assets", "/api/threat-intel", f"/api/alerts/{self.alert_id}/context"):
            with self.subTest(path=path):
                self.assertEqual(anonymous.get(path).status_code, 401)

    def test_missing_alert_returns_404(self):
        self.assertEqual(self.client.get("/api/alerts/evt-missing/context").status_code, 404)

    def test_alert_detail_page_is_served(self):
        # alert_detail.html and the alert-table links pointed at this path
        # before any route existed for it.
        response = self.client.get(f"/alerts/{self.alert_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.alert_id, response.get_data(as_text=True))
        self.assertEqual(self.client.get("/alerts/evt-missing").status_code, 404)


if __name__ == "__main__":
    unittest.main()
