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
from hawki_alert_analysis.assessment import bundle_reference_ids as app_bundle_ids  # noqa: E402

COMPLETE_ASSESSMENT = {
    "confirmed_observations": ["A traversal URI was requested."],
    "interpretation": "Probable exploitation attempt.",
    "attack_hypothesis": "Traversal followed by shell execution.",
    "confidence": {"level": "high", "rationale": "Three sources agree."},
    "severity": {"level": "critical", "rationale": "Internet-facing high-criticality asset."},
    "affected_entities": {"hosts": ["web-01"]},
    "attack_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "supporting_evidence": [{"statement": "Traversal alert", "event_ids": []}],
    "contradictory_evidence": [],
    "evidence_gaps": ["Full request body not captured."],
    "recommended_searches": [{"title": "Same source", "language": "KQL", "value": "source.ip:203.0.113.45"}],
    "recommended_response": ["Preserve the process tree."],
}


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


class AssessmentSchemaTests(unittest.TestCase):
    """The alert_summary path must always return a reviewed assessment."""

    def setUp(self):
        self.alert_id = app.ALERT_ANALYSIS.list_alerts()[0]["id"]
        self.context = {"alert_case": app.ALERT_ANALYSIS.get_case(self.alert_id).to_llm_context()}
        self.repair_default = app.CONFIG["assessment_repair_enabled"]

    def tearDown(self):
        app.CONFIG["assessment_repair_enabled"] = self.repair_default

    def run_with_replies(self, replies: list[dict]) -> tuple[dict, list[dict]]:
        """Drive call_llm against a scripted sequence of model responses."""
        sent: list[dict] = []
        remaining = list(replies)

        class StubResponse:
            def __init__(self, payload):
                self.payload = payload

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "model": "stub",
                    "choices": [{"message": {"content": json.dumps(self.payload)}}],
                }

        def fake_post(url, headers=None, json=None, timeout=None):  # noqa: A002
            sent.append(json or {})
            return StubResponse(remaining.pop(0) if remaining else replies[-1])

        original = app.requests.post
        app.requests.post = fake_post
        try:
            result = app.call_llm("alert_summary", "Analyze.", [], self.context)
        finally:
            app.requests.post = original
        return result, sent

    def test_complete_assessment_needs_no_correction(self):
        result, sent = self.run_with_replies([
            {"answer": "Done.", "evidence": [], "queries": [], "actions": [], "assessment": COMPLETE_ASSESSMENT},
        ])
        self.assertTrue(result["assessment_review"]["complete"])
        self.assertEqual(len(sent), 1)

    def test_incomplete_assessment_triggers_one_correction_pass(self):
        partial = {key: value for key, value in COMPLETE_ASSESSMENT.items() if key != "evidence_gaps"}
        result, sent = self.run_with_replies([
            {"answer": "Partial.", "evidence": [], "queries": [], "actions": [], "assessment": partial},
            {"answer": "Corrected.", "evidence": [], "queries": [], "actions": [], "assessment": COMPLETE_ASSESSMENT},
        ])
        self.assertEqual(len(sent), 2)
        self.assertTrue(result["assessment_review"]["complete"])
        self.assertEqual(
            result["assessment_review"]["sections_missing_before_repair"], ["evidence_gaps"]
        )
        self.assertIn("evidence_gaps", sent[1]["messages"][-1]["content"])

    def test_a_worse_correction_is_discarded(self):
        partial = {key: value for key, value in COMPLETE_ASSESSMENT.items() if key != "evidence_gaps"}
        result, _ = self.run_with_replies([
            {"answer": "Partial.", "evidence": [], "queries": [], "actions": [], "assessment": partial},
            {"answer": "Worse.", "evidence": [], "queries": [], "actions": [], "assessment": {}},
        ])
        # The first answer survives when the correction covers less.
        self.assertEqual(result["answer"], "Partial.")
        self.assertTrue(result["assessment"]["confirmed_observations"])

    def test_missing_assessment_key_still_yields_a_reviewed_shape(self):
        app.CONFIG["assessment_repair_enabled"] = False
        result, sent = self.run_with_replies([
            {"answer": "Prose only.", "evidence": [], "queries": [], "actions": []},
        ])
        self.assertEqual(len(sent), 1)
        self.assertFalse(result["assessment_review"]["complete"])
        self.assertEqual(result["answer"], "Prose only.")
        self.assertIn("interpretation", result["assessment"])

    def test_ungrounded_citations_are_reported(self):
        app.CONFIG["assessment_repair_enabled"] = False
        payload = dict(COMPLETE_ASSESSMENT)
        payload["supporting_evidence"] = [{"statement": "Invented", "event_ids": ["evt-nope"]}]
        result, _ = self.run_with_replies([
            {"answer": "x", "evidence": [], "queries": [], "actions": [], "assessment": payload},
        ])
        self.assertEqual(result["assessment_review"]["ungrounded_event_ids"], ["evt-nope"])

    def test_demo_fallback_reads_the_bundle(self):
        result = app.demo_agent_response("alert_summary", "Analyze.", self.context)
        self.assertIn("assessment_review", result)
        counts = self.context["alert_case"]["collection"]["counts"]
        # The old demo answer claimed no telemetry was supplied.
        self.assertNotIn("No corroborating raw telemetry", json.dumps(result))
        self.assertIn(str(counts["security_events"]), json.dumps(result["evidence"]))
        cited = {
            event_id
            for entry in result["assessment"]["supporting_evidence"]
            for event_id in entry["event_ids"]
        }
        valid, _ = app_bundle_ids(self.context["alert_case"])
        self.assertTrue(cited)
        self.assertTrue(cited <= valid)
        self.assertEqual(result["assessment_review"]["ungrounded_event_ids"], [])


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

    def test_no_mutation_observer_writes_into_what_it_watches(self):
        """Guard against the self-triggering observer that froze the tab.

        alert_analysis.js watched #alerts-table with subtree: true and assigned
        link.textContent inside it. Assigning textContent replaces the text
        node and registers as a mutation even when the value is unchanged, so
        the callback re-triggered itself forever, the microtask queue never
        drained, and the page stopped painting and stopped accepting input —
        a hang no server-side test can see.
        """
        source = (Path(app.BASE_DIR) / "static" / "alert_analysis.js").read_text(encoding="utf-8")
        self.assertNotIn("MutationObserver", source)

    def test_alert_rows_link_straight_to_the_case(self):
        # The link is rendered correctly rather than rewritten after the fact,
        # which is what removed the need for the observer.
        source = (Path(app.BASE_DIR) / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('href="/alerts/${encodeURIComponent(a.id)}"', source)

    def test_pages_load_no_script_the_csp_forbids(self):
        # script-src 'self' blocks inline blocks and CDN tags outright, so a
        # page carrying either is broken in the browser regardless of tests.
        import re

        for path in ("/", "/alerts", "/agent"):
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                self.assertEqual(re.findall(r"<script(?![^>]*\ssrc=)[^>]*>", html), [])
                sources = re.findall(r'<script[^>]*src="([^"]+)"', html)
                self.assertTrue(sources)
                self.assertEqual([src for src in sources if src.startswith("http")], [])

    def test_vendor_scripts_are_included_only_when_installed(self):
        vendor_dir = Path(app.BASE_DIR) / "static" / "vendor"
        installed = app.available_vendor_scripts()
        self.assertEqual(
            installed, [name for name in app.VENDOR_SCRIPTS if (vendor_dir / name).is_file()]
        )
        html = self.client.get("/alerts").get_data(as_text=True)
        for name in app.VENDOR_SCRIPTS:
            # A library that is not installed must not be referenced at all,
            # rather than 404ing on every page load.
            self.assertEqual(f"vendor/{name}" in html, name in installed)

    def test_healthz_answers_without_a_session(self):
        # The Docker health check has no session. It previously called
        # /api/build, got 401, and reported a healthy container as unhealthy.
        anonymous = app.app.test_client()
        response = anonymous.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.data), {"status": "ok"})

    def test_healthz_reveals_nothing_else(self):
        anonymous = app.app.test_client()
        body = json.loads(anonymous.get("/healthz").data)
        self.assertEqual(set(body), {"status"})
        # Build and service detail stay behind authentication.
        for path in ("/api/build", "/api/status"):
            with self.subTest(path=path):
                self.assertEqual(anonymous.get(path).status_code, 401)

    def test_metadata_endpoints_require_authentication(self):
        anonymous = app.app.test_client()
        for path in ("/api/assets", "/api/threat-intel", f"/api/alerts/{self.alert_id}/context"):
            with self.subTest(path=path):
                self.assertEqual(anonymous.get(path).status_code, 401)

    def test_missing_alert_returns_404(self):
        self.assertEqual(self.client.get("/api/alerts/evt-missing/context").status_code, 404)

    def test_config_reports_the_active_repository(self):
        status, payload = self.get("/api/config")
        repository = payload["alert_repository"]
        self.assertEqual(repository["type"], "fixture")
        self.assertTrue(repository["configured"])
        self.assertGreater(repository["alert_count"], 0)
        self.assertIn("effective_root", repository)

    def test_alert_detail_page_is_served(self):
        # alert_detail.html and the alert-table links pointed at this path
        # before any route existed for it.
        response = self.client.get(f"/alerts/{self.alert_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.alert_id, response.get_data(as_text=True))
        self.assertEqual(self.client.get("/alerts/evt-missing").status_code, 404)


if __name__ == "__main__":
    unittest.main()
