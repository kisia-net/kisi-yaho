"""Forwarding analysis results to the red team runner."""

from __future__ import annotations

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

import requests  # noqa: E402

import app  # noqa: E402
from hawki_alert_analysis import redteam_bridge as bridge  # noqa: E402

LIVE = "hawki.wazuh.live-evidence/v2"


def decide(**overrides):
    values = dict(
        enabled=True, runner_url="http://10.0.10.59:8091", token="secret", tools=["promptfoo"],
        bundle_schema=LIVE, demo=False, from_runner=False,
    )
    values.update(overrides)
    return bridge.forwarding_decision(**values)


class DecisionTests(unittest.TestCase):
    def test_live_real_result_is_sent(self):
        self.assertEqual(decide(), "send")

    def test_everything_else_is_not(self):
        self.assertEqual(decide(enabled=False), "disabled")
        self.assertEqual(decide(from_runner=True), "skipped_recursive_request")
        self.assertEqual(decide(bundle_schema="hawki.siem.evidence-bundle/v1"), "skipped_not_live")
        self.assertEqual(decide(demo=True), "skipped_demo_result")
        self.assertEqual(decide(token=""), "skipped_no_token")
        self.assertEqual(decide(runner_url=""), "skipped_no_runner_url")
        self.assertEqual(decide(tools=[]), "skipped_no_tools")

    def test_only_known_tools(self):
        self.assertEqual(bridge.parse_tools("promptfoo, garak ,rm -rf,promptfoo"), ["promptfoo", "garak"])


class DispatchTests(unittest.TestCase):
    def payload(self):
        return bridge.build_job_payload(
            analysis_id="a" * 32, alert_id="alert-1", request_text="Analyze.",
            prompt_sha256="p", bundle_sha256="b", bundle={"schema": LIVE},
            result={"answer": "x", "model": "hawki-local", "internal": "not sent"}, tools=["promptfoo"],
        )

    def test_posts_with_token_and_reports_outcome(self):
        outcomes = []
        response = mock.Mock(status_code=202, json=lambda: {"job_id": "job-7"})
        with mock.patch.object(bridge.requests, "post", return_value=response) as post:
            bridge.dispatch_in_background(
                runner_url="http://10.0.10.59:8091/", token="secret", timeout=3, payload=self.payload(),
                on_done=outcomes.append, start_thread=lambda thread: thread.run(),
            )
        url = post.call_args.args[0]
        self.assertEqual(url, "http://10.0.10.59:8091/api/jobs")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer secret")
        self.assertEqual(post.call_args.kwargs["timeout"], 3)
        self.assertNotIn("internal", post.call_args.kwargs["json"]["result"])
        self.assertEqual(outcomes, [{"analysis_id": "a" * 32, "status_code": 202, "dispatched": True, "job_id": "job-7"}])

    def test_runner_failure_is_recorded_not_raised(self):
        outcomes = []
        with mock.patch.object(bridge.requests, "post", side_effect=requests.ConnectTimeout("slow")):
            bridge.dispatch_in_background(
                runner_url="http://x", token="t", timeout=3, payload=self.payload(),
                on_done=outcomes.append, start_thread=lambda thread: thread.run(),
            )
        self.assertFalse(outcomes[0]["dispatched"])
        self.assertIn("slow", outcomes[0]["error"])


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        # Login starts a fresh session; set the token again for the POSTs.
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.alert_id = app.ALERT_ANALYSIS.list_alerts()[0]["id"]

    def analyze(self, headers=None):
        return self.client.post(
            f"/api/alerts/{self.alert_id}/analyze", json={},
            headers={"X-CSRF-Token": "test-token", **(headers or {})},
        )

    def test_every_analysis_gets_an_id_and_hashes(self):
        with mock.patch.dict(app.CONFIG, {"demo_mode": True, "llm_api_url": "http://127.0.0.1:9/v1/chat/completions"}):
            body = self.analyze().get_json()
        self.assertRegex(body["analysis_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(len(body["hashes"]["prompt_sha256"]), 64)
        self.assertEqual(len(body["hashes"]["bundle_sha256"]), 64)

    def test_fixture_and_demo_results_are_never_sent(self):
        config = {
            "demo_mode": True, "llm_api_url": "http://127.0.0.1:9/v1/chat/completions",
            "redteam_auto_eval_enabled": True, "redteam_runner_url": "http://10.0.10.59:8091",
            "redteam_runner_token": "secret", "redteam_auto_tools": ["promptfoo"],
        }
        with mock.patch.dict(app.CONFIG, config), mock.patch.object(app, "dispatch_in_background") as dispatch:
            body = self.analyze().get_json()
        dispatch.assert_not_called()
        self.assertEqual(body["redteam"]["status"], "skipped_not_live")

    def test_status_api_validates_and_reports_unconfigured(self):
        self.assertEqual(self.client.get("/api/redteam/jobs/not-an-id").status_code, 400)
        with mock.patch.dict(app.CONFIG, {"redteam_runner_url": "", "redteam_runner_token": ""}):
            self.assertEqual(self.client.get(f"/api/redteam/jobs/{'a' * 32}").status_code, 503)

    def test_status_api_proxies_the_runner(self):
        config = {"redteam_runner_url": "http://10.0.10.59:8091", "redteam_runner_token": "secret"}
        with mock.patch.dict(app.CONFIG, config), \
             mock.patch.object(app, "fetch_job_status", return_value=(200, {"status": "running"})):
            body = self.client.get(f"/api/redteam/jobs/{'a' * 32}").get_json()
        self.assertEqual(body["runner"]["status"], "running")

    def test_status_api_requires_login(self):
        anonymous = app.app.test_client()
        self.assertEqual(anonymous.get(f"/api/redteam/jobs/{'a' * 32}").status_code, 401)


if __name__ == "__main__":
    unittest.main()
