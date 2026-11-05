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

    def test_payload_meets_the_runner_contract(self):
        payload = self.payload()
        for key in ("schema", "analysis_id", "alert_id", "created_at", "tools", "model",
                    "request", "hashes", "evidence_bundle", "result"):
            self.assertIn(key, payload)
        for key in ("request", "hashes", "evidence_bundle", "result"):
            self.assertIsInstance(payload[key], dict, key)
        self.assertEqual(payload["request"]["text"], "Analyze.")
        self.assertIs(payload["result"]["demo"], False)
        self.assertEqual(payload["result"]["analysis_id"], payload["analysis_id"])
        self.assertEqual(payload["result"]["alert_id"], payload["alert_id"])
        self.assertEqual(payload["result"]["bundle_schema"], payload["evidence_bundle"]["schema"])
        self.assertNotIn("internal", payload["result"])
        self.assertIsNone(bridge.payload_problem(payload))

    def test_what_the_runner_refuses_is_not_sent(self):
        bad = self.payload()
        bad["analysis_id"] = "A" * 32
        self.assertEqual(bridge.payload_problem(bad), "analysis_id_not_32_hex")
        demo = self.payload()
        demo["result"]["demo"] = True
        self.assertEqual(bridge.payload_problem(demo), "demo_result")
        outcomes = []
        with mock.patch.object(bridge.requests, "post") as post:
            bridge.dispatch_in_background(
                runner_url="http://10.0.10.59:8091", token="secret", timeout=3, payload=bad,
                on_done=outcomes.append, start_thread=lambda thread: thread.run(),
            )
        post.assert_not_called()
        self.assertFalse(outcomes[0]["dispatched"])

    def test_the_runner_job_id_is_read_from_any_of_its_four_places(self):
        job_id = "6716f0c2a9e4b1d3c5f7a8b9"
        body = {"job_id": job_id, "id": job_id, "job": {"job_id": job_id, "id": job_id}}
        self.assertEqual(bridge.extract_job_id(body), job_id)

    def test_posts_with_token_and_reports_outcome(self):
        outcomes = []
        response = mock.Mock(status_code=202, json=lambda: {"job": {"id": "6716f0c2a9e4b1d3c5f7a8b9"}, "status": "queued"})
        with mock.patch.object(bridge.requests, "post", return_value=response) as post:
            bridge.dispatch_in_background(
                runner_url="http://10.0.10.59:8091/", token="secret", timeout=3, payload=self.payload(),
                on_done=outcomes.append, start_thread=lambda thread: thread.run(),
            )
        url = post.call_args.args[0]
        self.assertEqual(url, "http://10.0.10.59:8091/v1/jobs")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer secret")
        self.assertEqual(post.call_args.kwargs["timeout"], 3)
        self.assertNotIn("internal", post.call_args.kwargs["json"]["result"])
        self.assertEqual(outcomes, [{"analysis_id": "a" * 32, "status_code": 202, "dispatched": True,
                                     "job_id": "6716f0c2a9e4b1d3c5f7a8b9"}])

    def test_job_ids_are_read_from_the_usual_shapes(self):
        job = "6716f0c2a9e4b1d3c5f7a8b9"
        for body in ({"job_id": job}, {"id": job}, {"job": {"job_id": job}}, {"job": job}):
            self.assertEqual(bridge.extract_job_id(body), job)
        self.assertIsNone(bridge.extract_job_id({"job_id": "../../etc"}))
        self.assertIsNone(bridge.extract_job_id(["not", "a", "dict"]))

    def test_the_jobs_path_is_configurable_but_sane(self):
        self.assertEqual(bridge.jobs_path_or_default("/v2/evaluations/"), "/v2/evaluations")
        self.assertEqual(bridge.jobs_path_or_default("http://evil/x"), "/v1/jobs")
        self.assertEqual(bridge.jobs_path_or_default(""), "/v1/jobs")

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
        self.assertEqual(self.client.get("/api/redteam/jobs/x").status_code, 400)
        self.assertEqual(self.client.get("/api/redteam/jobs/a.b").status_code, 400)
        with mock.patch.dict(app.CONFIG, {"redteam_runner_url": "", "redteam_runner_token": ""}):
            self.assertEqual(self.client.get(f"/api/redteam/jobs/{'a' * 32}").status_code, 503)

    def test_status_api_finds_the_runner_job_for_an_analysis(self):
        job = "6716f0c2a9e4b1d3c5f7a8b9"
        index = bridge.RedteamJobIndex(Path(tempfile.mkdtemp()) / "jobs.jsonl")
        config = {"redteam_runner_url": "http://10.0.10.59:8091", "redteam_runner_token": "secret"}
        with mock.patch.dict(app.CONFIG, config), mock.patch.object(app, "REDTEAM_JOB_INDEX", index), \
             mock.patch.object(app, "fetch_job_status", return_value=(200, {"status": "running"})) as fetch:
            missing = self.client.get(f"/api/redteam/jobs/{'a' * 32}")
            app.redteam_dispatch_done({"analysis_id": "a" * 32, "dispatched": True, "status_code": 202, "job_id": job},
                                      alert_id="alert-1")
            body = self.client.get(f"/api/redteam/jobs/{'a' * 32}").get_json()
            direct = self.client.get(f"/api/redteam/jobs/{job}").get_json()
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(body["runner"]["status"], "running")
        self.assertEqual(body["job_id"], job)
        self.assertEqual(fetch.call_args.kwargs["job_id"], job)
        self.assertEqual(fetch.call_args.kwargs["jobs_path"], "/v1/jobs")
        self.assertEqual(direct["job_id"], job)

    def test_status_api_requires_login(self):
        anonymous = app.app.test_client()
        self.assertEqual(anonymous.get(f"/api/redteam/jobs/{'a' * 32}").status_code, 401)


if __name__ == "__main__":
    unittest.main()


class ServiceStatusTests(unittest.TestCase):
    """The dashboard's service panel shows the runner and why it is down."""

    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })

    def runner(self, url):
        with mock.patch.dict(app.CONFIG, {"redteam_runner_url": url, "redteam_auto_eval_enabled": False}):
            return self.client.get("/api/status").get_json()["services"]["redteam_runner"]

    def test_unconfigured_runner(self):
        status = self.runner("")
        self.assertFalse(status["configured"])
        self.assertFalse(status["auto_eval_enabled"])

    def test_closed_port_is_reported_as_refused(self):
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()  # nothing listens here now
        status = self.runner(f"http://127.0.0.1:{port}")
        self.assertFalse(status["ok"])
        self.assertEqual(status["error_kind"], "refused")

    def test_any_http_answer_counts_as_reachable(self):
        import http.server
        import threading

        class NotFound(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), NotFound)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            status = self.runner(f"http://127.0.0.1:{server.server_address[1]}")
        finally:
            server.shutdown()
        self.assertTrue(status["ok"])
        self.assertEqual(status["status_code"], 404)
