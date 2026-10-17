"""Rule cards follow the sensor: stop requests, reload retries, two-person rule."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import requests

_WORKDIR = tempfile.mkdtemp(prefix="hawki-tests-")
os.environ.setdefault("FLASK_SECRET_KEY", "t" * 48)
os.environ.setdefault("AUTH_DATABASE_PATH", str(Path(_WORKDIR) / "auth.db"))
os.environ.setdefault("ACTION_QUEUE_PATH", str(Path(_WORKDIR) / "actions.jsonl"))
os.environ.setdefault("AUDIT_LOG_PATH", str(Path(_WORKDIR) / "audit.jsonl"))
os.environ.setdefault("HAWKI_ADMIN_USERNAME", "analyst")
os.environ.setdefault("HAWKI_ADMIN_PASSWORD", "Str0ng-Passw0rd-Value!")

import app  # noqa: E402
from tests.test_suricata_editor_verify import fake_verifier  # noqa: E402

GATEWAY = {
    "response_actions_enabled": True,
    "suricata_gateway_url": "http://sensor.test:8095",
    "suricata_gateway_token": "test",
}


def gateway_answer(status, body):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response.url = "http://sensor.test:8095/actions"
    return response


RELOADING = gateway_answer(409, {"error": "reload_in_progress", "message": "still reloading", "detail": "x"})
APPLIED = gateway_answer(200, {"status": "applied"})


class RuleLifecycleTests(unittest.TestCase):
    sid = 9909300

    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        self.headers = {"X-CSRF-Token": "test-token", "Content-Type": "application/json"}
        patches = [
            mock.patch.dict(os.environ, {"SURICATA_SENSOR_HOST": "10.0.10.235", "SURICATA_SENSOR_INTERFACE": "ens5"}),
            mock.patch.dict(app.CONFIG, GATEWAY),
            mock.patch.object(app, "verify_suricata_detection_spec", fake_verifier),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def call(self, method, path, body=None):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        return self.client.open(path, method=method, data=json.dumps(body or {}), headers=self.headers)

    def new_rule(self):
        RuleLifecycleTests.sid += 1
        rule = (f'alert http any any -> $HOME_NET $HTTP_PORTS (msg:"lifecycle {self.sid}"; '
                f'flow:established,to_server; http.uri; content:"/lifecycle-{self.sid}"; sid:{self.sid}; rev:1;)')
        created = self.call("POST", "/api/rules", {
            "name": f"lifecycle {self.sid}", "host": "10.0.10.235", "interface": "ens5",
            "rule": rule, "enabled": True, "source": "rule_editor",
        })
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        rule_id = created.get_json()["rule"]["id"]
        self.assertEqual(self.call("POST", f"/api/rules/{rule_id}/verify-text").status_code, 200)
        return rule_id

    def stage(self, rule_id, body=None):
        staged = self.call("POST", f"/api/rules/{rule_id}/stage", body)
        self.assertIn(staged.status_code, (200, 201), staged.get_data(as_text=True))
        return staged.get_json()["action"]

    def decide(self, action_id, decision="approve"):
        return self.call("POST", f"/api/actions/{action_id}/decision", {"decision": decision})

    def rule(self, rule_id):
        rules = self.call("GET", "/api/rules").get_json()["rules"]
        return next(item for item in rules if item["id"] == rule_id)

    def active_rule(self):
        rule_id = self.new_rule()
        action = self.stage(rule_id)
        with mock.patch.object(app.requests, "post", return_value=APPLIED):
            self.assertEqual(self.decide(action["id"]).status_code, 200)
        self.assertEqual(self.rule(rule_id)["state"], "active")
        return rule_id

    def test_stop_request_keeps_active_until_rejected(self):
        rule_id = self.active_rule()
        action = self.stage(rule_id, {"enabled": False})
        self.assertEqual(action["type"], "suricata_rule_disable")
        self.assertTrue(action["payload"]["previous_enabled"])
        self.assertEqual(self.decide(action["id"], "reject").status_code, 200)
        rule = self.rule(rule_id)
        self.assertEqual((rule["state"], rule["enabled"]), ("active", True))

    def test_flipping_target_alone_keeps_sensor_state(self):
        rule_id = self.active_rule()
        response = self.call("PATCH", f"/api/rules/{rule_id}", {"enabled": False})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(self.rule(rule_id)["state"], "active")

    def test_reload_refusal_is_retried(self):
        rule_id = self.new_rule()
        action = self.stage(rule_id)
        with mock.patch.dict(app.CONFIG, {"suricata_reload_retry_enabled": True}), \
                mock.patch.object(app.requests, "post", return_value=RELOADING):
            decided = self.decide(action["id"]).get_json()["action"]
        self.assertEqual(decided["status"], "retry_waiting")
        rule = self.rule(rule_id)
        self.assertEqual(rule["state"], "staged")
        self.assertEqual(rule["last_action"]["status"], "retry_waiting")

        later = datetime.now(timezone.utc) + timedelta(hours=1)
        with app.app.app_context(), mock.patch.dict(app.CONFIG, {"suricata_reload_retry_enabled": True}), \
                mock.patch.object(app.requests, "post", return_value=APPLIED):
            self.assertEqual(app.process_reload_retries(now=later), [action["id"]])
        self.assertEqual(self.rule(rule_id)["state"], "active")

    def test_reload_refusal_without_retry_is_an_error(self):
        rule_id = self.new_rule()
        action = self.stage(rule_id)
        with mock.patch.object(app.requests, "post", return_value=RELOADING):
            decided = self.decide(action["id"]).get_json()["action"]
        self.assertEqual(decided["status"], "dispatch_failed")
        rule = self.rule(rule_id)
        self.assertEqual(rule["state"], "error")
        self.assertEqual(rule["last_action"]["gateway_error"], "reload_in_progress")

    def test_requester_cannot_approve_when_required(self):
        rule_id = self.new_rule()
        action = self.stage(rule_id)
        self.assertTrue(action["requested_by"]["username"])
        with mock.patch.dict(app.CONFIG, {"require_separate_approver": True}):
            blocked = self.decide(action["id"])
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.get_json()["code"], "self_approval_blocked")
        with mock.patch.object(app.requests, "post", return_value=APPLIED):
            self.assertEqual(self.decide(action["id"]).status_code, 200)


if __name__ == "__main__":
    unittest.main()
