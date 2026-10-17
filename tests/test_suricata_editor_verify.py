"""Editor rules can be verified and staged when they fit DetectionSpec/v1."""
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

import app  # noqa: E402

EDITOR_RULE = 'alert http any any -> any any (msg:"Editor URI test"; flow:established,to_server; http.uri; content:"/editor-only-path"; nocase; sid:9909100; rev:1;)'


def fake_verifier(spec):
    compiled = (
        f'{spec["requested_action"]} http any any -> $HOME_NET $HTTP_PORTS (msg:"{spec["message"]}"; '
        f'flow:to_server,established; http.uri; content:"{spec["uri_contains"]}"; sid:{spec["sid"]}; rev:{spec["rev"]};)'
    )
    return {
        "schema": "hawki.rule-verification-result/v1", "target_engine": "suricata", "target_version": "6.0.4",
        "sid": spec["sid"], "requested_action": spec["requested_action"], "compiled_action": spec["requested_action"],
        "compiled_rule": compiled, "verification": "PASS", "syntax_valid": True, "behavior_valid": True,
        "verification_method": "deterministic_detection_spec_replay/v1",
        "test_vector_source": "generated_from_detection_spec", "production_ruleset_modified": False,
        "live_enforcement_mode": "detection_only", "blocking_verified": False,
        "positive_alert_count": 1, "negative_alert_count": 0, "verified_at": "2026-10-17T07:00:00Z",
        "artifacts": {"compiled_rule_sha256": app.canonical_suricata_rule_sha256(compiled)},
    }


class SpecFromRuleTests(unittest.TestCase):
    def test_http_uri_rule_becomes_a_spec(self):
        spec, unsupported, changes = app.detection_spec_from_rule_text(EDITOR_RULE)
        self.assertEqual(unsupported, [])
        self.assertEqual((spec["sid"], spec["uri_contains"], spec["requested_action"]), (9909100, "/editor-only-path", "alert"))
        self.assertEqual(set(changes), {"header_normalized", "nocase_dropped"})

    def test_other_rules_get_reasons(self):
        cases = {
            'alert dns any any -> any any (msg:"x"; dns.query; content:"evil"; sid:9909101; rev:1;)': "protocol_not_http",
            'alert http any any -> any any (msg:"x"; content:"/a"; http.uri; sid:9909102; rev:1;)': "content_not_in_http_uri",
            'alert http any any -> any any (msg:"x"; http.uri; content:"/a"; pcre:"/b/"; sid:9909103; rev:1;)': "unsupported_options:pcre",
            'alert http any any -> any any (msg:"x"; http.uri; content:"|2f|a"; sid:9909104; rev:1;)': "content_not_plain",
            'alert http any any -> any any (msg:"x"; http.uri; content:"/a"; sid:100; rev:1;)': "needs_local_sid",
        }
        for rule, reason in cases.items():
            with self.subTest(reason=reason):
                spec, unsupported, _ = app.detection_spec_from_rule_text(rule)
                self.assertIsNone(spec)
                self.assertIn(reason, unsupported)


class VerifyEditorRuleApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        self.headers = {"X-CSRF-Token": "test-token", "Content-Type": "application/json"}
        self.env = mock.patch.dict(os.environ, {"SURICATA_SENSOR_HOST": "10.0.10.235", "SURICATA_SENSOR_INTERFACE": "ens5"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def post(self, path, body=None):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        return self.client.post(path, data=json.dumps(body or {}), headers=self.headers)

    def test_editor_rule_is_verified_then_stageable(self):
        created = self.post("/api/rules", {
            "name": "Editor URI test", "host": "10.0.10.235", "interface": "ens5",
            "rule": EDITOR_RULE, "enabled": True, "source": "rule_editor",
        })
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        rule_id = created.get_json()["rule"]["id"]
        self.assertNotEqual(self.post(f"/api/rules/{rule_id}/stage").status_code, 200)

        with mock.patch.object(app, "verify_suricata_detection_spec", fake_verifier):
            verified = self.post(f"/api/rules/{rule_id}/verify-text")
        self.assertEqual(verified.status_code, 200, verified.get_data(as_text=True))
        body = verified.get_json()
        self.assertEqual(body["rule"]["verification_status"], "passed")
        self.assertTrue(body["rule_changed"])
        self.assertIn("$HOME_NET $HTTP_PORTS", body["rule"]["rule"])

        staged = self.post(f"/api/rules/{rule_id}/stage")
        self.assertEqual(staged.status_code, 201, staged.get_data(as_text=True))
        self.assertEqual(staged.get_json()["action"]["status"], "pending_approval")

    def test_unverifiable_rule_explains_why(self):
        created = self.post("/api/rules", {
            "name": "DNS test", "host": "10.0.10.235", "interface": "ens5",
            "rule": 'alert dns any any -> any any (msg:"dns test"; dns.query; content:"evil"; sid:9909110; rev:1;)',
            "enabled": True, "source": "rule_editor",
        })
        rule_id = created.get_json()["rule"]["id"]
        response = self.post(f"/api/rules/{rule_id}/verify-text")
        self.assertEqual(response.status_code, 422)
        self.assertIn("protocol_not_http", response.get_json()["unsupported"])


if __name__ == "__main__":
    unittest.main()
