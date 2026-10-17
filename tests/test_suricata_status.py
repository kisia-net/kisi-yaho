"""Sidebar Suricata status: EveBox when configured, otherwise the gateway's /health."""
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

import app  # noqa: E402


class SuricataStatusTargetTests(unittest.TestCase):
    def checked(self, **config):
        seen = {}

        def fake(name, url, path=""):
            seen[name] = (url, path)
            return name, {"ok": True, "configured": bool(url)}

        with mock.patch.dict(app.CONFIG, config), mock.patch.object(app, "check_http_service", fake):
            with app.app.test_request_context("/api/status"):
                app.api_status()
        return seen["suricata"]

    def test_gateway_health_is_used_without_a_ui(self):
        target = self.checked(suricata_ui_url="", suricata_gateway_url="http://10.0.10.235:8095")
        self.assertEqual(target, ("http://10.0.10.235:8095", "/health"))

    def test_ui_wins_when_both_are_set(self):
        target = self.checked(suricata_ui_url="https://10.0.10.235:5636", suricata_gateway_url="http://10.0.10.235:8095")
        self.assertEqual(target, ("https://10.0.10.235:5636", ""))

    def test_neither_stays_unconfigured(self):
        self.assertEqual(self.checked(suricata_ui_url="", suricata_gateway_url="")[0], "")


if __name__ == "__main__":
    unittest.main()


class GatewayFailureReasonTests(unittest.TestCase):
    def dispatch(self, response=None, exc=None):
        record = {"id": "ACT-1", "type": "velociraptor_collection", "payload": {}}

        def fake_post(*args, **kwargs):
            if exc:
                raise exc
            return response

        with mock.patch.dict(app.CONFIG, {"response_actions_enabled": True,
                                          "velociraptor_gateway_url": "http://gw", "velociraptor_gateway_token": "t"}), \
                mock.patch.object(app.requests, "post", fake_post):
            return app.dispatch_action(record)

    def test_gateway_reason_is_kept(self):
        import requests
        response = requests.Response()
        response.status_code = 409
        response._content = b'{"error": "reload_in_progress", "message": "still reloading", "detail": "last change 06:57"}'
        response.url = "http://gw/actions"
        status, result = self.dispatch(response=response)
        self.assertEqual(status, "dispatch_failed")
        self.assertEqual((result["status_code"], result["gateway_error"]), (409, "reload_in_progress"))
        self.assertIn("06:57", result["gateway_detail"])

    def test_unreachable_gateway_is_named(self):
        import requests
        status, result = self.dispatch(exc=requests.ConnectionError("refused"))
        self.assertEqual((status, result["gateway_error"]), ("dispatch_failed", "unreachable"))
