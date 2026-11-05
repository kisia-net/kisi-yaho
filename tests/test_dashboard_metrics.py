"""Dashboard metrics as 전체 / 최근 24시간, over an exact, stated window."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

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
from hawki_alert_analysis.wazuh import WazuhEventRepository  # noqa: E402


class CountingClient:
    """Answers count queries: 7 inside any window, 900 without one."""

    def __init__(self):
        self.bodies = []

    def search(self, index, body):
        self.bodies.append((index, body))
        text = repr(body.get("query"))
        value = 7 if "'gte': '20" in text else 900
        return {"hits": {"total": {"value": value, "relation": "eq"}, "hits": []}}


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.client = CountingClient()
        self.repo = WazuhEventRepository(self.client)
        self.now = datetime(2026, 10, 4, 7, 43, 5, 123456, tzinfo=timezone.utc)
        self.summary = self.repo.dashboard_summary(hours=24, now=self.now)

    def test_the_window_is_exact_and_returned(self):
        self.assertEqual(self.summary["window"], {
            "start": "2026-10-03T07:43:05+00:00", "end": "2026-10-04T07:43:05+00:00", "hours": 24,
        })
        windowed = [body for _, body in self.client.bodies if "2026-10-03T07:43:05+00:00" in repr(body)]
        self.assertGreaterEqual(len(windowed), 4)
        self.assertFalse(any("now-24h" in repr(body) for _, body in self.client.bodies))

    def test_every_metric_has_a_total_beside_the_window(self):
        self.assertEqual(self.summary["alerts_24h"], 7)
        self.assertEqual(self.summary["totals"], {
            "alerts": 900, "level_8_plus": 900, "level_8_plus_attack": 900, "archive_events": 900,
        })


class DashboardRouteTests(unittest.TestCase):
    def test_fixture_dashboard_states_its_window_and_totals(self):
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        body = client.get("/api/dashboard").get_json()
        self.assertIn("alerts", body["totals"])
        self.assertIn("pending_actions", body["totals"])
        start = datetime.fromisoformat(body["window"]["start"])
        end = datetime.fromisoformat(body["window"]["end"])
        self.assertEqual((end - start).total_seconds(), 24 * 3600)
        self.assertIn("pending_actions_24h", body["stats"])


if __name__ == "__main__":
    unittest.main()
