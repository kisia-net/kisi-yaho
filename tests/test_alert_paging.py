"""Alert queue paging, the real total, and the 미처리 / 처리됨 filter."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
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
from hawki_alert_analysis.feedback import FeedbackStore  # noqa: E402
from hawki_alert_analysis.service import AlertAnalysisService  # noqa: E402
from hawki_alert_analysis.wazuh import MAX_RESULT_WINDOW, WazuhEventRepository  # noqa: E402


def hit(number):
    return {
        "_id": f"a{number}", "_index": "wazuh-alerts-4.x-2026.10.10",
        "_source": {"timestamp": f"2026-10-10T06:{number:02d}:00+00:00",
                    "rule": {"id": "31151", "level": 10, "description": "Multiple web server 400 error codes"},
                    "agent": {"name": "web-01"}, "data": {"srcip": "20.204.16.113"}},
    }


class Client:
    def __init__(self, total=1234, relation="eq"):
        self.bodies = []
        self.total = total
        self.relation = relation

    def search(self, index, body):
        self.bodies.append(body)
        size = body.get("size", 0)
        return {"hits": {"total": {"value": self.total, "relation": self.relation},
                         "hits": [hit(n) for n in range(min(size, 3))]}}


class IndexerPagingTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.service = AlertAnalysisService(WazuhEventRepository(self.client))

    def test_a_page_asks_the_indexer_for_its_slice_and_the_exact_total(self):
        result = self.service.page_alerts(since="now-24h", page=3, page_size=50)
        body = self.client.bodies[-1]
        self.assertEqual((body["from"], body["size"]), (100, 50))
        self.assertTrue(body["track_total_hits"])
        self.assertEqual(result["total"], 1234)
        self.assertEqual(result["pages"], 25)
        self.assertEqual(result["page"], 3)
        self.assertTrue(all("priority" in item for item in result["alerts"]))

    def test_open_leaves_out_handled_alerts_in_the_indexer(self):
        self.service.page_alerts(status="open", handled_ids=["x1", "x2"])
        must_not = self.client.bodies[-1]["query"]["bool"]["must_not"]
        self.assertIn({"ids": {"values": ["x1", "x2"]}}, must_not)

    def test_open_keeps_the_attack_category_exclusion(self):
        self.service.page_alerts(category="attack", status="open", handled_ids=["x1"])
        must_not = self.client.bodies[-1]["query"]["bool"]["must_not"]
        self.assertEqual(len(must_not), 2)

    def test_handled_keeps_only_handled_alerts(self):
        self.service.page_alerts(status="handled", handled_ids=["x1"])
        filters = self.client.bodies[-1]["query"]["bool"]["filter"]
        self.assertIn({"ids": {"values": ["x1"]}}, filters)

    def test_paging_stops_at_the_indexer_result_window(self):
        result = self.service.page_alerts(page=1000, page_size=50)
        body = self.client.bodies[-1]
        self.assertLessEqual(body["from"] + body["size"], MAX_RESULT_WINDOW)
        self.assertTrue(result["window_limited"])

    def test_a_lower_bound_total_is_reported_as_such(self):
        self.client.relation = "gte"
        self.assertEqual(self.service.page_alerts()["relation"], "gte")


class AlertListRouteTests(unittest.TestCase):
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
        response = self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        self.assertIn(response.status_code, (200, 302))
        self.ids = [item["id"] for item in app.ALERT_ANALYSIS.list_alerts()]

    def settle(self, alert_id, verdict):
        self.store.record(alert_id=alert_id, alert={}, verdict=verdict, note="", reviewer="analyst",
                          source="alert_analysis", now=datetime.now(timezone.utc))

    def get(self, **params):
        response = self.client.get("/api/alerts", query_string=params)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_pages_cover_every_alert_once_and_the_total_is_real(self):
        first = self.get(page=1, page_size=25)
        self.assertEqual(first["total"], len(self.ids))
        seen = []
        for page in range(1, first["pages"] + 1):
            seen += [item["id"] for item in self.get(page=page, page_size=25)["alerts"]]
        self.assertEqual(sorted(seen), sorted(self.ids))

    def test_settled_alerts_leave_the_open_queue(self):
        self.settle(self.ids[0], "false_positive")
        self.settle(self.ids[1], "investigating")
        open_ids = [item["id"] for item in self.get(status="open", page_size=200)["alerts"]]
        handled = self.get(status="handled", page_size=200)
        self.assertNotIn(self.ids[0], open_ids)
        self.assertIn(self.ids[1], open_ids)  # 추가 조사 stays open
        self.assertEqual([item["id"] for item in handled["alerts"]], [self.ids[0]])
        self.assertEqual(handled["alerts"][0]["handling"]["verdict"], "false_positive")

    def test_a_withdrawn_verdict_reopens_the_alert(self):
        self.settle(self.ids[0], "confirmed")
        self.settle(self.ids[0], "withdrawn")
        open_ids = [item["id"] for item in self.get(status="open", page_size=200)["alerts"]]
        self.assertIn(self.ids[0], open_ids)

    def test_bad_paging_input_is_refused(self):
        for params in ({"page_size": 7}, {"page": "x"}, {"status": "closed"}):
            response = self.client.get("/api/alerts", query_string=params)
            self.assertEqual(response.status_code, 400, params)


if __name__ == "__main__":
    unittest.main()
