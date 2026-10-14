"""Wazuh 대시보드 시각화와 같은 집계 (hawki_alert_analysis/wazuh_visuals.py)."""

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

import app  # noqa: E402
from hawki_alert_analysis.wazuh_visuals import block_pass_verdict, parse_visuals, visuals_query  # noqa: E402


def ip_bucket(ip, total, **signals):
    bucket = {"key": ip, "doc_count": total, "last_seen": {"value_as_string": "2026-10-12T23:17:04.008Z"}}
    for key in ("waf", "status_4xx", "status_5xx", "status_2xx", "success_rule"):
        bucket[key] = {"doc_count": signals.get(key, 0)}
    return bucket


PAYLOAD = {
    "aggregations": {
        "activity": {"buckets": [
            {"key_as_string": "2026-10-12T22:00:00.000Z", "doc_count": 9, "bands": {"buckets": [
                {"key": "low", "doc_count": 6}, {"key": "mid", "doc_count": 2}, {"key": "high", "doc_count": 1},
            ]}},
        ]},
        "web": {
            "by_ip": {"buckets": [
                ip_bucket("134.185.93.91", 50, waf=10, status_4xx=40),
                ip_bucket("52.141.3.247", 17, waf=3, status_4xx=13, status_2xx=1, success_rule=1),
            ]},
            "success": {"by_ip": {"buckets": [
                ip_bucket("52.141.3.247", 2, status_2xx=1, success_rule=1),
                ip_bucket("198.51.100.9", 1, status_2xx=1),
            ]}, "ip_count": {"value": 2}},
            "ip_count": {"value": 41},
            "statuses": {"buckets": [{"key": "404", "doc_count": 76}, {"key": "200", "doc_count": 1}]},
            "urls": {"buckets": [{"key": "/.env", "doc_count": 32, "sources": {"value": 4}}]},
        },
        "mitre": {"tactics": {"buckets": [
            {"key": "Discovery", "doc_count": 33, "techniques": {"buckets": [
                {"key": "File and Directory Discovery", "doc_count": 33},
            ]}},
        ]}},
    }
}


class QueryTests(unittest.TestCase):
    def test_one_query_with_the_same_conditions_as_the_saved_objects(self):
        body = visuals_query(timestamp_field="timestamp", since="now-24h")
        self.assertEqual(body["size"], 0)
        aggs = body["aggs"]
        self.assertEqual(aggs["activity"]["date_histogram"]["fixed_interval"], "1h")
        ranges = aggs["activity"]["aggs"]["bands"]["range"]["ranges"]
        self.assertEqual([item["key"] for item in ranges], ["low", "mid", "high"])
        self.assertEqual(ranges[1], {"key": "mid", "from": 7, "to": 10})
        self.assertNotIn("to", ranges[2])
        by_ip = aggs["web"]["aggs"]["by_ip"]["aggs"]
        self.assertEqual(by_ip["status_2xx"], {"filter": {"prefix": {"data.id": "2"}}})
        self.assertEqual(by_ip["success_rule"], {"filter": {"terms": {"rule.id": ["31106"]}}})
        self.assertEqual(
            aggs["mitre"]["filter"],
            {"bool": {"must_not": [{"terms": {"rule.groups": ["vulnerability-detector"]}}]}},
        )


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.visuals = parse_visuals(PAYLOAD)

    def test_activity_keeps_the_total_and_the_bands(self):
        self.assertEqual(self.visuals["activity"], [{
            "time": "2026-10-12T22:00:00.000Z", "count": 9, "bands": {"low": 6, "mid": 2, "high": 1},
        }])

    def test_a_success_signal_means_passed_and_sorts_first(self):
        rows = self.visuals["block_pass"]
        self.assertEqual([row["ip"] for row in rows], ["52.141.3.247", "198.51.100.9", "134.185.93.91"])
        self.assertEqual(rows[0]["verdict"], "passed")
        self.assertEqual(rows[0]["alerts"], 17, "the full bucket wins over the success-only one")
        self.assertTrue(rows[1]["partial"])
        self.assertEqual(rows[2]["verdict"], "blocked")
        self.assertEqual(self.visuals["block_pass_summary"], {"passed": 2, "blocked": 1, "observed": 0})
        self.assertEqual(self.visuals["block_pass_totals"], {"shown_ips": 3, "web_ips": 41, "passed_ips": 2, "ip_limit": 10})

    def test_verdict_rules(self):
        self.assertEqual(block_pass_verdict({"waf": 3, "status_2xx": 0}), "blocked")
        self.assertEqual(block_pass_verdict({"status_4xx": 1}), "blocked")
        self.assertEqual(block_pass_verdict({"success_rule": 1}), "passed")
        self.assertEqual(block_pass_verdict({}), "observed")

    def test_statuses_urls_and_mitre(self):
        self.assertEqual(self.visuals["statuses"][0], {"code": "404", "count": 76})
        self.assertEqual(self.visuals["urls"], [{"url": "/.env", "count": 32, "sources": 4}])
        self.assertEqual(self.visuals["mitre"][0]["techniques"][0]["count"], 33)

    def test_empty_payload(self):
        empty = parse_visuals({})
        self.assertEqual((empty["activity"], empty["block_pass"], empty["mitre"]), ([], [], []))


class RouteTests(unittest.TestCase):
    def login(self):
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        return client

    def test_fixture_repository_says_it_is_unavailable(self):
        if isinstance(app.ALERT_REPOSITORY, app.WazuhEventRepository):
            self.skipTest("live repository configured")
        body = self.login().get("/api/dashboard/wazuh-visuals").get_json()
        self.assertEqual(body, {"source": "fixture_repository", "available": False})

    def test_live_repository_is_cached_for_a_minute(self):
        calls = []

        def fake(*, hours):
            calls.append(hours)
            return {"hours": hours, "activity": []}

        app._wazuh_visuals_cache.clear()
        client = self.login()
        with mock.patch.object(app, "ALERT_REPOSITORY", app.WazuhEventRepository(object())), \
                mock.patch.object(app.SIEM, "wazuh_visuals", side_effect=fake):
            first = client.get("/api/dashboard/wazuh-visuals").get_json()
            second = client.get("/api/dashboard/wazuh-visuals").get_json()
        app._wazuh_visuals_cache.clear()
        self.assertEqual(calls, [24])
        self.assertTrue(first["available"])
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
