"""출처 흐름: sensor -> detection type -> priority."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
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
from hawki_alert_analysis.service import AlertAnalysisService  # noqa: E402
from hawki_alert_analysis.source_flow import build, classify, exclusive_filters, SOURCES  # noqa: E402
from hawki_alert_analysis.wazuh import WazuhEventRepository  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_wazuh_groups_pick_source_and_type(self):
        self.assertEqual(classify({"groups": ["vulnerability-detector"]}), ("vulnerability", "cve"))
        self.assertEqual(classify({"groups": ["ids", "suricata"], "decoder": "json"}), ("suricata", "ids"))
        self.assertEqual(classify({"groups": ["nginx", "web", "modsecurity"]}), ("modsecurity", "web_attack"))
        self.assertEqual(classify({"groups": ["syslog", "sshd", "authentication_failures"]}), ("ssh", "auth"))
        self.assertEqual(classify({"groups": ["web", "accesslog", "web_scan", "recon"]}), ("web", "scan"))
        self.assertEqual(classify({"groups": ["web", "accesslog", "attack"]}), ("web", "web_attack"))
        self.assertEqual(classify({"groups": []}), ("other", "other"))
        # Wazuh puts 31101 (400 error) in "attack"; it is an error response.
        self.assertEqual(classify({"groups": ["web", "accesslog", "attack"], "rule_id": "31101"}), ("web", "web_error"))
        self.assertEqual(classify({"groups": ["web", "appsec", "attack"], "rule_id": "31516"}), ("web", "web_attack"))

    def test_fixture_items_use_their_source_type(self):
        self.assertEqual(classify({"source": "suricata"})[0], "suricata")

    def test_indexer_filters_are_exclusive_in_spec_order(self):
        filters = exclusive_filters(SOURCES)
        self.assertEqual(list(filters)[-1], "other")
        self.assertEqual(filters[SOURCES[0][0]]["bool"]["must_not"], [])
        self.assertEqual(len(filters[SOURCES[2][0]]["bool"]["must_not"]), 2)
        self.assertEqual(len(filters["other"]["bool"]["must_not"]), len(SOURCES))


class BuildTests(unittest.TestCase):
    def test_links_balance_and_empty_entries_are_left_out(self):
        flow = build(
            source_type={("web", "scan"): 400, ("web", "web_attack"): 70, ("vulnerability", "cve"): 260},
            type_below={"scan": 380, "web_attack": 40, "cve": 100},
            type_band={("scan", "P1"): 5, ("scan", "P3"): 15, ("web_attack", "P2"): 30, ("cve", "P1"): 160},
            type_unscored={},
        )
        nodes = {node["id"]: node for node in flow["nodes"]}
        self.assertEqual(nodes["t:scan"]["value"], 400)
        self.assertEqual(nodes["p:below_8"]["value"], 520)
        self.assertNotIn("s:suricata", nodes)
        self.assertEqual(flow["total"], 730)
        self.assertEqual(flow["urgent"], 195)
        self.assertEqual([column["key"] for column in flow["table"]["columns"]], ["cve", "scan", "web_attack"])


def hit(number, level, groups):
    return {"_id": f"a{number}", "_index": "wazuh-alerts-4.x-2026.10.11",
            "_source": {"timestamp": "2026-10-11T06:00:00+00:00", "agent": {"name": "web-01"},
                        "rule": {"id": "31151", "level": level, "groups": groups, "description": "x"},
                        "data": {"srcip": "20.204.16.113"}}}


class IndexerTests(unittest.TestCase):
    def test_one_aggregation_and_the_level_8_alerts_for_priority(self):
        bodies = []

        class Client:
            def search(self, index, body):
                bodies.append(body)
                if body.get("aggs"):
                    level = lambda below, above: {"buckets": [{"key": "below_8", "doc_count": below},
                                                              {"key": "8_plus", "doc_count": above}]}
                    return {"hits": {"total": {"value": 12}}, "aggregations": {"sources": {"buckets": {
                        "web": {"doc_count": 10, "types": {"buckets": {
                            "scan": {"doc_count": 8, "levels": level(6, 2)},
                            "web_attack": {"doc_count": 2, "levels": level(2, 0)},
                            "cve": {"doc_count": 0, "levels": level(0, 0)}}}},
                        "vulnerability": {"doc_count": 2, "types": {"buckets": {
                            "cve": {"doc_count": 2, "levels": level(0, 2)}}}},
                    }}}}
                return {"hits": {"total": {"value": 4, "relation": "eq"}, "hits": [
                    hit(1, 10, ["web", "accesslog", "web_scan"]), hit(2, 10, ["web", "accesslog", "web_scan"]),
                    hit(3, 13, ["vulnerability-detector"]), hit(4, 12, ["vulnerability-detector"])]}}

        service = AlertAnalysisService(WazuhEventRepository(Client()))
        end = datetime(2026, 10, 11, 7, tzinfo=timezone.utc)
        flow = service.source_flow(start=end - timedelta(hours=24), end=end)
        self.assertEqual(flow["total"], 12)
        self.assertEqual(flow["level8_total"], 4)
        self.assertEqual(flow["scored"], 4)
        targets = {node["key"]: node["value"] for node in flow["nodes"] if node["column"] == 2}
        self.assertEqual(targets["below_8"], 8)
        self.assertEqual(sum(value for key, value in targets.items() if key.startswith("P")), 4)
        self.assertNotIn("unscored", targets)
        self.assertEqual({row["source"]: row["level_8_plus"] for row in flow["table"]["rows"]}, {"web": 2, "vulnerability": 2})
        self.assertTrue(all("now-" not in repr(body) for body in bodies))


class RouteTests(unittest.TestCase):
    def test_fixture_dashboard_has_a_source_flow_and_caches_it(self):
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        app._source_flow_cache.clear()
        first = client.get("/api/dashboard/source-flow")
        self.assertEqual(first.status_code, 200)
        body = first.get_json()
        self.assertEqual(body["total"], len(app.ALERT_ANALYSIS.list_alerts()))
        self.assertTrue(body["nodes"])
        with mock.patch.object(app.ALERT_ANALYSIS, "source_flow", side_effect=AssertionError("cached")):
            self.assertEqual(client.get("/api/dashboard/source-flow").status_code, 200)
        app._source_flow_cache.clear()


if __name__ == "__main__":
    unittest.main()
