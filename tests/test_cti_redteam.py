"""CTI feeds (blocklist.de, ThreatFox), the CTI status card, the evidence
agent's search_events query, and the red team evaluation status."""

from __future__ import annotations

import json
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
from hawki_alert_analysis.threat_intel import FileThreatIntelFeed  # noqa: E402
from hawki_alert_analysis.wazuh import WazuhEventRepository  # noqa: E402
from tests.test_live_cti import load_importer  # noqa: E402

NOW = datetime(2026, 10, 1, 6, 17, tzinfo=timezone.utc)


class ImporterFeedTests(unittest.TestCase):
    def setUp(self):
        self.importer = load_importer()
        self.dir = Path(tempfile.mkdtemp())

    def test_blocklist_is_suspicious_merged_and_public_only(self):
        lists = {"apache": "# comment\n1.2.3.4\n10.0.0.5\nnot-ip\n", "bruteforcelogin": "1.2.3.4\n5.6.7.8\n"}
        indicators, skipped = self.importer.convert_blocklist(lists, now=NOW)
        self.assertEqual([item["value"] for item in indicators], ["1.2.3.4", "5.6.7.8"])
        first = indicators[0]
        self.assertEqual(first["verdict"], "suspicious")
        self.assertEqual(first["categories"], ["web-attack", "web-login-bruteforce"])
        self.assertEqual(skipped, 2)
        self.assertGreater(first["valid_until"], NOW.isoformat())

    def test_threatfox_types_map_and_ports_are_stripped(self):
        records = [
            {"id": "1", "ioc": "45.95.11.22:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "QakBot", "confidence_level": 90},
            {"id": "2", "ioc": "evil.example.org", "ioc_type": "domain", "confidence_level": 50},
            {"id": "3", "ioc": "ABCDEF" * 10 + "abcd", "ioc_type": "sha256_hash"},
            {"id": "4", "ioc": "192.168.1.1:80", "ioc_type": "ip:port"},
            {"id": "5", "ioc": "x", "ioc_type": "unknown"},
        ]
        indicators, skipped = self.importer.convert_threatfox(records, now=NOW, ttl_days=7)
        found = {(item["type"], item["value"]) for item in indicators}
        self.assertIn(("ipv4-addr", "45.95.11.22"), found)
        self.assertIn(("domain-name", "evil.example.org"), found)
        self.assertIn(("file-hash-sha256", ("ABCDEF" * 10 + "abcd").lower()), found)
        self.assertEqual(skipped, 2)

    def test_no_threatfox_key_skips_only_that_feed(self):
        with mock.patch.dict(os.environ, {"THREATFOX_AUTH_KEY": ""}), \
             mock.patch.object(self.importer, "fetch", side_effect=lambda url, timeout: b"203.0.113.9\n198.51.100.20\n"):
            code = self.importer.main(["--feed", "threatfox", "--dir", str(self.dir), "--env-file", str(self.dir / "none")])
        self.assertEqual(code, 1)
        status = json.loads((self.dir / ".import-status").read_text())
        self.assertEqual(status["feeds"]["threatfox"]["state"], "no_key")

    def test_key_is_read_from_the_env_file(self):
        env_file = self.dir / ".env"
        env_file.write_text("OTHER=1\nTHREATFOX_AUTH_KEY=abc123\n")
        with mock.patch.dict(os.environ, {"THREATFOX_AUTH_KEY": ""}):
            self.assertEqual(self.importer.threatfox_key(env_file), "abc123")

    def test_blocklist_run_writes_its_own_file_and_status(self):
        with mock.patch.object(self.importer, "fetch", return_value=b"8.8.4.4\n"):
            code = self.importer.main(["--feed", "blocklist", "--dir", str(self.dir)])
        self.assertEqual(code, 0)
        feed = FileThreatIntelFeed(self.dir)
        self.assertEqual(feed.lookup("8.8.4.4")[0].verdict, "suspicious")
        self.assertEqual(feed.file_status()[0]["file"], "blocklistde.json")
        self.assertEqual(json.loads((self.dir / ".import-status").read_text())["feeds"]["blocklist"]["state"], "ok")


class Signed(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })


class Indexer:
    def __init__(self, aggregations):
        self.aggregations = aggregations

    def search(self, index, body):
        return {"hits": {"hits": []}, "aggregations": self.aggregations}


class CtiStatusTests(Signed):
    def write_feed(self, root, name, source, values, generated):
        (root / name).write_text(json.dumps({
            "source": source, "generated_at": generated.isoformat(),
            "indicators": [{"id": v, "type": "ipv4-addr", "value": v, "verdict": verdict, "confidence": 80,
                            "valid_until": (generated + timedelta(days=7)).isoformat()} for v, verdict in values],
        }))

    def test_feeds_states_and_24h_matches(self):
        root = Path(tempfile.mkdtemp())
        now = datetime.now(timezone.utc)
        self.write_feed(root, "abusech-feodo.json", "abuse.ch Feodo Tracker", [("45.95.11.22", "malicious")], now)
        self.write_feed(root, "blocklistde.json", "blocklist.de", [("167.86.81.69", "suspicious")], now - timedelta(hours=50))
        (root / ".import-status").write_text(json.dumps({"feeds": {"threatfox": {"file": "abusech-threatfox.json", "state": "no_key"}}}))
        aggregations = {
            "ips": {"buckets": [{"key": "167.86.81.69", "doc_count": 60}, {"key": "1.1.1.1", "doc_count": 5}]},
            "agents": {"buckets": [{"key": "001", "ips": {"buckets": [{"key": "167.86.81.69", "doc_count": 60}]}}]},
        }
        with mock.patch.object(app, "ALERT_REPOSITORY_KIND", "wazuh"), \
             mock.patch.object(app, "LIVE_THREAT_INTEL_ROOT", root), \
             mock.patch.object(app, "LIVE_THREAT_INTEL_FEED", FileThreatIntelFeed(root)), \
             mock.patch.object(app, "SIEM_INDEXER", Indexer(aggregations)):
            data = self.client.get("/api/threat-intel/status").get_json()
        states = {feed["file"]: feed["state"] for feed in data["feeds"]}
        self.assertEqual(states, {"abusech-feodo.json": "ok", "blocklistde.json": "stale", "abusech-threatfox.json": "no_key"})
        self.assertEqual(data["matches_24h"]["alerts"], 60)
        self.assertEqual(data["matches_24h"]["top"][0]["ip"], "167.86.81.69")
        self.assertEqual(data["matches_24h"]["by_agent"], {"001": 60})


class SearchEventsQueryTests(unittest.TestCase):
    def test_fixed_fields_and_a_phrase_never_a_query_string(self):
        captured = []

        class Client:
            def search(self, index, body):
                captured.append((index, body))
                return {"hits": {"hits": []}}

        repository = WazuhEventRepository(Client(), timestamp_field="timestamp")
        repository.search_events(around="2026-10-01T06:55:15+00:00", hours=99, agent_name="web-01",
                                 rule_id="31151", text="/wp-login.php", address="1.2.3.4")
        index, body = captured[0]
        self.assertEqual(index, repository.archive_index)
        text = json.dumps(body)
        self.assertNotIn("query_string", text)
        self.assertIn('"rule.id": "31151"', text)
        self.assertIn('"agent.name": "web-01"', text)
        self.assertEqual(body["query"]["bool"]["must"][0]["multi_match"]["type"], "phrase")
        window = body["query"]["bool"]["filter"][0]["range"]["timestamp"]
        self.assertEqual(window["gte"], "2026-09-30T06:55:15+00:00")  # hours clamped to 24


class RedteamStatusTests(Signed):
    def test_stages(self):
        analysis = "c" * 32
        self.assertEqual(self.client.get(f"/api/redteam/status/{analysis}").get_json()["stage"], "sending")
        app.append_audit("redteam_eval_dispatched", {"analysis_id": analysis, "dispatched": False, "status_code": 400})
        refused = self.client.get(f"/api/redteam/status/{analysis}").get_json()
        self.assertEqual((refused["stage"], refused["status_code"]), ("refused", 400))

        accepted_id = "d" * 32
        app.append_audit("redteam_eval_dispatched", {"analysis_id": accepted_id, "dispatched": True,
                                                     "status_code": 202, "job_id": "6716f0c2a9e4b1d3c5f7a8b9"})
        with mock.patch.object(app, "fetch_job_status", return_value=(200, {"job_id": "6716f0c2a9e4b1d3c5f7a8b9", "status": "running"})):
            accepted = self.client.get(f"/api/redteam/status/{accepted_id}").get_json()
        self.assertEqual((accepted["stage"], accepted["runner"]["status"]), ("accepted", "running"))
        self.assertEqual(self.client.get("/api/redteam/status/not-an-id").status_code, 400)

    def test_recent_lists_analyses_with_their_outcome(self):
        analysis = "e" * 32
        app.append_audit("alert_analysis_completed", {"analysis_id": analysis, "alert_id": "alert-7", "redteam": "send"})
        app.append_audit("redteam_eval_dispatched", {"analysis_id": analysis, "dispatched": True, "status_code": 202, "job_id": "j" * 24})
        data = self.client.get("/api/redteam/recent").get_json()
        item = next(entry for entry in data["items"] if entry["analysis_id"] == analysis)
        self.assertEqual((item["alert_id"], item["dispatch"]["status_code"]), ("alert-7", 202))


if __name__ == "__main__":
    unittest.main()


class AlertSearchPushdownTests(unittest.TestCase):
    """The alert-list search runs in the indexer, not on the 100 rows returned."""

    class Client:
        def __init__(self):
            self.bodies = []

        def search(self, index, body):
            self.bodies.append(body)
            return {"hits": {"hits": [{
                "_id": "cve-free", "_index": "wazuh-alerts-4.x-2026.10.01",
                "_source": {"timestamp": "2026-10-01T06:55:17+00:00",
                            "rule": {"id": "31151", "level": 10, "description": "Multiple web server 400 error codes"},
                            "agent": {"name": "web-01"}, "full_log": "207.175.220.59 - - GET /.amplifyrc 403"},
            }]}}

    def service(self):
        from hawki_alert_analysis.service import AlertAnalysisService
        from hawki_alert_analysis.wazuh import WazuhEventRepository

        client = self.Client()
        return client, AlertAnalysisService(WazuhEventRepository(client))

    @staticmethod
    def text_clause(body):
        for clause in body["query"]["bool"].get("filter", []):
            if "bool" in clause and "should" in clause["bool"]:
                return clause["bool"]["should"]
        return None

    def test_ip_search_reaches_the_indexer_for_all_categories(self):
        client, service = self.service()
        alerts = service.list_alerts(query="207.175.220.59", category="all", since="now-24h", order="level")
        should = self.text_clause(client.bodies[-1])
        self.assertIn({"term": {"data.srcip": "207.175.220.59"}}, should)
        self.assertIn({"match_phrase": {"full_log": "207.175.220.59"}}, should)
        self.assertNotIn("must_not", client.bodies[-1]["query"]["bool"])
        # The indexer already matched; the row is kept even though the
        # address is only in full_log, which the row does not carry.
        self.assertEqual([a["id"] for a in alerts], ["cve-free"])

    def test_query_alone_uses_the_indexer(self):
        client, service = self.service()
        service.list_alerts(query="web-01")
        self.assertIsNotNone(self.text_clause(client.bodies[-1]))

    def test_plain_text_has_no_address_terms_and_is_escaped(self):
        from hawki_alert_analysis.wazuh import alert_text_clause

        should = alert_text_clause("a*b?c")["bool"]["should"]
        self.assertFalse(any("data.srcip" in item.get("term", {}) for item in should))
        wildcard = next(item["wildcard"]["rule.description"] for item in should if "wildcard" in item and "rule.description" in item["wildcard"])
        self.assertEqual(wildcard["value"], "*a\\*b\\?c*")
        self.assertIsNone(alert_text_clause("   "))
        self.assertEqual(len(alert_text_clause("x" * 500)["bool"]["should"][0]["match_phrase"]["full_log"]), 128)

    def test_without_search_no_text_clause(self):
        client, service = self.service()
        service.list_alerts(category="attack", since="now-24h")
        self.assertIsNone(self.text_clause(client.bodies[-1]))


class AlertHistoryRedteamTests(unittest.TestCase):
    def test_history_carries_the_red_team_decision(self):
        source = Path(app.__file__).read_text(encoding="utf-8")
        start = source.index("def api_alert_history")
        self.assertIn('"redteam": detail.get("redteam")', source[start:start + 3000])
