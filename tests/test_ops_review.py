"""2026-10-01 화면 점검 반영분: CVE 경보 분리, 경보 기간·정렬, 감사 로그,
추천 검색 확인, KST, 포괄 인용, 증거 에이전트 건너뛰기, 경보 이전 기록, 호스트 배지."""

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
os.environ.setdefault("WAZUH_API_URL", "https://127.0.0.1:55000")
os.environ.setdefault("WAZUH_API_USERNAME", "test")
os.environ.setdefault("WAZUH_API_PASSWORD", "test")

import app  # noqa: E402
from hawki_alert_analysis.auto_report import AutoReportSettings  # noqa: E402
from hawki_alert_analysis.explain import build_explanation  # noqa: E402
from hawki_alert_analysis.live_bundle import _kst  # noqa: E402
from hawki_alert_analysis.service import AlertAnalysisService  # noqa: E402
from hawki_alert_analysis.siem import SiemService  # noqa: E402
from hawki_alert_analysis.wazuh import WazuhEventRepository  # noqa: E402

from tests.test_auto_report import Harness, alert  # noqa: E402


def hit(doc_id, *, level=10, groups=("web",), time="2026-10-01T05:00:00+00:00"):
    return {"_id": doc_id, "_index": "wazuh-alerts-4.x-2026.10.01", "_source": {
        "timestamp": time, "agent": {"name": "web-01", "id": "001"},
        "rule": {"id": "31151", "level": level, "description": "x", "groups": list(groups)},
    }}


class Client:
    def __init__(self, hits=None, aggregations=None):
        self.bodies = []
        self.hits = hits or []
        self.aggregations = aggregations or {}

    def search(self, index, body):
        self.bodies.append((index, body))
        return {"hits": {"total": {"value": len(self.hits)}, "hits": self.hits}, "aggregations": self.aggregations}


class SignedIn(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })


class AlertListTests(unittest.TestCase):
    def test_attack_category_leaves_cve_findings_out_in_the_indexer(self):
        client = Client([hit("a")])
        WazuhEventRepository(client, timestamp_field="timestamp").list_alerts(category="attack", since="now-24h", order="level")
        body = client.bodies[-1][1]
        self.assertEqual(body["query"]["bool"]["must_not"], [{"terms": {"rule.groups": ["vulnerability-detector"]}}])
        self.assertIn({"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}}, body["query"]["bool"]["filter"])
        self.assertEqual(list(body["sort"][0]), ["rule.level"])

    def test_vulnerability_category_selects_only_cve_findings(self):
        client = Client([hit("v", groups=("vulnerability-detector",))])
        WazuhEventRepository(client, timestamp_field="timestamp").list_alerts(category="vulnerability")
        self.assertIn({"terms": {"rule.groups": ["vulnerability-detector"]}}, client.bodies[-1][1]["query"]["bool"]["filter"])

    def test_default_listing_is_unchanged(self):
        client = Client([hit("a")])
        WazuhEventRepository(client, timestamp_field="timestamp").list_alerts()
        body = client.bodies[-1][1]
        self.assertNotIn("filter", body["query"]["bool"])
        self.assertNotIn("must_not", body["query"]["bool"])
        self.assertEqual(list(body["sort"][0]), ["timestamp"])

    def test_service_passes_the_options_to_a_live_repository(self):
        client = Client([hit("a", level=12), hit("b", level=5)])
        alerts = AlertAnalysisService(WazuhEventRepository(client, timestamp_field="timestamp")).list_alerts(category="attack", since="now-7d", order="level")
        self.assertEqual([item["id"] for item in alerts], ["a", "b"])
        self.assertIn("must_not", client.bodies[-1][1]["query"]["bool"])


class AlertApiTests(SignedIn):
    def test_unknown_category_and_period_are_refused(self):
        self.assertEqual(self.client.get("/api/alerts?category=other").status_code, 400)
        self.assertEqual(self.client.get("/api/alerts?range=2y").status_code, 400)

    def test_options_reach_the_service(self):
        with mock.patch.object(app.ALERT_ANALYSIS, "list_alerts", return_value=[]) as listing:
            response = self.client.get("/api/alerts?category=attack&range=24h&sort=priority&min_level=8")
        self.assertEqual(response.status_code, 200)
        listing.assert_called_once_with(min_level=8, query="", category="attack", since="now-24h", order="level")


class HostFilterTests(SignedIn):
    def test_host_reaches_the_indexer(self):
        client = Client([hit("a")])
        WazuhEventRepository(client, timestamp_field="timestamp").list_alerts(category="vulnerability", host="web-01")
        self.assertIn({"term": {"agent.name": "web-01"}}, client.bodies[-1][1]["query"]["bool"]["filter"])

    def test_api_validates_and_passes_the_host(self):
        self.assertEqual(self.client.get("/api/alerts?host=bad host!").status_code, 400)
        with mock.patch.object(app.ALERT_ANALYSIS, "list_alerts", return_value=[]) as listing:
            self.client.get("/api/alerts?category=vulnerability&range=7d&host=web-01")
        self.assertEqual(listing.call_args.kwargs["host"], "web-01")


class AutoReportExclusionTests(unittest.TestCase):
    def test_cve_findings_are_excluded_by_default(self):
        self.assertEqual(AutoReportSettings.from_env({}).exclude_groups, ("vulnerability-detector",))
        self.assertEqual(AutoReportSettings.from_env({"AUTO_ANALYSIS_EXCLUDE_GROUPS": ""}).exclude_groups, ())

    def test_the_worker_skips_excluded_groups(self):
        harness = Harness()
        cve = alert("cve-1", 10, level=13, rule="23506")
        cve["groups"] = ["vulnerability-detector"]
        attack = alert("atk-1", 20)
        attack["groups"] = ["web", "attack"]
        harness.alerts = [cve, attack]
        summary = harness.reporter.run_cycle()
        self.assertEqual(summary.get("excluded"), 1)
        self.assertNotIn("cve-1", harness.built)
        self.assertIn("atk-1", harness.built)

    def test_the_indexer_read_leaves_them_out(self):
        client = Client([])
        repository = WazuhEventRepository(client, timestamp_field="timestamp")
        with mock.patch.object(app, "ALERT_REPOSITORY", repository):
            from datetime import datetime, timezone
            app.auto_fetch_alerts(datetime(2026, 10, 1, tzinfo=timezone.utc), 8, 50)
        self.assertEqual(client.bodies[-1][1]["query"]["bool"]["must_not"], [{"terms": {"rule.groups": ["vulnerability-detector"]}}])


class AuditTests(SignedIn):
    def test_filters_and_choices(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        response = mock.Mock(status_code=200)
        response.raise_for_status = lambda: None
        response.json = lambda: {"hits": {"total": {"value": 0}, "hits": []}}
        with mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": True}), \
             mock.patch.object(app.requests, "post", return_value=response):
            self.client.post("/api/log-search", json={"query": 'data.srcip:"1.2.3.4"'}, headers={"X-CSRF-Token": "test-token"})
        app.append_audit("login_failed", {"username": "x"})
        data = self.client.get("/api/audit?type=login_failed").get_json()
        self.assertTrue(data["events"])
        self.assertTrue(all(event["event_type"] == "login_failed" for event in data["events"]))
        self.assertIn("wazuh_log_search", data["event_types"])
        self.assertIn("analyst", data["actors"])
        found = self.client.get("/api/audit?q=1.2.3.4").get_json()
        self.assertTrue(all("1.2.3.4" in json.dumps(event) for event in found["events"]))

    def test_failed_sign_in_records_the_browser(self):
        anonymous = app.app.test_client()
        with anonymous.session_transaction() as session:
            session["_csrf_token"] = "t2"
        anonymous.post("/login", data={"username": "nobody", "password": "wrong", "csrf_token": "t2", "next": "/"},
                       headers={"User-Agent": "test-browser/1.0"})
        last = [event for event in app.read_jsonl(app.AUDIT_LOG_PATH) if event["event_type"] == "login_failed"][-1]
        self.assertEqual(last["detail"]["user_agent"], "test-browser/1.0")
        self.assertFalse(last["detail"]["via_proxy"])

    def test_proxy_headers_are_not_trusted_by_default(self):
        self.assertEqual(app.TRUST_PROXY_HOPS, 0)


class SearchCheckTests(SignedIn):
    def check(self, status_code=200, payload=None, **params):
        response = mock.Mock(status_code=status_code)
        response.json = lambda: payload or {}
        response.raise_for_status = lambda: None
        query = {"query": 'data.srcip:"1.2.3.4"', "target": "alerts", "start": "now-24h", "end": "now", **params}
        with mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": True}), \
             mock.patch.object(app.requests, "post", return_value=response) as post:
            result = self.client.get("/api/log-search/check", query_string=query)
        return result, post

    def test_counts_without_documents(self):
        result, post = self.check(payload={"hits": {"total": {"value": 12}}})
        self.assertEqual(result.get_json(), {"status": "ok", "count": 12})
        self.assertEqual(post.call_args.kwargs["json"]["size"], 0)
        last = app.read_jsonl(app.AUDIT_LOG_PATH)[-1]
        self.assertEqual(last["event_type"], "wazuh_log_search_check")
        self.assertEqual(last["detail"]["result_count"], 12)

    def test_an_odd_indexer_reply_is_a_502_not_a_crash(self):
        response = mock.Mock(status_code=200)
        response.json = lambda: ["not", "an", "object"]
        response.raise_for_status = lambda: None
        with mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": True}), \
             mock.patch.object(app.requests, "post", return_value=response):
            result = self.client.get("/api/log-search/check", query_string={"query": "*"})
        self.assertEqual(result.status_code, 502)

    def test_zero_and_parse_errors_are_reported_not_raised(self):
        result, _ = self.check(payload={"hits": {"total": {"value": 0}}})
        self.assertEqual(result.get_json()["status"], "empty")
        result, _ = self.check(status_code=400, payload={"error": {"root_cause": [{"reason": "Failed to parse query"}]}})
        self.assertEqual(result.get_json()["status"], "error")
        self.assertIn("parse", result.get_json()["error"])

    def test_bad_input_is_refused(self):
        self.assertEqual(self.check(target="other")[0].status_code, 400)
        self.assertEqual(self.check(start="2026-10-01T09:00")[0].status_code, 400)
        self.assertEqual(self.check(query="")[0].status_code, 400)


class AlertHistoryTests(SignedIn):
    def test_reports_and_analyses_for_the_alert(self):
        root = Path(tempfile.mkdtemp())
        from hawki_alert_analysis.auto_report import ReportStore
        store = ReportStore(root)
        store.save({"id": "AR-20261001-aaaaaa", "created_at": "2026-10-01T06:00:00+00:00",
                    "alert": {"id": "other"}, "group": {"alert_ids": ["other", "alert-9"], "occurrences": 2},
                    "priority": {"band": "P1"}, "ai": {"status": "completed"}, "review": {"status": "unreviewed"}})
        app.append_audit("alert_analysis_completed", {"alert_id": "alert-9", "analysis_id": "b" * 32, "model": "m"})
        with mock.patch.object(app, "AUTO_REPORT_STORE", store):
            data = self.client.get("/api/alerts/alert-9/history").get_json()
        self.assertEqual(data["reports"][0]["id"], "AR-20261001-aaaaaa")
        self.assertEqual(data["reports"][0]["occurrences"], 2)
        self.assertEqual(data["analyses"][0]["analysis_id"], "b" * 32)
        self.assertEqual(self.client.get("/api/alerts/bad id!/history").status_code, 400)


class ExplanationAndTimeTests(unittest.TestCase):
    def test_a_claim_citing_almost_everything_is_broad(self):
        ids = ["TRIGGER"] + [f"CTX-{n:03d}" for n in range(1, 10)]
        bundle = {"schema": "hawki.wazuh.live-evidence/v2",
                  "trigger": {"evidence_id": "TRIGGER"},
                  "investigation_context": [{"evidence_id": value} for value in ids[1:]]}
        result = {"assessment": {"supporting_evidence": [
            {"statement": "all of it", "event_ids": ids},
            {"statement": "one", "event_ids": ["CTX-003"]},
        ]}}
        explanation = build_explanation(result, bundle)
        self.assertTrue(explanation["claims"][0]["broad"])
        self.assertFalse(explanation["claims"][1]["broad"])
        self.assertEqual(explanation["summary"]["broad"], 1)
        self.assertEqual(explanation["summary"]["evidence_cited"], 10)
        self.assertEqual(explanation["summary"]["evidence_cited_specifically"], 1)

    def test_trigger_time_in_kst(self):
        self.assertEqual(_kst("2026-10-01T06:55:15.000+0000"), "2026-10-01 15:55:15 KST")
        self.assertIsNone(_kst(""))

    def test_prompt_asks_for_runnable_searches_and_kst(self):
        self.assertIn("language` `wazuh`", app.BASE_SYSTEM_PROMPT)
        self.assertIn("KST", app.BASE_SYSTEM_PROMPT)
        self.assertNotIn("Artifact.Windows.Registry", app.OUTPUT_LANGUAGE_DIRECTIVES["ko"])


class HostBadgeTests(unittest.TestCase):
    def test_counts_per_agent(self):
        aggregations = {"by_agent": {"buckets": [{"key": "001", "doc_count": 40, "high": {"doc_count": 3}}]}}
        client = Client(aggregations=aggregations)
        siem = SiemService(client, mock.Mock(), alert_index="wazuh-alerts-*", archive_index="wazuh-archives-*")
        badges = siem.host_badges()
        self.assertEqual(badges["001"]["alerts_24h"], 40)
        self.assertEqual(badges["001"]["high_24h"], 3)
        self.assertEqual(badges["001"]["critical_vulnerabilities"], 40)  # the fake answers both queries alike
        first = client.bodies[0][1]
        self.assertEqual(first["query"]["bool"]["must_not"], [{"terms": {"rule.groups": ["vulnerability-detector"]}}])


if __name__ == "__main__":
    unittest.main()
