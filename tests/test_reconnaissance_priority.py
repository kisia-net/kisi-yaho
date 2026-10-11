"""Reconnaissance and error-response alerts stop at P3 (66 reports, 64 P1)."""

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
from hawki_alert_analysis.assets import FileAssetInventory  # noqa: E402
from hawki_alert_analysis.auto_report import (  # noqa: E402
    AutoReportSettings,
    ReportStore,
    rescored_priority,
    selection_reasons,
)
from hawki_alert_analysis.priority import compute_priority, priority_for_alert_item  # noqa: E402
from hawki_alert_analysis.threat_intel import FileThreatIntelFeed  # noqa: E402

WEB_01 = [{"id": "asset-web", "criticality": "high", "exposure": "internet_facing",
           "data_classification": "confidential",
           "match": {"on_trigger_alert": True, "observed_roles": ["event_host"]}}]
SCAN_31151 = {"rule": {"level": 10, "id": "31151", "groups": ["web", "accesslog", "web_scan", "recon"]},
              "agent": {"name": "web-01"}}


def intel(verdict, on_trigger=True, confidence=50):
    return [{"id": "ind-1", "verdict": verdict, "confidence": confidence,
             "match": {"on_trigger_alert": on_trigger, "matched_value": "52.141.3.247"}}]


class CeilingTests(unittest.TestCase):
    def test_the_web_01_400_error_report_moves_from_p1_79_to_p3(self):
        priority = compute_priority(SCAN_31151, WEB_01, intel_matches=intel("suspicious"))
        # 40 + 18 + 10 + 5 + 6 = 79 before; the cut brings it to the top of P3.
        self.assertEqual((priority["score"], priority["band"]), (49, "P3"))
        cut = priority["factors"][-1]
        self.assertEqual((cut["factor"], cut["points"], cut["kind"]), ("reconnaissance_ceiling", -30, "scan"))
        self.assertEqual(sum(factor["points"] for factor in priority["factors"]), priority["score"])

    def test_a_known_malicious_sender_keeps_the_full_score(self):
        priority = compute_priority(SCAN_31151, WEB_01, intel_matches=intel("malicious", confidence=90))
        self.assertEqual(priority["band"], "P1")
        self.assertNotIn("reconnaissance_ceiling", [factor["factor"] for factor in priority["factors"]])

    def test_malicious_only_in_the_context_does_not_lift_the_cut(self):
        priority = compute_priority(SCAN_31151, WEB_01, intel_matches=intel("malicious", on_trigger=False))
        self.assertEqual(priority["band"], "P3")

    def test_attacks_and_low_scores_are_untouched(self):
        attack = {"rule": {"level": 10, "id": "31153", "groups": ["web", "accesslog", "attack"]}, "agent": {"name": "web-01"}}
        self.assertEqual(compute_priority(attack, WEB_01)["band"], "P1")
        error = {"rule": {"level": 5, "id": "31101", "groups": ["web", "accesslog", "attack"]}, "agent": {"name": "web-01"}}
        low = compute_priority(error, WEB_01)
        # A single 400 response on web-01: 20 + 33 = 53 (P2) before.
        self.assertEqual((low["score"], low["band"]), (49, "P3"))
        self.assertIn("reconnaissance_ceiling", [factor["factor"] for factor in low["factors"]])
        quiet = {"rule": {"level": 5, "id": "31151", "groups": ["web_scan"]}, "agent": {"name": "x"}}
        self.assertNotIn("reconnaissance_ceiling", [f["factor"] for f in compute_priority(quiet, [])["factors"]])

    def test_the_alert_queue_badge_agrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "t").mkdir()
            (root / "a" / "inv.json").write_text(json.dumps({"assets": [{
                "id": "asset-web", "hostname": "web-01", "ip_addresses": ["10.0.1.201"],
                "criticality": "high", "exposure": "internet_facing", "data_classification": "confidential"}]}))
            (root / "t" / "feed.json").write_text(json.dumps({"indicators": []}))
            item = {"rule_level": 10, "rule_id": "31151", "groups": ["web", "accesslog", "web_scan", "recon"],
                    "host": "web-01", "agent_ip": "10.0.1.201", "source_ip": "52.141.3.247"}
            priority = priority_for_alert_item(item, asset_inventory=FileAssetInventory(root / "a"),
                                               threat_intel_feed=FileThreatIntelFeed(root / "t"))
        self.assertEqual(priority["band"], "P3")


class SelectionTests(unittest.TestCase):
    def facts(self, verdict):
        priority = compute_priority(SCAN_31151, WEB_01, intel_matches=intel(verdict, confidence=90))
        return {"priority": priority, "threat_intelligence": [{"verdict": verdict, "expired": False}]}

    def test_a_listed_scanner_alone_does_not_make_a_report(self):
        self.assertEqual(selection_reasons(self.facts("suspicious"), AutoReportSettings()), [])

    def test_a_known_malicious_scanner_still_does(self):
        self.assertEqual(selection_reasons(self.facts("malicious"), AutoReportSettings()),
                         ["priority_P1", "threat_intel_match"])


def stored_report(report_id, created_at, rule_id="31151", groups=("web", "accesslog", "web_scan", "recon")):
    factors = [
        {"factor": "wazuh_rule_level", "value": 10, "points": 40},
        {"factor": "asset_criticality", "value": "high", "points": 18},
        {"factor": "asset_exposure", "value": "internet_facing", "points": 10},
        {"factor": "asset_data_classification", "value": "confidential", "points": 5},
        # Written before the factor carried a verdict: read from the value.
        {"factor": "threat_intel_match", "value": "suspicious (50) 52.141.3.247", "on_trigger": True, "points": 6},
    ]
    return {"schema": "hawki.auto-report/v1", "id": report_id, "created_at": created_at, "updated_at": created_at,
            "alert": {"id": f"al-{report_id}", "rule_id": rule_id, "groups": list(groups), "title": "Multiple web server 400",
                      "level": 10, "host": "web-01"},
            "selection": {"reasons": ["priority_P1", "threat_intel_match"]},
            "group": {"occurrences": 1}, "priority": {"score": 79, "band": "P1", "factors": factors},
            "assets": [], "threat_intelligence": [], "evidence": {}, "ai": {"status": "completed"},
            "review": {"status": "unreviewed"}, "redteam": "not_sent"}


class StoredReportTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.store = ReportStore(Path(self.dir.name) / "reports")
        now = datetime.now(timezone.utc)
        self.store.save(stored_report("AR-20261011-aaaaaa", (now - timedelta(hours=2)).isoformat()))
        self.store.save(stored_report("AR-20261005-bbbbbb", (now - timedelta(days=6)).isoformat(),
                                      rule_id="31153", groups=("web", "accesslog", "attack")))
        self.store.save(stored_report("AR-20260920-cccccc", (now - timedelta(days=21)).isoformat()))
        for target, value in (("AUTO_REPORT_STORE", self.store), ("AUDIT_LOG_PATH", Path(self.dir.name) / "audit.jsonl")):
            patcher = mock.patch.object(app, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_rescoring_uses_the_stored_factors(self):
        report = self.store.get("AR-20261011-aaaaaa")
        new = rescored_priority(report)
        self.assertEqual((new["score"], new["band"]), (49, "P3"))
        again = rescored_priority({**report, "priority": new})
        self.assertEqual(again["factors"], new["factors"])  # replaced, not stacked
        self.assertEqual(rescored_priority(self.store.get("AR-20261005-bbbbbb"))["band"], "P1")

    def test_the_command_is_a_dry_run_until_apply(self):
        runner = app.app.test_cli_runner()
        dry = json.loads(runner.invoke(args=["auto-report-rescore"]).output)
        self.assertEqual((dry["mode"], dry["changed"]), ("dry_run", 2))
        self.assertEqual(dry["bands_before"], {"P1": 3})
        self.assertEqual(dry["bands_after"], {"P1": 1, "P3": 2})
        self.assertEqual(self.store.get("AR-20261011-aaaaaa")["priority"]["band"], "P1")

        applied = json.loads(runner.invoke(args=["auto-report-rescore", "--apply"]).output)
        self.assertEqual(applied["mode"], "applied")
        stored = self.store.get("AR-20261011-aaaaaa")["priority"]
        self.assertEqual(stored["band"], "P3")
        self.assertEqual(stored["rescored"]["from"], {"score": 79, "band": "P1"})
        self.assertEqual(json.loads(runner.invoke(args=["auto-report-rescore"]).output)["changed"], 0)


class RangeTests(StoredReportTests):
    def setUp(self):
        super().setUp()
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })

    def get(self, **params):
        response = self.client.get("/api/auto-reports", query_string=params)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_the_period_narrows_the_list_and_the_counts(self):
        self.assertEqual(self.get()["counts"]["total"], 3)
        day = self.get(range="24h")
        self.assertEqual((day["range"], day["counts"]["total"], day["counts"]["unreviewed"]), ("24h", 1, 1))
        self.assertEqual([item["id"] for item in day["reports"]], ["AR-20261011-aaaaaa"])
        self.assertEqual(self.get(range="7d")["counts"]["total"], 2)
        self.assertEqual(self.client.get("/api/auto-reports?range=1y").status_code, 400)

    def test_the_dashboard_card_count_matches_the_page_it_opens(self):
        stages = {stage["id"]: stage for stage in self.client.get("/api/dashboard/flow").get_json()["stages"]}
        self.assertEqual(stages["selected"]["link"], "/auto-reports?range=24h")
        self.assertEqual(stages["selected"]["count"], self.get(range="24h")["counts"]["total"])
        self.assertEqual(stages["analysis"]["link"], "/redteam?range=24h")
        page = self.client.get("/auto-reports").get_data(as_text=True)
        self.assertIn('name="range"', page)


if __name__ == "__main__":
    unittest.main()
