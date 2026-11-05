"""Threat intelligence on the live Wazuh path, and the feed importer."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from hawki_alert_analysis.assets import NullAssetInventory
from hawki_alert_analysis.live_bundle import build_live_evidence_bundle
from hawki_alert_analysis.threat_intel import (
    FileThreatIntelFeed,
    NullThreatIntelFeed,
    live_observables,
)

ROOT = Path(__file__).resolve().parents[1]

BAD_IP = "45.95.11.22"
OLD_IP = "45.95.11.33"
SKETCHY_IP = "45.95.11.44"


def indicator(value, *, verdict="malicious", confidence=90, valid_until="2099-01-01T00:00:00+00:00"):
    return {
        "id": f"t-{value}",
        "type": "ipv4-addr",
        "value": value,
        "verdict": verdict,
        "confidence": confidence,
        "valid_until": valid_until,
        "description": "test indicator",
    }


class FakeRepository:
    def __init__(self, feed, *, trigger_ip=BAD_IP, context_ip="10.0.10.5"):
        self.asset_inventory = NullAssetInventory()
        self.threat_intel_feed = feed
        self.trigger = {
            "id": "a1",
            "index": "wazuh-alerts-4.x-2026.09.30",
            "timestamp": "2026-09-30T05:00:00.000+0000",
            "agent": {"id": "001", "name": "web-01", "ip": "10.0.1.201"},
            "rule": {"id": "31106", "level": 5},
            "decoder": {"name": "web-accesslog"},
            "location": "/var/log/nginx/access.log",
            "data": {"srcip": trigger_ip, "url": "/../../etc/passwd"},
            "full_log": f"{trigger_ip} GET /../../etc/passwd",
        }
        self.context_ip = context_ip

    def get_alert_record(self, alert_id):
        return self.trigger

    def get_alert_context(self, alert_id, *, limit=20):
        return {
            "archive_index": "wazuh-archives-*",
            "window_seconds": 300,
            "candidate_count": 1,
            "suppressed_routine_count": 0,
            "events": [{
                "id": "c1",
                "index": "wazuh-archives-4.x-2026.09.30",
                "timestamp": "2026-09-30T05:00:02.000+0000",
                "agent": {"id": "002", "name": "vm", "ip": "10.0.10.235"},
                "rule": {},
                "decoder": {"name": "json"},
                "location": "/var/log/suricata/eve.json",
                "data": {"src_ip": "10.0.1.201", "dest_ip": self.context_ip},
                "full_log": "",
                "relevance_score": 4,
                "relevance_reasons": ["wazuh_detection"],
                "delta_seconds": 2.0,
            }],
        }


class LiveCtiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.write_feed([
            indicator(BAD_IP),
            indicator(OLD_IP, valid_until="2020-01-01T00:00:00+00:00"),
            indicator(SKETCHY_IP, verdict="suspicious", confidence=50),
        ])
        self.feed = FileThreatIntelFeed(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def write_feed(self, indicators):
        (self.root / "feed.json").write_text(
            json.dumps({"source": "test", "indicators": indicators}), encoding="utf-8"
        )

    def factor(self, bundle):
        for item in bundle["priority"]["factors"]:
            if item["factor"] == "threat_intel_match":
                return item
        return None

    def test_trigger_hit_adds_twenty_and_cites_evidence(self):
        bundle = build_live_evidence_bundle(FakeRepository(self.feed), "a1")
        intel = bundle["threat_intelligence"]
        self.assertTrue(intel["feed_configured"])
        self.assertEqual(intel["matches"][0]["value"], BAD_IP)
        self.assertEqual(intel["matches"][0]["match"]["observed_in_event_ids"], ["TRIGGER"])
        self.assertEqual(self.factor(bundle)["points"], 20)
        # level 5 (20) + CTI (20); no inventory, so no asset factors.
        self.assertEqual(bundle["priority"]["score"], 40)

    def test_context_only_hit_is_halved(self):
        repo = FakeRepository(self.feed, trigger_ip="10.9.9.9", context_ip=BAD_IP)
        bundle = build_live_evidence_bundle(repo, "a1")
        self.assertEqual(self.factor(bundle)["points"], 10)
        self.assertFalse(self.factor(bundle)["on_trigger"])

    def test_expired_indicator_is_reported_but_not_scored(self):
        bundle = build_live_evidence_bundle(FakeRepository(self.feed, trigger_ip=OLD_IP), "a1")
        self.assertTrue(bundle["threat_intelligence"]["matches"][0]["match"]["indicator_expired"])
        self.assertIsNone(self.factor(bundle))

    def test_suspicious_scores_less_than_malicious(self):
        bundle = build_live_evidence_bundle(FakeRepository(self.feed, trigger_ip=SKETCHY_IP), "a1")
        self.assertEqual(self.factor(bundle)["points"], 6)

    def test_only_the_strongest_match_counts(self):
        repo = FakeRepository(self.feed, trigger_ip=BAD_IP, context_ip=SKETCHY_IP)
        bundle = build_live_evidence_bundle(repo, "a1")
        factors = [f for f in bundle["priority"]["factors"] if f["factor"] == "threat_intel_match"]
        self.assertEqual(len(factors), 1)
        self.assertEqual(factors[0]["points"], 20)

    def test_address_in_free_text_is_not_looked_up(self):
        # Red-team angle: planting a known-bad IP in a log message or URL path
        # must not manufacture an intelligence hit. Only structured fields count.
        repo = FakeRepository(self.feed, trigger_ip="10.9.9.9")
        repo.trigger["full_log"] = f"GET /?next={BAD_IP} {BAD_IP}"
        repo.trigger["data"]["url"] = f"/redirect?to={BAD_IP}"
        bundle = build_live_evidence_bundle(repo, "a1")
        self.assertEqual(bundle["threat_intelligence"]["matches"], [])

    def test_no_feed_means_not_configured(self):
        repo = FakeRepository(NullThreatIntelFeed())
        bundle = build_live_evidence_bundle(repo, "a1")
        self.assertFalse(bundle["threat_intelligence"]["feed_configured"])
        self.assertIsNone(self.factor(bundle))

    def test_feed_refresh_is_picked_up_without_restart(self):
        self.feed.RESCAN_SECONDS = 0
        self.assertEqual(self.feed.lookup("45.95.11.55"), [])
        self.write_feed([indicator("45.95.11.55")])
        self.assertEqual(len(self.feed.lookup("45.95.11.55")), 1)

    def test_sysmon_hashes_and_suricata_names_are_observables(self):
        item = {"data": {
            "win": {"eventdata": {"hashes": "SHA256=AAAA,MD5=BBBB"}},
            "dns": {"rrname": "c2.example.net."},
            "http": {"hostname": "evil.example.org", "url": "/x"},
        }}
        found = {(o["type"], o["value"]) for o in live_observables(item)}
        self.assertIn(("file-hash-sha256", "aaaa"), found)
        self.assertIn(("file-hash-md5", "bbbb"), found)
        self.assertIn(("domain-name", "c2.example.net"), found)
        self.assertIn(("domain-name", "evil.example.org"), found)
        self.assertNotIn(("url", "/x"), found)


def load_importer():
    spec = importlib.util.spec_from_file_location("import_cti", ROOT / "tools" / "import_cti.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["import_cti"] = module
    spec.loader.exec_module(module)
    return module


class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.importer = load_importer()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_converts_filters_and_loads_in_the_app_format(self):
        records = [
            {"ip_address": "45.95.11.22", "port": 443, "status": "online", "malware": "QakBot",
             "first_seen": "2026-09-01 10:00:00", "last_online": "2026-09-29"},
            {"ip_address": "45.95.11.22", "port": 8080, "status": "offline", "malware": "QakBot"},
            {"ip_address": "45.95.11.23", "port": 447, "status": "offline", "malware": "Emotet"},
            {"ip_address": "10.0.10.123", "status": "online"},   # private: must never enter
            {"ip_address": "not-an-ip"},
        ]
        source = self.dir / "feodo.json"
        source.write_text(json.dumps(records), encoding="utf-8")
        output = self.dir / "live" / "abusech-feodo.json"

        self.assertEqual(self.importer.main(["--input", str(source), "--output", str(output)]), 0)

        feed = FileThreatIntelFeed(output.parent)
        values = sorted(i.value for i in feed.all_indicators())
        self.assertEqual(values, ["45.95.11.22", "45.95.11.23"])
        online = feed.lookup("45.95.11.22")[0]
        self.assertEqual(online.confidence, 90)  # the online entry wins the duplicate
        self.assertFalse(online.is_expired(datetime.now(timezone.utc)))
        self.assertEqual(feed.lookup("10.0.10.123"), [])

    def test_empty_download_keeps_the_existing_file(self):
        output = self.dir / "abusech-feodo.json"
        output.write_text('{"indicators": [{"value": "45.95.11.22"}]}', encoding="utf-8")
        source = self.dir / "empty.json"
        source.write_text("[]", encoding="utf-8")
        self.assertEqual(self.importer.main(["--input", str(source), "--output", str(output)]), 1)
        self.assertIn("45.95.11.22", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
