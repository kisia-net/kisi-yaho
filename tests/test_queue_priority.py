"""Priority badges in the alert queue come from the same code as analysis."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hawki_alert_analysis.assets import FileAssetInventory, NullAssetInventory
from hawki_alert_analysis.priority import priority_for_alert_item
from hawki_alert_analysis.threat_intel import FileThreatIntelFeed, NullThreatIntelFeed


class QueuePriorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "a").mkdir()
        (root / "t").mkdir()
        (root / "a" / "inv.json").write_text(json.dumps({"assets": [{
            "id": "asset-web", "hostname": "web-01", "ip_addresses": ["10.0.1.201"],
            "criticality": "high", "exposure": "internet_facing",
            "data_classification": "confidential",
        }]}), encoding="utf-8")
        (root / "t" / "feed.json").write_text(json.dumps({"indicators": [{
            "value": "45.95.11.22", "verdict": "malicious", "confidence": 90,
        }]}), encoding="utf-8")
        self.inventory = FileAssetInventory(root / "a")
        self.feed = FileThreatIntelFeed(root / "t")

    def tearDown(self):
        self.tmp.cleanup()

    def test_wazuh_item_uses_level_asset_and_cti(self):
        item = {"rule_level": 5, "host": "web-01", "agent_ip": "10.0.1.201", "source_ip": "45.95.11.22"}
        priority = priority_for_alert_item(item, asset_inventory=self.inventory, threat_intel_feed=self.feed)
        # 20 (level 5) + 18 + 10 + 5 + 20 (CTI on the trigger)
        self.assertEqual(priority["score"], 73)
        self.assertEqual(priority["band"], "P1")
        self.assertEqual(sum(f["points"] for f in priority["factors"]), 73)

    def test_same_alert_without_context_ranks_lower(self):
        item = {"rule_level": 5, "host": "web-01", "agent_ip": "10.0.1.201", "source_ip": "45.95.11.22"}
        priority = priority_for_alert_item(
            item, asset_inventory=NullAssetInventory(), threat_intel_feed=NullThreatIntelFeed()
        )
        self.assertEqual((priority["score"], priority["band"]), (20, "P4"))

    def test_fixture_item_without_level_uses_severity(self):
        item = {"severity": "critical", "host": "web-01"}
        priority = priority_for_alert_item(item, asset_inventory=self.inventory, threat_intel_feed=None)
        self.assertEqual(priority["factors"][0]["factor"], "source_severity")
        self.assertEqual(priority["factors"][0]["points"], 60)


if __name__ == "__main__":
    unittest.main()
