from __future__ import annotations

import unittest
from pathlib import Path

from hawki_alert_analysis.assets import FileAssetInventory
from hawki_alert_analysis.bundle import BUNDLE_SCHEMA
from hawki_alert_analysis.repository import FixtureEventRepository
from hawki_alert_analysis.threat_intel import FileThreatIntelFeed


ROOT = Path(__file__).resolve().parents[1]


def build_repository() -> FixtureEventRepository:
    return FixtureEventRepository(
        ROOT / "data" / "scenarios",
        asset_inventory=FileAssetInventory(ROOT / "data" / "assets"),
        threat_intel_feed=FileThreatIntelFeed(ROOT / "data" / "threat_intel"),
    )


class AlertAnalysisFixtureTests(unittest.TestCase):
    def setUp(self):
        self.repo = build_repository()

    def test_fixture_exposes_alerts(self):
        alerts = self.repo.list_alerts()
        self.assertGreaterEqual(len(alerts), 3)
        self.assertTrue(any("path traversal" in item["title"].lower() for item in alerts))

    def test_every_declared_source_file_loads(self):
        # The Nginx fixture was once excluded by .gitignore, which broke the
        # whole repository on a fresh clone.
        scenario = self.repo._load()[0]
        declared = {source["type"] for source in scenario.manifest["sources"]}
        loaded = {event.source_type for event in scenario.events}
        self.assertEqual(declared, loaded)

    def test_http_status_200_is_not_reinterpreted_as_port_200(self):
        scenario = self.repo._load()[0]
        nginx = next(event for event in scenario.events if event.source_type == "nginx" and "../../" in event.message)
        self.assertEqual(nginx.http["response"]["status_code"], 200)
        self.assertEqual(nginx.destination_port, 80)
        self.assertNotEqual(nginx.destination_port, 200)

    def test_case_correlates_network_web_and_host_evidence(self):
        alert = next(item for item in self.repo.list_alerts() if "path traversal" in item["title"].lower())
        case = self.repo.build_alert_case(alert["id"])
        source_types = {case.trigger.source_type, *(event.source_type for event in case.related_events)}
        self.assertIn("suricata", source_types)
        self.assertIn("nginx", source_types)
        self.assertIn("wazuh", source_types)
        self.assertIn("web-01", case.entities["hosts"])
        self.assertIn("203.0.113.45", case.entities["source_ips"])


class MetadataBundleTests(unittest.TestCase):
    def setUp(self):
        self.repo = build_repository()
        alert = next(
            item for item in self.repo.list_alerts() if "path traversal" in item["title"].lower()
        )
        self.alert_id = alert["id"]
        self.case = self.repo.build_alert_case(self.alert_id)
        self.bundle = self.case.to_llm_context()

    def test_bundle_carries_the_four_metadata_blocks(self):
        self.assertEqual(self.bundle["schema"], BUNDLE_SCHEMA)
        self.assertEqual(
            list(self.bundle["metadata"]),
            ["security_alerts", "security_events", "assets", "threat_intelligence"],
        )
        for block in self.bundle["metadata"].values():
            self.assertTrue(block["description"])

    def test_alert_block_starts_with_the_trigger_and_keeps_raw_records(self):
        alerts = self.bundle["metadata"]["security_alerts"]["items"]
        self.assertEqual(alerts[0]["role"], "trigger")
        self.assertEqual(alerts[0]["id"], self.alert_id)
        self.assertTrue(all(item["event"]["kind"] == "alert" for item in alerts))
        self.assertIn("event.original", alerts[0])

    def test_event_block_holds_non_alert_telemetry_with_originals(self):
        events = self.bundle["metadata"]["security_events"]["items"]
        self.assertTrue(events)
        self.assertTrue(all(item["event"]["kind"] != "alert" for item in events))
        self.assertIn("nginx", {item["source_type"] for item in events})
        self.assertTrue(all("event.original" in item for item in events))

    def test_asset_block_resolves_the_affected_host(self):
        block = self.bundle["metadata"]["assets"]
        web = next(item for item in block["items"] if item["hostname"] == "web-01")
        self.assertEqual(web["criticality"], "high")
        self.assertEqual(web["exposure"], "internet_facing")
        self.assertTrue(web["match"]["on_trigger_alert"])
        self.assertIn("web-01", web["match"]["matched_on"])
        # External addresses have no inventory record and must be reported.
        self.assertIn("203.0.113.45", block["unresolved_identifiers"])

    def test_threat_block_matches_attacker_and_c2_addresses(self):
        block = self.bundle["metadata"]["threat_intelligence"]
        by_value = {item["match"]["matched_value"]: item for item in block["items"]}
        self.assertEqual(by_value["203.0.113.45"]["verdict"], "malicious")
        self.assertTrue(by_value["203.0.113.45"]["match"]["on_trigger_alert"])
        self.assertEqual(by_value["198.51.100.77"]["verdict"], "malicious")
        self.assertIn("T1071", by_value["198.51.100.77"]["mitre_techniques"])
        self.assertGreater(block["coverage"]["observables_checked"], 0)

    def test_expired_indicators_are_not_reported_as_current(self):
        indicators = {
            indicator.value: indicator
            for indicator in self.repo.threat_intel_feed.all_indicators()
        }
        self.assertTrue(indicators["203.0.113.9"].is_expired())
        self.assertFalse(indicators["198.51.100.77"].is_expired())

    def test_blocks_are_cross_referenced_by_event_id(self):
        trigger = self.bundle["metadata"]["security_alerts"]["items"][0]
        self.assertIn("asset-web-01", trigger["links"]["asset_ids"])
        self.assertIn("ti-ipv4-203.0.113.45", trigger["links"]["indicator_ids"])

    def test_counts_match_the_delivered_items(self):
        counts = self.bundle["collection"]["counts"]
        metadata = self.bundle["metadata"]
        self.assertEqual(counts["security_alerts"], len(metadata["security_alerts"]["items"]))
        self.assertEqual(counts["security_events"], len(metadata["security_events"]["items"]))
        self.assertEqual(counts["assets"], len(metadata["assets"]["items"]))
        self.assertEqual(counts["threat_indicators"], len(metadata["threat_intelligence"]["items"]))

    def test_budget_drops_supporting_events_before_alerts_and_says_so(self):
        small = self.case.to_llm_context(max_related=3)
        metadata = small["metadata"]
        self.assertEqual(metadata["security_alerts"]["count"], 4)
        self.assertEqual(metadata["security_events"]["count"], 0)
        self.assertGreater(small["collection"]["omitted_for_size"]["security_events"], 0)
        # Enrichment is never a casualty of the event budget.
        self.assertTrue(metadata["assets"]["items"])
        self.assertTrue(metadata["threat_intelligence"]["items"])

    def test_timeline_is_ordered(self):
        timestamps = [line.split(" | ")[0] for line in self.bundle["timeline"]]
        self.assertEqual(timestamps, sorted(timestamps))


class ObservableExtractionTests(unittest.TestCase):
    def setUp(self):
        self.repo = build_repository()

    def test_uri_and_host_keep_their_semantic_roles(self):
        scenario = self.repo._load()[0]
        event = next(
            item for item in scenario.events
            if item.source_type == "suricata" and item.http.get("request", {}).get("uri")
        )
        observables = event.observables()
        by_field = {item["field"]: item for item in observables}
        self.assertEqual(by_field["http.request.uri"]["type"], "url")
        self.assertEqual(by_field["http.request.uri"]["value"], "/../../../../etc/passwd")
        self.assertEqual(by_field["http.request.host"]["type"], "domain-name")
        self.assertEqual(by_field["http.request.host"]["value"], "portal.example.local")
        # Both endpoints are reported, each keeping its own field.
        self.assertEqual(by_field["source.ip"]["value"], "203.0.113.45")
        self.assertEqual(by_field["destination.ip"]["value"], "192.168.50.20")
        self.assertTrue(all(item["type"] == "ipv4-addr" for item in observables if item["field"].endswith(".ip")))

    def test_lookup_without_configured_collections_is_empty_not_fatal(self):
        bare = FixtureEventRepository(ROOT / "data" / "scenarios")
        alert = next(item for item in bare.list_alerts() if "path traversal" in item["title"].lower())
        bundle = bare.build_alert_case(alert["id"]).to_llm_context()
        self.assertEqual(bundle["metadata"]["assets"]["count"], 0)
        self.assertEqual(bundle["metadata"]["threat_intelligence"]["count"], 0)
        self.assertTrue(bundle["metadata"]["security_alerts"]["items"])


if __name__ == "__main__":
    unittest.main()
