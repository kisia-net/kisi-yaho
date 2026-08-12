from __future__ import annotations

import unittest
from pathlib import Path

from hawki_alert_analysis.repository import FixtureEventRepository


ROOT = Path(__file__).resolve().parents[1]


class AlertAnalysisFixtureTests(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureEventRepository(ROOT / "data" / "scenarios")

    def test_fixture_exposes_alerts(self):
        alerts = self.repo.list_alerts()
        self.assertGreaterEqual(len(alerts), 3)
        self.assertTrue(any("path traversal" in item["title"].lower() for item in alerts))

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


if __name__ == "__main__":
    unittest.main()
