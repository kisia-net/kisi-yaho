"""Host status bar: attack activity and exposure kept apart (10주차 멘토링 3번)."""

from __future__ import annotations

import unittest

from hawki_alert_analysis.siem import host_health


class HostHealthTests(unittest.TestCase):
    def test_attacked_and_exposed_is_danger(self):
        health = host_health({"high_24h": 26, "critical_vulnerabilities": 219})
        self.assertEqual((health["state"], health["label"]), ("danger", "위험"))
        self.assertIn("최근 24시간 레벨 10 이상 공격 경보 26건", health["reasons"])
        self.assertIn("치명 취약점 219건", health["reasons"])

    def test_either_alone_is_warning(self):
        self.assertEqual(host_health({"high_24h": 3})["state"], "warning")
        self.assertEqual(host_health({"critical_vulnerabilities": 1})["state"], "warning")

    def test_high_findings_only_is_watch(self):
        self.assertEqual(host_health({"high_vulnerabilities": 5, "alerts_24h": 40})["state"], "watch")

    def test_nothing_serious_is_healthy_even_with_ordinary_alerts(self):
        health = host_health({"alerts_24h": 120})
        self.assertEqual((health["state"], health["label"]), ("healthy", "양호"))
        self.assertTrue(health["reasons"])

    def test_levels_order_the_bar(self):
        levels = [host_health(badge)["level"] for badge in (
            {"high_24h": 1, "critical_vulnerabilities": 1}, {"high_24h": 1}, {"high_vulnerabilities": 1}, {},
        )]
        self.assertEqual(levels, sorted(levels, reverse=True))


class BadgeSeverityTests(unittest.TestCase):
    def test_critical_and_high_are_counted_apart(self):
        from hawki_alert_analysis.siem import SiemService

        class Indexer:
            def search(self, index, body):
                if "vulnerabilities" in index:
                    return {"aggregations": {"by_agent": {"buckets": [{
                        "key": "001", "doc_count": 260,
                        "severity": {"buckets": [{"key": "Critical", "doc_count": 219},
                                                 {"key": "High", "doc_count": 41}]},
                    }]}}}
                return {"aggregations": {"by_agent": {"buckets": [
                    {"key": "001", "doc_count": 80, "high": {"doc_count": 26}},
                ]}}}

        service = SiemService.__new__(SiemService)
        service.indexer = Indexer()
        service.alert_index = "wazuh-alerts-*"
        service.timestamp_field = "timestamp"
        badge = service.host_badges()["001"]
        self.assertEqual((badge["critical_vulnerabilities"], badge["high_vulnerabilities"]), (219, 41))
        self.assertEqual(badge["health"]["state"], "danger")


if __name__ == "__main__":
    unittest.main()
