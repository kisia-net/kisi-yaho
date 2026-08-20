"""Tests for building a scenario from a directory of collected logs."""

from __future__ import annotations

import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from hawki_alert_analysis.ingest import build_manifest, detect_sources, sniff_source_type, write_scenario
from hawki_alert_analysis.repository import FixtureEventRepository

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data" / "scenarios" / "web_path_traversal"

AUTH_LOG = """Aug 11 10:20:44 web-01 sshd[3120]: Failed password for invalid user admin from 203.0.113.45 port 51704 ssh2
Aug 11 10:21:09 web-01 sudo:  www-data : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c id
*** log rotated ***
"""

APACHE_LOG = (
    '203.0.113.45 - - [11/Aug/2026:10:21:03 +0000] "GET /../../../../etc/passwd HTTP/1.1" '
    '200 421 "-" "curl/8.5.0"\n'
)


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="hawki-ingest-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def write(self, name: str, content: str) -> Path:
        path = self.dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_producer_name_beats_generic_format_name(self):
        path = self.write("apache_access.log", APACHE_LOG)
        source_type, reason = sniff_source_type(path)
        self.assertEqual(source_type, "apache")
        self.assertIn("apache", reason)

    def test_generic_access_log_falls_back_to_nginx(self):
        source_type, _ = sniff_source_type(self.write("access.log", APACHE_LOG))
        self.assertEqual(source_type, "nginx")

    def test_content_sniffing_when_the_name_says_nothing(self):
        eve = self.write("unnamed-1", (FIXTURE / "suricata_eve.jsonl").read_text(encoding="utf-8"))
        source_type, reason = sniff_source_type(eve)
        self.assertEqual(source_type, "suricata")
        self.assertIn("EVE", reason)

        wazuh = self.write("unnamed-2", (FIXTURE / "wazuh_alerts.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(sniff_source_type(wazuh)[0], "wazuh")

        syslog = self.write("unnamed-3", AUTH_LOG)
        self.assertEqual(sniff_source_type(syslog)[0], "syslog")

        combined = self.write("unnamed-4", APACHE_LOG)
        self.assertEqual(sniff_source_type(combined)[0], "nginx")

    def test_unreadable_files_are_reported_not_dropped_silently(self):
        self.write("notes.txt", "just some prose\n")
        self.write("empty.log", "")
        self.write("broken.json", '{"not": "a known producer"}\n')
        detected, unclassified, _ = detect_sources(self.dir)
        self.assertEqual(detected, [])
        joined = " ".join(unclassified)
        for name in ("notes.txt", "empty.log", "broken.json"):
            self.assertIn(name, joined)

    def test_suricata_own_output_is_named_not_reported_as_unreadable(self):
        # A Suricata run leaves these beside eve.json. Reporting them as
        # unreadable buries the one line that matters in a failed collection.
        self.write("fast.log", "")
        self.write("suricata.log", "16/8/2026 -- 14:42:44 - <Info> -- Loading suricata.yaml\n")
        self.write("stats.log", "Date: 8/16/2026 -- 14:43:29 (uptime: 0d, 00h 00m 00s)\n")
        self.write("eve.json", '{"timestamp":"2026-08-11T14:03:01.1+0000","event_type":"stats"}\n')

        detected, unclassified, non_telemetry = detect_sources(self.dir)
        self.assertEqual([source.path.name for source in detected], ["eve.json"])
        self.assertEqual(unclassified, [])
        named = " ".join(non_telemetry)
        for name in ("fast.log", "suricata.log", "stats.log"):
            self.assertIn(name, named)

    def test_scenario_and_label_files_are_not_treated_as_logs(self):
        self.write("scenario.json", "{}")
        self.write("labels.json", "{}")
        self.write("auth.log", AUTH_LOG)
        detected, unclassified, _ = detect_sources(self.dir)
        self.assertEqual([source.path.name for source in detected], ["auth.log"])
        self.assertEqual(unclassified, [])


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="hawki-ingest-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        (self.dir / "auth.log").write_text(AUTH_LOG, encoding="utf-8")
        (self.dir / "apache_access.log").write_text(APACHE_LOG, encoding="utf-8")
        shutil.copy(FIXTURE / "suricata_eve.jsonl", self.dir / "eve.json")
        shutil.copy(FIXTURE / "wazuh_alerts.jsonl", self.dir / "wazuh_alerts.json")

    def test_auto_mode_selects_the_most_severe_alert_as_trigger(self):
        result = build_manifest(self.dir, scenario_id="collected", host_name="web-01", year=2026)
        self.assertEqual(
            {source.source_type for source in result.sources},
            {"authlog", "apache", "suricata", "wazuh"},
        )
        # The Suricata traversal alert is severity 1 -> critical.
        self.assertEqual(
            result.manifest["trigger"],
            {"source_type": "suricata", "kind": "alert", "rule_id": "2100001"},
        )
        self.assertEqual(result.alert_count, 4)

    def test_labels_override_detection_and_carry_ground_truth(self):
        labels = {
            "id": "COLLECTED-001",
            "name": "Labelled case",
            "trigger": {"source_type": "wazuh", "kind": "alert", "rule_id": "100501"},
            "correlation_window_seconds": 120,
            "expected": {"attack_techniques": ["T1190"]},
        }
        result = build_manifest(self.dir, scenario_id="ignored", labels=labels)
        self.assertEqual(result.manifest["id"], "COLLECTED-001")
        self.assertEqual(result.manifest["name"], "Labelled case")
        self.assertEqual(result.manifest["trigger"]["rule_id"], "100501")
        self.assertEqual(result.manifest["correlation_window_seconds"], 120)
        self.assertEqual(result.manifest["expected"], {"attack_techniques": ["T1190"]})

    def test_labelled_run_still_counts_what_it_collected(self):
        # A declared trigger used to skip the read entirely, so a healthy
        # collection reported "0 events, 0 alerts" and tripped the warning
        # meant for a collection that genuinely produced nothing.
        labels = {"trigger": {"source_type": "suricata", "kind": "alert", "rule_id": "2100001"}}
        result = build_manifest(self.dir, scenario_id="collected", labels=labels, year=2026)
        self.assertGreater(result.event_count, 0)
        self.assertEqual(result.alert_count, 4)
        self.assertFalse(result.trigger_unmatched)

    def test_labelled_trigger_matching_nothing_is_reported(self):
        # Otherwise the typo surfaces as an AlertNotFound at load time, far
        # from the file that caused it.
        labels = {"trigger": {"source_type": "suricata", "kind": "alert", "rule_id": "9999999"}}
        result = build_manifest(self.dir, scenario_id="collected", labels=labels, year=2026)
        self.assertTrue(result.trigger_unmatched)

    def test_ingest_never_writes_into_the_source_directory(self):
        # Collected corpora are often extracted read-only, and ingest must not
        # modify the evidence it is reading.
        before = sorted(path.name for path in self.dir.iterdir())
        self.dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            result = build_manifest(self.dir, scenario_id="collected", year=2026)
        finally:
            self.dir.chmod(stat.S_IRWXU)
        self.assertTrue(result.sources)
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), before)

    def test_written_scenario_loads_through_the_repository(self):
        out_root = Path(tempfile.mkdtemp(prefix="hawki-scenarios-"))
        self.addCleanup(shutil.rmtree, out_root, ignore_errors=True)
        result = build_manifest(self.dir, scenario_id="collected", host_name="web-01", year=2026)
        write_scenario(self.dir, out_root / "collected", result)

        repository = FixtureEventRepository(out_root)
        alerts = repository.list_alerts()
        self.assertEqual(len(alerts), 4)

        case = repository.build_alert_case(
            next(alert["id"] for alert in alerts if "traversal" in alert["title"].lower())
        )
        bundle = case.to_llm_context()
        sources = {item["source_type"] for item in bundle["collection"]["sources"]}
        self.assertEqual(sources, {"authlog", "apache", "suricata", "wazuh"})
        self.assertEqual(
            list(bundle["metadata"]),
            ["security_alerts", "security_events", "assets", "threat_intelligence"],
        )
        # The rotation banner is unreadable and must be reported, not hidden.
        self.assertTrue(any("log rotated" in entry for entry in repository.skipped_lines))

    def test_directory_without_alerts_leaves_the_trigger_unresolved(self):
        bare = Path(tempfile.mkdtemp(prefix="hawki-noalert-"))
        self.addCleanup(shutil.rmtree, bare, ignore_errors=True)
        (bare / "auth.log").write_text(AUTH_LOG, encoding="utf-8")
        result = build_manifest(bare, scenario_id="noalert", year=2026)
        self.assertEqual(result.manifest["trigger"], {"kind": "alert"})
        self.assertEqual(result.alert_count, 0)

    def test_manifest_is_json_serializable_and_indented_on_disk(self):
        out_root = Path(tempfile.mkdtemp(prefix="hawki-scenarios-"))
        self.addCleanup(shutil.rmtree, out_root, ignore_errors=True)
        result = build_manifest(self.dir, scenario_id="collected", year=2026)
        path = write_scenario(self.dir, out_root / "collected", result)
        reloaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(reloaded["id"], "collected")
        self.assertTrue(path.read_text(encoding="utf-8").endswith("\n"))


if __name__ == "__main__":
    unittest.main()
