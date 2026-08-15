"""Tests for the log adapters added for collected corpora.

Normalization maps what a producer states and nothing more. These tests pin
that boundary: an outcome is read from the producer's own wording, and a line
no adapter understands is rejected rather than guessed at.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from hawki_alert_analysis.adapters import ApacheAdapter, AuthLogAdapter, SyslogAdapter


class SyslogAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = SyslogAdapter()

    def test_rfc3164_line_is_parsed(self):
        event = self.adapter.normalize(
            "Aug 11 10:21:09 web-01 sshd[3841]: Failed password for invalid user admin "
            "from 203.0.113.45 port 51822 ssh2",
            defaults={"year": 2026},
        )
        self.assertEqual(event.timestamp_dt, datetime(2026, 8, 11, 10, 21, 9, tzinfo=timezone.utc))
        self.assertEqual(event.host_name, "web-01")
        self.assertEqual(event.process["name"], "sshd")
        self.assertEqual(event.process["pid"], 3841)
        self.assertEqual(event.source_ip, "203.0.113.45")
        self.assertEqual(event.source_port, 51822)
        self.assertEqual(event.user_name, "admin")
        self.assertEqual(event.outcome, "failure")
        self.assertIn("authentication", event.category)

    def test_success_wording_maps_to_success(self):
        event = self.adapter.normalize(
            "Aug 11 10:22:30 web-01 sshd[3402]: Accepted publickey for deploy "
            "from 198.51.100.14 port 44210 ssh2",
            defaults={"year": 2026},
        )
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.user_name, "deploy")

    def test_outcome_is_not_invented_when_the_producer_states_none(self):
        event = self.adapter.normalize(
            "Aug 11 10:21:09 web-01 sudo:  www-data : TTY=unknown ; PWD=/ ; USER=root ; "
            "COMMAND=/bin/sh -c id",
            defaults={"year": 2026},
        )
        self.assertEqual(event.outcome, "")
        self.assertEqual(event.user_name, "www-data")
        self.assertEqual(event.process["command_line"], "/bin/sh -c id")
        self.assertIn("process", event.category)

    def test_missing_year_is_assumed_and_flagged(self):
        event = self.adapter.normalize("Aug 11 10:21:09 web-01 cron[9]: run", defaults={})
        self.assertEqual(event.timestamp_dt.year, datetime.now(timezone.utc).year)
        self.assertIn("assumed-year", event.tags)

    def test_supplied_year_is_not_flagged(self):
        event = self.adapter.normalize("Aug 11 10:21:09 web-01 cron[9]: run", defaults={"year": 2026})
        self.assertNotIn("assumed-year", event.tags)

    def test_unparsable_line_is_rejected(self):
        for line in ("*** rotation ***", "", "totally unstructured text"):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    self.adapter.normalize(line, defaults={"year": 2026})

    def test_non_ascii_message_survives(self):
        event = self.adapter.normalize(
            "Aug 11 10:21:10 web-01 systemd[1]: Sitzung geöffnet für 사용자",
            defaults={"year": 2026},
        )
        self.assertIn("사용자", event.message)
        self.assertEqual(event.raw.count("geöffnet"), 1)

    def test_host_default_overrides_the_logged_host(self):
        # Collected corpora often carry a short or wrong hostname per file.
        event = self.adapter.normalize(
            "Aug 11 10:21:09 localhost cron[9]: run",
            defaults={"year": 2026, "host_name": "web-01"},
        )
        self.assertEqual(event.host_name, "web-01")


class AuthLogAdapterTests(unittest.TestCase):
    def test_dataset_identifies_authentication_source(self):
        event = AuthLogAdapter().normalize(
            "Aug 11 10:20:44 web-01 sshd[3120]: Failed password for root from 203.0.113.45 port 1 ssh2",
            defaults={"year": 2026},
        )
        self.assertEqual(event.source_type, "authlog")
        self.assertEqual(event.source_dataset, "linux.auth")
        self.assertEqual(event.outcome, "failure")


class ApacheAdapterTests(unittest.TestCase):
    def test_combined_format_keeps_apache_provenance(self):
        line = (
            '203.0.113.45 - - [11/Aug/2026:10:21:03 +0000] "GET /../../../../etc/passwd HTTP/1.1" '
            '200 421 "-" "curl/8.5.0"'
        )
        event = ApacheAdapter().normalize(line, defaults={"host_name": "web-01"})
        self.assertEqual(event.source_type, "apache")
        self.assertEqual(event.source_dataset, "apache.access")
        # The status code stays a status code.
        self.assertEqual(event.http["response"]["status_code"], 200)
        self.assertIsNone(event.destination_port)
        self.assertEqual(event.http["request"]["uri"], "/../../../../etc/passwd")

    def test_apache_and_nginx_lines_get_distinct_ids(self):
        from hawki_alert_analysis.adapters import NginxAdapter

        line = '203.0.113.45 - - [11/Aug/2026:10:21:03 +0000] "GET / HTTP/1.1" 200 1 "-" "curl"'
        apache = ApacheAdapter().normalize(line)
        nginx = NginxAdapter().normalize(line)
        self.assertNotEqual(apache.id, nginx.id)


FLAT_SYSMON = {
    "@timestamp": "2026-08-11T14:03:02.418Z",
    "EventID": 1,
    "Hostname": "WIN-WS-07",
    "UtcTime": "2026-08-11 14:03:02.418",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoP -W Hidden -Enc SQBF",
    "ProcessId": "6412",
    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "ParentProcessId": "5108",
    "User": "CORP\\j.lee",
    "Hashes": "SHA1=6CBCE4,MD5=7353F6,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628D1E01F0DE4E1E0FA0",
    "RuleName": "technique_id=T1059.001",
}

NESTED_SYSMON = {
    "Event": {
        "System": {
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
            "EventID": 3,
            "Computer": "WIN-WS-07",
        },
        "EventData": {
            "UtcTime": "2026-08-11 14:03:05.742",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "SourceIp": "192.168.60.41",
            "SourcePort": "51288",
            "DestinationIp": "198.51.100.77",
            "DestinationPort": "443",
            "Protocol": "tcp",
        },
    }
}

WINLOGBEAT_SYSMON = {
    "@timestamp": "2026-08-11T14:03:04.106Z",
    "winlog": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 22,
        "computer_name": "WIN-WS-07",
        "event_data": {
            "UtcTime": "2026-08-11 14:03:04.106",
            "QueryName": "updates.cdn-sync.example.invalid",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "User": "CORP\\j.lee",
        },
    },
}


class SysmonAdapterTests(unittest.TestCase):
    def setUp(self):
        from hawki_alert_analysis.adapters import SysmonAdapter

        self.adapter = SysmonAdapter()

    def test_flat_process_creation(self):
        event = self.adapter.normalize(FLAT_SYSMON)
        self.assertEqual(event.kind, "event")  # Sysmon is telemetry, not detection
        self.assertEqual(event.category, ["process"])
        self.assertEqual(event.host_name, "WIN-WS-07")
        self.assertEqual(event.user_name, "CORP\\j.lee")
        self.assertEqual(event.process["name"], "powershell.exe")
        self.assertEqual(event.process["pid"], 6412)
        self.assertEqual(event.process["parent"]["name"], "WINWORD.EXE")
        self.assertEqual(
            event.process["hash"]["sha256"],
            "de96a6e69944335375dc1ac238336066889d9ffc7d73628d1e01f0de4e1e0fa0",
        )
        self.assertIn("sysmon-rule:technique_id=T1059.001", event.tags)
        # A Sysmon config label is not a detection verdict.
        self.assertEqual(event.rule, {})
        self.assertEqual(event.severity, "info")

    def test_nested_evtx_shape_network_connection(self):
        event = self.adapter.normalize(NESTED_SYSMON)
        self.assertEqual(event.category, ["network"])
        self.assertEqual(event.source_ip, "192.168.60.41")
        self.assertEqual(event.source_port, 51288)
        self.assertEqual(event.destination_ip, "198.51.100.77")
        self.assertEqual(event.destination_port, 443)
        self.assertEqual(event.network_transport, "tcp")

    def test_winlogbeat_shape_dns_query_is_an_observable(self):
        event = self.adapter.normalize(WINLOGBEAT_SYSMON)
        self.assertEqual(event.dns["question"]["name"], "updates.cdn-sync.example.invalid")
        self.assertEqual(event.network_application, "dns")
        observables = {item["field"]: item for item in event.observables()}
        self.assertEqual(observables["dns.question.name"]["type"], "domain-name")

    def test_file_events_hash_the_file_not_the_process(self):
        event = self.adapter.normalize(
            {
                "EventID": 11,
                "UtcTime": "2026-08-11 14:03:07.933",
                "Hostname": "WIN-WS-07",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\j.lee\\AppData\\Local\\Temp\\update.exe",
                "Hashes": "SHA256=9F2C4B",
            }
        )
        self.assertEqual(event.category, ["file"])
        self.assertEqual(event.file["name"], "update.exe")
        self.assertEqual(event.file["hash"]["sha256"], "9f2c4b")
        self.assertNotIn("hash", event.process)

    def test_unknown_event_id_is_kept_rather_than_dropped(self):
        event = self.adapter.normalize(
            {"EventID": 255, "UtcTime": "2026-08-11 14:03:07.933", "Hostname": "WIN-WS-07"}
        )
        self.assertEqual(event.category, ["host"])
        self.assertIn("sysmon_event_255", event.message)

    def test_event_without_a_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            self.adapter.normalize({"EventID": 1, "Hostname": "WIN-WS-07"})

    def test_port_values_outside_range_are_dropped(self):
        event = self.adapter.normalize(
            {
                "EventID": 3,
                "UtcTime": "2026-08-11 14:03:05.742",
                "Hostname": "WIN-WS-07",
                "DestinationIp": "198.51.100.77",
                "DestinationPort": "99999",
            }
        )
        self.assertIsNone(event.destination_port)


class SysmonHashParsingTests(unittest.TestCase):
    def test_hash_string_is_split_and_lowercased(self):
        from hawki_alert_analysis.adapters import parse_sysmon_hashes

        parsed = parse_sysmon_hashes("SHA1=AABB,MD5=CCDD,SHA256=EEFF,IMPHASH=1122")
        self.assertEqual(parsed, {"sha1": "aabb", "md5": "ccdd", "sha256": "eeff", "imphash": "1122"})

    def test_malformed_values_are_ignored(self):
        from hawki_alert_analysis.adapters import parse_sysmon_hashes

        self.assertEqual(parse_sysmon_hashes("garbage"), {})
        self.assertEqual(parse_sysmon_hashes(""), {})
        self.assertEqual(parse_sysmon_hashes(None), {})


if __name__ == "__main__":
    unittest.main()
