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


if __name__ == "__main__":
    unittest.main()
