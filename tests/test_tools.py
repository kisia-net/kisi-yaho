"""Tests for the collection and evaluation entry points.

Run as subprocesses, because that is how they are used and because each one
manipulates sys.path and the environment on import.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data" / "scenarios" / "web_path_traversal"


def run(args: list[str], **env_overrides) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "FLASK_SECRET_KEY": "t" * 48,
        "HAWKI_ADMIN_USERNAME": "evaluator",
        "HAWKI_ADMIN_PASSWORD": "Evaluation-Harness-Pw!1",
        **env_overrides,
    }
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


class IngestCliTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="hawki-cli-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.logs = self.work / "logs"
        self.logs.mkdir()
        shutil.copy(FIXTURE / "suricata_eve.jsonl", self.logs / "eve.json")

    def test_dry_run_reports_without_writing(self):
        result = run(
            ["-m", "hawki_alert_analysis.ingest", str(self.logs), "--dry-run"],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suricata", result.stdout)
        self.assertIn("--dry-run: nothing written", result.stdout)
        self.assertFalse((self.logs / "scenario.json").exists())

    def test_writes_a_loadable_scenario(self):
        out = self.work / "scenarios" / "case"
        result = run(
            ["-m", "hawki_alert_analysis.ingest", str(self.logs), "--out", str(out), "--id", "CLI-001"],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((out / "scenario.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["id"], "CLI-001")
        self.assertEqual(manifest["trigger"]["source_type"], "suricata")
        self.assertTrue((out / "eve.json").exists())

    def test_directory_with_no_readable_source_fails_loudly(self):
        empty = self.work / "empty"
        empty.mkdir()
        (empty / "notes.txt").write_text("prose\n", encoding="utf-8")
        result = run(["-m", "hawki_alert_analysis.ingest", str(empty)])
        self.assertEqual(result.returncode, 1)
        self.assertIn("no scenario was written", result.stdout)

    def test_missing_directory_is_rejected(self):
        result = run(["-m", "hawki_alert_analysis.ingest", str(self.work / "nope")])
        self.assertEqual(result.returncode, 2)
        self.assertIn("is not a directory", result.stderr)


class CollectPcapTests(unittest.TestCase):
    def test_missing_suricata_explains_instead_of_faking_collection(self):
        if shutil.which("suricata"):
            self.skipTest("suricata is installed; the missing-binary path cannot be exercised")
        work = Path(tempfile.mkdtemp(prefix="hawki-pcap-"))
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        capture = work / "capture.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        result = run(
            ["tools/collect_pcap.py", str(capture), "--out", str(work / "scenario")],
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Suricata was not found", result.stderr)
        self.assertIn("apt install suricata", result.stderr)
        self.assertFalse((work / "scenario").exists())

    def test_missing_capture_is_rejected(self):
        result = run(["tools/collect_pcap.py", "/nonexistent.pcap", "--out", "/tmp/x"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("is not a file", result.stderr)


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="hawki-eval-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)

    def test_demo_run_scores_every_alert(self):
        report = self.work / "report.json"
        result = run(
            ["tools/evaluate.py", "--json", str(report)],
            AUTH_DATABASE_PATH=str(self.work / "auth.db"),
            AUDIT_LOG_PATH=str(self.work / "audit.jsonl"),
            ACTION_QUEUE_PATH=str(self.work / "actions.jsonl"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("schema-complete", result.stdout)
        self.assertIn("Demo path", result.stdout)

        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["mode"], "demo")
        self.assertTrue(payload["alerts"])
        for record in payload["alerts"]:
            self.assertIn("schema", record)
            self.assertIn("grounding", record)
            # The demo path cites only real ids.
            self.assertEqual(record["grounding"]["ungrounded"], [])

    def test_unknown_alert_filter_reports_no_match(self):
        result = run(
            ["tools/evaluate.py", "--alert", "evt-does-not-exist"],
            AUTH_DATABASE_PATH=str(self.work / "auth.db"),
            AUDIT_LOG_PATH=str(self.work / "audit.jsonl"),
            ACTION_QUEUE_PATH=str(self.work / "actions.jsonl"),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("No alerts matched", result.stderr)


if __name__ == "__main__":
    unittest.main()
