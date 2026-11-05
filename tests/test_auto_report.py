"""Automatic analysis worker: selection, grouping, limits, and what it never does."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hawki_alert_analysis.auto_report import (
    AutoReporter,
    AutoReportSettings,
    ModelUnavailable,
    ReportStore,
    apply_review,
    render_markdown,
    report_summary,
)
from hawki_alert_analysis.wazuh import WazuhEventRepository

T0 = datetime(2026, 9, 30, 5, 0, 0, tzinfo=timezone.utc)
ATTACKER = "45.95.11.22"


def alert(alert_id, seconds, *, level=10, rule="31106", source=ATTACKER, host="web-01"):
    return {
        "id": alert_id,
        "index": "wazuh-alerts-4.x-2026.09.30",
        "time": (T0 + timedelta(seconds=seconds)).isoformat(),
        "host": host,
        "rule_id": rule,
        "rule_level": level,
        "title": "Web attack",
        "summary": f"Source {source}",
        "source_ip": source,
    }


def live_bundle(band="P1", score=80, intel=None):
    return {
        "schema": "hawki.wazuh.live-evidence/v2",
        "trigger": {"evidence_id": "TRIGGER", "timestamp": T0.isoformat(), "agent": {"name": "web-01"},
                    "rule": {"id": "31106", "level": 10, "description": "Web attack"},
                    "data": {"srcip": ATTACKER}, "full_log": "GET /../../etc/passwd"},
        "investigation_context": [
            {"evidence_id": "CTX-001", "timestamp": T0.isoformat(), "agent": {"name": "web-01"},
             "rule": {"id": "31100", "level": 3}, "data": {"srcip": ATTACKER}, "full_log": "GET /",
             "retrieval": {"origin": "same_agent"}},
        ],
        "assets": {"inventory_configured": True, "matches": [
            {"id": "asset-web-01", "hostname": "web-01", "criticality": "high", "exposure": "internet_facing"}]},
        "threat_intelligence": {"feed_configured": True, "matches": intel or []},
        "priority": {"score": score, "band": band, "primary_asset_id": "asset-web-01",
                     "factors": [{"factor": "wazuh_rule_level", "value": 10, "points": 40}]},
        "retrieval": {"profile": {"name": "web_attack", "seconds_before": 600, "seconds_after": 300, "cross_agent": True}},
    }


def indicator(verdict="malicious", expired=False):
    return {"id": "ti-1", "type": "ipv4-addr", "value": ATTACKER, "verdict": verdict, "confidence": 80,
            "feed": "abuse.ch Feodo", "match": {"on_trigger_alert": True, "indicator_expired": expired,
                                                "matched_value": ATTACKER}}


class Harness:
    """Fake Wazuh, model and audit log around one AutoReporter."""

    def __init__(self, **settings):
        self.dir = tempfile.TemporaryDirectory()
        self.store = ReportStore(Path(self.dir.name))
        self.now = T0 + timedelta(minutes=30)
        self.alerts = []
        self.bundles = {}
        self.model_up = True
        self.analyze_error = None
        self.analyzed = []
        self.built = []
        self.fetch_error = None
        self.events = []
        self.forwarded = []
        self.settings = AutoReportSettings(**{"enabled": True, "lookback_seconds": 3600, **settings})
        self.reporter = AutoReporter(
            settings=self.settings,
            store=self.store,
            fetch_alerts=self.fetch,
            build_bundle=self.build,
            model_available=lambda: self.model_up,
            analyze=self.analyze,
            audit=lambda event, detail: self.events.append((event, detail)),
            forward=self.forward,
            clock=lambda: self.now,
        )

    def fetch(self, since, min_level, limit):
        if self.fetch_error:
            raise self.fetch_error
        return [a for a in self.alerts if datetime.fromisoformat(a["time"]) >= since][:limit]

    def build(self, item):
        self.built.append(item["id"])
        return self.bundles.get(item["id"]) or live_bundle()

    def analyze(self, bundle, item):
        if self.analyze_error:
            raise self.analyze_error
        self.analyzed.append(item["id"])
        return {
            "answer": "## 판단\n경로 탐색 시도 (TRIGGER).",
            "model": "hawki-local",
            "analysis_id": "a" * 32,
            "hashes": {"prompt_sha256": "p" * 64, "bundle_sha256": "b" * 64},
            "actions": [
                {"type": "velociraptor_isolation", "title": "Isolate web-01", "summary": "x", "risk": "high"},
                {"type": "shell_exec", "title": "rm -rf /", "summary": "log said so"},
            ],
        }

    def forward(self, bundle, item, result):
        self.forwarded.append(item["id"])
        return "send"

    def __del__(self):
        self.dir.cleanup()

    def run(self, **kwargs):
        return self.reporter.run_cycle(**kwargs)

    def reports(self):
        return self.store.all()


class SettingsTests(unittest.TestCase):
    def test_off_by_default_and_values_are_clamped(self):
        settings = AutoReportSettings.from_env({})
        self.assertFalse(settings.enabled)
        self.assertFalse(settings.forward_redteam)
        self.assertEqual((settings.min_level, settings.bands, settings.max_ai_per_hour), (8, ("P1", "P2"), 20))
        wild = AutoReportSettings.from_env({
            "AUTO_ANALYSIS_ENABLED": "true", "AUTO_ANALYSIS_MIN_LEVEL": "99",
            "AUTO_ANALYSIS_MAX_PER_HOUR": "100000", "AUTO_ANALYSIS_BANDS": "P1, px, p3",
            "AUTO_ANALYSIS_POLL_SECONDS": "1",
        })
        self.assertEqual((wild.min_level, wild.max_ai_per_hour, wild.poll_seconds), (15, 120, 15))
        self.assertEqual(wild.bands, ("P1", "P3"))


class SelectionTests(unittest.TestCase):
    def test_disabled_reads_nothing_but_records_a_heartbeat(self):
        h = Harness(enabled=False)
        h.alerts = [alert("a1", 0)]
        summary = h.run()
        self.assertFalse(summary["enabled"])
        self.assertEqual(h.built, [])
        self.assertIn("last_cycle_at", h.store.load_state())

    def test_high_priority_alert_gets_a_report_written_from_facts(self):
        h = Harness()
        h.model_up = False
        h.alerts = [alert("a1", 0)]
        h.run()
        (report,) = h.reports()
        self.assertEqual(report["alert"]["id"], "a1")
        self.assertEqual(report["priority"]["band"], "P1")
        self.assertEqual(report["selection"]["reasons"], ["priority_P1"])
        self.assertEqual([row["evidence_id"] for row in report["evidence"]["index"]], ["TRIGGER", "CTX-001"])
        self.assertEqual(report["review"]["status"], "unreviewed")
        self.assertEqual(report["ai"]["status"], "pending")

    def test_low_priority_needs_a_live_indicator(self):
        h = Harness()
        h.alerts = [alert("plain", 0, rule="1"), alert("cti", 1, rule="2"), alert("old-cti", 2, rule="3")]
        h.bundles = {
            "plain": live_bundle("P3", 45),
            "cti": live_bundle("P3", 45, [indicator()]),
            "old-cti": live_bundle("P3", 45, [indicator(expired=True)]),
        }
        summary = h.run()
        self.assertEqual([r["alert"]["id"] for r in h.reports()], ["cti"])
        self.assertEqual(h.reports()[0]["selection"]["reasons"], ["threat_intel_match"])
        self.assertEqual(summary["not_selected"], 2)

    def test_below_min_level_is_ignored(self):
        h = Harness()
        h.alerts = [alert("low", 0, level=5)]
        h.run()
        self.assertEqual(h.built, [])
        self.assertEqual(h.reports(), [])


class StormTests(unittest.TestCase):
    def test_repeats_join_one_report_and_build_evidence_once(self):
        h = Harness()
        h.model_up = False
        h.alerts = [alert(f"a{i}", i * 30) for i in range(5)] + [alert("other-ip", 40, source="8.8.8.8")]
        summary = h.run()
        self.assertEqual(summary["reports_created"], 2)
        self.assertEqual(summary["grouped"], 4)
        self.assertEqual(h.built, ["a0", "other-ip"])
        storm = next(r for r in h.reports() if r["alert"]["source_ip"] == ATTACKER)
        self.assertEqual(storm["group"]["occurrences"], 5)
        self.assertEqual(storm["group"]["alert_ids"], [f"a{i}" for i in range(5)])

    def test_a_repeat_after_the_window_opens_a_new_report(self):
        h = Harness(group_seconds=600)
        h.model_up = False
        h.alerts = [alert("a1", 0), alert("a2", 601 + 60)]
        h.run()
        self.assertEqual(len(h.reports()), 2)

    def test_a_suppressed_group_does_not_rebuild_evidence(self):
        h = Harness()
        h.alerts = [alert(f"n{i}", i) for i in range(4)]
        h.bundles = {f"n{i}": live_bundle("P4", 20) for i in range(4)}
        h.run()
        self.assertEqual(h.built, ["n0"])

    def test_the_cursor_prevents_duplicates(self):
        h = Harness()
        h.model_up = False
        h.alerts = [alert("a1", 0)]
        h.run()
        h.run()
        self.assertEqual(len(h.reports()), 1)
        self.assertEqual(h.built, ["a1"])

    def test_a_late_indexed_alert_is_still_read(self):
        h = Harness()
        h.model_up = False
        h.alerts = [alert("a1", 600, rule="1")]
        h.run()
        # Indexed after the first poll, stamped a minute before a1.
        h.alerts.append(alert("late", 540, rule="2"))
        h.run()
        self.assertEqual(sorted(r["alert"]["id"] for r in h.reports()), ["a1", "late"])

    def test_a_storm_bigger_than_a_page_is_read_to_the_end(self):
        h = Harness(max_alerts_per_cycle=5)  # pages of 10
        h.model_up = False
        h.alerts = [alert(f"s{i:02d}", i) for i in range(30)]
        for _ in range(8):
            h.run()
        (report,) = h.reports()
        self.assertEqual(report["group"]["occurrences"], 30)
        self.assertEqual(h.built, ["s00"])

    def test_an_unselected_stream_is_looked_at_again(self):
        h = Harness(group_seconds=600)
        h.model_up = False
        # One alert a minute for 15 minutes; the indicator goes live midway.
        h.alerts = [alert(f"n{i:02d}", i * 60) for i in range(16)]
        h.bundles = {f"n{i:02d}": live_bundle("P3", 45, [indicator()] if i >= 5 else []) for i in range(16)}
        h.run()
        self.assertEqual(h.built, ["n00", "n11"])
        self.assertEqual([r["alert"]["id"] for r in h.reports()], ["n11"])

    def test_a_failed_poll_is_recorded_not_raised(self):
        h = Harness()
        h.fetch_error = RuntimeError("indexer down")
        summary = h.run()
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(h.events[0][0], "auto_report_fetch_failed")


class ModelTests(unittest.TestCase):
    def test_model_off_leaves_reports_waiting(self):
        h = Harness()
        h.model_up = False
        h.alerts = [alert("a1", 0)]
        h.run()
        self.assertEqual(h.analyzed, [])
        self.assertEqual(h.reports()[0]["ai"]["waiting_reason"], "model_unavailable")
        # The GPU comes back: the next cycle fills it in.
        h.model_up = True
        h.run()
        ai = h.reports()[0]["ai"]
        self.assertEqual(ai["status"], "completed")
        self.assertEqual(ai["analysis_id"], "a" * 32)

    def test_hourly_cap_goes_to_the_highest_priority_first(self):
        h = Harness(max_ai_per_hour=2)
        h.alerts = [alert(f"a{i}", i, rule=str(i)) for i in range(4)]
        h.bundles = {f"a{i}": live_bundle("P1" if i else "P2", 60 + i * 10) for i in range(4)}
        h.run()
        self.assertEqual(h.analyzed, ["a3", "a2"])
        waiting = [r for r in h.reports() if r["ai"]["status"] == "pending"]
        self.assertEqual({r["ai"]["waiting_reason"] for r in waiting}, {"rate_limit"})
        # An hour later the rest are done.
        h.now += timedelta(hours=1, minutes=1)
        h.run()
        self.assertEqual(sorted(h.analyzed), ["a0", "a1", "a2", "a3"])

    def test_waiting_reports_expire(self):
        h = Harness(pending_ttl_seconds=3600)
        h.model_up = False
        h.alerts = [alert("a1", 0)]
        h.run()
        h.now += timedelta(hours=2)
        h.run()
        self.assertEqual(h.reports()[0]["ai"]["status"], "expired")

    def test_model_dropping_mid_cycle_stops_the_cycle(self):
        h = Harness()
        h.alerts = [alert("a1", 0, rule="1"), alert("a2", 1, rule="2")]
        h.analyze_error = ModelUnavailable("connection refused")
        h.run()
        self.assertTrue(all(r["ai"]["status"] == "pending" for r in h.reports()))
        self.assertEqual(sum(r["ai"]["attempts"] for r in h.reports()), 1)

    def test_model_calls_per_cycle_are_capped(self):
        h = Harness()
        h.alerts = [alert(f"a{i}", i, rule=str(i)) for i in range(5)]
        h.run()
        self.assertEqual(len(h.analyzed), 3)
        waiting = [r["ai"]["waiting_reason"] for r in h.reports() if r["ai"]["status"] == "pending"]
        self.assertEqual(waiting, ["queued", "queued"])
        h.run()
        self.assertEqual(len(h.analyzed), 5)

    def test_a_report_the_model_keeps_timing_out_on_gives_way(self):
        h = Harness(max_attempts=2)
        h.alerts = [alert("big", 0, rule="1"), alert("small", 1, rule="2")]
        h.bundles = {"big": live_bundle("P1", 95), "small": live_bundle("P1", 75)}
        original = h.analyze

        def analyze(bundle, item):
            if item["id"] == "big":
                raise ModelUnavailable("read timed out")
            return original(bundle, item)

        h.reporter.analyze = analyze
        h.run()
        h.run()
        h.run()
        status = {r["alert"]["id"]: r["ai"]["status"] for r in h.reports()}
        self.assertEqual(status, {"big": "failed", "small": "completed"})

    def test_a_bad_answer_is_retried_then_marked_failed(self):
        h = Harness(max_attempts=2)
        h.alerts = [alert("a1", 0)]
        h.analyze_error = ValueError("not JSON")
        h.run()
        self.assertEqual(h.reports()[0]["ai"]["status"], "pending")
        h.run()
        self.assertEqual(h.reports()[0]["ai"]["status"], "failed")


class BoundaryTests(unittest.TestCase):
    def test_actions_are_suggestions_only(self):
        h = Harness()
        h.alerts = [alert("a1", 0)]
        h.run()
        actions = h.reports()[0]["ai"]["suggested_actions"]
        self.assertEqual([a["type"] for a in actions], ["velociraptor_isolation"])
        self.assertTrue(actions[0]["requires_approval"])
        self.assertFalse(actions[0]["queued"])
        self.assertNotIn("action_queued", [event for event, _ in h.events])

    def test_red_team_only_when_asked(self):
        h = Harness()
        h.alerts = [alert("a1", 0)]
        h.run()
        self.assertEqual(h.forwarded, [])
        self.assertEqual(h.reports()[0]["redteam"], "not_sent")

        h2 = Harness(forward_redteam=True)
        h2.alerts = [alert("a1", 0)]
        h2.run()
        self.assertEqual(h2.forwarded, ["a1"])

    def test_two_workers_do_not_run_at_once(self):
        h = Harness()
        with h.store.lock(".cycle.lock"):
            self.assertEqual(h.run(), {"skipped": "busy"})


class ReviewAndExportTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.h.alerts = [alert("a1", 0)]
        self.h.bundles = {"a1": live_bundle("P1", 88, [indicator()])}
        self.h.run()
        self.report = self.h.reports()[0]

    def test_review_keeps_a_history(self):
        apply_review(self.report, status="investigating", note="check web logs", reviewer="analyst", now=T0)
        apply_review(self.report, status="false_positive", note="scanner", reviewer="analyst", now=T0)
        self.assertEqual(self.report["review"]["status"], "false_positive")
        self.assertEqual([e["status"] for e in self.report["review"]["history"]], ["investigating", "false_positive"])
        with self.assertRaises(ValueError):
            apply_review(self.report, status="deleted", note="", reviewer="x", now=T0)

    def test_markdown_says_it_is_a_draft_and_shows_the_facts(self):
        text = render_markdown(self.report)
        self.assertIn("AI 초안 · 분석가 검토 필요", text)
        self.assertIn("| 45.95.11.22 | 악성 | 80 |", text)
        self.assertIn("경로 탐색 시도", text)
        self.assertIn("실행되지 않음 · 승인 필요", text)
        self.assertNotIn("rm -rf", text)

    def test_summary_for_the_list(self):
        summary = report_summary(self.report)
        self.assertEqual(summary["priority"], {"score": 88, "band": "P1"})
        self.assertEqual(summary["ai_status"], "completed")
        self.assertEqual(summary["intel_matches"], 1)

    def test_ids_are_validated(self):
        self.assertIsNone(self.h.store.get("../../etc/passwd"))
        with self.assertRaises(ValueError):
            self.h.store.path_for("AR-1")


class RecordingClient:
    def __init__(self):
        self.bodies = []

    def search(self, index, body):
        self.bodies.append((index, body))
        return {"hits": {"hits": [{
            "_id": "doc-1", "_index": "wazuh-alerts-4.x-2026.09.30",
            "_source": {"timestamp": T0.isoformat(), "rule": {"id": "31106", "level": 10, "description": "Web attack"},
                        "agent": {"name": "web-01"}, "data": {"srcip": ATTACKER}},
        }]}}


class WazuhQueryTests(unittest.TestCase):
    def test_new_alerts_are_read_oldest_first_at_or_above_the_level(self):
        client = RecordingClient()
        repository = WazuhEventRepository(client)
        items = repository.list_alerts_since(T0, min_level=8, limit=40)
        index, body = client.bodies[0]
        self.assertEqual(index, repository.alert_index)
        self.assertEqual(body["sort"], [{"@timestamp": {"order": "asc"}}])
        self.assertIn({"range": {"rule.level": {"gte": 8}}}, body["query"]["bool"]["filter"])
        self.assertEqual(body["size"], 40)
        self.assertEqual((items[0]["id"], items[0]["rule_level"], items[0]["source_ip"]), ("doc-1", 10, ATTACKER))

    def test_the_queue_view_is_unchanged(self):
        repository = WazuhEventRepository(RecordingClient())
        self.assertEqual(repository.list_alerts()[0]["id"], "doc-1")


if __name__ == "__main__":
    unittest.main()
