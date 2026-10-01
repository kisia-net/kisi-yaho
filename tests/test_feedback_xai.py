"""Analyst feedback in the next analysis, and the code-computed explanation."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hawki_alert_analysis.explain import build_explanation, evidence_records, severity_agreement
from hawki_alert_analysis.feedback import FeedbackStore, context_block, identity

NOW = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
WEB = identity("31106", "web-01", "45.95.11.22")


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.store = FeedbackStore(Path(self.dir.name) / "feedback.jsonl")

    def add(self, alert_id, alert=WEB, verdict="false_positive", days_ago=1, note="scanner", reviewer="analyst"):
        return self.store.record(
            alert_id=alert_id, alert=alert, verdict=verdict, note=note, reviewer=reviewer,
            source="alert_analysis", now=NOW - timedelta(days=days_ago),
        )

    def similar(self, alert=WEB, exclude="new"):
        return self.store.similar(alert, exclude_alert_id=exclude, now=NOW)

    def test_same_rule_and_host_or_source(self):
        self.add("a-host", identity("31106", "web-01", "1.1.1.1"))
        self.add("a-source", identity("31106", "db-01", "45.95.11.22"))
        self.add("other-rule", identity("5710", "web-01", "45.95.11.22"))
        self.add("rule-only", identity("31106", "db-02", "9.9.9.9"))
        self.assertEqual(sorted(m["alert_id"] for m in self.similar()), ["a-host", "a-source"])

    def test_closest_then_newest_at_most_three(self):
        self.add("both-old", days_ago=10)
        self.add("host-new", identity("31106", "web-01", "1.1.1.1"), days_ago=0)
        self.add("both-new", days_ago=2)
        self.add("host-older", identity("31106", "web-01", "2.2.2.2"), days_ago=5)
        found = [m["alert_id"] for m in self.similar()]
        self.assertEqual(found, ["both-new", "both-old", "host-new"])
        self.assertEqual(self.similar()[0]["match"], ["same_rule", "same_host", "same_source_ip"])

    def test_only_settled_recent_and_not_itself(self):
        self.add("open", verdict="investigating")
        self.add("ancient", days_ago=200)
        self.add("new")  # the alert being analysed
        self.assertEqual(self.similar(), [])

    def test_the_latest_verdict_for_an_alert_wins(self):
        self.add("a1", verdict="false_positive", days_ago=3)
        self.add("a1", verdict="confirmed", days_ago=1)
        (match,) = self.similar()
        self.assertEqual(match["verdict"], "confirmed")

    def test_context_block_has_no_names_and_trims_notes(self):
        self.add("a1", note="x" * 900, reviewer="kim")
        block = context_block(self.similar())
        item = block["items"][0]
        self.assertEqual(item["feedback_id"], "FB-1")
        self.assertNotIn("reviewer", item)
        self.assertNotIn("kim", str(block))
        self.assertEqual(len(item["note"]), 300)
        self.assertIn("not evidence", block["description"])
        self.assertEqual(block["counts"], {"confirmed": 0, "false_positive": 1})

    def test_unknown_verdict_is_refused(self):
        with self.assertRaises(ValueError):
            self.add("a1", verdict="benign")


def live_bundle():
    return {
        "schema": "hawki.wazuh.live-evidence/v2",
        "trigger": {"evidence_id": "TRIGGER", "timestamp": "2026-09-30T05:10:00+00:00",
                    "agent": {"name": "web-01"}, "rule": {"id": "31106", "level": 10, "description": "Web attack"},
                    "data": {"srcip": "45.95.11.22"}, "full_log": "GET /../../etc/passwd",
                    "provenance": {"source_kind": "wazuh_alert", "retrieval_reason": ["trigger"]}},
        "investigation_context": [
            {"evidence_id": "CTX-001", "timestamp": "2026-09-30T05:09:00+00:00", "agent": {"name": "web-01"},
             "rule": {"id": "31100", "level": 3}, "data": {"srcip": "45.95.11.22"}, "full_log": "GET /",
             "provenance": {"source_kind": "wazuh_archive", "retrieval_reason": ["same_source_ip"]},
             "retrieval": {"origin": "same_agent"}},
            {"evidence_id": "CTX-002", "timestamp": "2026-09-30T05:11:00+00:00", "agent": {"name": "ids-01"},
             "rule": {"id": "86601", "level": 3}, "data": {"src_ip": "45.95.11.22"}, "full_log": "ET SCAN",
             "provenance": {"source_kind": "agent_expansion", "retrieval_reason": ["agent_tool:search_address"]},
             "retrieval": {"origin": "agent_search"}},
        ],
        "priority": {"score": 82, "band": "P1", "factors": [{"factor": "wazuh_rule_level", "value": 10, "points": 40}]},
        "retrieval": {"profile": {"name": "web_attack", "seconds_before": 600, "seconds_after": 300, "cross_agent": True}},
        "agent_retrieval": {"calls": [{"tool": "search_address"}], "added_evidence_ids": ["CTX-002"], "stopped": "finish"},
        "analyst_feedback": {"items": [{"feedback_id": "FB-1", "verdict": "false_positive", "recorded_at": "2026-09-29T00:00:00+00:00",
                                        "match": ["same_rule", "same_host"], "note": "scanner"}]},
    }


def result(severity="high"):
    return {
        "assessment": {
            "severity": {"level": severity, "rationale": "internet-facing asset"},
            "confidence": {"level": "medium", "rationale": "FB-1 was a scanner, but the source differs"},
            "supporting_evidence": [
                {"statement": "Traversal request from the attacker", "event_ids": ["TRIGGER", "CTX-001"]},
                {"statement": "Seen by the IDS too", "event_ids": ["CTX-002", "CTX-404"]},
                {"statement": "Made-up correlation", "event_ids": ["CTX-777"]},
            ],
            "contradictory_evidence": [{"statement": "HTTP 404 response", "event_ids": []}],
            "confirmed_observations": ["one request"],
        },
        "assessment_review": {"missing_sections": ["recommended_searches"]},
    }


class ExplanationTests(unittest.TestCase):
    def test_claims_are_checked_against_the_package(self):
        explanation = build_explanation(result(), live_bundle())
        statuses = [(c["kind"], c["status"]) for c in explanation["claims"]]
        self.assertEqual(statuses, [
            ("supporting", "grounded"), ("supporting", "partial"),
            ("supporting", "ungrounded"), ("contradictory", "uncited"),
        ])
        self.assertEqual(explanation["claims"][1]["unknown_event_ids"], ["CTX-404"])
        summary = explanation["summary"]
        self.assertEqual((summary["claims"], summary["grounded"], summary["evidence_total"], summary["evidence_cited"]),
                         (4, 1, 3, 3))
        self.assertEqual(summary["missing_sections"], ["recommended_searches"])

    def test_each_cited_id_leads_to_the_original_log(self):
        evidence = build_explanation(result(), live_bundle())["evidence"]
        self.assertEqual(evidence["TRIGGER"]["log"], "GET /../../etc/passwd")
        self.assertEqual(evidence["TRIGGER"]["origin"], "trigger")
        self.assertEqual(evidence["CTX-002"]["source_kind"], "agent_expansion")
        self.assertEqual(evidence["CTX-002"]["source_ip"], "45.95.11.22")
        self.assertTrue(all(record["cited"] for record in evidence.values()))

    def test_severity_is_compared_with_the_deterministic_band(self):
        self.assertEqual(build_explanation(result("high"), live_bundle())["conclusion"]["agreement"], "consistent")
        self.assertEqual(build_explanation(result("low"), live_bundle())["conclusion"]["agreement"], "model_lower")
        self.assertEqual(severity_agreement("critical", "P3"), "model_higher")
        self.assertEqual(severity_agreement("", "P1"), "unknown")

    def test_inputs_are_listed(self):
        inputs = build_explanation(result(), live_bundle())["inputs"]
        self.assertEqual(inputs["agent_added_evidence"], ["CTX-002"])
        self.assertEqual(inputs["feedback"][0]["verdict"], "false_positive")
        self.assertEqual(inputs["correlation_profile"]["name"], "web_attack")

    def test_fixture_packages_and_garbage(self):
        bundle = {"schema": "hawki.siem.evidence-bundle/v1", "metadata": {
            "security_alerts": {"items": [{"id": "evt-1", "@timestamp": "t", "message": "Path traversal",
                                            "host": {"name": "web-01"}, "source": {"ip": "203.0.113.45"}}]},
            "security_events": {"items": [{"id": "evt-2", "message": "GET /"}]}}}
        records = evidence_records(bundle)
        self.assertEqual(records["evt-1"]["origin"], "trigger")
        self.assertEqual(records["evt-2"]["origin"], "correlated_event")
        explanation = build_explanation({"answer": "no structure"}, bundle, priority={"band": "P2", "factors": []})
        self.assertEqual(explanation["claims"], [])
        self.assertEqual(explanation["conclusion"]["priority"]["band"], "P2")
        self.assertEqual(build_explanation({}, {})["summary"]["evidence_total"], 0)


if __name__ == "__main__":
    unittest.main()
