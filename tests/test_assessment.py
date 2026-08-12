"""Tests for the structured alert assessment schema.

Two behaviours matter here: normalization has to be tolerant enough to keep a
small model's analysis, and review has to be strict enough that a missing
section or an invented event id is always visible.
"""

from __future__ import annotations

import unittest

from hawki_alert_analysis.assessment import (
    REQUIRED_SECTIONS,
    assessment_markdown,
    normalize_assessment,
    review_assessment,
)

BUNDLE = {
    "metadata": {
        "security_alerts": {"items": [{"id": "evt-aaa"}, {"id": "evt-bbb"}]},
        "security_events": {"items": [{"id": "evt-ccc"}]},
        "threat_intelligence": {"items": [{"id": "ti-ipv4-203.0.113.45"}]},
    }
}

COMPLETE = {
    "confirmed_observations": ["A traversal URI was requested."],
    "interpretation": "Probable exploitation attempt.",
    "attack_hypothesis": "Traversal followed by shell execution.",
    "confidence": {"level": "high", "rationale": "Three sources agree."},
    "severity": {"level": "critical", "rationale": "Internet-facing high-criticality asset."},
    "affected_entities": {"hosts": ["web-01"], "users": ["www-data"]},
    "attack_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "supporting_evidence": [{"statement": "Traversal alert", "event_ids": ["evt-aaa"]}],
    "contradictory_evidence": [{"statement": "Response was small", "event_ids": ["evt-ccc"]}],
    "evidence_gaps": ["Full request body not captured."],
    "recommended_searches": [{"title": "Same source", "language": "KQL", "value": "source.ip:203.0.113.45"}],
    "recommended_response": ["Preserve the process tree."],
}


class NormalizationTests(unittest.TestCase):
    def test_complete_assessment_round_trips(self):
        assessment = normalize_assessment(COMPLETE)
        self.assertEqual(assessment["confidence"], {"level": "high", "rationale": "Three sources agree."})
        self.assertEqual(assessment["attack_techniques"][0]["id"], "T1190")
        self.assertEqual(assessment["supporting_evidence"][0]["event_ids"], ["evt-aaa"])
        self.assertTrue(review_assessment(assessment, BUNDLE)["complete"])

    def test_bare_strings_are_accepted_where_objects_were_requested(self):
        assessment = normalize_assessment(
            {
                "confirmed_observations": "One observation only.",
                "confidence": "high confidence",
                "severity": "severity: critical",
                "attack_techniques": "T1059.004",
                "supporting_evidence": "The shell was spawned by nginx.",
                "recommended_searches": "host.name:web-01",
            }
        )
        self.assertEqual(assessment["confirmed_observations"], ["One observation only."])
        self.assertEqual(assessment["confidence"]["level"], "high")
        self.assertEqual(assessment["severity"]["level"], "critical")
        self.assertEqual(assessment["attack_techniques"][0]["id"], "T1059.004")
        self.assertEqual(assessment["supporting_evidence"][0]["statement"], "The shell was spawned by nginx.")
        self.assertEqual(assessment["recommended_searches"][0]["value"], "host.name:web-01")

    def test_alternate_key_names_are_accepted(self):
        assessment = normalize_assessment(
            {
                "hypothesis": "Exploitation then execution.",
                "mitre": [{"technique_id": "T1071", "technique_name": "Application Layer Protocol"}],
                "missing_evidence": ["No PCAP retained."],
                "entities": {"host": "web-01", "ips": ["203.0.113.45"]},
                "response_options": ["Isolate the host."],
            }
        )
        self.assertEqual(assessment["attack_hypothesis"], "Exploitation then execution.")
        self.assertEqual(assessment["attack_techniques"][0]["id"], "T1071")
        self.assertEqual(assessment["evidence_gaps"], ["No PCAP retained."])
        self.assertEqual(assessment["affected_entities"]["hosts"], ["web-01"])
        self.assertEqual(assessment["affected_entities"]["addresses"], ["203.0.113.45"])
        self.assertEqual(assessment["recommended_response"], ["Isolate the host."])

    def test_garbage_input_yields_an_empty_but_valid_shape(self):
        for value in (None, "", [], "not an object", 42):
            with self.subTest(value=value):
                assessment = normalize_assessment(value)
                self.assertEqual(set(assessment), set(REQUIRED_SECTIONS) | {"contradictory_evidence"})
                self.assertFalse(review_assessment(assessment, BUNDLE)["complete"])


class ReviewTests(unittest.TestCase):
    def test_missing_sections_are_named(self):
        payload = dict(COMPLETE)
        del payload["evidence_gaps"]
        del payload["recommended_response"]
        review = review_assessment(normalize_assessment(payload), BUNDLE)
        self.assertFalse(review["complete"])
        self.assertEqual(sorted(review["missing_sections"]), ["evidence_gaps", "recommended_response"])

    def test_invented_event_ids_are_reported_not_silently_kept(self):
        payload = dict(COMPLETE)
        payload["supporting_evidence"] = [
            {"statement": "Real citation", "event_ids": ["evt-aaa"]},
            {"statement": "Invented citation", "event_ids": ["evt-does-not-exist", "evt-ccc"]},
        ]
        assessment = normalize_assessment(payload)
        review = review_assessment(assessment, BUNDLE)
        self.assertEqual(review["ungrounded_event_ids"], ["evt-does-not-exist"])
        self.assertEqual(assessment["supporting_evidence"][0]["unknown_event_ids"], [])
        self.assertEqual(
            assessment["supporting_evidence"][1]["unknown_event_ids"], ["evt-does-not-exist"]
        )
        # The statement itself is preserved for the analyst to judge.
        self.assertEqual(assessment["supporting_evidence"][1]["statement"], "Invented citation")

    def test_empty_contradictory_evidence_is_a_note_not_a_missing_section(self):
        payload = dict(COMPLETE)
        payload["contradictory_evidence"] = []
        review = review_assessment(normalize_assessment(payload), BUNDLE)
        self.assertTrue(review["complete"])
        self.assertIn("No contradictory evidence was reported.", review["notes"])

    def test_uncited_evidence_is_noted(self):
        payload = dict(COMPLETE)
        payload["supporting_evidence"] = [{"statement": "No citation given"}]
        payload["contradictory_evidence"] = []
        review = review_assessment(normalize_assessment(payload), BUNDLE)
        self.assertEqual(review["citations"], 0)
        self.assertIn("No evidence entry cited an event id.", review["notes"])


class MarkdownTests(unittest.TestCase):
    def test_markdown_covers_the_reported_sections(self):
        text = assessment_markdown(normalize_assessment(COMPLETE))
        for heading in ("Assessment", "Hypothesis", "Confirmed observations", "Supporting evidence"):
            self.assertIn(heading, text)
        self.assertIn("evt-aaa", text)
        self.assertIn("critical", text)

    def test_empty_assessment_produces_no_stray_headings(self):
        self.assertEqual(assessment_markdown(normalize_assessment({})), "")


if __name__ == "__main__":
    unittest.main()
