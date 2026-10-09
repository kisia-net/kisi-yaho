"""Public aggregate contract tests, without network/model calls."""
import unittest
from hawki_redteam_ui import public_scan


def scan(tool, values):
    return {"schema": "hawki.deep-scan/v1", "scan_id": "a" * 24,
            "alert_id": "real-wazuh-alert", "status": "completed", "tools": {tool: values}}


class PublicMetricsTests(unittest.TestCase):
    def test_request_audit_forwards_counts_but_no_private_payload(self):
        value = scan("promptfoo", {"request_audit": {
            "sent": 1, "received": 0, "skipped": 5, "retries": 0,
            "response": "private", "headers": {"Authorization": "private"}}})
        audit = public_scan(value)["tools"]["promptfoo"]["request_audit"]
        self.assertEqual(audit, {"sent": 1, "received": 0, "skipped": 5, "retries": 0})

    def test_request_audit_rejects_impossible_counts(self):
        for values in ({"sent": 1, "received": 2}, {"sent": True}, {"retries": 1}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                public_scan(scan("promptfoo", {"request_audit": values}))

    def test_aggregate_rates_recomputed_and_private_cases_stripped(self):
        value = scan("promptfoo", {"counts": {}, "security_evaluation": {
            "attack_attempted": 5, "attack_evaluated": 4, "attack_goal_hits": 1,
            "attack_goal_hit_rate": 999, "cases": [{"private": "not-forwarded"}],
            "counts": {"quality_failure": 1, "diagnostic_warning": 1}}})
        metrics = public_scan(value)["tools"]["promptfoo"]["security_evaluation"]
        self.assertEqual(metrics["attack_goal_hit_rate"], 0.25)
        self.assertEqual(metrics["attack_evaluation_coverage"], 0.8)
        self.assertNotIn("cases", metrics)

    def test_zero_denominator_is_not_zero_percent_or_safe(self):
        metrics = public_scan(scan("promptfoo", {"security_evaluation": {}}))["tools"]["promptfoo"]["security_evaluation"]
        self.assertIsNone(metrics["attack_goal_hit_rate"])

    def test_inconsistent_negative_or_boolean_counters_rejected(self):
        for metrics in ({"attack_goal_hits": 2, "attack_evaluated": 1}, {"attack_attempted": -1}, {"attack_attempted": True}):
            with self.subTest(metrics=metrics), self.assertRaises(ValueError):
                public_scan(scan("promptfoo", {"security_evaluation": metrics}))

    def test_response_audit_is_aggregate_only_and_no_eval_visible(self):
        values = {"evaluation_coverage": "not_evaluated", "process_exit_verified": False,
            "response_audit": {"received": 1, "structured": 0, "malformed_or_missing": 1, "response": "private"},
            "raw_response": "private", "report_path": "private/path"}
        result = public_scan(scan("garak", values))["tools"]["garak"]
        self.assertEqual(result["evaluation_coverage"], "not_evaluated")
        self.assertFalse(result["process_exit_verified"])
        self.assertEqual(result["response_audit"], {"received": 1, "structured": 0, "malformed_or_missing": 1})
        self.assertNotIn("raw_response", result)
        self.assertNotIn("report_path", result)

    def test_bad_audit_counts_rejected(self):
        with self.assertRaises(ValueError):
            public_scan(scan("garak", {"response_audit": {"received": 1, "structured": 2}}))
