"""A live package over AGENT_CONTEXT_MAX_CHARS is fitted, not refused."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_WORKDIR = tempfile.mkdtemp(prefix="hawki-tests-")
os.environ.setdefault("FLASK_SECRET_KEY", "t" * 48)
os.environ.setdefault("AUTH_DATABASE_PATH", str(Path(_WORKDIR) / "auth.db"))
os.environ.setdefault("ACTION_QUEUE_PATH", str(Path(_WORKDIR) / "actions.jsonl"))
os.environ.setdefault("AUDIT_LOG_PATH", str(Path(_WORKDIR) / "audit.jsonl"))
os.environ.setdefault("HAWKI_ADMIN_USERNAME", "analyst")
os.environ.setdefault("HAWKI_ADMIN_PASSWORD", "Str0ng-Passw0rd-Value!")
os.environ.setdefault("WAZUH_API_URL", "https://127.0.0.1:55000")
os.environ.setdefault("WAZUH_API_USERNAME", "test")
os.environ.setdefault("WAZUH_API_PASSWORD", "test")

import app  # noqa: E402
from hawki_alert_analysis.assets import NullAssetInventory  # noqa: E402
from hawki_alert_analysis.live_bundle import TRUNCATION_MARK, build_live_evidence_bundle, fit_live_bundle  # noqa: E402
from hawki_alert_analysis.threat_intel import NullThreatIntelFeed  # noqa: E402

ATTACKER = "45.95.11.22"


def event(number, *, relevance, delta, log_size=300, kind=None):
    item = {
        "id": f"doc-{number}", "index": "wazuh-archives-4.x-2026.10.01",
        "timestamp": f"2026-10-01T05:{10 + number:02d}:00+00:00",
        "agent": {"id": "001", "name": "web-01"}, "rule": {"id": "31100", "level": 3},
        "decoder": {"name": "web-accesslog"}, "location": "/var/log/nginx/access.log",
        "data": {"srcip": ATTACKER, "url": "/x" * 20},
        "full_log": f"{number} " + "A" * log_size,
        "relevance_score": relevance, "relevance_reasons": ["same_source_ip"], "delta_seconds": delta,
    }
    if kind:
        item["origin"] = kind
    return item


class Repository:
    def __init__(self, events):
        self.asset_inventory = NullAssetInventory()
        self.threat_intel_feed = NullThreatIntelFeed()
        self.events = events

    def get_alert_record(self, alert_id):
        return {
            "id": "alert-1", "index": "wazuh-alerts-4.x-2026.10.01", "timestamp": "2026-10-01T05:10:00+00:00",
            "agent": {"id": "001", "name": "web-01"}, "rule": {"id": "31106", "level": 10, "description": "Web attack"},
            "decoder": {"name": "web-accesslog"}, "data": {"srcip": ATTACKER}, "full_log": "GET /../../etc/passwd",
        }

    def get_alert_context(self, alert_id, *, limit=20, window_override=None):
        return {"events": self.events[:limit], "window_seconds": 600, "candidate_count": len(self.events)}


def size(bundle):
    return len(json.dumps({"alert_id": "alert-1", "alert_case": bundle}, ensure_ascii=False, separators=(",", ":")))


class FitTests(unittest.TestCase):
    def build(self, events):
        self.repository = Repository(events)
        return build_live_evidence_bundle(self.repository, "alert-1", max_context=30)

    def fit(self, bundle, limit):
        return fit_live_bundle(bundle, measure=size, limit=limit, repository=self.repository)

    def test_a_package_that_fits_is_left_alone(self):
        bundle = self.build([event(1, relevance=5, delta=10)])
        before = json.dumps(bundle, sort_keys=True)
        self.assertIsNone(self.fit(bundle, 10 ** 6))
        self.assertEqual(json.dumps(bundle, sort_keys=True), before)

    def test_long_logs_are_shortened_before_anything_is_dropped(self):
        bundle = self.build([event(n, relevance=5, delta=n, log_size=4000) for n in range(1, 4)])
        limit = size(bundle) - 6000
        report = self.fit(bundle, limit)
        self.assertTrue(report["fits"])
        self.assertEqual(report["dropped_evidence_ids"], [])
        self.assertTrue(all(item["full_log"].endswith(TRUNCATION_MARK) for item in bundle["investigation_context"]))
        self.assertEqual(bundle["trigger"]["full_log"], "GET /../../etc/passwd")
        self.assertLessEqual(size(bundle), limit)

    def test_the_least_relevant_and_farthest_go_first(self):
        events = [
            event(1, relevance=6, delta=5),
            event(2, relevance=2, delta=30),
            event(3, relevance=2, delta=500),
            event(4, relevance=9, delta=900),
        ]
        bundle = self.build(events)
        each = (size(bundle) - size(self.build([]))) // 4
        report = self.fit(bundle, size(bundle) - each - 50)
        self.assertTrue(report["fits"])
        self.assertEqual(report["dropped_evidence_ids"][0], "CTX-003")
        kept = [item["evidence_id"] for item in bundle["investigation_context"]]
        self.assertIn("CTX-001", kept)
        self.assertIn("CTX-004", kept)

    def test_dropped_items_leave_no_trace_behind(self):
        bundle = self.build([event(n, relevance=n, delta=n) for n in range(1, 9)])
        report = self.fit(bundle, size(self.build([])) + 3000)
        dropped = set(report["dropped_evidence_ids"])
        self.assertTrue(dropped)
        self.assertFalse(dropped & {o["evidence_id"] for o in bundle["control_outcomes"]})
        self.assertNotIn(next(iter(dropped)), json.dumps(bundle["lineage"]))
        self.assertEqual(bundle["retrieval"]["selected_count"], len(bundle["investigation_context"]))
        self.assertEqual(bundle["retrieval"]["context_fit"]["dropped_evidence_ids"], report["dropped_evidence_ids"])
        self.assertIn("TRIGGER", {o["evidence_id"] for o in bundle["control_outcomes"]})

    def test_the_trigger_is_kept_even_when_everything_else_goes(self):
        bundle = self.build([event(n, relevance=1, delta=n, log_size=2000) for n in range(1, 6)])
        report = self.fit(bundle, size(self.build([])) + 400)
        self.assertEqual(bundle["investigation_context"], [])
        self.assertEqual(bundle["trigger"]["evidence_id"], "TRIGGER")
        self.assertTrue(report["fits"])


class AppTests(unittest.TestCase):
    def test_the_analysis_path_no_longer_fails_on_a_big_package(self):
        repository = Repository([event(n, relevance=n % 5, delta=n * 10, log_size=3000) for n in range(1, 17)])
        bundle = build_live_evidence_bundle(repository, "alert-1", max_context=16)
        with mock.patch.dict(app.CONFIG, {"agent_context_max_chars": 20000}), \
             mock.patch.object(app, "ALERT_REPOSITORY", repository):
            with self.assertRaises(ValueError):
                app.serialize_agent_context({"alert_id": "alert-1", "alert_case": bundle})
            report = app.fit_bundle_to_context("alert-1", bundle)
            text = app.serialize_agent_context({"alert_id": "alert-1", "alert_case": bundle})
        self.assertTrue(report["fits"])
        self.assertLessEqual(len(text), 20000)
        self.assertIn('"context_fit"', text)

    def test_fixture_packages_are_not_touched(self):
        self.assertIsNone(app.fit_bundle_to_context("x", {"schema": "hawki.siem.evidence-bundle/v1"}))

    def test_the_prompt_explains_context_fit(self):
        self.assertIn("retrieval.context_fit", app.BASE_SYSTEM_PROMPT)

    def test_the_explanation_reports_it(self):
        from hawki_alert_analysis.explain import build_explanation

        repository = Repository([event(n, relevance=1, delta=n, log_size=2000) for n in range(1, 6)])
        bundle = build_live_evidence_bundle(repository, "alert-1", max_context=16)
        fit_live_bundle(bundle, measure=size, limit=size(bundle) - 2500, repository=repository)
        inputs = build_explanation({}, bundle)["inputs"]
        self.assertTrue(inputs["context_fit"]["shortened_fields"] or inputs["context_fit"]["dropped_evidence_ids"])


if __name__ == "__main__":
    unittest.main()


class LevelFilterTests(unittest.TestCase):
    """The alert list filters by level in the indexer, not on the newest page."""

    class Client:
        def __init__(self):
            self.bodies = []

        def search(self, index, body):
            self.bodies.append(body)
            return {"hits": {"hits": [{
                "_id": "hi", "_index": "wazuh-alerts-4.x-2026.10.01",
                "_source": {"timestamp": "2026-10-01T05:00:00+00:00", "rule": {"id": "31151", "level": 10, "description": "x"},
                            "agent": {"name": "web-01"}},
            }]}}

    def test_min_level_reaches_the_query(self):
        from hawki_alert_analysis.service import AlertAnalysisService
        from hawki_alert_analysis.wazuh import WazuhEventRepository

        client = self.Client()
        service = AlertAnalysisService(WazuhEventRepository(client))
        alerts = service.list_alerts(min_level=8)
        self.assertIn({"range": {"rule.level": {"gte": 8}}}, client.bodies[-1]["query"]["bool"]["filter"])
        self.assertEqual([a["id"] for a in alerts], ["hi"])

        service.list_alerts()
        self.assertNotIn("filter", client.bodies[-1]["query"]["bool"])
