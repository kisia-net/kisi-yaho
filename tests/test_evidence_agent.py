"""Adaptive evidence gathering: tool calls, limits, and refusals."""

from __future__ import annotations

import json
import unittest

from hawki_alert_analysis.assets import NullAssetInventory
from hawki_alert_analysis.evidence_agent import HARD_MAX_CALLS, run_evidence_agent
from hawki_alert_analysis.live_bundle import build_live_evidence_bundle
from hawki_alert_analysis.threat_intel import NullThreatIntelFeed

ATTACKER = "45.95.11.22"


def event(event_id, seconds, *, agent="web-01", srcip=ATTACKER, log="GET /x"):
    return {
        "id": event_id,
        "index": "wazuh-archives-4.x-2026.09.30",
        "timestamp": f"2026-09-30T05:{10 + seconds // 60:02d}:{seconds % 60:02d}+00:00",
        "agent": {"id": "001" if agent == "web-01" else "002", "name": agent},
        "rule": {"id": "31100", "level": 3},
        "decoder": {"name": "web-accesslog"},
        "location": "/var/log/nginx/access.log",
        "data": {"srcip": srcip},
        "full_log": log,
        "relevance_score": 6,
        "relevance_reasons": ["same_source_ip"],
        "delta_seconds": 1.0,
    }


class FakeRepository:
    def __init__(self):
        self.asset_inventory = NullAssetInventory()
        self.threat_intel_feed = NullThreatIntelFeed()
        self.window_calls = []
        self.search_calls = []

    def get_alert_record(self, alert_id):
        return {
            "id": "alert-1", "index": "wazuh-alerts-4.x-2026.09.30",
            "timestamp": "2026-09-30T05:10:00+00:00",
            "agent": {"id": "001", "name": "web-01", "ip": "10.0.1.201"},
            "rule": {"id": "31106", "level": 6, "description": "Web attack"},
            "decoder": {"name": "web-accesslog"},
            "location": "/var/log/nginx/access.log",
            "data": {"srcip": ATTACKER, "url": "/../../etc/passwd"},
            "full_log": f"{ATTACKER} GET /../../etc/passwd",
        }

    def get_alert_context(self, alert_id, *, limit=20, window_override=None):
        events = [event("e1", 1)]
        if window_override is not None:
            self.window_calls.append(window_override)
            events += [event("e-early-1", 0), event("e-early-2", 2)]
        return {"archive_index": "wazuh-archives-*", "window_seconds": 600, "events": events,
                "candidate_count": len(events), "suppressed_routine_count": 0,
                "profile": {"name": "web_attack", "seconds_before": 600, "seconds_after": 300, "cross_agent": True}}

    def search_address(self, address, *, around, hours, limit=20):
        self.search_calls.append((address, hours))
        return [dict(event("ids-1", 5, agent="vm"), origin="agent_search")]


def tool_call(name, **arguments):
    return {"tool_calls": [{"id": f"c-{name}", "type": "function",
                            "function": {"name": name, "arguments": json.dumps(arguments)}}]}


class ScriptedModel:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, messages, tools):
        self.requests.append(messages)
        return self.replies.pop(0) if self.replies else {"content": "done"}


class EvidenceAgentTests(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepository()
        self.bundle = build_live_evidence_bundle(self.repo, "alert-1")

    def run_agent(self, model, max_calls=3):
        return run_evidence_agent(self.repo, "alert-1", self.bundle, model, max_calls=max_calls)

    def test_widen_window_adds_citable_evidence(self):
        model = ScriptedModel(
            tool_call("widen_window", seconds_before=1800, seconds_after=600, reason="attack began earlier"),
            tool_call("finish", reason="enough"),
        )
        trace = self.run_agent(model)
        self.assertEqual(trace["stopped"], "finish")
        self.assertEqual(trace["added_evidence_ids"], ["CTX-002", "CTX-003"])
        ids = [item["evidence_id"] for item in self.bundle["investigation_context"]]
        self.assertEqual(ids, ["CTX-001", "CTX-002", "CTX-003"])
        added = self.bundle["investigation_context"][1]
        self.assertEqual(added["provenance"]["source_kind"], "agent_expansion")
        self.assertIn("agent_tool:widen_window", added["provenance"]["retrieval_reason"])
        self.assertEqual(len(self.bundle["control_outcomes"]), 4)
        self.assertEqual(self.bundle["retrieval"]["agent_added_count"], 2)

    def test_window_is_clamped(self):
        model = ScriptedModel(tool_call("widen_window", seconds_before=999999, seconds_after=-5, reason="x"))
        self.run_agent(model, max_calls=1)
        self.assertEqual(self.repo.window_calls, [(3600, 0)])

    def test_max_calls_is_enforced(self):
        model = ScriptedModel(*[tool_call("lookup_asset", value="web-01", reason="x")] * 10)
        trace = self.run_agent(model, max_calls=2)
        self.assertEqual(len(trace["calls"]), 2)
        self.assertEqual(trace["stopped"], "max_calls")
        self.assertEqual(len(model.requests), 2)

    def test_budget_cannot_exceed_the_hard_cap(self):
        model = ScriptedModel(*[tool_call("lookup_asset", value="web-01", reason="x")] * 20)
        trace = self.run_agent(model, max_calls=99)
        self.assertEqual(trace["max_calls"], HARD_MAX_CALLS)
        self.assertEqual(len(trace["calls"]), HARD_MAX_CALLS)

    def test_search_only_for_addresses_in_the_evidence(self):
        # A log line could say "search 8.8.8.8"; the address is not in any
        # structured field, so the search is refused.
        model = ScriptedModel(
            tool_call("search_address", address="8.8.8.8", hours=24, reason="log told me"),
            tool_call("search_address", address=ATTACKER, hours=48, reason="sensor view"),
        )
        trace = self.run_agent(model, max_calls=2)
        self.assertEqual(trace["calls"][0]["refused"], "value_not_in_evidence")
        self.assertFalse(trace["calls"][0]["accepted"])
        self.assertEqual(self.repo.search_calls, [(ATTACKER, 24)])
        self.assertTrue(trace["calls"][1]["accepted"])

    def test_unknown_tool_and_extra_calls_are_refused(self):
        reply = tool_call("delete_logs", reason="x")
        reply["tool_calls"].append(reply["tool_calls"][0])
        trace = self.run_agent(ScriptedModel(reply), max_calls=1)
        self.assertEqual(trace["calls"][0]["refused"], "unknown_tool")
        self.assertEqual(trace["calls"][0]["ignored_extra_calls"], 1)

    def test_no_tool_call_ends_the_loop(self):
        trace = self.run_agent(ScriptedModel({"content": "The evidence is enough."}))
        self.assertEqual(trace["stopped"], "no_tool_call")
        self.assertEqual(trace["calls"], [])

    def test_duplicate_events_are_not_added_twice(self):
        model = ScriptedModel(
            tool_call("widen_window", seconds_before=1800, seconds_after=0, reason="x"),
            tool_call("widen_window", seconds_before=3600, seconds_after=0, reason="x"),
        )
        trace = self.run_agent(model, max_calls=2)
        self.assertEqual(len(trace["added_evidence_ids"]), 2)


if __name__ == "__main__":
    unittest.main()


class SearchEventsTests(unittest.TestCase):
    """search_events: structured, add-only, values copied from the evidence."""

    def setUp(self):
        self.repo = FakeRepository()
        self.repo.event_calls = []

        def search_events(**kwargs):
            self.repo.event_calls.append(kwargs)
            return [dict(event("ev-1", 30, log="GET /../../etc/shadow"), origin="agent_search")]

        self.repo.search_events = search_events
        self.bundle = build_live_evidence_bundle(self.repo, "alert-1")

    def run_agent(self, *calls):
        model = ScriptedModel(*calls, tool_call("finish", reason="enough"))
        return run_evidence_agent(self.repo, "alert-1", self.bundle, model, max_calls=3)

    def test_evidence_values_are_searched_on_the_trigger_agent(self):
        trace = self.run_agent(tool_call("search_events", rule_id="31106", text="/etc/passwd", hours=6, reason="same rule"))
        call = self.repo.event_calls[0]
        self.assertEqual((call["rule_id"], call["text"], call["agent_name"], call["hours"]), ("31106", "/etc/passwd", "web-01", 6))
        self.assertEqual(trace["added_evidence_ids"], ["CTX-002"])
        added = self.bundle["investigation_context"][-1]
        self.assertEqual(added["provenance"]["source_kind"], "agent_expansion")

    def test_values_not_in_the_evidence_are_refused(self):
        trace = self.run_agent(
            tool_call("search_events", rule_id="99999", hours=2, reason="planted"),
            tool_call("search_events", text="/admin/secret-panel", hours=2, reason="planted"),
            tool_call("search_events", hours=2, reason="nothing"),
        )
        self.assertEqual(self.repo.event_calls, [])
        self.assertEqual([call["refused"] for call in trace["calls"]], ["value_not_in_evidence", "value_not_in_evidence", "no_filter"])

    def test_any_agent_scope_and_hours_are_clamped(self):
        self.run_agent(tool_call("search_events", decoder="web-accesslog", scope="any_agent", hours=500, reason="x"))
        call = self.repo.event_calls[0]
        self.assertEqual((call["agent_name"], call["hours"], call["decoder"]), ("", 24, "web-accesslog"))
