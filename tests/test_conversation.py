"""AI 작업공간 일반 대화 (hawki_chat_agent, 권민석): tool routing, limits, audit."""

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
import hawki_chat_agent  # noqa: E402
from hawki_alert_analysis.service import AlertAnalysisService  # noqa: E402
from hawki_alert_analysis.wazuh import WazuhEventRepository  # noqa: E402


class Client:
    def __init__(self):
        self.bodies = []

    def search(self, index, body):
        self.bodies.append((index, body))
        return {"hits": {"total": {"value": 3, "relation": "eq"}, "hits": [
            {"_id": "x1", "_index": "wazuh-archives-4.x", "_source": {"timestamp": "2026-10-01T05:00:00Z", "full_log": "GET /.env"}},
        ]}, "aggregations": {}}


def model_reply(content):
    response = mock.Mock(status_code=200)
    response.raise_for_status = lambda: None
    response.json = lambda: {"choices": [{"message": {"content": json.dumps(content, ensure_ascii=False)}, "finish_reason": "stop"}]}
    return response


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.service = AlertAnalysisService(WazuhEventRepository(self.client, timestamp_field="timestamp"))
        self.config = {"wazuh_search_enabled": True}

    def test_search_is_a_phrase_filter_in_a_bounded_window(self):
        result = hawki_chat_agent._tool("search_logs", {"text": "/.env", "host": "web-01", "start": "now-2h"}, self.config, self.service, {})
        self.assertEqual(result["status"], "success")
        index, body = self.client.bodies[-1]
        self.assertEqual(body["query"]["bool"]["must"][0]["multi_match"]["type"], "phrase")
        self.assertNotIn("query_string", json.dumps(body))

    def test_bad_arguments_are_refused_before_any_search(self):
        for name, arguments in (("search_logs", {"index": "x"}), ("nope", {}), ("search_logs", {"start": "now-90d"}),
                                ("search_logs", {"source": "users"})):
            result = hawki_chat_agent._tool(name, arguments, self.config, self.service, {})
            self.assertEqual(result["status"], "invalid_request", (name, arguments))
        self.assertEqual(self.client.bodies, [])

    def test_disabled_search_runs_nothing(self):
        result = hawki_chat_agent._tool("search_logs", {}, {"wazuh_search_enabled": False}, self.service, {})
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(self.client.bodies, [])


class ConversationApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"

    def post(self, message="오늘 web-01 요약"):
        return self.client.post("/api/agent/conversation", json={"message": message, "history": [], "context": {}},
                                headers={"X-CSRF-Token": "test-token"})

    def test_one_tool_then_an_answer_and_the_turn_is_audited(self):
        repository = WazuhEventRepository(Client(), timestamp_field="timestamp")
        replies = [model_reply({"tool": "summarize_logs", "arguments": {"host": "web-01"}}),
                   model_reply({"answer": "web-01에서 3건 (R-1)"})]
        with mock.patch.object(app, "ALERT_ANALYSIS", AlertAnalysisService(repository)), \
             mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": True}), \
             mock.patch.object(hawki_chat_agent.requests, "post", side_effect=replies):
            response = self.post()
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["answer"], "web-01에서 3건 (R-1)")
        self.assertEqual([entry["tool"] for entry in data["tool_trace"]], ["summarize_logs"])
        last = app.read_jsonl(app.AUDIT_LOG_PATH)[-1]
        self.assertEqual(last["event_type"], "agent_conversation")
        self.assertEqual(last["detail"]["tools"][0]["tool"], "summarize_logs")
        self.assertNotIn("오늘", json.dumps(last))

    def test_unreachable_model_is_a_korean_502(self):
        with mock.patch.object(hawki_chat_agent.requests, "post", side_effect=app.requests.ConnectionError("down")):
            response = self.post()
        self.assertEqual(response.status_code, 502)
        self.assertIn("LLM", response.get_json()["error"])

    def test_empty_message_is_refused(self):
        self.assertEqual(self.post(" ").status_code, 400)

    def test_conversation_is_a_valid_session_mode(self):
        response = self.client.post("/api/chat-sessions", json={
            "id": "s-conversation-1", "mode": "conversation", "title": "t", "history": [], "transcript": [], "context": {},
        }, headers={"X-CSRF-Token": "test-token"})
        self.assertNotEqual(response.status_code, 400, response.get_json())


if __name__ == "__main__":
    unittest.main()


class ContextFitTests(unittest.TestCase):
    def test_records_fit_the_configured_limit_oldest_first(self):
        big = {"status": "success", "total_matches": 900, "returned": 40,
               "events": [{"ref": f"E{n}", "source": {"full_log": "x" * 400}} for n in range(40)]}
        trace = [{"ref": f"R-1-{n}", "tool": "search_logs", "result": json.loads(json.dumps(big))} for n in range(1, 4)]
        fitted = hawki_chat_agent._fit_records(trace, 9000)
        self.assertLessEqual(len(json.dumps(fitted, ensure_ascii=False)), 9000)
        self.assertIn("compacted", fitted[0]["result"])
        self.assertEqual(fitted[0]["result"]["total_matches"], 900)
        self.assertEqual(fitted[-1]["result"]["returned"], len(fitted[-1]["result"]["events"]))
        self.assertEqual(len(trace[0]["result"]["events"]), 40)  # the trace shown to the analyst is untouched

    def test_small_records_are_left_alone(self):
        trace = [{"ref": "R-1-1", "tool": "environment", "result": {"status": "success"}}]
        self.assertEqual(hawki_chat_agent._fit_records(trace, 9000), trace)

    def test_budget_follows_agent_context_max_chars(self):
        small = hawki_chat_agent._evidence_budget({"agent_context_max_chars": 20000}, "i" * 5000, "m", [])
        large = hawki_chat_agent._evidence_budget({"agent_context_max_chars": 48000}, "i" * 5000, "m", [])
        self.assertEqual(large - small, 28000)
