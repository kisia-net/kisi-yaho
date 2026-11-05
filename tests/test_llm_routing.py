"""Which model answers which request, and recording what actually answered."""

from __future__ import annotations

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

import requests  # noqa: E402

import app  # noqa: E402

QWEN_ROOT = "/models/hub/models--Qwen--Qwen3.5-27B-FP8/snapshots/97f5941b"


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


class FakeServer:
    """Answers chat completions and /models like vLLM does."""

    def __init__(self, models=None, models_error=None):
        self.posts = []
        self.gets = []
        self.models = models if models is not None else [{"id": "hawki-local", "root": QWEN_ROOT}]
        self.models_error = models_error

    def post(self, url, headers=None, json=None, timeout=None):
        self.posts.append({"url": url, "headers": headers or {}, "body": json})
        return FakeResponse({
            "model": json["model"],
            "choices": [{"message": {"content": '{"answer": "ok"}'}, "finish_reason": "stop"}],
        })

    def get(self, url, headers=None, timeout=None, allow_redirects=None):
        self.gets.append(url)
        if self.models_error:
            raise self.models_error
        return FakeResponse({"data": self.models})


BASE = {
    "llm_api_url": "http://gpu:8000/v1/chat/completions",
    "llm_model": "hawki-local",
    "llm_api_key": "chat-key",
    "llm_analysis_model": "",
    "llm_analysis_api_url": "",
    "llm_analysis_api_key": "",
    "llm_analysis_disable_thinking": False,
}


class RoutingTests(unittest.TestCase):
    def setUp(self):
        app._served_model_cache.clear()
        self.server = FakeServer()
        for name, value in (("post", self.server.post), ("get", self.server.get)):
            patcher = mock.patch.object(app.requests, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_llm(self, role="analysis", **config):
        with mock.patch.dict(app.CONFIG, {**BASE, **config}):
            return app.call_llm("log_search", "hi", [], {}, role=role)

    def test_unset_everything_goes_where_it_went_before(self):
        result = self.run_llm()
        sent = self.server.posts[0]
        self.assertEqual(sent["url"], BASE["llm_api_url"])
        self.assertEqual(sent["body"]["model"], "hawki-local")
        self.assertEqual(sent["headers"]["Authorization"], "Bearer chat-key")
        self.assertNotIn("chat_template_kwargs", sent["body"])
        self.assertFalse(result["generation"]["thinking_disabled"])

    def test_analysis_uses_its_own_model_and_chat_keeps_the_default(self):
        split = {
            "llm_analysis_model": "hawki-analysis",
            "llm_analysis_api_url": "http://gpu:8001/v1/chat/completions",
            "llm_analysis_api_key": "analysis-key",
        }
        self.run_llm("analysis", **split)
        self.run_llm("chat", **split)
        analysis, chat = self.server.posts
        self.assertEqual((analysis["url"], analysis["body"]["model"]),
                         ("http://gpu:8001/v1/chat/completions", "hawki-analysis"))
        self.assertEqual(analysis["headers"]["Authorization"], "Bearer analysis-key")
        self.assertEqual((chat["url"], chat["body"]["model"]), (BASE["llm_api_url"], "hawki-local"))
        self.assertEqual(chat["headers"]["Authorization"], "Bearer chat-key")

    def test_analysis_model_alone_keeps_the_default_server_and_key(self):
        self.run_llm(llm_analysis_model="hawki-analysis")
        sent = self.server.posts[0]
        self.assertEqual(sent["url"], BASE["llm_api_url"])
        self.assertEqual(sent["body"]["model"], "hawki-analysis")
        self.assertEqual(sent["headers"]["Authorization"], "Bearer chat-key")

    def test_thinking_is_switched_off_for_analysis_only(self):
        result = self.run_llm("analysis", llm_analysis_disable_thinking=True)
        self.run_llm("chat", llm_analysis_disable_thinking=True)
        analysis, chat = self.server.posts
        self.assertEqual(analysis["body"]["chat_template_kwargs"], {"enable_thinking": False})
        self.assertNotIn("chat_template_kwargs", chat["body"])
        self.assertTrue(result["generation"]["thinking_disabled"])

    def test_evidence_agent_follows_the_analysis_model(self):
        with mock.patch.dict(app.CONFIG, {**BASE, "llm_analysis_model": "hawki-analysis",
                                          "llm_analysis_disable_thinking": True}):
            app.evidence_agent_llm_call([{"role": "user", "content": "x"}], [])
        body = self.server.posts[0]["body"]
        self.assertEqual(body["model"], "hawki-analysis")
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})

    def test_the_weights_behind_the_alias_are_recorded(self):
        result = self.run_llm()
        self.assertEqual(result["model"], "hawki-local")
        self.assertEqual(result["generation"]["served_model"], QWEN_ROOT)
        self.assertEqual(result["generation"]["llm_role"], "analysis")
        self.assertEqual(self.server.gets, ["http://gpu:8000/v1/models"])

    def test_the_model_list_is_asked_once_per_minute_not_per_analysis(self):
        self.run_llm()
        self.run_llm()
        self.assertEqual(len(self.server.gets), 1)

    def test_an_unreachable_model_list_never_breaks_the_analysis(self):
        self.server.models_error = requests.ConnectionError("down")
        result = self.run_llm()
        self.assertIsNone(result["generation"]["served_model"])
        self.assertEqual(result["answer"], "ok")

    def test_an_alias_the_server_does_not_list_is_unknown(self):
        self.server.models = [{"id": "other", "root": "/models/other"}]
        result = self.run_llm()
        self.assertIsNone(result["generation"]["served_model"])


if __name__ == "__main__":
    unittest.main()
