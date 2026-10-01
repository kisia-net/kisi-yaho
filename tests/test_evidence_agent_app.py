"""The analysis endpoint's use of the evidence agent must never break it."""

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
from tests.test_evidence_agent import FakeRepository, ScriptedModel, tool_call  # noqa: E402
from hawki_alert_analysis.live_bundle import build_live_evidence_bundle  # noqa: E402


class GatherMoreEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepository()
        self.bundle = build_live_evidence_bundle(self.repo, "alert-1")
        patcher = mock.patch.object(app, "ALERT_REPOSITORY", self.repo)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unreachable_model_keeps_the_original_evidence(self):
        with mock.patch.object(app, "evidence_agent_llm_call", side_effect=requests.ConnectionError("down")):
            result = app.gather_more_evidence("alert-1", self.bundle)
        self.assertEqual(result["agent_retrieval"]["stopped"], "error")
        self.assertEqual(len(result["investigation_context"]), 1)

    def test_oversized_result_is_reverted(self):
        model = ScriptedModel(tool_call("widen_window", seconds_before=1800, seconds_after=0, reason="x"))
        # Fits before the agent runs, too big after it added evidence.
        with mock.patch.object(app, "evidence_agent_llm_call", model), \
             mock.patch.object(app, "serialize_agent_context", side_effect=[None, ValueError("too big")]):
            result = app.gather_more_evidence("alert-1", self.bundle)
        self.assertEqual(result["agent_retrieval"]["stopped"], "context_limit_reverted")
        self.assertEqual(len(result["investigation_context"]), 1)

    def test_a_package_already_over_the_limit_skips_the_agent(self):
        model = mock.Mock(side_effect=AssertionError("the agent must not be called"))
        with mock.patch.object(app, "evidence_agent_llm_call", model), \
             mock.patch.object(app, "serialize_agent_context", side_effect=ValueError("too big")):
            result = app.gather_more_evidence("alert-1", self.bundle)
        model.assert_not_called()
        self.assertEqual(result["agent_retrieval"]["stopped"], "no_room")
        self.assertEqual(len(result["investigation_context"]), 1)

    def test_added_evidence_reaches_the_analysis(self):
        model = ScriptedModel(
            tool_call("widen_window", seconds_before=1800, seconds_after=0, reason="x"),
            tool_call("finish", reason="enough"),
        )
        with mock.patch.object(app, "evidence_agent_llm_call", model):
            result = app.gather_more_evidence("alert-1", self.bundle)
        self.assertEqual(len(result["investigation_context"]), 3)
        self.assertEqual(result["agent_retrieval"]["stopped"], "finish")


if __name__ == "__main__":
    unittest.main()
