"""Korean API messages, assessment rendering, and the doubled demo answer."""

from __future__ import annotations

import ast
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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
from hawki_alert_analysis.assessment import assessment_markdown, normalize_assessment  # noqa: E402
from hawki_alert_analysis.ui_messages import (  # noqa: E402
    ERROR_MESSAGES_KO,
    localize_error_payload,
)


def error_literals() -> set[str]:
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "error"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    found.add(value.value)
    return found


class ErrorMessageTests(unittest.TestCase):
    def test_every_error_message_has_a_korean_version(self):
        missing = sorted(error_literals() - set(ERROR_MESSAGES_KO))
        self.assertEqual(missing, [], "add these to hawki_alert_analysis/ui_messages.py")

    def test_payload_keeps_code_and_english(self):
        body = {"error": "Alert not found.", "code": "not_found", "detail": "x"}
        localized = localize_error_payload(body, "ko")
        self.assertEqual(localized["error"], "경보를 찾을 수 없습니다.")
        self.assertEqual(localized["error_en"], "Alert not found.")
        self.assertEqual(localized["code"], "not_found")
        self.assertEqual(localized["detail"], "x")

    def test_english_mode_and_unknown_messages_pass_through(self):
        body = {"error": "Alert not found."}
        self.assertIs(localize_error_payload(body, "en"), body)
        unknown = {"error": "Something only an exception says"}
        self.assertIs(localize_error_payload(unknown, "ko"), unknown)

    def test_http_response_is_localized_with_status_unchanged(self):
        client = app.app.test_client()
        response = client.get("/api/alerts")  # no session
        self.assertEqual(response.status_code, 401)
        body = json.loads(response.data)
        self.assertEqual(body["error"], "로그인이 필요합니다.")
        self.assertEqual(body["error_en"], "Authentication required.")


class AssessmentRenderingTests(unittest.TestCase):
    ASSESSMENT = {
        "interpretation": "Probable exploitation attempt.",
        "severity": {"level": "high", "rationale": "Internet-facing."},
        "confidence": {"level": "low", "rationale": "One source."},
        "confirmed_observations": ["A traversal URI was requested."],
    }

    def test_korean_headings_and_levels(self):
        text = assessment_markdown(normalize_assessment(self.ASSESSMENT), "ko")
        self.assertIn("### 판단 요약", text)
        self.assertIn("### 확인된 관측 사실", text)
        self.assertIn("**심각도: 높음**", text)
        self.assertIn("**신뢰도: 낮음**", text)

    def test_english_rendering_is_unchanged(self):
        text = assessment_markdown(normalize_assessment(self.ASSESSMENT))
        self.assertIn("### Assessment", text)
        self.assertIn("**Severity: high**", text)

    def test_answer_equal_to_the_rendered_assessment_is_not_repeated(self):
        detail = assessment_markdown(
            normalize_assessment(self.ASSESSMENT), app.CONFIG["llm_output_language"]
        )
        result = app.apply_assessment_schema(
            {"answer": detail, "assessment": self.ASSESSMENT}, context={}
        )
        self.assertEqual(result["answer"].count(detail), 1)

    def test_distinct_briefing_still_comes_first(self):
        result = app.apply_assessment_schema(
            {"answer": "Short briefing.", "assessment": self.ASSESSMENT}, context={}
        )
        self.assertTrue(result["answer"].startswith("Short briefing."))
        self.assertIn("---", result["answer"])

    def test_review_notes_get_codes(self):
        result = app.apply_assessment_schema({"answer": "", "assessment": self.ASSESSMENT}, context={})
        review = result["assessment_review"]
        self.assertIn("no_contradictory_evidence", review["note_codes"])
        if app.CONFIG["llm_output_language"] == "ko":
            self.assertEqual(len(review["notes_localized"]), len(review["notes"]))


if __name__ == "__main__":
    unittest.main()
