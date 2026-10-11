"""Searching for what an attack was after (10주차 멘토링 5번)."""

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

import app  # noqa: E402
from hawki_alert_analysis.auto_report import ReportStore, report_summary  # noqa: E402
from hawki_alert_analysis.sensitive import category_for_query, classify, report_facets  # noqa: E402
from hawki_alert_analysis.wazuh import alert_text_clause  # noqa: E402


class CategoryTests(unittest.TestCase):
    def test_analyst_words_name_a_category(self):
        self.assertEqual(category_for_query("Credential"), "credential")
        self.assertEqual(category_for_query("자격증명"), "credential")
        self.assertEqual(category_for_query(".env"), "secret_config")
        self.assertEqual(category_for_query("wp-login"), "admin_login")
        self.assertIsNone(category_for_query("207.175.220.59"))

    def test_paths_are_classified_without_the_category_word(self):
        hits = classify(["/.aws/credentials", "/.env.production", "/wp-login.php", "/index.php?f=../../etc/passwd"])
        self.assertIn("/.aws/credentials", hits["credential"])
        self.assertIn("/.env.production", hits["secret_config"])
        self.assertIn("/wp-login.php", hits["admin_login"])
        self.assertIn("traversal", hits)

    def test_ordinary_requests_hit_nothing(self):
        self.assertEqual(classify(["/index.html", "/static/app.js", "GET / HTTP/1.1"]), {})


class AlertSearchTests(unittest.TestCase):
    def test_a_category_word_searches_its_paths_in_the_indexer(self):
        should = alert_text_clause("credential")["bool"]["should"]
        self.assertIn({"match_phrase": {"full_log": "passwd"}}, should)
        self.assertIn({"wildcard": {"data.url": {"value": "*id_rsa*", "case_insensitive": True}}}, should)
        # The word itself is still searched as before.
        self.assertIn({"match_phrase": {"full_log": "credential"}}, should)

    def test_other_text_is_unchanged(self):
        should = alert_text_clause("web-01")["bool"]["should"]
        self.assertFalse(any("passwd" in repr(clause) for clause in should))


class ReportFacetTests(unittest.TestCase):
    bundle = {
        "trigger": {"data": {"url": "/.env"}, "full_log": "1.2.3.4 - - \"GET /.env HTTP/1.1\" 404"},
        "investigation_context": [
            {"data": {"url": "/.aws/credentials"}, "full_log": "GET /.aws/credentials 404"},
            {"data": {}, "full_log": "1.2.3.4 \"POST /wp-login.php HTTP/1.1\" 200"},
        ],
    }

    def test_facets_come_from_the_evidence(self):
        facets = report_facets(self.bundle)
        self.assertEqual(facets["source"], "evidence")
        self.assertIn("/.env", facets["paths"])
        self.assertIn("/wp-login.php", facets["paths"])
        self.assertEqual(sorted(facets["sensitive"]), ["admin_login", "credential", "secret_config"])

    def test_old_reports_fall_back_to_the_alert_summary(self):
        summary = report_summary({"id": "AR-1", "alert": {"summary": "Source 1.2.3.4 GET /wp-config.php.bak"}})
        self.assertEqual(summary["sensitive"], ["backup", "secret_config"])

    def test_the_report_list_finds_reports_by_category(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = ReportStore(Path(directory.name))
        store.save({"id": "AR-20261011-aaaaaa", "created_at": "2026-10-11T00:00:00+00:00",
                    "alert": {"id": "a1", "title": "Web scan", "summary": "GET /index.html"},
                    "facets": report_facets(self.bundle), "review": {"status": "unreviewed"}, "ai": {"status": "completed"}})
        store.save({"id": "AR-20261011-bbbbbb", "created_at": "2026-10-11T00:00:00+00:00",
                    "alert": {"id": "a2", "title": "SSH", "summary": "sshd failure"},
                    "review": {"status": "unreviewed"}, "ai": {"status": "completed"}})
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        with mock.patch.object(app, "AUTO_REPORT_STORE", store):
            by_word = client.get("/api/auto-reports?q=credential").get_json()
            by_filter = client.get("/api/auto-reports?sensitive=secret_config").get_json()
            refused = client.get("/api/auto-reports?sensitive=nope")
        self.assertEqual([item["id"] for item in by_word["reports"]], ["AR-20261011-aaaaaa"])
        self.assertEqual(by_word["query_category"], "credential")
        self.assertEqual([item["id"] for item in by_filter["reports"]], ["AR-20261011-aaaaaa"])
        self.assertEqual(refused.status_code, 400)


if __name__ == "__main__":
    unittest.main()
