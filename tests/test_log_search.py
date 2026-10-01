"""로그 검색: "*" means everything, and a field query passes through unchanged."""

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


class LogSearchTests(unittest.TestCase):
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

    def search(self, query):
        response = mock.Mock(status_code=200)
        response.raise_for_status = lambda: None
        response.json = lambda: {"hits": {"total": {"value": 0}, "hits": []}}
        with mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": True}), \
             mock.patch.object(app.requests, "post", return_value=response) as post:
            result = self.client.post("/api/log-search", json={"query": query},
                                      headers={"X-CSRF-Token": "test-token"})
        self.assertEqual(result.status_code, 200)
        return post.call_args.kwargs["json"]["query"]["bool"]["must"][0]

    def test_star_means_everything(self):
        self.assertEqual(self.search("*"), {"match_all": {}})
        self.assertEqual(self.search(""), {"match_all": {}})

    def test_field_queries_are_unchanged(self):
        must = self.search('data.srcip:"207.175.220.59" AND rule.level:>=8')
        self.assertEqual(must["query_string"]["query"], 'data.srcip:"207.175.220.59" AND rule.level:>=8')
        self.assertFalse(must["query_string"]["allow_leading_wildcard"])


if __name__ == "__main__":
    unittest.main()
