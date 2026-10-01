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

    def post_search(self, **payload):
        response = mock.Mock(status_code=200)
        response.raise_for_status = lambda: None
        response.json = lambda: {"hits": {"total": {"value": 0}, "hits": []}}
        with mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": True}), \
             mock.patch.object(app.requests, "post", return_value=response) as post:
            result = self.client.post("/api/log-search", json=payload, headers={"X-CSRF-Token": "test-token"})
        return result, post

    def test_the_period_accepts_presets_and_zoned_instants(self):
        for start, end in (("now-15m", "now"), ("now-30d", "now"), ("now-7d/d", "now/d"),
                           ("2026-09-30T15:00:00.000Z", "2026-10-01T09:30:00+09:00")):
            result, post = self.post_search(query="*", start_time=start, end_time=end)
            self.assertEqual(result.status_code, 200, (start, end))
            window = post.call_args.kwargs["json"]["query"]["bool"]["filter"][0]["range"]["timestamp"]
            self.assertEqual(window, {"gte": start, "lte": end})

    def test_a_period_the_indexer_would_misread_is_refused(self):
        # A zone-less time would be read as UTC: 9 hours off for a Korean analyst.
        for start in ("2026-10-01T09:00", "yesterday", "now-24h; DROP", "now-24x"):
            result, post = self.post_search(query="*", start_time=start, end_time="now")
            self.assertEqual(result.status_code, 400, start)
            post.assert_not_called()

    def test_an_empty_period_means_the_last_24_hours(self):
        result, post = self.post_search(query="*", start_time="", end_time="")
        self.assertEqual(result.status_code, 200)
        window = post.call_args.kwargs["json"]["query"]["bool"]["filter"][0]["range"]["timestamp"]
        self.assertEqual(window, {"gte": "now-24h", "lte": "now"})

    def test_the_page_names_the_targets_instead_of_index_patterns(self):
        html = self.client.get("/logs").get_data(as_text=True)
        self.assertIn('id="log-target"', html)
        self.assertIn(">보안 경보</option>", html)
        self.assertIn(">전체 원시 로그</option>", html)
        self.assertIn('data-range="now-24h"', html)
        self.assertIn('type="datetime-local"', html)
        self.assertIn("data-host-select", html)
        self.assertIn('id="log-index" value="wazuh-alerts-*"', html)


class LogSearchHostsTests(unittest.TestCase):
    setUp = LogSearchTests.setUp
    """The 호스트 dropdown: Wazuh agents first, indexer names when the API is down."""

    AGENTS = {"data": {"affected_items": [
        {"id": "002", "name": "db-01", "ip": "10.0.10.21", "status": "disconnected"},
        {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1", "status": "active"},
        {"id": "001", "name": "web-01", "ip": "10.0.10.20", "status": "active"},
        {"id": "003", "name": "", "status": "active"},
    ]}}

    def hosts(self, *, agents=None, agents_error=None, indexer=None, search_enabled=True):
        api = mock.Mock()
        if agents_error:
            api.agents.side_effect = agents_error
        else:
            api.agents.return_value = agents
        response = mock.Mock(status_code=200)
        response.raise_for_status = lambda: None
        response.json = lambda: indexer or {}
        with mock.patch.object(app, "WAZUH_API", api), \
             mock.patch.dict(app.CONFIG, {"wazuh_search_enabled": search_enabled}), \
             mock.patch.object(app.requests, "post", return_value=response) as post:
            result = self.client.get("/api/log-search/hosts")
        self.assertEqual(result.status_code, 200)
        return result.get_json(), post

    def test_registered_agents_with_status_manager_first(self):
        data, post = self.hosts(agents=self.AGENTS)
        self.assertEqual(data["source"], "wazuh_api")
        self.assertEqual([h["name"] for h in data["hosts"]], ["wazuh-manager", "web-01", "db-01"])
        self.assertTrue(data["hosts"][0]["manager"])
        self.assertEqual(data["hosts"][2]["status"], "disconnected")
        post.assert_not_called()

    def test_falls_back_to_names_seen_in_the_indexer(self):
        buckets = {"aggregations": {"hosts": {"buckets": [
            {"key": "web-01", "doc_count": 120, "agent_id": {"buckets": [{"key": "001"}]}},
            {"key": "wazuh-manager", "doc_count": 40, "agent_id": {"buckets": [{"key": "000"}]}},
        ]}}}
        data, post = self.hosts(agents_error=app.WazuhServerAPIError("down"), indexer=buckets)
        self.assertEqual(data["source"], "indexer")
        self.assertEqual([h["name"] for h in data["hosts"]], ["wazuh-manager", "web-01"])
        self.assertEqual(data["hosts"][1]["events_7d"], 120)
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["size"], 0)
        self.assertEqual(body["aggs"]["hosts"]["terms"]["field"], "agent.name")

    def test_nothing_available_is_an_empty_list_not_an_error(self):
        data, post = self.hosts(agents_error=app.WazuhServerAPIError("down"), search_enabled=False)
        self.assertEqual(data, {"source": None, "total": 0, "hosts": []})
        post.assert_not_called()

    def test_requires_sign_in(self):
        anonymous = app.app.test_client()
        self.assertIn(anonymous.get("/api/log-search/hosts").status_code, (302, 401))


if __name__ == "__main__":
    unittest.main()
