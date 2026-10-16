"""2026-10-16 화면 다듬기: alert queue ranking/grouping and Korean red team reasons."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_WORKDIR = tempfile.mkdtemp(prefix="hawki-polish-")
os.environ.setdefault("FLASK_SECRET_KEY", "p" * 48)
os.environ.setdefault("AUTH_DATABASE_PATH", str(Path(_WORKDIR) / "auth.db"))
os.environ.setdefault("ACTION_QUEUE_PATH", str(Path(_WORKDIR) / "actions.jsonl"))
os.environ.setdefault("AUDIT_LOG_PATH", str(Path(_WORKDIR) / "audit.jsonl"))
os.environ.setdefault("HAWKI_ADMIN_USERNAME", "analyst")
os.environ.setdefault("HAWKI_ADMIN_PASSWORD", "Str0ng-Passw0rd-Value!")
os.environ.setdefault("WAZUH_API_URL", "https://127.0.0.1:55000")
os.environ.setdefault("WAZUH_API_USERNAME", "test")
os.environ.setdefault("WAZUH_API_PASSWORD", "test")

import app  # noqa: E402
from hawki_alert_analysis.service import AlertAnalysisService  # noqa: E402


class WindowRepository:
    """search_alert_window only: the shape the live indexer adapter gives."""

    def __init__(self, alerts):
        self.alerts = alerts
        self.asset_inventory = None
        self.threat_intel_feed = None

    def search_alert_window(self, min_level, **options):
        return {"alerts": [dict(item) for item in self.alerts], "total": len(self.alerts), "relation": "eq"}


def alert(i, score, rule="100", src="1.1.1.1", host="web-01"):
    return {"id": f"a{i}", "time": f"2026-10-16T06:{i:02d}:00.000+0000", "rule_id": rule,
            "source_ip": src, "host": host, "title": rule, "priority": {"score": score, "band": "P"}}


class RankedQueueTests(unittest.TestCase):
    def test_rank_is_over_the_period_not_per_page(self):
        # Wazuh-level order would put the score-80 alert last; priority puts it first.
        rows = [alert(i, 10, rule=str(i)) for i in range(1, 30)] + [alert(30, 80, rule="hot")]
        page = AlertAnalysisService(WindowRepository(rows)).page_alerts(page_size=10, rank=True, group=False)
        self.assertEqual(page["alerts"][0]["id"], "a30")
        self.assertEqual(page["pages"], 3)
        self.assertEqual(page["unit"], "alert")

    def test_groups_are_counted_over_the_period_and_paged_as_rows(self):
        rows = [alert(i, 30) for i in range(1, 21)] + [alert(40 + i, 50, rule="r2", src="2.2.2.2") for i in range(5)]
        service = AlertAnalysisService(WindowRepository(rows))
        first = service.page_alerts(page_size=1, rank=True, group=True)
        self.assertEqual(first["unit_total"], 2)
        self.assertEqual(first["groups"][0]["count"], 5)  # the higher score group leads
        second = service.page_alerts(page=2, page_size=1, rank=True, group=True)
        self.assertEqual(second["groups"][0]["count"], 20)
        self.assertEqual(second["total"], 25)


class KoreanRedteamJobTests(unittest.TestCase):
    def test_reason_from_failures_becomes_korean_on_the_check(self):
        body = {"job": {"tool_results": {"promptfoo": {
            "status": "failed",
            "checks": [{"assertion": "EvidenceIdsInBundle", "status": "failed"},
                       {"assertion": "HumanApproval", "status": "passed"}],
            "failures": [{"assertion": "EvidenceIdsInBundle",
                          "reason": "Cited evidence IDs are absent from the bundle: CTX-017."}],
        }}}}
        out = app.korean_redteam_job(body)["job"]["tool_results"]["promptfoo"]
        row = out["checks"][0]
        self.assertEqual(row["name_ko"], "인용 증거 ID 존재 확인")
        self.assertIn("증거 묶음에 없는 ID를 인용했습니다", row["reason_ko"])
        self.assertIn("CTX-017", row["reason"])  # the English original stays
        self.assertEqual(out["check_counts"]["failed"], 1)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        response = self.client.get("/login")
        import re
        token = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
        self.client.post("/login", data={"username": "analyst", "password": "Str0ng-Passw0rd-Value!",
                                         "csrf_token": token.group(1) if token else ""})

    def test_agent_has_one_screen_and_mode_links_open_the_conversation(self):
        for url in ("/agent", "/agent?view=classic", "/agent?mode=alert_summary&alert_id=x"):
            html = self.client.get(url).get_data(as_text=True)
            self.assertIn("agent-workspace.js", html, url)
            self.assertNotIn("작업별 분석", html, url)

    def test_dashboard_shows_both_flows_and_no_shortcut_panel(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('data-flow-pane="process"', html)
        self.assertIn('data-flow-pane="source"', html)
        self.assertNotIn('role="tablist" aria-label="흐름 보기"', html)
        self.assertNotIn("분석 작업 화면", html)
        self.assertIn('data-service-short="llm"', html)  # connection status lives in the sidebar


if __name__ == "__main__":
    unittest.main()
