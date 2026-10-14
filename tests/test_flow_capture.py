"""데이터 흐름 캡처 (hawki_alert_analysis/flow_capture.py)."""

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
from hawki_alert_analysis.control_outcomes import derive_control_outcome  # noqa: E402
from hawki_alert_analysis.flow_capture import (  # noqa: E402
    FlowCaptureStore,
    build_flow,
    field_paths,
    raw_format,
    to_markdown,
)

ACCESS = ('52.141.3.247 - - [13/Oct/2026:08:17:04 +0900] "GET /portal/index.php?page=....//etc/passwd HTTP/1.1" '
          '200 2845 "-" "Mozilla/5.0"')
MODSEC = ('2026/10/13 08:16:28 [error] 2014#2014: *4756 [client 52.141.3.247] ModSecurity: Access denied with '
          'code 403 (phase 2). [id "930100"] [msg "Path Traversal Attack (/../)"]')
EVE = {"event_type": "alert", "src_ip": "52.141.3.247", "alert": {"action": "allowed", "signature": "ET WEB_SERVER /etc/passwd"}}


def item(evidence_id, agent, location, decoder, full_log, data, rule=None, origin="same_agent"):
    value = {
        "evidence_id": evidence_id,
        "provenance": {"source_index": "wazuh-archives-4.x-2026.10.13", "source_document_id": evidence_id.lower()},
        "timestamp": "2026-10-12T23:17:04.008+0000",
        "agent": agent, "decoder": {"name": decoder}, "location": location,
        "data": data, "full_log": full_log, "rule": rule or {},
    }
    if evidence_id != "TRIGGER":
        value["retrieval"] = {"origin": origin}
    return value


WEB = {"id": "001", "name": "web-01", "ip": "10.0.1.201"}
IDS = {"id": "002", "name": "ids-01", "ip": "10.0.1.50"}


def bundle():
    trigger = item("TRIGGER", WEB, "/var/log/nginx/access.log", "web-accesslog", ACCESS,
                   {"srcip": "52.141.3.247", "url": "/portal/index.php?page=....//etc/passwd", "id": "200"},
                   {"id": "31106", "level": 6, "description": "A web attack returned code 200 (success).",
                    "groups": ["web", "attack"], "mitre": {"id": ["T1190"]}})
    trigger.update(id="alert-1", index="wazuh-alerts-4.x-2026.10.13", timestamp_kst="2026-10-13 08:17:04 KST")
    context = [
        item("CTX-001", WEB, "/var/log/nginx/error.log", "nginx-errorlog", MODSEC,
             {"srcip": "52.141.3.247"}, {"id": "31333", "level": 7, "description": "ModSecurity rejected a query",
                                         "groups": ["modsecurity"]}),
        item("CTX-002", IDS, "/var/log/suricata/eve.json", "json", json.dumps(EVE), EVE,
             {"id": "86601", "level": 10, "description": "Suricata alert", "groups": ["ids", "suricata"]},
             origin="cross_agent"),
        item("CTX-003", WEB, "/var/log/nginx/access.log", "web-accesslog", ACCESS.replace(" 200 ", " 404 "),
             {"srcip": "52.141.3.247", "id": "404"}),
    ]
    package = {
        "schema": "hawki.wazuh.live-evidence/v2",
        "trigger": trigger,
        "investigation_context": context,
        "control_outcomes": [derive_control_outcome(value) for value in [trigger, *context]],
        "lineage": {"edges": [{}, {}]},
        "priority": {"band": "P2", "score": 57},
        "assets": {"matches": [{"id": "asset-web", "hostname": "web-01", "criticality": "high"}]},
        "threat_intelligence": {"matches": []},
        "retrieval": {"profile": {"name": "web_attack"}, "candidate_count": 28, "selected_count": 3},
        "evidence_handling": ["..."],
        "agent_retrieval": {
            "calls": [{"tool": "search_address", "arguments": {"address": "52.141.3.247"}, "accepted": True,
                       "added_evidence_ids": ["CTX-003"]}],
            "added_evidence_ids": ["CTX-003"], "stopped": "finish",
        },
    }
    return package


RESULT = {
    "model": "hawki-local", "analysis_id": "an-1",
    "answer": "우회 1건이 200 으로 응답됐습니다.\n\n---\n### 판단 요약\n길게 덧붙인 렌더링",
    "assessment": {
        "confirmed_observations": ["..."],
        "supporting_evidence": [{"statement": "...", "event_ids": ["TRIGGER", "CTX-002", "CTX-099"]}],
    },
    "assessment_review": {"complete": True, "missing_sections": []},
    "actions": [{"type": "velociraptor_collection", "title": "web-01 증거 수집", "target": "web-01"}],
}


class StageTests(unittest.TestCase):
    def setUp(self):
        self.doc = build_flow("alert-1", bundle(), result=RESULT, mode="captured",
                              snapshots={"initial": {"context_count": 2, "size_chars": 10}})
        self.stages = self.doc["stages"]

    def test_raw_lines_are_grouped_by_server_and_source(self):
        servers = {server["server"]: server for server in self.stages["raw"]["servers"]}
        self.assertEqual(set(servers), {"web-01", "ids-01"})
        web = {source["label"]: source for source in servers["web-01"]["sources"]}
        self.assertEqual(web["nginx 접근 로그"]["count"], 2)
        self.assertEqual(web["nginx 접근 로그"]["samples"][0]["evidence_id"], "TRIGGER", "the trigger is shown first")
        self.assertEqual(web["nginx 접근 로그"]["format"], "텍스트 한 줄")
        self.assertEqual(servers["ids-01"]["sources"][0]["format"], "JSON 한 줄")

    def test_events_show_the_fields_the_decoder_produced(self):
        decoders = {(group["server"], group["decoder"]): group for group in self.stages["event"]["decoders"]}
        self.assertIn("data.alert.signature", decoders[("ids-01", "json")]["data_fields"])
        self.assertEqual(decoders[("web-01", "web-accesslog")]["example"]["evidence_id"], "TRIGGER")
        self.assertNotIn("rule", decoders[("web-01", "web-accesslog")]["example"])

    def test_alert_stage_separates_rule_matches(self):
        alert = self.stages["alert"]
        self.assertEqual(alert["trigger"]["rule"]["id"], "31106")
        self.assertIn("rule.mitre.id[]", alert["rule_fields"])
        self.assertEqual(alert["context_without_rule"], 1)
        self.assertEqual(alert["alert_count"], 3)
        self.assertEqual({item["rule_id"] for item in alert["related_rules"]}, {"31333", "86601"})

    def test_evidence_stage_counts_and_control_outcomes(self):
        evidence = self.stages["evidence"]
        self.assertEqual(evidence["context_by_origin"], {"same_agent": 2, "cross_agent": 1})
        self.assertEqual(evidence["control_summary"].get("BLOCKED"), 1)
        self.assertEqual(evidence["control_summary"].get("NOT_BLOCKED"), 1)
        self.assertNotIn("evidence_handling", evidence["blocks"])

    def test_ai_stages(self):
        retrieval = self.stages["ai_retrieval"]
        self.assertTrue(retrieval["ran"])
        self.assertEqual(retrieval["calls"][0]["tool"], "search_address")
        judgment = self.stages["ai_judgment"]
        self.assertEqual([item["evidence_id"] for item in judgment["citations"]], ["TRIGGER", "CTX-002", "CTX-099"])
        self.assertEqual(judgment["unknown_citations"], ["CTX-099"])
        self.assertEqual(judgment["citations"][1]["server"], "ids-01")
        self.assertEqual(self.stages["response"]["proposed"][0]["type"], "velociraptor_collection")

    def test_sizes_and_counts_follow_the_stage_order(self):
        self.assertEqual([stage["key"] for stage in self.doc["stage_order"]][:4], ["raw", "event", "alert", "evidence"])
        self.assertEqual(self.doc["counts"]["raw"], 4)
        self.assertGreater(self.doc["sizes"]["event"], self.doc["sizes"]["raw"])
        self.assertEqual(self.doc["counts"]["ai_judgment"], 3)

    def test_without_an_analysis_the_ai_stages_say_so(self):
        doc = build_flow("alert-1", {k: v for k, v in bundle().items() if k != "agent_retrieval"})
        self.assertEqual(doc["stages"]["ai_retrieval"], {"ran": False})
        self.assertEqual(doc["stages"]["ai_judgment"], {"ran": False})
        self.assertIsNone(doc["counts"]["ai_judgment"])

    def test_markdown_has_every_stage_and_only_the_model_briefing(self):
        text = to_markdown(self.doc)
        for heading in ("① 서버별 원본 로그", "② 이벤트", "③ 경보", "④ 증거 패키지", "⑤ AI 증거 수집", "⑥ AI 판단", "⑦ 조치"):
            self.assertIn(heading, text)
        self.assertIn(ACCESS, text)
        self.assertIn("우회 1건이 200 으로 응답됐습니다.", text)
        self.assertNotIn("길게 덧붙인 렌더링", text.split("assessment:")[0])
        self.assertIn("증거에 없는 id", text)


class HelperTests(unittest.TestCase):
    def test_field_paths(self):
        self.assertEqual(field_paths({"a": {"b": 1, "c": [1]}, "d": [{"e": 2}]}), ["a.b", "a.c[]", "d[].e"])

    def test_raw_format(self):
        self.assertEqual(raw_format('{"a": 1}'), "JSON 한 줄")
        self.assertEqual(raw_format("{not json"), "텍스트 한 줄")
        self.assertEqual(raw_format(""), "원문 없음")


class StoreTests(unittest.TestCase):
    def test_keeps_the_newest_captures_per_alert(self):
        store = FlowCaptureStore(Path(tempfile.mkdtemp()), keep=2)
        for index in range(3):
            store.save({"alert_id": "alert-1", "n": index})
        store.save({"alert_id": "alert-2", "n": 9})
        captures = store.list("alert-1")
        self.assertEqual([capture["n"] for capture in captures], [2, 1])
        self.assertEqual(store.latest("alert-2")["n"], 9)
        self.assertIsNone(store.latest("missing"))


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.client.post("/login", data={
            "username": os.environ["HAWKI_ADMIN_USERNAME"], "password": os.environ["HAWKI_ADMIN_PASSWORD"],
            "csrf_token": "test-token", "next": "/",
        })
        self.store = FlowCaptureStore(Path(tempfile.mkdtemp()))
        self.queue = Path(tempfile.mkdtemp()) / "actions.jsonl"
        self.queue.write_text(
            json.dumps({"id": "ACT-1", "type": "velociraptor_collection", "status": "pending_approval",
                        "alert_id": "alert-1"}) + "\n"
            + json.dumps({"id": "ACT-2", "type": "velociraptor_collection", "status": "pending_approval",
                          "alert_id": "other"}) + "\n",
            encoding="utf-8",
        )
        self.patches = [
            mock.patch.object(app, "FLOW_CAPTURE_STORE", self.store),
            mock.patch.object(app, "ACTION_QUEUE_PATH", self.queue),
            mock.patch.object(app.ALERT_ANALYSIS, "evidence_bundle", return_value=bundle()),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def test_without_a_capture_the_flow_is_rebuilt_live(self):
        body = self.client.get("/api/alerts/alert-1/flow").get_json()
        self.assertEqual(body["mode"], "live")
        self.assertEqual(body["captures"], [])
        self.assertEqual([item["id"] for item in body["stages"]["response"]["queued"]], ["ACT-1"])

    def test_the_latest_capture_is_served_with_current_approvals(self):
        self.store.save(build_flow("alert-1", bundle(), result=RESULT, mode="captured"))
        body = self.client.get("/api/alerts/alert-1/flow").get_json()
        self.assertEqual(body["mode"], "captured")
        self.assertEqual(body["stages"]["ai_judgment"]["model"], "hawki-local")
        self.assertEqual([item["id"] for item in body["stages"]["response"]["queued"]], ["ACT-1"])
        live = self.client.get("/api/alerts/alert-1/flow?view=live").get_json()
        self.assertEqual(live["mode"], "live")
        self.assertEqual(len(live["captures"]), 1)

    def test_markdown_download(self):
        response = self.client.get("/api/alerts/alert-1/flow.md")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/markdown", response.content_type)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertIn("① 서버별 원본 로그", response.get_data(as_text=True))

    def test_fixture_bundles_are_refused(self):
        with mock.patch.object(app.ALERT_ANALYSIS, "evidence_bundle", return_value={"schema": "hawki.alert-case/v1"}):
            response = self.client.get("/api/alerts/alert-1/flow")
        self.assertEqual(response.status_code, 400)

    def test_queued_action_keeps_the_alert_it_came_from(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        response = self.client.post(
            "/api/actions/queue",
            json={"action": {"type": "velociraptor_collection", "title": "수집"}, "source": "agent:alert_summary",
                  "alert_id": "alert-1"},
            headers={"X-CSRF-Token": "test-token"},
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["action"]["alert_id"], "alert-1")

    def test_the_page_renders(self):
        response = self.client.get("/alerts/alert-1/flow")
        self.assertEqual(response.status_code, 200)
        self.assertIn("flow_capture.js", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
