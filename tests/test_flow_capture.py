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
    capture_record,
    dropped_by_fit,
    field_paths,
    raw_format,
    to_markdown,
    verify_capture,
)
from hawki_alert_analysis.redteam_bridge import sha256_json  # noqa: E402

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
        "threat_intelligence": {"matches": [{"value": "52.141.3.247", "type": "ipv4-addr", "feed": "blocklist.de",
                                             "verdict": "suspicious", "confidence": 50}]},
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
        self.assertEqual(evidence["threat_intelligence"][0]["feed"], "blocklist.de")

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


class RecordTests(unittest.TestCase):
    def capture(self, package):
        result = {**RESULT, "hashes": {"bundle_sha256": sha256_json(package), "prompt_sha256": "p" * 64}}
        record = capture_record(source="manual", bundle=package, result=result, request_text="분석해 줘",
                                model_replies=[{"stage": "alert_summary:answer", "chars": 3, "content": "{}"}])
        # Through JSON, as the store keeps it.
        return json.loads(json.dumps(build_flow("alert-1", package, result=result, mode="captured", record=record),
                                     ensure_ascii=False, default=str))

    def test_the_saved_package_rehashes_to_the_audited_hash(self):
        package = bundle()
        doc = self.capture(package)
        audit = [{"event_type": "alert_analysis_completed", "timestamp": "t",
                  "detail": {"analysis_id": "an-1", "bundle_sha256": sha256_json(package)}}]
        check = verify_capture(doc, audit)
        self.assertTrue(check["matches_capture"])
        self.assertTrue(check["matches_audit"])
        self.assertEqual(check["model_reply_count"], 1)

    def test_a_changed_package_or_missing_audit_does_not_verify(self):
        doc = self.capture(bundle())
        doc["record"]["evidence_package"]["priority"]["score"] = 99
        check = verify_capture(doc, [])
        self.assertFalse(check["matches_capture"])
        self.assertIsNone(check["audit_record"])
        self.assertFalse(check["matches_audit"])

    def test_without_a_package_nothing_is_claimed(self):
        doc = build_flow("alert-1", bundle())
        self.assertFalse(verify_capture(doc, [])["checked"])

    def test_markdown_states_the_check_and_the_reply(self):
        doc = self.capture(bundle())
        doc["verification"] = verify_capture(doc, [])
        text = to_markdown(doc)
        self.assertIn("모델 응답 원문", text)
        self.assertIn("감사 로그", text)
        self.assertIn("아직 이 흐름에 연결되지 않았습니다", text)


class OmissionTests(unittest.TestCase):
    def test_every_raw_line_is_kept_and_the_page_folds_the_rest(self):
        package = bundle()
        package["investigation_context"] += [
            item(f"CTX-{n:03d}", WEB, "/var/log/nginx/access.log", "web-accesslog", f"line {n}", {"srcip": "1.2.3.4"})
            for n in range(10, 16)
        ]
        raw = build_flow("alert-1", package)["stages"]["raw"]
        access = next(source for server in raw["servers"] for source in server["sources"]
                      if source["location"] == "/var/log/nginx/access.log")
        self.assertEqual(len(access["samples"]), access["count"])
        self.assertEqual(access["samples"][0]["evidence_id"], "TRIGGER")
        self.assertEqual(raw["preview_lines"], 3)

    def test_evidence_removed_by_the_fit_is_kept_beside_the_capture(self):
        before = bundle()
        after = json.loads(json.dumps(before))
        after["investigation_context"] = after["investigation_context"][:1]
        after["retrieval"]["context_fit"] = {"dropped_evidence_ids": ["CTX-002", "CTX-003"]}
        dropped = dropped_by_fit(before, after)
        self.assertEqual([entry["evidence_id"] for entry in dropped], ["CTX-002", "CTX-003"])
        self.assertEqual(dropped[0]["server"], "ids-01")
        self.assertTrue(dropped[0]["full_log"])
        doc = build_flow("alert-1", after, mode="captured", record={"dropped_evidence": dropped})
        self.assertEqual(len(doc["stages"]["evidence"]["dropped"]), 2)
        self.assertIn("모델에 보내지 않은 증거 2건", to_markdown(doc))
        self.assertEqual(dropped_by_fit(before, before), [])

    def test_retrieval_status_says_why_nothing_was_gathered(self):
        off = build_flow("alert-1", {k: v for k, v in bundle().items() if k != "agent_retrieval"},
                         snapshots={"agent_status": "disabled", "sent": {"context_count": 3}})
        self.assertIn("AGENT_TOOL_LOOP_ENABLED=false", off["stages"]["ai_retrieval"]["status_label"])
        auto = build_flow("alert-1", bundle(), snapshots={"agent_status": "not_in_auto_report"})
        self.assertEqual(auto["stages"]["ai_retrieval"]["status"], "not_in_auto_report")
        ran = build_flow("alert-1", bundle(), snapshots={"initial": {}})
        self.assertEqual(ran["stages"]["ai_retrieval"]["status"], "finish")

    def test_missing_audit_is_not_called_a_mismatch_and_demo_is_flagged(self):
        package = bundle()
        result = {**RESULT, "demo": True, "hashes": {"bundle_sha256": sha256_json(package)}}
        doc = json.loads(json.dumps(build_flow(
            "alert-1", package, result=result, mode="captured",
            record=capture_record(source="manual", bundle=package, result=result, request_text="", model_replies=[])),
            default=str))
        check = verify_capture(doc, [])
        self.assertEqual(check["status"], "audit_missing")
        self.assertTrue(check["demo"])
        audited = verify_capture(doc, [{"event_type": "alert_analysis_completed",
                                        "detail": {"analysis_id": "an-1", "bundle_sha256": "0" * 64}}])
        self.assertEqual(audited["status"], "mismatch")

    def test_manual_and_automatic_captures_are_kept_separately(self):
        store = FlowCaptureStore(Path(tempfile.mkdtemp()), keep=2)
        for n in range(3):
            store.save({"alert_id": "a", "n": n, "record": {"source": "manual"}})
        store.save({"alert_id": "a", "n": 9, "record": {"source": "auto_report"}})
        kept = store.list("a")
        self.assertEqual(sorted((c["record"]["source"], c["n"]) for c in kept),
                         [("auto_report", 9), ("manual", 1), ("manual", 2)])


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

    def test_without_a_capture_the_last_saved_analysis_fills_the_ai_stages(self):
        root = Path(tempfile.mkdtemp())
        with mock.patch.object(app, "LAST_ANALYSIS_ROOT", root):
            app.save_last_analysis("alert-1", {**RESULT, "agent_retrieval": {"calls": [], "stopped": "finish"},
                                               "hashes": {"bundle_sha256": "b" * 64}})
            body = self.client.get("/api/alerts/alert-1/flow").get_json()
            live = self.client.get("/api/alerts/alert-1/flow?view=live").get_json()
        self.assertEqual(body["mode"], "last_analysis")
        self.assertEqual(body["stages"]["ai_judgment"]["model"], "hawki-local")
        self.assertFalse(body["verification"]["checked"])
        self.assertIn("다를 수 있음", body["basis"])
        self.assertEqual(live["mode"], "live")
        self.assertFalse(live["stages"]["ai_judgment"]["ran"])

    def test_analysis_captures_the_package_the_reply_and_matches_the_audit_log(self):
        reply = json.dumps({"answer": "요약", "assessment": RESULT["assessment"], "actions": []}, ensure_ascii=False)

        class Reply:
            def raise_for_status(self):
                return None

            def json(self):
                return {"model": "hawki-local", "choices": [{"finish_reason": "stop", "message": {"content": reply}}]}

        audit = Path(tempfile.mkdtemp()) / "audit.jsonl"
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        with mock.patch.object(app.requests, "post", return_value=Reply()), \
                mock.patch.object(app, "AUDIT_LOG_PATH", audit), \
                mock.patch.dict(app.CONFIG, {"agent_tool_loop_enabled": False, "redteam_auto_eval_enabled": False}):
            response = self.client.post("/api/alerts/alert-1/analyze", json={},
                                        headers={"X-CSRF-Token": "test-token"})
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            self.assertTrue(response.get_json()["flow_capture"]["saved"])
            self.assertNotIn("model_replies", response.get_json(), "reply text stays out of the result")
            body = self.client.get("/api/alerts/alert-1/flow").get_json()
            package = self.client.get("/api/alerts/alert-1/flow/package.json")
        self.assertEqual(body["mode"], "captured")
        self.assertEqual(body["record"]["source"], "manual")
        self.assertNotIn("evidence_package", body["record"], "the package is a separate download")
        self.assertTrue(body["record"]["has_evidence_package"])
        self.assertEqual(body["record"]["model_replies"][0]["content"], reply)
        self.assertTrue(body["verification"]["matches_capture"])
        self.assertTrue(body["verification"]["matches_audit"])
        self.assertEqual(package.status_code, 200)
        self.assertEqual(sha256_json(package.get_json()), body["verification"]["recomputed_bundle_sha256"])
        self.assertEqual(body["verification"]["status"], "verified")
        self.assertEqual(body["stages"]["ai_retrieval"]["status"], "disabled")

    def test_the_automatic_report_is_captured_too(self):
        reply = json.dumps({"answer": "자동 요약", "assessment": RESULT["assessment"], "actions": []}, ensure_ascii=False)

        class Reply:
            def raise_for_status(self):
                return None

            def json(self):
                return {"model": "hawki-local", "choices": [{"finish_reason": "stop", "message": {"content": reply}}]}

        package = bundle()
        with mock.patch.object(app.requests, "post", return_value=Reply()):
            result = app.auto_analyze(package, {"id": "alert-1"})
        capture = self.store.latest("alert-1")
        self.assertEqual(capture["record"]["source"], "auto_report")
        self.assertEqual(capture["record"]["analysis_id"], result["analysis_id"])
        self.assertEqual(capture["record"]["model_replies"][0]["content"], reply)
        self.assertEqual(sha256_json(capture["record"]["evidence_package"]), result["hashes"]["bundle_sha256"])
        self.assertEqual(capture["stages"]["ai_retrieval"]["status"], "not_in_auto_report")
        # Opened from the report: that analysis's capture is chosen.
        body = self.client.get(f"/api/alerts/alert-1/flow?analysis={result['analysis_id']}").get_json()
        self.assertEqual(body["record"]["analysis_id"], result["analysis_id"])
        self.assertEqual(body["notice"], "")
        missing = self.client.get("/api/alerts/alert-1/flow?analysis=deadbeef").get_json()
        self.assertIn("캡처가 없습니다", missing["notice"])

    def test_auto_build_hands_the_dropped_evidence_to_auto_analyze(self):
        before = bundle()

        def fit(alert_id, package):
            package["investigation_context"] = package["investigation_context"][:1]
            package.setdefault("retrieval", {})["context_fit"] = {"dropped_evidence_ids": ["CTX-002", "CTX-003"]}

        reply = json.dumps({"answer": "자동", "assessment": RESULT["assessment"], "actions": []}, ensure_ascii=False)

        class Reply:
            def raise_for_status(self):
                return None

            def json(self):
                return {"model": "hawki-local", "choices": [{"finish_reason": "stop", "message": {"content": reply}}]}

        with mock.patch.object(app.ALERT_ANALYSIS, "evidence_bundle", return_value=before), \
                mock.patch.object(app, "fit_bundle_to_context", side_effect=fit), \
                mock.patch.object(app.requests, "post", return_value=Reply()):
            package = app.auto_build_bundle({"id": "alert-1"})
            app.auto_analyze(package, {"id": "alert-1"})
        capture = self.store.latest("alert-1")
        self.assertEqual([entry["evidence_id"] for entry in capture["stages"]["evidence"]["dropped"]], ["CTX-002", "CTX-003"])
        self.assertEqual(capture["stages"]["ai_retrieval"]["before"]["context_count"], 3)
        self.assertNotIn(id(package), app._auto_fit_notes)

    def test_package_download_needs_a_capture(self):
        self.assertEqual(self.client.get("/api/alerts/alert-1/flow/package.json").status_code, 404)

    def test_the_page_renders(self):
        response = self.client.get("/alerts/alert-1/flow")
        self.assertEqual(response.status_code, 200)
        self.assertIn("flow_capture.js", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
