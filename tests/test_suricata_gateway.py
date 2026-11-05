"""Sensor-side Suricata deployment gateway (tools/suricata_gateway/gateway.py)."""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hawki_suricata_gateway", ROOT / "tools/suricata_gateway/gateway.py")
gw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gw)

TOKEN = "t" * 32
PY = sys.executable
OK = json.dumps([PY, "-c", "import sys; sys.exit(0)"])
FAIL = json.dumps([PY, "-c", "import sys; sys.exit(1)"])
# suricatasc answering NOK still exits 0.
NOK = json.dumps([PY, "-c", 'print(\'{"message": "Reload already in progress", "return": "NOK"}\')'])
# suricata -T stand-in: rejects any rule file containing BADRULE.
TEST = json.dumps([PY, "-c", "import sys; sys.exit(1 if 'BADRULE' in open(sys.argv[1]).read() else 0)", "{rules}"])

RULE = 'alert http any any -> any any (msg:"HAW-KI test"; content:"/wp-login.php"; sid:9900012; rev:2;)'


def action(**overrides):
    payload = {"rule": RULE, "sid": 9900012, "revision": 2, "host": "10.0.10.235", "interface": "ens5"}
    payload.update(overrides.pop("payload", {}))
    body = {"id": "ACT-20261017-AAAAAA", "type": "suricata_rule", "payload": payload}
    body.update(overrides)
    return body


class GatewayBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = {
            "HAWKI_GW_TOKEN": TOKEN,
            "HAWKI_GW_RULES_FILE": str(self.tmp / "rules/hawki.rules"),
            "HAWKI_GW_STATE_FILE": str(self.tmp / "state/applied.jsonl"),
            "HAWKI_GW_SENSOR_HOST": "10.0.10.235",
            "HAWKI_GW_SENSOR_INTERFACE": "ens5",
            "HAWKI_GW_TEST_CMD": TEST,
            "HAWKI_GW_RELOAD_CMD": OK,
            "HAWKI_GW_STATUS_CMD": OK,
        }

    def gateway(self, **env):
        with mock.patch.dict(os.environ, {**self.env, **env}, clear=False):
            return gw.Gateway(gw.Config())

    def rules_text(self):
        return (self.tmp / "rules/hawki.rules").read_text(encoding="utf-8")


class GatewayTests(GatewayBase):
    def test_deploy_writes_the_rule_and_records_it(self):
        result = self.gateway().apply(action())
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["operation"], "deploy")
        self.assertIn("sid:9900012", self.rules_text())

    def test_same_sid_replaces_instead_of_duplicating(self):
        g = self.gateway()
        g.apply(action())
        newer = RULE.replace("rev:2", "rev:3")
        g.apply(action(id="ACT-20261017-BBBBBB", payload={"rule": newer, "revision": 3}))
        text = self.rules_text()
        self.assertEqual(text.count("sid:9900012"), 1)
        self.assertIn("rev:3", text)

    def test_disable_removes_the_rule(self):
        g = self.gateway()
        g.apply(action())
        g.apply(action(id="ACT-20261017-CCCCCC", type="suricata_rule_disable", payload={"rule": ""}))
        self.assertNotIn("sid:9900012", self.rules_text())

    def test_repeat_of_an_applied_action_is_not_applied_twice(self):
        g = self.gateway()
        g.apply(action())
        self.assertTrue(g.apply(action())["repeated"])

    def test_drop_is_refused_on_a_detection_only_sensor(self):
        with self.assertRaises(gw.GatewayError) as caught:
            self.gateway().apply(action(payload={"rule": RULE.replace("alert", "drop", 1)}))
        self.assertEqual(caught.exception.code, "action_not_allowed")

    def test_sid_must_match_the_rule(self):
        with self.assertRaises(gw.GatewayError) as caught:
            self.gateway().apply(action(payload={"sid": 9900099}))
        self.assertEqual(caught.exception.code, "sid_mismatch")

    def test_other_sensor_is_refused(self):
        with self.assertRaises(gw.GatewayError) as caught:
            self.gateway().apply(action(payload={"host": "10.0.10.9"}))
        self.assertEqual(caught.exception.code, "wrong_host")

    def test_multi_line_rule_is_refused(self):
        with self.assertRaises(gw.GatewayError) as caught:
            self.gateway().apply(action(payload={"rule": RULE + "\nalert ip any any -> any any (sid:9900013;)"}))
        self.assertEqual(caught.exception.code, "bad_rule")

    def test_failed_suricata_test_leaves_the_file_untouched(self):
        g = self.gateway()
        g.apply(action())
        before = self.rules_text()
        bad = 'alert http any any -> any any (msg:"BADRULE"; sid:9900020; rev:1;)'
        with self.assertRaises(gw.GatewayError) as caught:
            g.apply(action(id="ACT-20261017-DDDDDD", payload={"rule": bad, "sid": 9900020, "revision": 1}))
        self.assertEqual(caught.exception.code, "test_failed")
        self.assertEqual(self.rules_text(), before)
        self.assertEqual([p.name for p in (self.tmp / "rules").iterdir() if p.name.startswith(".hawki-")], [])

    def test_failed_reload_restores_the_previous_file(self):
        self.gateway().apply(action())
        before = self.rules_text()
        g = self.gateway(HAWKI_GW_RELOAD_CMD=FAIL)
        newer = RULE.replace("rev:2", "rev:3")
        with self.assertRaises(gw.GatewayError) as caught:
            g.apply(action(id="ACT-20261017-EEEEEE", payload={"rule": newer, "revision": 3}))
        self.assertEqual(caught.exception.code, "reload_failed")
        self.assertEqual(self.rules_text(), before)

    def test_nok_answer_from_suricatasc_counts_as_failure(self):
        self.gateway().apply(action())
        before = self.rules_text()
        newer = RULE.replace("rev:2", "rev:3")
        with self.assertRaises(gw.GatewayError) as caught:
            self.gateway(HAWKI_GW_RELOAD_CMD=NOK).apply(action(id="ACT-20261017-FFFFFF", payload={"rule": newer, "revision": 3}))
        self.assertEqual(caught.exception.code, "reload_failed")
        self.assertEqual(self.rules_text(), before)

    def test_change_waits_for_the_previous_reload(self):
        self.gateway().apply(action())
        old_reload = json.dumps([PY, "-c", 'print(\'{"message": [{"id": 0, "last_reload": "2000-01-01T00:00:00.000000+0000"}], "return": "OK"}\')'])
        newer = RULE.replace("rev:2", "rev:3")
        with self.assertRaises(gw.GatewayError) as caught:
            self.gateway(HAWKI_GW_RELOAD_TIME_CMD=old_reload).apply(action(id="ACT-20261017-GGGGGG", payload={"rule": newer, "revision": 3}))
        self.assertEqual(caught.exception.code, "reload_in_progress")
        fresh_reload = json.dumps([PY, "-c", 'print(\'{"message": [{"id": 0, "last_reload": "2999-01-01T00:00:00.000000+0000"}], "return": "OK"}\')'])
        result = self.gateway(HAWKI_GW_RELOAD_TIME_CMD=fresh_reload).apply(action(id="ACT-20261017-GGGGGG", payload={"rule": newer, "revision": 3}))
        self.assertEqual(result["status"], "applied")

    def test_short_token_refuses_to_start(self):
        with self.assertRaises(SystemExit):
            self.gateway(HAWKI_GW_TOKEN="short")

    def test_health_reports_suricata_state(self):
        self.assertEqual(self.gateway().health()[0], 200)
        self.assertEqual(self.gateway(HAWKI_GW_STATUS_CMD=FAIL).health()[0], 503)


class GatewayHttpTests(GatewayBase):
    def serve(self):
        g = self.gateway()
        server = gw.ThreadingHTTPServer(("127.0.0.1", 0), gw.make_handler(g))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def post(self, base, body, token=TOKEN):
        request = urllib.request.Request(
            base + "/actions", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_requires_the_token(self):
        status, body = self.post(self.serve(), action(), token="wrong" * 8)
        self.assertEqual((status, body["error"]), (401, "unauthorized"))

    def test_http_applies_with_the_token(self):
        status, body = self.post(self.serve(), action())
        self.assertEqual((status, body["status"]), (200, "applied"))

    def test_http_health_needs_no_token(self):
        with urllib.request.urlopen(self.serve() + "/health", timeout=10) as response:
            self.assertEqual(json.loads(response.read())["suricata_running"], True)


if __name__ == "__main__":
    unittest.main()
