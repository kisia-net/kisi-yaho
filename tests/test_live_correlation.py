"""Live correlation retrieval: profiles, busy windows, cross-agent evidence.

An in-memory stand-in for the Wazuh Indexer evaluates the handful of query
shapes get_alert_context sends, so the retrieval logic is exercised end to end
without AWS.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from hawki_alert_analysis.correlation_profiles import select_profile
from hawki_alert_analysis.live_bundle import build_live_evidence_bundle
from hawki_alert_analysis.wazuh import WazuhEventRepository

T0 = datetime(2026, 9, 30, 5, 0, 0, tzinfo=timezone.utc)
ATTACKER = "45.95.11.22"


def ts(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat()


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def get(doc, dotted):
    value = doc
    for key in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def clause_matches(doc, clause) -> bool:
    if "term" in clause:
        (field, value), = clause["term"].items()
        return str(get(doc, field)) == str(value)
    if "range" in clause:
        (field, bounds), = clause["range"].items()
        value = get(doc, field)
        if value is None:
            return False
        moment = parse(value)
        return parse(bounds["gte"]) <= moment <= parse(bounds["lte"])
    raise AssertionError(f"unsupported clause {clause}")


class FakeIndexer:
    def __init__(self, alert, archive):
        self.alert = alert
        self.archive = archive
        self.bodies = []

    def search(self, index, body):
        self.bodies.append(body)
        query = body["query"]
        if "ids" in query:
            wanted = set(query["ids"]["values"])
            docs = [self.alert] if self.alert["_id"] in wanted else []
        else:
            boolean = query["bool"]
            docs = []
            for doc in self.archive:
                source = doc["_source"]
                if not all(clause_matches(source, c) for c in boolean.get("filter", [])):
                    continue
                if any(clause_matches(source, c) for c in boolean.get("must_not", [])):
                    continue
                should = boolean.get("should", [])
                if should and not any(clause_matches(source, c) for c in should):
                    continue
                docs.append(doc)
        for sort in reversed(body.get("sort", [])):
            (field, spec), = sort.items()
            docs.sort(key=lambda d: parse(get(d["_source"], field)), reverse=spec["order"] == "desc")
        return {"hits": {"hits": docs[: body.get("size", 10)]}}


def trigger_doc(groups, decoder="web-accesslog", srcip=ATTACKER):
    return {
        "_id": "alert-1",
        "_index": "wazuh-alerts-4.x-2026.09.30",
        "_source": {
            "timestamp": ts(0),
            "agent": {"id": "001", "name": "web-01", "ip": "10.0.1.201"},
            "rule": {"id": "31106", "level": 6, "groups": groups},
            "decoder": {"name": decoder},
            "location": "/var/log/nginx/access.log",
            "data": {"srcip": srcip} if srcip else {},
            "full_log": f"{srcip} GET /../../etc/passwd",
        },
    }


def web_event(n, seconds, *, agent="001", srcip=ATTACKER):
    return {
        "_id": f"web-{agent}-{n}",
        "_index": "wazuh-archives-4.x-2026.09.30",
        "_source": {
            "timestamp": ts(seconds),
            "agent": {"id": agent, "name": "web-01"},
            "rule": {"id": "31100", "level": 3},
            "decoder": {"name": "web-accesslog"},
            "location": "/var/log/nginx/access.log",
            "data": {"srcip": srcip},
            "full_log": f"{srcip} GET /item/{n}",
        },
    }


def suricata_event(n, seconds, *, src=ATTACKER, dest="10.0.1.201"):
    return {
        "_id": f"ids-{n}",
        "_index": "wazuh-archives-4.x-2026.09.30",
        "_source": {
            "timestamp": ts(seconds),
            "agent": {"id": "002", "name": "vm"},
            "rule": {"id": "86601", "level": 3, "groups": ["ids", "suricata"]},
            "decoder": {"name": "json"},
            "location": "/var/log/suricata/eve.json",
            "data": {"src_ip": src, "dest_ip": dest, "alert": {"signature": "ET WEB path traversal"}},
            "full_log": "",
        },
    }


def repository(alert, archive, *, candidate_limit=200):
    client = FakeIndexer(alert, archive)
    repo = WazuhEventRepository(
        client,
        archive_index="wazuh-archives-*",
        candidate_limit=candidate_limit,
        window_seconds=300,
        timestamp_field="timestamp",
    )
    return repo, client


class ProfileSelectionTests(unittest.TestCase):
    def pick(self, groups, decoder=""):
        return select_profile({"rule": {"groups": groups}, "decoder": {"name": decoder}}, default_seconds=300)

    def test_alert_types_get_their_own_windows(self):
        self.assertEqual(self.pick(["web", "accesslog", "attack"]).name, "web_attack")
        self.assertEqual(self.pick(["syslog", "sshd", "authentication_failed"]).name, "authentication")
        self.assertEqual(self.pick(["sysmon", "sysmon_process"]).name, "endpoint_process")
        self.assertEqual(self.pick(["ids", "suricata"]).name, "network_ids")
        self.assertEqual(self.pick(["ossec"]).name, "default")

    def test_brute_force_looks_back_thirty_minutes(self):
        profile = self.pick(["sshd", "authentication_failed"])
        self.assertEqual(profile.seconds_before, 1800)
        self.assertTrue(profile.cross_agent)

    def test_child_decoder_uses_its_parent(self):
        trigger = {"rule": {"groups": []}, "decoder": {"name": "sshd-success", "parent": "sshd"}}
        self.assertEqual(select_profile(trigger, default_seconds=300).name, "authentication")

    def test_default_keeps_the_configured_window(self):
        profile = select_profile({"rule": {"groups": ["x"]}}, default_seconds=450)
        self.assertEqual((profile.seconds_before, profile.seconds_after), (450, 450))
        self.assertFalse(profile.cross_agent)


class RetrievalTests(unittest.TestCase):
    def test_busy_window_still_reaches_events_after_the_trigger(self):
        # 300 events before the trigger used to fill the 200-event budget with
        # the oldest ones, leaving nothing from after the alert.
        archive = [web_event(i, -290 + i * 0.9) for i in range(300)]
        archive += [web_event(1000 + i, 5 + i) for i in range(5)]
        repo, _ = repository(trigger_doc(["web", "accesslog", "attack"]), archive)
        context = repo.get_alert_context("alert-1", limit=16)
        after = [e for e in context["events"] if parse(e["timestamp"]) > T0]
        self.assertTrue(after, "no event after the trigger survived retrieval")
        self.assertEqual(context["candidate_breakdown"]["same_agent_after"], 5)
        self.assertEqual(context["candidate_breakdown"]["same_agent_before"], 100)

    def test_sensor_on_another_agent_joins_a_web_alert(self):
        archive = [web_event(i, -30 + i) for i in range(3)]
        archive += [suricata_event(1, -29), suricata_event(2, 40, src="10.0.1.201", dest=ATTACKER)]
        archive += [suricata_event(3, -20, src="8.8.8.8")]  # unrelated address
        repo, client = repository(trigger_doc(["web", "accesslog", "attack"]), archive)
        context = repo.get_alert_context("alert-1", limit=16)

        cross = [e for e in context["events"] if e["origin"] == "cross_agent"]
        self.assertEqual(sorted(e["id"] for e in cross), ["ids-1", "ids-2"])
        for event in cross:
            self.assertIn("other_agent_same_address", event["relevance_reasons"])
            self.assertIn("same_source_ip", event["relevance_reasons"])

        cross_query = client.bodies[-1]["query"]["bool"]
        self.assertEqual(cross_query["must_not"], [{"term": {"agent.id": "001"}}])

    def test_endpoint_profile_does_not_search_other_agents(self):
        archive = [suricata_event(1, -10)]
        repo, client = repository(
            trigger_doc(["sysmon", "sysmon_process"], decoder="sysmon-linux"), archive
        )
        context = repo.get_alert_context("alert-1", limit=16)
        self.assertEqual(context["candidate_breakdown"]["cross_agent"], 0)
        self.assertEqual(context["profile"]["name"], "endpoint_process")
        # get_alert_record + before + after; no cross-agent query.
        self.assertEqual(len(client.bodies), 3)

    def test_cross_agent_evidence_keeps_a_few_slots(self):
        archive = [web_event(i, -200 + i) for i in range(60)]
        archive += [suricata_event(n, -100 + n) for n in range(3)]
        repo, _ = repository(trigger_doc(["web", "accesslog", "attack"]), archive)
        context = repo.get_alert_context("alert-1", limit=16)
        self.assertEqual(len(context["events"]), 16)
        self.assertEqual(sum(e["origin"] == "cross_agent" for e in context["events"]), 3)

    def test_bundle_reports_profile_and_origin(self):
        archive = [web_event(0, -5), suricata_event(1, -4)]
        repo, _ = repository(trigger_doc(["web", "accesslog", "attack"]), archive)
        bundle = build_live_evidence_bundle(repo, "alert-1", max_context=16)
        retrieval = bundle["retrieval"]
        self.assertEqual(retrieval["profile"]["name"], "web_attack")
        self.assertEqual(retrieval["window"]["seconds_before"], 600)
        origins = {item["retrieval"]["origin"] for item in bundle["investigation_context"]}
        self.assertEqual(origins, {"same_agent", "cross_agent"})


if __name__ == "__main__":
    unittest.main()
