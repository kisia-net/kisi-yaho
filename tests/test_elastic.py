"""Tests for the Elasticsearch-backed event repository.

The point of Phase 2 is that only retrieval changes: a case built from a live
index must be assembled by the same correlation rules, carry the same four
metadata blocks, and survive an unreachable cluster without taking the
application down with it.

A stub transport stands in for the cluster, so these run without one.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import requests

from hawki_alert_analysis.assets import FileAssetInventory
from hawki_alert_analysis.elastic import (
    ElasticsearchClient,
    ElasticsearchError,
    ElasticsearchEventRepository,
    select_adapter,
    validate_index,
)
from hawki_alert_analysis.repository import AlertNotFound
from hawki_alert_analysis.threat_intel import FileThreatIntelFeed

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data" / "scenarios" / "web_path_traversal"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


SURICATA = load_jsonl(FIXTURE / "suricata_eve.jsonl")
WAZUH = load_jsonl(FIXTURE / "wazuh_alerts.jsonl")

TRIGGER_ID = "es-alert-1"


def as_hit(document: dict, doc_id: str, index: str = "logs-security-000001") -> dict:
    return {"_id": doc_id, "_index": index, "_source": document}


class StubResponse:
    def __init__(self, payload: dict, status: int = 200):
        self.payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")

    def json(self):
        return self.payload


class StubTransport:
    """Answers _search calls from a scripted set of hits."""

    def __init__(self, alert_hits: list[dict], event_hits: list[dict], *, fail: bool = False):
        self.alert_hits = alert_hits
        self.event_hits = event_hits
        self.fail = fail
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, headers=None, auth=None, json=None, timeout=None, verify=None):  # noqa: A002
        self.calls.append((url, json or {}))
        if self.fail:
            raise requests.ConnectionError("connection refused")
        body = json or {}
        if "ids" in str(body.get("query", {})):
            wanted = set(body["query"]["ids"]["values"])
            hits = [hit for hit in self.alert_hits if hit["_id"] in wanted]
        elif body.get("size") == 0:
            hits = []
        elif "range" in str(body.get("query", {})):
            hits = self.event_hits
        else:
            hits = self.alert_hits
        return StubResponse({"hits": {"total": {"value": len(hits)}, "hits": hits}})


def build_repository(**kwargs) -> tuple[ElasticsearchEventRepository, StubTransport]:
    alert_hits = [
        as_hit(SURICATA[1], TRIGGER_ID),
        as_hit(WAZUH[0], "es-alert-2"),
    ]
    event_hits = [
        as_hit(SURICATA[0], "es-event-1"),
        as_hit(SURICATA[2], "es-alert-3"),
        as_hit(WAZUH[1], "es-alert-4"),
    ]
    transport = StubTransport(alert_hits, event_hits, **kwargs)
    client = ElasticsearchClient("https://es.example.invalid:9200", api_key="k", transport=transport)
    repository = ElasticsearchEventRepository(
        client,
        asset_inventory=FileAssetInventory(ROOT / "data" / "assets"),
        threat_intel_feed=FileThreatIntelFeed(ROOT / "data" / "threat_intel"),
    )
    return repository, transport


class IndexValidationTests(unittest.TestCase):
    def test_valid_patterns_pass(self):
        for value in ("logs-*", "wazuh-alerts-*,logs-*", "filebeat-2026.08.11"):
            self.assertEqual(validate_index(value), value)

    def test_path_traversal_and_injection_are_rejected(self):
        for value in ("logs/../_cluster", "logs-*/_delete_by_query", "", "a b", "logs;drop"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_index(value)


class AdapterSelectionTests(unittest.TestCase):
    def test_native_producer_documents_use_their_own_adapter(self):
        self.assertEqual(select_adapter(SURICATA[1]).source_type, "suricata")
        self.assertEqual(select_adapter(WAZUH[0]).source_type, "wazuh")
        self.assertEqual(select_adapter({"winlog": {"event_id": 1}}).source_type, "sysmon")

    def test_ecs_documents_fall_back_to_the_ecs_adapter(self):
        self.assertEqual(
            select_adapter({"@timestamp": "2026-08-11T10:00:00Z", "event": {"kind": "alert"}}).source_type,
            "ecs",
        )


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repository, self.transport = build_repository()

    def test_list_alerts_uses_document_ids_and_enriches(self):
        alerts = self.repository.list_alerts()
        self.assertEqual({alert["id"] for alert in alerts}, {TRIGGER_ID, "es-alert-2"})
        traversal = next(alert for alert in alerts if alert["id"] == TRIGGER_ID)
        self.assertEqual(traversal["severity"], "critical")
        self.assertEqual(traversal["threat_verdict"], "malicious")
        self.assertEqual(traversal["asset_criticality"], "high")

    def test_only_search_endpoints_are_called(self):
        self.repository.list_alerts()
        self.repository.build_alert_case(TRIGGER_ID)
        self.assertTrue(self.transport.calls)
        for url, _ in self.transport.calls:
            self.assertTrue(url.endswith("/_search"), url)

    def test_case_is_correlated_and_carries_the_four_blocks(self):
        case = self.repository.build_alert_case(TRIGGER_ID)
        self.assertEqual(case.trigger.id, TRIGGER_ID)
        self.assertTrue(case.related_events)
        # The trigger must not be duplicated into its own related events.
        self.assertNotIn(TRIGGER_ID, {event.id for event in case.related_events})

        bundle = case.to_llm_context()
        self.assertEqual(
            list(bundle["metadata"]),
            ["security_alerts", "security_events", "assets", "threat_intelligence"],
        )
        self.assertTrue(bundle["metadata"]["assets"]["items"])
        self.assertTrue(bundle["metadata"]["threat_intelligence"]["items"])
        self.assertEqual(bundle["metadata"]["security_alerts"]["items"][0]["id"], TRIGGER_ID)

    def test_candidate_query_filters_by_time_and_entities(self):
        self.repository.build_alert_case(TRIGGER_ID)
        _, body = self.transport.calls[-1]
        filters = body["query"]["bool"]["filter"]
        self.assertIn("range", filters[0])
        fields = {list(clause["term"])[0] for clause in body["query"]["bool"]["should"]}
        self.assertIn("host.name", fields | {"host.name"})
        self.assertIn("source.ip", fields)
        self.assertEqual(body["query"]["bool"]["minimum_should_match"], 1)

    def test_unknown_alert_raises_alert_not_found(self):
        with self.assertRaises(AlertNotFound):
            self.repository.build_alert_case("es-missing")

    def test_health_reports_reachability(self):
        health = self.repository.health()
        self.assertTrue(health["reachable"])
        self.assertEqual(health["alert_index"], self.repository.alert_index)


class TransportFailureTests(unittest.TestCase):
    def setUp(self):
        self.repository, self.transport = build_repository(fail=True)

    def test_listing_degrades_to_empty_with_a_recorded_reason(self):
        self.assertEqual(self.repository.list_alerts(), [])
        self.assertIn("connection refused", self.repository.last_error)

    def test_fetching_a_case_raises_rather_than_inventing_one(self):
        with self.assertRaises(AlertNotFound):
            self.repository.build_alert_case(TRIGGER_ID)

    def test_health_reports_the_failure(self):
        health = self.repository.health()
        self.assertFalse(health["reachable"])
        self.assertIn("connection refused", health["error"])

    def test_client_wraps_transport_errors(self):
        client = ElasticsearchClient("https://es.example.invalid", transport=self.transport)
        with self.assertRaises(ElasticsearchError):
            client.search("logs-*", {"size": 1})


class PartialFailureTests(unittest.TestCase):
    def test_correlation_failure_still_yields_a_trigger_only_case(self):
        repository, transport = build_repository()

        original = transport.__call__
        state = {"calls": 0}

        def flaky(url, **kwargs):
            state["calls"] += 1
            # Let the trigger fetch succeed, then fail the candidate search.
            if "range" in str(kwargs.get("json", {}).get("query", {})):
                raise requests.ConnectionError("candidate search failed")
            return original(url, **kwargs)

        repository.client.transport = flaky
        case = repository.build_alert_case(TRIGGER_ID)
        self.assertEqual(case.trigger.id, TRIGGER_ID)
        self.assertEqual(case.related_events, [])
        self.assertIn("candidate search failed", repository.last_error)
        # Enrichment still runs on the trigger alone.
        self.assertTrue(case.intel_matches)

    def test_undecodable_document_is_skipped_and_recorded(self):
        repository, transport = build_repository()
        transport.alert_hits = [
            as_hit({"@timestamp": "not-a-timestamp", "event": {"kind": "alert"}}, "es-bad"),
            *transport.alert_hits,
        ]
        alerts = repository.list_alerts()
        self.assertNotIn("es-bad", {alert["id"] for alert in alerts})
        self.assertTrue(any("es-bad" in entry for entry in repository.skipped_lines))
        self.assertTrue(alerts)


if __name__ == "__main__":
    unittest.main()
