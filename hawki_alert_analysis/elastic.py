"""Phase 2: an event repository backed by Elasticsearch.

This is the swap the architecture was built for. `ElasticsearchEventRepository`
exposes the same interface as `FixtureEventRepository`, so correlation,
enrichment, bundling, the assessment schema, and the agent are untouched — the
only thing that changes is where events come from.

Retrieval is deliberately thin. Elasticsearch selects *candidates* by time and
entity; ranking and case assembly stay in `correlate.build_case`, so a case
built from a live index is assembled by exactly the same rules as one built
from a fixture, and stays comparable to it.

Read-only by construction: only _search and _count are ever issued, and index
patterns are validated before they reach a URL.

Reachability is not assumed. A transport failure records itself on the
repository and yields an empty result rather than propagating a 500 to every
page that lists alerts; `last_error` says why the list is empty.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import quote

import requests

from .adapters import ECSAdapter, SuricataAdapter, SysmonAdapter, WazuhAdapter
from .assets import AssetInventory, NullAssetInventory, match_assets
from .correlate import build_case
from .models import AlertCase, CanonicalEvent, parse_timestamp
from .repository import AlertNotFound
from .threat_intel import NullThreatIntelFeed, ThreatIntelFeed, match_indicators

INDEX_PATTERN = re.compile(r"^[A-Za-z0-9._*,\-]{1,256}$")

DEFAULT_ALERT_INDEX = "wazuh-alerts-*,logs-*,filebeat-*"
DEFAULT_EVENT_INDEX = "logs-*,filebeat-*,winlogbeat-*,packetbeat-*"

# Document shapes this repository knows how to normalize, checked in order.
_ECS = ECSAdapter()
_SURICATA = SuricataAdapter()
_WAZUH = WazuhAdapter()
_SYSMON = SysmonAdapter()


class ElasticsearchError(RuntimeError):
    pass


def validate_index(value: str) -> str:
    index = str(value or "").strip()
    if not INDEX_PATTERN.match(index):
        raise ValueError(f"Unsupported index pattern: {value!r}")
    return index


def select_adapter(document: dict[str, Any]):
    """Pick the adapter matching a document's shape.

    Indices hold a mix: ECS-normalized documents from an ingest pipeline
    alongside raw producer records shipped verbatim. Both are read rather than
    forcing one convention on the cluster.
    """
    if "event_type" in document or "flow_id" in document:
        return _SURICATA
    if isinstance(document.get("rule"), dict) and isinstance(document.get("agent"), dict):
        return _WAZUH
    if "winlog" in document or "EventID" in document or "EventId" in document:
        return _SYSMON
    if isinstance(document.get("Event"), dict) and "System" in document["Event"]:
        return _SYSMON
    return _ECS


class ElasticsearchClient:
    """Minimal read-only Elasticsearch HTTP client.

    Deliberately not the official client library: this needs two endpoints, and
    a small seam (`transport`) makes the repository testable without a cluster.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str = "",
        username: str = "",
        password: str = "",
        verify_tls: bool = True,
        timeout: float = 20.0,
        transport: Any = None,
    ):
        self.base_url = str(base_url or "").rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        # Injected in tests; defaults to requests.post.
        self.transport = transport or requests.post

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if not self.api_key and self.username and self.password:
            return (self.username, self.password)
        return None

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        index = validate_index(index)
        url = f"{self.base_url}/{quote(index, safe='*,-_.')}/_search"
        try:
            response = self.transport(
                url,
                headers=self._headers(),
                auth=self._auth(),
                json=body,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise ElasticsearchError(f"Elasticsearch request failed: {exc}") from exc
        except ValueError as exc:
            raise ElasticsearchError(f"Elasticsearch returned invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ElasticsearchError("Elasticsearch returned an unexpected payload")
        return payload


def _hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    hits = payload.get("hits")
    values = hits.get("hits") if isinstance(hits, dict) else None
    return [hit for hit in values if isinstance(hit, dict)] if isinstance(values, list) else []


class ElasticsearchEventRepository:
    """Live event repository. Interface-compatible with FixtureEventRepository."""

    def __init__(
        self,
        client: ElasticsearchClient,
        *,
        alert_index: str = DEFAULT_ALERT_INDEX,
        event_index: str = DEFAULT_EVENT_INDEX,
        asset_inventory: AssetInventory | None = None,
        threat_intel_feed: ThreatIntelFeed | None = None,
        alert_limit: int = 100,
        candidate_limit: int = 200,
        window_seconds: int = 300,
        minimum_correlation_score: int = 2,
        timestamp_field: str = "@timestamp",
    ):
        self.client = client
        self.alert_index = validate_index(alert_index)
        self.event_index = validate_index(event_index)
        self.asset_inventory: AssetInventory = asset_inventory or NullAssetInventory()
        self.threat_intel_feed: ThreatIntelFeed = threat_intel_feed or NullThreatIntelFeed()
        self.alert_limit = max(1, min(int(alert_limit), 1000))
        self.candidate_limit = max(1, min(int(candidate_limit), 1000))
        self.window_seconds = max(1, int(window_seconds))
        self.minimum_correlation_score = int(minimum_correlation_score)
        self.timestamp_field = timestamp_field
        self.skipped_lines: list[str] = []
        self.last_error: str = ""

    # -- retrieval ---------------------------------------------------------

    def _normalize_hit(self, hit: dict[str, Any]) -> CanonicalEvent | None:
        document = hit.get("_source")
        if not isinstance(document, dict):
            return None
        adapter = select_adapter(document)
        try:
            event = adapter.normalize(document)
        except (ValueError, KeyError, TypeError) as exc:
            if len(self.skipped_lines) < 50:
                self.skipped_lines.append(f"{hit.get('_id', '<no id>')}: {exc}")
            return None
        # The document id is the addressable identity in a live cluster, so it
        # replaces the content hash the fixture repository derives.
        if hit.get("_id"):
            event.id = str(hit["_id"])
        if hit.get("_index"):
            event.correlation = {**event.correlation, "index": str(hit["_index"])}
        return event

    def _alert_query(self) -> dict[str, Any]:
        return {
            "size": self.alert_limit,
            "sort": [{self.timestamp_field: {"order": "desc"}}],
            "query": {
                "bool": {
                    "should": [
                        {"term": {"event.kind": "alert"}},
                        {"exists": {"field": "rule.id"}},
                        {"exists": {"field": "alert.signature"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }

    def _candidate_query(self, trigger: CanonicalEvent) -> dict[str, Any]:
        start = trigger.timestamp_dt.timestamp() - self.window_seconds
        end = trigger.timestamp_dt.timestamp() + self.window_seconds

        # Entity terms narrow the window server-side. Scoring still happens in
        # correlate.build_case, so a live case ranks by the same rules a
        # fixture case does.
        entity_clauses: list[dict[str, Any]] = []
        for field, value in (
            ("host.name", trigger.host_name),
            ("source.ip", trigger.source_ip),
            ("destination.ip", trigger.source_ip),
            ("source.ip", trigger.destination_ip),
            ("destination.ip", trigger.destination_ip),
            ("user.name", trigger.user_name),
        ):
            if value:
                entity_clauses.append({"term": {field: value}})

        query: dict[str, Any] = {
            "bool": {
                "filter": [
                    {
                        "range": {
                            self.timestamp_field: {
                                "gte": int(start * 1000),
                                "lte": int(end * 1000),
                                "format": "epoch_millis",
                            }
                        }
                    }
                ]
            }
        }
        if entity_clauses:
            query["bool"]["should"] = entity_clauses
            query["bool"]["minimum_should_match"] = 1

        return {
            "size": self.candidate_limit,
            "sort": [{self.timestamp_field: {"order": "asc"}}],
            "query": query,
        }

    # -- EventRepository interface -----------------------------------------

    def reload(self) -> None:
        self.skipped_lines = []
        self.last_error = ""
        for collection in (self.asset_inventory, self.threat_intel_feed):
            reload_collection = getattr(collection, "reload", None)
            if callable(reload_collection):
                reload_collection()

    def list_alerts(self) -> list[dict[str, Any]]:
        try:
            payload = self.client.search(self.alert_index, self._alert_query())
        except (ElasticsearchError, ValueError) as exc:
            # An unreachable cluster must not take down every page that lists
            # alerts. The reason is recorded and surfaced through /api/config.
            self.last_error = str(exc)
            return []

        self.last_error = ""
        alerts: list[dict[str, Any]] = []
        for hit in _hits(payload):
            event = self._normalize_hit(hit)
            if event is None or event.kind != "alert":
                continue
            mitre = event.rule.get("mitre", {}) if isinstance(event.rule.get("mitre"), dict) else {}
            mitre_ids = mitre.get("id", []) if isinstance(mitre.get("id"), list) else []
            asset = self.asset_inventory.lookup(event.host_name) or self.asset_inventory.lookup(
                event.destination_ip
            )
            verdicts = [
                indicator.verdict
                for value in (event.source_ip, event.destination_ip)
                for indicator in self.threat_intel_feed.lookup(value)
                if not indicator.is_expired()
            ]
            alerts.append(
                {
                    "id": event.id,
                    "scenario_id": str(event.correlation.get("index", "")),
                    "severity": event.severity,
                    "title": event.rule.get("name") or event.message,
                    "source": event.source_type,
                    "host": event.host_name or event.destination_ip,
                    "mitre": " / ".join(str(value) for value in mitre_ids) or "—",
                    "time": event.timestamp,
                    "status": "New",
                    "risk": {"critical": 90, "high": 78, "medium": 58, "low": 35}.get(event.severity, 45),
                    "summary": event.message,
                    "asset_criticality": asset.criticality if asset else "",
                    "asset_business_service": asset.business_service if asset else "",
                    "threat_verdict": next(
                        (value for value in ("malicious", "suspicious") if value in verdicts), ""
                    ),
                }
            )
        alerts.sort(key=lambda item: item["time"], reverse=True)
        return alerts

    def get_alert(self, alert_id: str) -> CanonicalEvent:
        body = {"size": 1, "query": {"ids": {"values": [str(alert_id)]}}}
        try:
            payload = self.client.search(self.alert_index, body)
        except (ElasticsearchError, ValueError) as exc:
            self.last_error = str(exc)
            raise AlertNotFound(f"{alert_id} could not be retrieved: {exc}") from exc

        for hit in _hits(payload):
            event = self._normalize_hit(hit)
            if event is not None:
                return event
        raise AlertNotFound(alert_id)

    def enrich_case(self, case: AlertCase) -> AlertCase:
        events = [case.trigger, *case.related_events]
        case.asset_matches, case.unresolved_assets = match_assets(
            self.asset_inventory, events, trigger_id=case.trigger.id
        )
        case.intel_matches, case.intel_stats = match_indicators(
            self.threat_intel_feed, events, trigger_id=case.trigger.id
        )
        return case

    def build_alert_case(self, alert_id: str) -> AlertCase:
        trigger = self.get_alert(alert_id)
        try:
            payload = self.client.search(self.event_index, self._candidate_query(trigger))
            candidates = self._dedupe(
                [self._normalize_hit(hit) for hit in _hits(payload)], trigger
            )
        except (ElasticsearchError, ValueError) as exc:
            # A case with only its trigger is still analyzable, and saying the
            # correlation failed is better than returning nothing.
            self.last_error = str(exc)
            candidates = []

        case = build_case(
            case_id=f"case-{alert_id}",
            scenario_id=str(trigger.correlation.get("index", "elasticsearch")),
            title=trigger.rule.get("name") or trigger.message,
            trigger=trigger,
            events=candidates,
            window_seconds=self.window_seconds,
            minimum_score=self.minimum_correlation_score,
        )
        return self.enrich_case(case)

    @staticmethod
    def _dedupe(events: Iterable[CanonicalEvent | None], trigger: CanonicalEvent) -> list[CanonicalEvent]:
        """Drop failures and the trigger's own copy from the candidate set."""
        seen: set[str] = {trigger.id}
        unique: list[CanonicalEvent] = []
        for event in events:
            if event is None or event.id in seen:
                continue
            seen.add(event.id)
            unique.append(event)
        return unique

    def health(self) -> dict[str, Any]:
        """Reachability probe for status surfaces."""
        try:
            payload = self.client.search(self.alert_index, {"size": 0})
        except (ElasticsearchError, ValueError) as exc:
            self.last_error = str(exc)
            return {"reachable": False, "error": str(exc), "alert_index": self.alert_index}
        total = payload.get("hits", {}).get("total")
        count = total.get("value") if isinstance(total, dict) else total
        self.last_error = ""
        return {
            "reachable": True,
            "alert_index": self.alert_index,
            "event_index": self.event_index,
            "matching_documents": count,
        }


def parse_window(value: Any, default: int = 300) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


__all__ = [
    "DEFAULT_ALERT_INDEX",
    "DEFAULT_EVENT_INDEX",
    "ElasticsearchClient",
    "ElasticsearchError",
    "ElasticsearchEventRepository",
    "parse_timestamp",
    "select_adapter",
    "validate_index",
]
