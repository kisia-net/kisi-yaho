"""Phase 2: an event repository backed by Wazuh Indexer.

This is the swap the architecture was built for. `WazuhEventRepository`
exposes the same interface as `FixtureEventRepository`, so correlation,
enrichment, bundling, the assessment schema, and the agent are untouched — the
only thing that changes is where events come from.

Retrieval is deliberately thin. Wazuh Indexer selects *candidates* by time and
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

DEFAULT_ALERT_INDEX = "wazuh-alerts-*"
DEFAULT_EVENT_INDEX = "wazuh-alerts-*"

# Document shapes this repository knows how to normalize, checked in order.
_ECS = ECSAdapter()
_SURICATA = SuricataAdapter()
_WAZUH = WazuhAdapter()
_SYSMON = SysmonAdapter()


class WazuhIndexerError(RuntimeError):
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


class WazuhIndexerClient:
    """Minimal read-only Wazuh Indexer HTTP client.

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
            raise WazuhIndexerError(f"Wazuh Indexer request failed: {exc}") from exc
        except ValueError as exc:
            raise WazuhIndexerError(f"Wazuh Indexer returned invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise WazuhIndexerError("Wazuh Indexer returned an unexpected payload")
        return payload


def _hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    hits = payload.get("hits")
    values = hits.get("hits") if isinstance(hits, dict) else None
    return [hit for hit in values if isinstance(hit, dict)] if isinstance(values, list) else []


class WazuhEventRepository:
    """Live event repository. Interface-compatible with FixtureEventRepository."""

    def __init__(
        self,
        client: WazuhIndexerClient,
        *,
        alert_index: str = DEFAULT_ALERT_INDEX,
        event_index: str = DEFAULT_EVENT_INDEX,
        archive_index: str = "wazuh-archives-*",
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
        self.archive_index = validate_index(archive_index)
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
        """Return recent alerts using native Wazuh rule semantics."""

        try:
            payload = self.client.search(
                self.alert_index,
                self._alert_query(),
            )
        except (WazuhIndexerError, ValueError) as exc:
            self.last_error = str(exc)
            return []

        self.last_error = ""
        alerts: list[dict[str, Any]] = []

        for hit in _hits(payload):
            source = hit.get("_source")
            if not isinstance(source, dict):
                continue

            rule = (
                source.get("rule")
                if isinstance(source.get("rule"), dict)
                else {}
            )
            if not rule.get("id"):
                continue

            agent = (
                source.get("agent")
                if isinstance(source.get("agent"), dict)
                else {}
            )
            decoder = (
                source.get("decoder")
                if isinstance(source.get("decoder"), dict)
                else {}
            )
            data = (
                source.get("data")
                if isinstance(source.get("data"), dict)
                else {}
            )
            eventdata = (
                data.get("eventdata")
                if isinstance(data.get("eventdata"), dict)
                else {}
            )

            try:
                rule_level = int(rule.get("level"))
            except (TypeError, ValueError):
                rule_level = None

            mitre = (
                rule.get("mitre")
                if isinstance(rule.get("mitre"), dict)
                else {}
            )
            mitre_ids = mitre.get("id")
            if not isinstance(mitre_ids, list):
                mitre_ids = []

            groups = rule.get("groups")
            if not isinstance(groups, list):
                groups = []

            source_ip = (
                data.get("srcip")
                or data.get("src_ip")
                or eventdata.get("sourceIp")
                or eventdata.get("sourceIP")
                or ""
            )

            summary_parts: list[str] = []

            if source_ip:
                summary_parts.append(f"Source {source_ip}")

            if decoder.get("name") == "web-accesslog":
                method = str(data.get("protocol") or "").strip()
                url = str(data.get("url") or "").strip()
                status = str(data.get("id") or "").strip()

                if method or url:
                    summary_parts.append(
                        " ".join(
                            value
                            for value in (method, url)
                            if value
                        )
                    )
                if status:
                    summary_parts.append(f"HTTP {status}")

            if not summary_parts:
                full_log = str(source.get("full_log") or "").strip()
                if full_log:
                    summary_parts.append(full_log[:220])

            alerts.append(
                {
                    "id": str(hit.get("_id") or ""),
                    "index": str(hit.get("_index") or ""),
                    "time": (
                        source.get("timestamp")
                        or source.get("@timestamp")
                        or ""
                    ),
                    "host": (
                        agent.get("name")
                        or agent.get("ip")
                        or ""
                    ),
                    "agent_id": agent.get("id"),
                    "agent_ip": agent.get("ip"),
                    "rule_id": str(rule.get("id") or ""),
                    "rule_level": rule_level,
                    "title": (
                        str(rule.get("description") or "")
                        or "Wazuh alert"
                    ),
                    "summary": " · ".join(summary_parts),
                    "groups": groups,
                    "mitre": (
                        " / ".join(str(value) for value in mitre_ids)
                        or "—"
                    ),
                    "decoder": str(decoder.get("name") or ""),
                    "location": str(source.get("location") or ""),
                    "source_ip": str(source_ip),
                }
            )

        alerts.sort(
            key=lambda item: str(item.get("time") or ""),
            reverse=True,
        )
        return alerts

    def dashboard_summary(
        self,
        *,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Return small live SOC metrics from Wazuh Indexer."""

        window = {
            "range": {
                self.timestamp_field: {
                    "gte": f"now-{max(int(hours), 1)}h",
                    "lte": "now",
                }
            }
        }

        def count(
            index: str,
            query: dict[str, Any],
        ) -> int:
            payload = self.client.search(
                index,
                {
                    "size": 0,
                    "track_total_hits": True,
                    "query": query,
                },
            )

            total = payload.get("hits", {}).get("total", 0)

            if isinstance(total, dict):
                total = total.get("value", 0)

            return int(total or 0)

        alerts_24h = count(
            self.alert_index,
            window,
        )

        level_8_plus = count(
            self.alert_index,
            {
                "bool": {
                    "filter": [
                        window,
                        {
                            "range": {
                                "rule.level": {
                                    "gte": 8
                                }
                            }
                        },
                    ]
                }
            },
        )

        archive_events_24h = count(
            self.archive_index,
            window,
        )

        return {
            "alerts_24h": alerts_24h,
            "level_8_plus_24h": level_8_plus,
            "archive_events_24h": archive_events_24h,
            "recent_alerts": self.list_alerts()[:6],
        }

    def get_alert_record(self, alert_id: str) -> dict[str, Any]:
        """Return the native Wazuh source document for analyst evidence."""
        body = {
            "size": 1,
            "_source": [
                "timestamp",
                "agent",
                "manager",
                "rule",
                "decoder",
                "location",
                "data",
                "full_log",
                "input",
            ],
            "query": {"ids": {"values": [str(alert_id)]}},
        }

        try:
            payload = self.client.search(self.alert_index, body)
        except WazuhIndexerError as exc:
            self.last_error = str(exc)
            raise
        except ValueError as exc:
            self.last_error = str(exc)
            raise WazuhIndexerError(str(exc)) from exc

        hits = _hits(payload)
        if not hits:
            raise AlertNotFound(alert_id)

        hit = hits[0]
        source = hit.get("_source")
        if not isinstance(source, dict):
            raise AlertNotFound(alert_id)

        self.last_error = ""

        return {
            "id": str(hit.get("_id", alert_id)),
            "index": str(hit.get("_index", "")),
            "timestamp": source.get("timestamp"),
            "agent": source.get("agent")
                if isinstance(source.get("agent"), dict) else {},
            "manager": source.get("manager")
                if isinstance(source.get("manager"), dict) else {},
            "rule": source.get("rule")
                if isinstance(source.get("rule"), dict) else {},
            "decoder": source.get("decoder")
                if isinstance(source.get("decoder"), dict) else {},
            "location": source.get("location"),
            "data": source.get("data")
                if isinstance(source.get("data"), dict) else {},
            "full_log": source.get("full_log"),
            "input": source.get("input"),
        }

    def get_alert_context(
        self,
        alert_id: str,
        *,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Return bounded raw evidence surrounding a Wazuh alert."""
        from datetime import datetime, timedelta

        trigger = self.get_alert_record(alert_id)

        agent = trigger.get("agent") or {}
        agent_id = str(agent.get("id") or "").strip()
        trigger_time_raw = str(trigger.get("timestamp") or "").strip()

        if not agent_id or not trigger_time_raw:
            raise WazuhIndexerError(
                "Trigger alert is missing agent.id or timestamp."
            )

        def parse_time(value: str) -> datetime:
            value = value.strip()
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)

        trigger_time = parse_time(trigger_time_raw)
        start = trigger_time - timedelta(seconds=self.window_seconds)
        end = trigger_time + timedelta(seconds=self.window_seconds)

        body = {
            "size": self.candidate_limit,
            "sort": [
                {self.timestamp_field: {"order": "asc"}}
            ],
            "_source": [
                "timestamp",
                "agent",
                "rule",
                "decoder",
                "location",
                "data",
                "full_log",
            ],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"agent.id": agent_id}},
                        {
                            "range": {
                                self.timestamp_field: {
                                    "gte": start.isoformat(),
                                    "lte": end.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
        }

        try:
            payload = self.client.search(self.archive_index, body)
        except (WazuhIndexerError, ValueError) as exc:
            self.last_error = str(exc)
            if isinstance(exc, WazuhIndexerError):
                raise
            raise WazuhIndexerError(str(exc)) from exc

        trigger_data = trigger.get("data") or {}
        trigger_rule = trigger.get("rule") or {}
        trigger_decoder = trigger.get("decoder") or {}

        trigger_srcip = str(trigger_data.get("srcip") or "")
        trigger_location = str(trigger.get("location") or "")
        trigger_decoder_name = str(trigger_decoder.get("name") or "")
        trigger_full_log = str(trigger.get("full_log") or "")

        selected: list[dict[str, Any]] = []
        suppressed = 0

        for hit in _hits(payload):
            source = hit.get("_source")
            if not isinstance(source, dict):
                continue

            full_log = str(source.get("full_log") or "")
            location = str(source.get("location") or "")
            decoder = source.get("decoder")
            decoder = decoder if isinstance(decoder, dict) else {}
            rule = source.get("rule")
            rule = rule if isinstance(rule, dict) else {}
            data = source.get("data")
            data = data if isinstance(data, dict) else {}

            # Routine command collectors stay in archives but are not
            # automatically promoted into alert investigation context.
            if (
                decoder.get("name") == "ossec"
                and full_log.startswith("ossec: output:")
            ):
                suppressed += 1
                continue

            timestamp_raw = str(source.get("timestamp") or "")
            try:
                event_time = parse_time(timestamp_raw)
                delta_seconds = abs(
                    (event_time - trigger_time).total_seconds()
                )
            except (TypeError, ValueError):
                delta_seconds = self.window_seconds + 1

            # Do not repeat the trigger itself.
            if (
                full_log
                and full_log == trigger_full_log
                and delta_seconds <= 2
            ):
                continue

            score = 0
            reasons: list[str] = []

            import re

            srcip = str(data.get("srcip") or "").strip()

            if not srcip and full_log:
                match = re.match(
                    r"^\s*((?:\d{1,3}\.){3}\d{1,3})\b",
                    full_log,
                )
                if match:
                    srcip = match.group(1)

            same_source_ip = bool(
                trigger_srcip and srcip == trigger_srcip
            )

            if same_source_ip:
                score += 5
                reasons.append("same_source_ip")

            if trigger_location and location == trigger_location:
                score += 2
                reasons.append("same_log_source")

            if (
                trigger_decoder_name
                and decoder.get("name") == trigger_decoder_name
            ):
                score += 1
                reasons.append("same_decoder")

            try:
                rule_level = int(rule.get("level", 0))
            except (TypeError, ValueError):
                rule_level = 0

            if rule.get("id") or rule_level >= 3:
                score += 3
                reasons.append("wazuh_detection")

            if delta_seconds <= 120:
                score += 1
                reasons.append("within_120_seconds")

            if trigger_srcip and not same_source_ip:
                continue

            if score < 4:
                continue

            selected.append({
                "id": str(hit.get("_id", "")),
                "index": str(hit.get("_index", "")),
                "timestamp": source.get("timestamp"),
                "agent": source.get("agent") or {},
                "rule": rule,
                "decoder": decoder,
                "location": source.get("location"),
                "data": data,
                "full_log": source.get("full_log"),
                "relevance_score": score,
                "relevance_reasons": reasons,
                "delta_seconds": round(delta_seconds, 3),
            })

        selected.sort(
            key=lambda item: (
                -int(item["relevance_score"]),
                float(item["delta_seconds"]),
            )
        )

        selected = selected[:max(1, min(int(limit), 50))]

        # Analyst presentation should remain chronological.
        selected.sort(key=lambda item: str(item.get("timestamp") or ""))

        return {
            "alert_id": alert_id,
            "agent": trigger.get("agent") or {},
            "trigger_timestamp": trigger.get("timestamp"),
            "window_seconds": self.window_seconds,
            "archive_index": self.archive_index,
            "candidate_count": len(_hits(payload)),
            "suppressed_routine_count": suppressed,
            "selected_count": len(selected),
            "events": selected,
        }

    def get_alert(self, alert_id: str) -> CanonicalEvent:
        body = {"size": 1, "query": {"ids": {"values": [str(alert_id)]}}}
        try:
            payload = self.client.search(self.alert_index, body)
        except (WazuhIndexerError, ValueError) as exc:
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
        except (WazuhIndexerError, ValueError) as exc:
            # A case with only its trigger is still analyzable, and saying the
            # correlation failed is better than returning nothing.
            self.last_error = str(exc)
            candidates = []

        case = build_case(
            case_id=f"case-{alert_id}",
            scenario_id=str(trigger.correlation.get("index", "wazuh")),
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
        except (WazuhIndexerError, ValueError) as exc:
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
    "WazuhIndexerClient",
    "WazuhIndexerError",
    "WazuhEventRepository",
    "parse_timestamp",
    "select_adapter",
    "validate_index",
]
