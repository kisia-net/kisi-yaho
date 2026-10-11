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

import ipaddress
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import quote

import requests

from .adapters import ECSAdapter, SuricataAdapter, SysmonAdapter, WazuhAdapter
from .assets import AssetInventory, NullAssetInventory, match_assets
from .correlate import build_case
from .correlation_profiles import select_profile
from .models import AlertCase, CanonicalEvent, parse_timestamp
from .repository import AlertNotFound
from .threat_intel import NullThreatIntelFeed, ThreatIntelFeed, match_indicators
from .sensitive import category_for_query, category_patterns

INDEX_PATTERN = re.compile(r"^[A-Za-z0-9._*,\-]{1,256}$")

# Where the lab's decoders put addresses: classic decoders (nginx, sshd,
# ModSecurity) use srcip/dstip, Suricata EVE through Wazuh uses src_ip/dest_ip.
SOURCE_IP_FIELDS = ["data.srcip", "data.src_ip"]
DESTINATION_IP_FIELDS = ["data.dstip", "data.dest_ip"]
# Cap on events pulled from other agents per alert; they compete with the
# same-agent evidence for the same few context slots.
CROSS_AGENT_LIMIT = 50
# Context slots held for other agents' events when any were found.
CROSS_AGENT_RESERVED = 4


def _field(record: dict[str, Any], dotted: str) -> Any:
    value: Any = record
    for key in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _event_source_ip(record: dict[str, Any]) -> str:
    for name in SOURCE_IP_FIELDS:
        value = str(_field(record, name) or "").strip()
        if value:
            return value
    return ""


DEFAULT_ALERT_INDEX = "wazuh-alerts-*"
# Wazuh's vulnerability detector raises one alert per CVE per package: an
# inventory finding, not an attack. Listed apart from attack alerts.
VULNERABILITY_GROUPS = ("vulnerability-detector",)


def is_vulnerability_alert(groups: Any) -> bool:
    return isinstance(groups, (list, tuple)) and any(group in VULNERABILITY_GROUPS for group in groups)


ALERT_TEXT_MAX = 128


def _wildcard_literal(text: str) -> str:
    return re.sub(r"([\\*?])", r"\\\1", text)


def alert_text_clause(text: str) -> dict[str, Any] | None:
    """Indexer clause for the alert-list search box.

    The search used to filter the 100 rows the indexer returned. With
    "전체" and 우선순위순 those rows were CVE alerts, so searching an
    attacker IP found nothing while the IP had hundreds of alerts.
    Matches the log text, rule description, URL, rule id, host, decoder,
    rule group, MITRE id, and for an IP address the source/destination/agent address fields.
    """
    text = str(text or "").strip()[:ALERT_TEXT_MAX]
    if not text:
        return None
    pattern = f"*{_wildcard_literal(text)}*"
    should: list[dict[str, Any]] = [
        {"match_phrase": {"full_log": text}},
        {"wildcard": {"rule.description": {"value": pattern, "case_insensitive": True}}},
        {"wildcard": {"data.url": {"value": pattern, "case_insensitive": True}}},
        {"term": {"rule.id": text}},
        {"term": {"agent.name": text}},
        {"term": {"agent.id": text}},
        {"term": {"decoder.name": text}},
        {"term": {"rule.groups": text}},
        {"term": {"rule.mitre.id": text}},
    ]
    try:
        address = str(ipaddress.ip_address(text))
    except ValueError:
        address = ""
    if address:
        should.extend({"term": {field: address}} for field in SOURCE_IP_FIELDS + DESTINATION_IP_FIELDS + ["agent.ip"])
    # A category word ("credential", "자격증명", ".env") also searches the
    # paths and file names that mean it (hawki_alert_analysis/sensitive.py).
    category = category_for_query(text)
    for literal in category_patterns(category or ""):
        should.append({"wildcard": {"data.url": {"value": f"*{_wildcard_literal(literal)}*", "case_insensitive": True}}})
        should.append({"match_phrase": {"full_log": literal}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


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


# OpenSearch's default index.max_result_window: from + size beyond it fails.
MAX_RESULT_WINDOW = 10000


def _total_hits(payload: dict[str, Any]) -> tuple[int, str]:
    total = (payload.get("hits") or {}).get("total") if isinstance(payload.get("hits"), dict) else None
    if isinstance(total, dict):
        try:
            return int(total.get("value") or 0), str(total.get("relation") or "eq")
        except (TypeError, ValueError):
            return 0, "eq"
    try:
        return int(total or 0), "eq"
    except (TypeError, ValueError):
        return 0, "eq"


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

    def _alert_query(
        self,
        min_level: int = 0,
        *,
        category: str = "all",
        since: str = "",
        order: str = "newest",
        host: str = "",
        text: str = "",
    ) -> dict[str, Any]:
        query: dict[str, Any] = {
            "bool": {
                "should": [
                    {"term": {"event.kind": "alert"}},
                    {"exists": {"field": "rule.id"}},
                    {"exists": {"field": "alert.signature"}},
                ],
                "minimum_should_match": 1,
            }
        }
        filters: list[dict[str, Any]] = []
        if min_level > 0:
            # Filtered in the indexer. Filtering the newest page afterwards
            # found nothing whenever the last alert_limit alerts were all
            # low level, while the dashboard counted thousands at level 8+.
            filters.append({"range": {"rule.level": {"gte": int(min_level)}}})
        if since:
            filters.append({"range": {self.timestamp_field: {"gte": since, "lte": "now"}}})
        if host:
            filters.append({"term": {"agent.name": host}})
        text_clause = alert_text_clause(text)
        if text_clause:
            filters.append(text_clause)
        if category == "vulnerability":
            filters.append({"terms": {"rule.groups": list(VULNERABILITY_GROUPS)}})
        elif category == "attack":
            query["bool"]["must_not"] = [{"terms": {"rule.groups": list(VULNERABILITY_GROUPS)}}]
        if filters:
            query["bool"]["filter"] = filters
        # "level": the highest levels in the period first, so a page of 100
        # holds the alerts that matter instead of the newest scanner noise.
        sort = (
            [{"rule.level": {"order": "desc", "unmapped_type": "long"}}, {self.timestamp_field: {"order": "desc"}}]
            if order == "level"
            else [{self.timestamp_field: {"order": "desc"}}]
        )
        return {"size": self.alert_limit, "sort": sort, "query": query}

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

    def list_alerts(
        self,
        min_level: int = 0,
        *,
        category: str = "all",
        since: str = "",
        order: str = "newest",
        host: str = "",
        text: str = "",
    ) -> list[dict[str, Any]]:
        """Return recent alerts using native Wazuh rule semantics."""

        try:
            payload = self.client.search(
                self.alert_index,
                self._alert_query(min_level, category=category, since=since, order=order, host=host, text=text),
            )
        except (WazuhIndexerError, ValueError) as exc:
            self.last_error = str(exc)
            return []

        self.last_error = ""
        alerts = self._alert_items(_hits(payload))
        if order != "level":
            alerts.sort(
                key=lambda item: str(item.get("time") or ""),
                reverse=True,
            )
        return alerts

    def search_alert_page(
        self,
        min_level: int = 0,
        *,
        category: str = "all",
        since: str = "",
        order: str = "newest",
        host: str = "",
        text: str = "",
        offset: int = 0,
        size: int = 50,
        exclude_ids: list[str] | None = None,
        only_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """One page of the alert queue and how many alerts match in total.

        The indexer counts the matches (track_total_hits), so "전체 N건" is
        the real number and not the size of the newest page. Deep paging
        stops at MAX_RESULT_WINDOW, the indexer's default from+size limit.
        """
        size = max(1, min(int(size), 200))
        offset = max(0, int(offset))
        window_limited = offset + size > MAX_RESULT_WINDOW
        if window_limited:
            offset = max(0, MAX_RESULT_WINDOW - size)
        body = self._alert_query(min_level, category=category, since=since, order=order, host=host, text=text)
        body.update({"from": offset, "size": size, "track_total_hits": True})
        query = body["query"]["bool"]
        if exclude_ids:
            query.setdefault("must_not", []).append({"ids": {"values": list(exclude_ids)}})
        if only_ids is not None:
            query.setdefault("filter", []).append({"ids": {"values": list(only_ids)}})
        try:
            payload = self.client.search(self.alert_index, body)
        except (WazuhIndexerError, ValueError) as exc:
            self.last_error = str(exc)
            return {"alerts": [], "total": 0, "relation": "eq", "error": True, "window_limited": window_limited}
        self.last_error = ""
        total, relation = _total_hits(payload)
        return {
            "alerts": self._alert_items(_hits(payload)),
            "total": total,
            "relation": relation,
            "window_limited": window_limited,
        }

    def list_alerts_since(
        self,
        since: datetime,
        *,
        min_level: int,
        limit: int = 100,
        exclude_groups: tuple[str, ...] | list[str] = (),
    ) -> list[dict[str, Any]]:
        """Alerts at or above min_level from `since` on, oldest first.

        Used by the automatic analysis worker, which must not miss a level-10
        alert just because a hundred level-3 alerts arrived after it; the
        queue view (list_alerts) only ever shows the most recent hundred.
        Errors are raised, not swallowed: the worker records them.
        """
        body = {
            "size": max(1, min(int(limit), 500)),
            "sort": [{self.timestamp_field: {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                self.timestamp_field: {
                                    "gte": int(since.timestamp() * 1000),
                                    "format": "epoch_millis",
                                }
                            }
                        },
                        {"range": {"rule.level": {"gte": int(min_level)}}},
                    ]
                }
            },
        }
        if exclude_groups:
            body["query"]["bool"]["must_not"] = [{"terms": {"rule.groups": list(exclude_groups)}}]
        payload = self.client.search(self.alert_index, body)
        return self._alert_items(_hits(payload))

    def _alert_items(self, hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Alert-queue rows from indexer hits, in the order given."""
        alerts: list[dict[str, Any]] = []

        for hit in hits:
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

        return alerts

    def dashboard_summary(
        self,
        *,
        hours: int = 24,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Return small live SOC metrics from Wazuh Indexer.

        Each metric is counted twice: everything retained ("전체") and the
        last `hours` (10주차 멘토링 1번). The window is fixed here to exact
        timestamps and returned, so the page can say which 24 hours it means
        (e.g. 10.03 16:43:05 ~ 10.04 16:43:05) instead of a relative "now-24h".
        """
        end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        start = end - timedelta(hours=max(int(hours), 1))
        window = {
            "range": {
                self.timestamp_field: {
                    "gte": start.isoformat(),
                    "lte": end.isoformat(),
                }
            }
        }
        everything = {"match_all": {}}

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

        # The same level-8+ count without the vulnerability detector's
        # one-alert-per-CVE findings: the number of attack alerts to look at.
        level_8_plus_attack = count(
            self.alert_index,
            {
                "bool": {
                    "filter": [window, {"range": {"rule.level": {"gte": 8}}}],
                    "must_not": [{"terms": {"rule.groups": list(VULNERABILITY_GROUPS)}}],
                }
            },
        )

        level_8 = {"range": {"rule.level": {"gte": 8}}}
        not_cve = [{"terms": {"rule.groups": list(VULNERABILITY_GROUPS)}}]
        totals = {
            "alerts": count(self.alert_index, everything),
            "level_8_plus": count(self.alert_index, {"bool": {"filter": [level_8]}}),
            "level_8_plus_attack": count(self.alert_index, {"bool": {"filter": [level_8], "must_not": not_cve}}),
            "archive_events": count(self.archive_index, everything),
        }

        return {
            "alerts_24h": alerts_24h,
            "level_8_plus_24h": level_8_plus,
            "level_8_plus_attack_24h": level_8_plus_attack,
            "archive_events_24h": archive_events_24h,
            "totals": totals,
            "window": {"start": start.isoformat(), "end": end.isoformat(), "hours": max(int(hours), 1)},
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
        window_override: tuple[int, int] | None = None,
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
        profile = select_profile(trigger, default_seconds=self.window_seconds)
        if window_override is not None:
            # The evidence agent may widen the window within fixed bounds
            # (evidence_agent.WINDOW_LIMITS); everything else about the
            # profile, including cross-agent search, stays as selected.
            before, after = window_override
            profile = replace(
                profile,
                name=f"{profile.name}+widened",
                seconds_before=max(profile.seconds_before, int(before)),
                seconds_after=max(profile.seconds_after, int(after)),
            )
        start = trigger_time - timedelta(seconds=profile.seconds_before)
        end = trigger_time + timedelta(seconds=profile.seconds_after)

        source_fields = [
            "timestamp",
            "agent",
            "rule",
            "decoder",
            "location",
            "data",
            "full_log",
        ]

        def time_range(gte: datetime, lte: datetime) -> dict[str, Any]:
            return {
                "range": {
                    self.timestamp_field: {
                        "gte": gte.isoformat(),
                        "lte": lte.isoformat(),
                    }
                }
            }

        def search(body: dict[str, Any]) -> list[dict[str, Any]]:
            try:
                return _hits(self.client.search(self.archive_index, body))
            except (WazuhIndexerError, ValueError) as exc:
                self.last_error = str(exc)
                if isinstance(exc, WazuhIndexerError):
                    raise
                raise WazuhIndexerError(str(exc)) from exc

        # Same agent, fetched outward from the trigger in both directions.
        # One ascending query capped at candidate_limit filled up with the
        # oldest events of a busy window and could return nothing after the
        # trigger at all; splitting the budget keeps the events nearest the
        # trigger on both sides.
        half = max(1, self.candidate_limit // 2)
        same_agent = {"term": {"agent.id": agent_id}}
        before_hits = search({
            "size": half,
            "sort": [{self.timestamp_field: {"order": "desc"}}],
            "_source": source_fields,
            "query": {"bool": {"filter": [same_agent, time_range(start, trigger_time)]}},
        })
        after_hits = search({
            "size": half,
            "sort": [{self.timestamp_field: {"order": "asc"}}],
            "_source": source_fields,
            "query": {"bool": {"filter": [same_agent, time_range(trigger_time, end)]}},
        })

        # Other agents that saw the trigger's source address: the network
        # sensor for a web alert, the other servers for a brute-force source.
        trigger_srcip_value = _event_source_ip(trigger)
        cross_hits: list[dict[str, Any]] = []
        if profile.cross_agent and trigger_srcip_value:
            cross_hits = search({
                "size": min(CROSS_AGENT_LIMIT, self.candidate_limit),
                "sort": [{self.timestamp_field: {"order": "asc"}}],
                "_source": source_fields,
                "query": {
                    "bool": {
                        "filter": [time_range(start, end)],
                        "must_not": [same_agent],
                        "should": [
                            {"term": {field: trigger_srcip_value}}
                            for field in SOURCE_IP_FIELDS + DESTINATION_IP_FIELDS
                        ],
                        "minimum_should_match": 1,
                    }
                },
            })

        hits: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        cross_ids: set[str] = set()
        for origin, batch in (
            ("same_agent", before_hits + after_hits),
            ("cross_agent", cross_hits),
        ):
            for hit in batch:
                hit_id = str(hit.get("_id", ""))
                if hit_id and hit_id in seen_ids:
                    continue
                seen_ids.add(hit_id)
                if origin == "cross_agent":
                    cross_ids.add(hit_id)
                hits.append(hit)

        trigger_data = trigger.get("data") or {}
        trigger_rule = trigger.get("rule") or {}
        trigger_decoder = trigger.get("decoder") or {}

        trigger_srcip = trigger_srcip_value
        trigger_location = str(trigger.get("location") or "")
        trigger_decoder_name = str(trigger_decoder.get("name") or "")
        trigger_full_log = str(trigger.get("full_log") or "")

        selected: list[dict[str, Any]] = []
        suppressed = 0

        for hit in hits:
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

            srcip = _event_source_ip(source)
            other_agent = str(hit.get("_id", "")) in cross_ids

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

            if not same_source_ip and other_agent and trigger_srcip:
                # The sensor may record the address as the destination of a
                # reply; the cross-agent query only returned the event because
                # one of these fields held the trigger's source address.
                same_source_ip = trigger_srcip in {
                    str(_field(source, name) or "").strip()
                    for name in SOURCE_IP_FIELDS + DESTINATION_IP_FIELDS
                }

            if same_source_ip:
                score += 5
                reasons.append("same_source_ip")

            if other_agent:
                reasons.append("other_agent_same_address")

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
                "origin": "cross_agent" if other_agent else "same_agent",
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

        def rank(item: dict[str, Any]) -> tuple[int, float]:
            return (-int(item["relevance_score"]), float(item["delta_seconds"]))

        # Same-agent events always outscore cross-agent ones (they add the
        # same-log-source and same-decoder points), so without a reservation
        # the other agents' view would never survive a busy window. A few
        # slots are held for it; unused slots go back to the same agent.
        budget = max(1, min(int(limit), 50))
        cross = sorted((i for i in selected if i["origin"] == "cross_agent"), key=rank)
        local = sorted((i for i in selected if i["origin"] != "cross_agent"), key=rank)
        reserved = cross[:min(CROSS_AGENT_RESERVED, budget)]
        remaining = sorted(local + cross[len(reserved):], key=rank)
        selected = reserved + remaining[:budget - len(reserved)]

        # Analyst presentation should remain chronological.
        selected.sort(key=lambda item: str(item.get("timestamp") or ""))

        return {
            "alert_id": alert_id,
            "agent": trigger.get("agent") or {},
            "trigger_timestamp": trigger.get("timestamp"),
            "window_seconds": max(profile.seconds_before, profile.seconds_after),
            "window": {
                "seconds_before": profile.seconds_before,
                "seconds_after": profile.seconds_after,
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "profile": profile.to_dict(),
            "archive_index": self.archive_index,
            "candidate_count": len(hits),
            "candidate_breakdown": {
                "same_agent_before": len(before_hits),
                "same_agent_after": len(after_hits),
                "cross_agent": len(cross_hits),
            },
            "suppressed_routine_count": suppressed,
            "selected_count": len(selected),
            "events": selected,
        }

    def search_address(
        self,
        address: str,
        *,
        around: str,
        hours: int,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Archive events on any agent that carry `address`, within +/- hours.

        Read-only, bounded, and only reachable through the evidence agent's
        validated tool call (the address must already appear in the evidence).
        """
        from datetime import datetime, timedelta

        value = str(around or "").strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        center = datetime.fromisoformat(value)
        span = timedelta(hours=max(1, min(int(hours), 24)))
        body = {
            "size": max(1, min(int(limit), 50)),
            "sort": [{self.timestamp_field: {"order": "desc"}}],
            "_source": ["timestamp", "agent", "rule", "decoder", "location", "data", "full_log"],
            "query": {
                "bool": {
                    "filter": [{
                        "range": {
                            self.timestamp_field: {
                                "gte": (center - span).isoformat(),
                                "lte": (center + span).isoformat(),
                            }
                        }
                    }],
                    "should": [
                        {"term": {field: address}}
                        for field in SOURCE_IP_FIELDS + DESTINATION_IP_FIELDS
                    ],
                    "minimum_should_match": 1,
                }
            },
        }
        try:
            payload = self.client.search(self.archive_index, body)
        except (WazuhIndexerError, ValueError) as exc:
            self.last_error = str(exc)
            raise WazuhIndexerError(str(exc)) from exc

        events: list[dict[str, Any]] = []
        for hit in _hits(payload):
            source = hit.get("_source")
            if not isinstance(source, dict):
                continue
            events.append({
                "origin": "agent_search",
                "id": str(hit.get("_id", "")),
                "index": str(hit.get("_index", "")),
                "timestamp": source.get("timestamp"),
                "agent": source.get("agent") or {},
                "rule": source.get("rule") or {},
                "decoder": source.get("decoder") or {},
                "location": source.get("location"),
                "data": source.get("data") or {},
                "full_log": source.get("full_log"),
                "relevance_score": None,
                "relevance_reasons": ["agent_tool:search_address"],
                "delta_seconds": None,
            })
        return events

    def search_events(
        self,
        *,
        around: str,
        hours: int,
        agent_name: str = "",
        rule_id: str = "",
        decoder: str = "",
        text: str = "",
        address: str = "",
        limit: int = 30,
    ) -> list[dict[str, Any]]:
        """Archive events matching structured filters, within +/- hours.

        Reached only through the evidence agent's validated search_events
        call: every value has already been checked to appear in the evidence,
        and the filters are fixed fields, never a free query string.
        """
        from datetime import datetime, timedelta

        value = str(around or "").strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        center = datetime.fromisoformat(value)
        span = timedelta(hours=max(1, min(int(hours), 24)))
        filters: list[dict[str, Any]] = [{
            "range": {self.timestamp_field: {"gte": (center - span).isoformat(), "lte": (center + span).isoformat()}}
        }]
        if agent_name:
            filters.append({"term": {"agent.name": agent_name}})
        if rule_id:
            filters.append({"term": {"rule.id": rule_id}})
        if decoder:
            filters.append({"term": {"decoder.name": decoder}})
        if address:
            filters.append({"bool": {
                "should": [{"term": {field: address}} for field in SOURCE_IP_FIELDS + DESTINATION_IP_FIELDS],
                "minimum_should_match": 1,
            }})
        query: dict[str, Any] = {"bool": {"filter": filters}}
        if text:
            query["bool"]["must"] = [{"multi_match": {"query": text, "type": "phrase", "fields": ["data.url", "full_log"]}}]
        body = {
            "size": max(1, min(int(limit), 50)),
            "sort": [{self.timestamp_field: {"order": "desc"}}],
            "_source": ["timestamp", "agent", "rule", "decoder", "location", "data", "full_log"],
            "query": query,
        }
        try:
            payload = self.client.search(self.archive_index, body)
        except (WazuhIndexerError, ValueError) as exc:
            self.last_error = str(exc)
            raise WazuhIndexerError(str(exc)) from exc

        events: list[dict[str, Any]] = []
        for hit in _hits(payload):
            source = hit.get("_source")
            if not isinstance(source, dict):
                continue
            events.append({
                "origin": "agent_search",
                "id": str(hit.get("_id", "")),
                "index": str(hit.get("_index", "")),
                "timestamp": source.get("timestamp"),
                "agent": source.get("agent") or {},
                "rule": source.get("rule") or {},
                "decoder": source.get("decoder") or {},
                "location": source.get("location"),
                "data": source.get("data") or {},
                "full_log": source.get("full_log"),
                "relevance_score": None,
                "relevance_reasons": ["agent_tool:search_events"],
                "delta_seconds": None,
            })
        return events

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
