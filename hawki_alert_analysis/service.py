from __future__ import annotations

from typing import Any

from .bundle import BUNDLE_SCHEMA
from .live_bundle import LIVE_BUNDLE_SCHEMA, build_live_evidence_bundle
from .priority import priority_for_alert_item
from .repository import EventRepository
from .wazuh import is_vulnerability_alert
from .source_flow import build as build_source_flow, classify as classify_source


class AlertAnalysisService:
    def __init__(self, repository: EventRepository):
        self.repository = repository

    def list_alerts(
        self,
        *,
        min_level: int = 0,
        severity: str = "all",
        status: str = "all",
        query: str = "",
        category: str = "all",
        since: str = "",
        order: str = "newest",
        host: str = "",
    ) -> list[dict[str, Any]]:
        live = callable(getattr(self.repository, "list_alerts_since", None))
        searched = False
        if live and (min_level > 0 or category != "all" or since or order != "newest" or host or query):
            # Live Wazuh: the indexer applies level, period, category, host,
            # search text and order, so the page holds the alerts asked for
            # rather than a filtered copy of the newest hundred.
            alerts = self.repository.list_alerts(
                min_level=min_level, category=category, since=since, order=order, host=host, text=query,
            )
            searched = True
        else:
            alerts = self.repository.list_alerts()
            if category in {"attack", "vulnerability"}:
                want = category == "vulnerability"
                alerts = [item for item in alerts if is_vulnerability_alert(item.get("groups")) == want]
            if host:
                alerts = [item for item in alerts if str(item.get("host") or "") == host]

        if min_level > 0:
            filtered = []
            for item in alerts:
                try:
                    level = int(item.get("rule_level"))
                except (TypeError, ValueError):
                    continue
                if level >= min_level:
                    filtered.append(item)
            alerts = filtered

        # Legacy fixture compatibility only.
        elif severity != "all":
            alerts = [
                item
                for item in alerts
                if str(item.get("severity", "")).lower()
                == severity
            ]

        if status != "all":
            alerts = [
                item
                for item in alerts
                if str(item.get("status", "")).lower()
                == status
            ]

        if query and not searched:
            needle = query.lower()
            alerts = [
                item
                for item in alerts
                if needle
                in " ".join(
                    str(value).lower()
                    for value in item.values()
                )
            ]

        # Queue priority, added after filtering so a search never matches the
        # wording of a priority factor.
        inventory = getattr(self.repository, "asset_inventory", None)
        feed = getattr(self.repository, "threat_intel_feed", None)
        for item in alerts:
            item["priority"] = priority_for_alert_item(
                item, asset_inventory=inventory, threat_intel_feed=feed
            )

        return alerts

    def page_alerts(
        self,
        *,
        min_level: int = 0,
        query: str = "",
        category: str = "all",
        since: str = "",
        order: str = "newest",
        host: str = "",
        page: int = 1,
        page_size: int = 100,
        status: str = "all",
        handled_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """One page of the queue, the real total, and the 처리 상태 filter.

        status "open" leaves out alerts with a settled analyst verdict,
        "handled" keeps only those; `handled_ids` names them. Live Wazuh does
        all of it in the indexer so every page and the total agree.
        """
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 200))
        handled = list(handled_ids or [])
        offset = (page - 1) * page_size
        searcher = getattr(self.repository, "search_alert_page", None)
        if callable(searcher):
            result = searcher(
                min_level, category=category, since=since, order=order, host=host, text=query,
                offset=offset, size=page_size,
                exclude_ids=handled if status == "open" else None,
                only_ids=handled if status == "handled" else None,
            )
            alerts = list(result.get("alerts") or [])
            total = int(result.get("total") or 0)
            relation = str(result.get("relation") or "eq")
            window_limited = bool(result.get("window_limited"))
            inventory = getattr(self.repository, "asset_inventory", None)
            feed = getattr(self.repository, "threat_intel_feed", None)
            for item in alerts:
                item["priority"] = priority_for_alert_item(
                    item, asset_inventory=inventory, threat_intel_feed=feed
                )
        else:
            options = {"host": host} if host else {}
            matching = self.list_alerts(
                min_level=min_level, query=query, category=category, since=since, order=order, **options,
            )
            wanted = set(handled)
            if status == "open":
                matching = [item for item in matching if str(item.get("id")) not in wanted]
            elif status == "handled":
                matching = [item for item in matching if str(item.get("id")) in wanted]
            total, relation, window_limited = len(matching), "eq", False
            alerts = matching[offset:offset + page_size]
        pages = max(1, -(-total // page_size)) if total else 1
        return {
            "alerts": alerts,
            "total": total,
            "relation": relation,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "window_limited": window_limited,
        }

    def source_flow(self, *, start: Any = None, end: Any = None) -> dict[str, Any]:
        """출처 흐름: sensor -> detection type -> HAW-KI priority (level 8+)."""
        counter = getattr(self.repository, "source_flow_counts", None)
        if callable(counter):
            counts = counter(start=start, end=end)
            items = counts["level8_items"]
            source_type = counts["source_type"]
            type_below = counts["type_below"]
            source_level8 = counts["source_level8"]
            level8_total = counts["level8_total"]
        else:
            source_type, type_below, source_level8, items = {}, {}, {}, []
            for item in self.repository.list_alerts():
                source, kind = classify_source(item)
                source_type[(source, kind)] = source_type.get((source, kind), 0) + 1
                try:
                    level = int(item.get("rule_level"))
                except (TypeError, ValueError):
                    level = 0
                if level >= 8:
                    items.append(item)
                    source_level8[source] = source_level8.get(source, 0) + 1
                else:
                    type_below[kind] = type_below.get(kind, 0) + 1
            level8_total = len(items)

        inventory = getattr(self.repository, "asset_inventory", None)
        feed = getattr(self.repository, "threat_intel_feed", None)
        type_band: dict[tuple[str, str], int] = {}
        type_scored: dict[str, int] = {}
        for item in items:
            _, kind = classify_source(item)
            band = str((priority_for_alert_item(item, asset_inventory=inventory, threat_intel_feed=feed) or {}).get("band") or "P4")
            type_band[(kind, band)] = type_band.get((kind, band), 0) + 1
            type_scored[kind] = type_scored.get(kind, 0) + 1
        # Level 8+ alerts past the scoring limit: counted, not prioritised.
        type_level8: dict[str, int] = {}
        for (source, kind), count in source_type.items():
            type_level8[kind] = type_level8.get(kind, 0) + count
        for kind, below in type_below.items():
            type_level8[kind] = type_level8.get(kind, 0) - below
        type_unscored = {kind: max(total - type_scored.get(kind, 0), 0) for kind, total in type_level8.items()}

        flow = build_source_flow(source_type, type_below, type_band, type_unscored)
        for row in flow["table"]["rows"]:
            row["level_8_plus"] = int(source_level8.get(row["source"]) or 0)
        flow["level8_total"] = level8_total
        flow["scored"] = len(items)
        return flow

    def get_case(self, alert_id: str):
        return self.repository.build_alert_case(alert_id)

    def evidence_bundle(self, alert_id: str, *, max_related: int = 30) -> dict[str, Any]:
        """Build the evidence package appropriate to the active repository."""

        if (
            callable(getattr(self.repository, "get_alert_record", None))
            and callable(getattr(self.repository, "get_alert_context", None))
        ):
            return build_live_evidence_bundle(
                self.repository,
                alert_id,
                max_context=max_related,
            )

        return self.get_case(alert_id).to_llm_context(
            max_related=max_related
        )

    def list_assets(self) -> list[dict[str, Any]]:
        inventory = getattr(self.repository, "asset_inventory", None)
        if inventory is None:
            return []
        return [asset.to_dict() for asset in inventory.all_assets()]

    def list_indicators(self) -> list[dict[str, Any]]:
        feed = getattr(self.repository, "threat_intel_feed", None)
        if feed is None:
            return []
        return [
            {**indicator.to_dict(), "expired": indicator.is_expired()}
            for indicator in feed.all_indicators()
        ]

    def collection_summary(self) -> dict[str, Any]:
        """Counts for each collected metadata category, for status surfaces."""
        return {
            "bundle_schema": BUNDLE_SCHEMA,
            "metadata_blocks": [
                "security_alerts",
                "security_events",
                "assets",
                "threat_intelligence",
            ],
            "alerts": len(self.list_alerts()),
            "assets": len(self.list_assets()),
            "threat_indicators": len(self.list_indicators()),
        }

    def default_analysis_request(self) -> str:
        if (
            callable(getattr(self.repository, "get_alert_record", None))
            and callable(getattr(self.repository, "get_alert_context", None))
        ):
            return (
                "Analyze the supplied native Wazuh evidence as a SOC analyst. "
                "TRIGGER is the detection that opened the investigation and CTX-* "
                "records are bounded supporting events selected deterministically. "
                "Separate directly observed facts from inference. Cite supporting "
                "and contradictory evidence only with TRIGGER or supplied CTX-* "
                "identifiers. Treat Wazuh rule metadata as producer metadata, not "
                "proof of compromise. Retrieval relevance scores explain why an "
                "event was selected; they are not security severity or model "
                "confidence. Do not assume asset criticality, exposure, threat "
                "intelligence, exploitation, persistence, credential compromise, "
                "or malware execution when those facts are not supplied. Map to "
                "ATT&CK only when supported by the evidence; otherwise leave the "
                "mapping empty. State evidence gaps and recommend the next bounded "
                "search or collection steps."
            )

        return (
            "Analyze this alert case as a SOC analyst. Use the supplied detections, "
            "correlated events, asset context, and threat intelligence. Separate "
            "confirmed observations from inference, cite evidence ids exactly, "
            "state evidence gaps, and recommend the next searches or collection steps."
        )
