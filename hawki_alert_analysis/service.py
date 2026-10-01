from __future__ import annotations

from typing import Any

from .bundle import BUNDLE_SCHEMA
from .live_bundle import LIVE_BUNDLE_SCHEMA, build_live_evidence_bundle
from .priority import priority_for_alert_item
from .repository import EventRepository
from .wazuh import is_vulnerability_alert


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
        if live and (min_level > 0 or category != "all" or since or order != "newest" or host):
            # Live Wazuh: the indexer applies level, period, category, host
            # and order, so the page holds the alerts asked for rather than a
            # filtered copy of the newest hundred.
            alerts = self.repository.list_alerts(
                min_level=min_level, category=category, since=since, order=order, host=host,
            )
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

        if query:
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
