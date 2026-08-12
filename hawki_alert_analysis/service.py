from __future__ import annotations

from typing import Any

from .bundle import BUNDLE_SCHEMA
from .repository import EventRepository


class AlertAnalysisService:
    def __init__(self, repository: EventRepository):
        self.repository = repository

    def list_alerts(self, *, severity: str = "all", status: str = "all", query: str = "") -> list[dict[str, Any]]:
        alerts = self.repository.list_alerts()
        if severity != "all":
            alerts = [item for item in alerts if str(item.get("severity", "")).lower() == severity]
        if status != "all":
            alerts = [item for item in alerts if str(item.get("status", "")).lower() == status]
        if query:
            needle = query.lower()
            alerts = [
                item for item in alerts
                if needle in " ".join(str(value).lower() for value in item.values())
            ]
        return alerts

    def get_case(self, alert_id: str):
        return self.repository.build_alert_case(alert_id)

    def evidence_bundle(self, alert_id: str, *, max_related: int = 30) -> dict[str, Any]:
        """The exact four-block metadata bundle delivered to the LLM/SLM."""
        return self.get_case(alert_id).to_llm_context(max_related=max_related)

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
        return (
            "Analyze this alert case as a SOC analyst. The bundle contains four metadata blocks: security "
            "alerts, correlated raw security events, asset inventory context, and threat intelligence. Use all "
            "four. Reconstruct the most plausible sequence from the multi-source evidence, and separate confirmed "
            "observations from inference. Identify supporting and contradictory evidence, affected entities, "
            "likely ATT&CK techniques, confidence, severity rationale that accounts for asset criticality and "
            "exposure, evidence gaps, and the next searches or collection steps. Do not treat temporal "
            "correlation alone as proof of causation, and do not treat a threat-intelligence match as proof of "
            "compromise."
        )
