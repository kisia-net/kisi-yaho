from __future__ import annotations

from typing import Any

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

    def default_analysis_request(self) -> str:
        return (
            "Analyze this alert case as a SOC analyst. Reconstruct the most plausible sequence from the supplied "
            "multi-source evidence. Separate confirmed observations from inference. Identify supporting and "
            "contradictory evidence, affected entities, likely ATT&CK techniques, confidence, severity rationale, "
            "evidence gaps, and the next searches or collection steps. Do not treat temporal correlation alone as "
            "proof of causation."
        )
