from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .adapters import ECSAdapter, NginxAdapter, SuricataAdapter, WazuhAdapter
from .assets import AssetInventory, NullAssetInventory, match_assets
from .correlate import build_case
from .models import AlertCase, CanonicalEvent
from .threat_intel import NullThreatIntelFeed, ThreatIntelFeed, match_indicators


class AlertNotFound(KeyError):
    pass


class EventRepository(Protocol):
    def list_alerts(self) -> list[dict[str, Any]]: ...
    def get_alert(self, alert_id: str) -> CanonicalEvent: ...
    def build_alert_case(self, alert_id: str) -> AlertCase: ...


ADAPTERS = {
    "suricata": SuricataAdapter(),
    "nginx": NginxAdapter(),
    "wazuh": WazuhAdapter(),
    "ecs": ECSAdapter(),
}


@dataclass(slots=True)
class LoadedScenario:
    manifest: dict[str, Any]
    events: list[CanonicalEvent]


class FixtureEventRepository:
    """Native-format fixture repository.

    Only this class knows that events come from files. The rest of HAW-KI works
    against canonical events/cases, so a live repository can replace it later.
    """

    def __init__(
        self,
        root: Path,
        *,
        asset_inventory: AssetInventory | None = None,
        threat_intel_feed: ThreatIntelFeed | None = None,
    ):
        self.root = Path(root)
        self.asset_inventory: AssetInventory = asset_inventory or NullAssetInventory()
        self.threat_intel_feed: ThreatIntelFeed = threat_intel_feed or NullThreatIntelFeed()
        self._scenarios: list[LoadedScenario] | None = None

    def _load_jsonl(self, path: Path) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                value = json.loads(line)
                if isinstance(value, dict):
                    values.append(value)
        return values

    def _load_source(self, scenario_dir: Path, source: dict[str, Any], scenario_id: str) -> list[CanonicalEvent]:
        source_type = str(source["type"])
        adapter = ADAPTERS[source_type]
        defaults = source.get("defaults") if isinstance(source.get("defaults"), dict) else {}
        path = scenario_dir / str(source["path"])

        if source_type == "nginx":
            rows: list[Any] = [line.rstrip("\n") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        else:
            rows = self._load_jsonl(path)

        events: list[CanonicalEvent] = []
        for row in rows:
            events.append(adapter.normalize(row, scenario_id=scenario_id, defaults=defaults))
        return events

    def _load(self) -> list[LoadedScenario]:
        if self._scenarios is not None:
            return self._scenarios
        scenarios: list[LoadedScenario] = []
        if not self.root.exists():
            self._scenarios = []
            return []
        for manifest_path in sorted(self.root.glob("*/scenario.json")):
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            scenario_id = str(manifest["id"])
            events: list[CanonicalEvent] = []
            for source in manifest.get("sources", []):
                if isinstance(source, dict):
                    events.extend(self._load_source(manifest_path.parent, source, scenario_id))
            scenarios.append(LoadedScenario(manifest=manifest, events=events))
        self._scenarios = scenarios
        return scenarios

    def reload(self) -> None:
        self._scenarios = None
        for collection in (self.asset_inventory, self.threat_intel_feed):
            reload_collection = getattr(collection, "reload", None)
            if callable(reload_collection):
                reload_collection()

    def enrich_case(self, case: AlertCase) -> AlertCase:
        """Attach the asset and threat-intelligence metadata blocks.

        Enrichment runs over the whole case (trigger plus correlated events) so
        an indicator hit on a supporting event is not lost, and records where
        each match was observed.
        """
        events = [case.trigger, *case.related_events]
        case.asset_matches, case.unresolved_assets = match_assets(
            self.asset_inventory, events, trigger_id=case.trigger.id
        )
        case.intel_matches, case.intel_stats = match_indicators(
            self.threat_intel_feed, events, trigger_id=case.trigger.id
        )
        return case

    def _trigger_for_scenario(self, scenario: LoadedScenario) -> CanonicalEvent:
        selector = scenario.manifest.get("trigger") if isinstance(scenario.manifest.get("trigger"), dict) else {}
        for event in scenario.events:
            if selector.get("source_type") and event.source_type != selector["source_type"]:
                continue
            if selector.get("rule_id") and str(event.rule.get("id", "")) != str(selector["rule_id"]):
                continue
            if selector.get("kind") and event.kind != selector["kind"]:
                continue
            return event
        raise AlertNotFound(f"No trigger matched scenario {scenario.manifest.get('id')}")

    def list_alerts(self) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        for scenario in self._load():
            for event in scenario.events:
                if event.kind != "alert":
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
                        "scenario_id": scenario.manifest.get("id", ""),
                        "severity": event.severity,
                        "title": event.rule.get("name") or event.message,
                        "source": event.source_type,
                        "host": event.host_name or event.destination_ip,
                        "mitre": " / ".join(str(value) for value in mitre_ids) or "—",
                        "time": event.timestamp,
                        "status": "New",
                        "risk": {"critical": 90, "high": 78, "medium": 58, "low": 35}.get(event.severity, 45),
                        "summary": event.message,
                        # Enrichment previews for the triage queue. The full
                        # metadata blocks live on the alert case.
                        "asset_criticality": asset.criticality if asset else "",
                        "asset_business_service": asset.business_service if asset else "",
                        "threat_verdict": next(
                            (value for value in ("malicious", "suspicious") if value in verdicts),
                            "",
                        ),
                    }
                )
        alerts.sort(key=lambda item: item["time"], reverse=True)
        return alerts

    def get_alert(self, alert_id: str) -> CanonicalEvent:
        for scenario in self._load():
            for event in scenario.events:
                if event.id == alert_id and event.kind == "alert":
                    return event
        raise AlertNotFound(alert_id)

    def build_alert_case(self, alert_id: str) -> AlertCase:
        for scenario in self._load():
            trigger = next((event for event in scenario.events if event.id == alert_id and event.kind == "alert"), None)
            if trigger is None:
                continue
            manifest = scenario.manifest
            case = build_case(
                case_id=f"case-{alert_id.removeprefix('evt-')}",
                scenario_id=str(manifest.get("id", "")),
                title=str(manifest.get("name") or trigger.message),
                trigger=trigger,
                events=scenario.events,
                window_seconds=int(manifest.get("correlation_window_seconds", 300)),
                minimum_score=int(manifest.get("minimum_correlation_score", 2)),
            )
            return self.enrich_case(case)
        raise AlertNotFound(alert_id)
