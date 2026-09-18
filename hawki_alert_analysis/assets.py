"""Asset inventory (자산정보) collection and case enrichment.

This is one of the four metadata blocks delivered to the LLM/SLM. Only the
repository implementation knows where inventory records come from; the rest of
HAW-KI works against `Asset` objects, so a live CMDB, Wazuh agent inventory, or
Wazuh Indexer asset index can replace the file-backed inventory later without
touching the enrichment or bundle code.

Design rule: enrichment attaches business context, it does not infer attack
meaning. "criticality: critical" is inventory truth, not a verdict about the
alert.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Protocol

from .models import CanonicalEvent

# Where an asset value was observed inside the correlated evidence. Roles are
# recorded so the model can tell "the alert is about this host" apart from
# "this host merely appeared as a destination address".
ROLE_EVENT_HOST = "event_host"
ROLE_SOURCE_IP = "source_ip"
ROLE_DESTINATION_IP = "destination_ip"


@dataclass(slots=True)
class Asset:
    id: str
    hostname: str = ""
    fqdn: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    asset_type: str = ""
    environment: str = ""
    zone: str = ""
    exposure: str = ""
    criticality: str = ""
    business_service: str = ""
    owner: str = ""
    operating_system: str = ""
    services: list[str] = field(default_factory=list)
    accounts_of_interest: list[str] = field(default_factory=list)
    data_classification: str = ""
    compliance_scope: list[str] = field(default_factory=list)
    backup_state: str = ""
    patch_state: str = ""
    location: str = ""
    last_inventoried: str = ""
    tags: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def identifiers(self) -> set[str]:
        values = {self.hostname, self.fqdn, *self.ip_addresses}
        return {str(value).strip().lower() for value in values if str(value).strip()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "ip_addresses": self.ip_addresses,
            "asset_type": self.asset_type,
            "environment": self.environment,
            "zone": self.zone,
            "exposure": self.exposure,
            "criticality": self.criticality,
            "business_service": self.business_service,
            "owner": self.owner,
            "operating_system": self.operating_system,
            "services": self.services,
            "accounts_of_interest": self.accounts_of_interest,
            "data_classification": self.data_classification,
            "compliance_scope": self.compliance_scope,
            "backup_state": self.backup_state,
            "patch_state": self.patch_state,
            "location": self.location,
            "last_inventoried": self.last_inventoried,
            "tags": self.tags,
            "inventory_source": self.source,
        }


@dataclass(slots=True)
class AssetMatch:
    """One inventory record resolved from the evidence, with provenance."""

    asset: Asset
    matched_on: list[str] = field(default_factory=list)
    observed_roles: list[str] = field(default_factory=list)
    observed_in: list[str] = field(default_factory=list)
    on_trigger: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.asset.to_dict(),
            "match": {
                "matched_on": self.matched_on,
                "observed_roles": self.observed_roles,
                "observed_in_event_ids": self.observed_in,
                "on_trigger_alert": self.on_trigger,
            },
        }


def asset_from_record(record: dict[str, Any], *, source: str = "") -> Asset:
    def text(key: str) -> str:
        value = record.get(key, "")
        return "" if value is None else str(value)

    def string_list(key: str) -> list[str]:
        value = record.get(key, [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    hostname = text("hostname") or text("name")
    identifier = text("id") or (f"asset-{hostname}" if hostname else "")
    if not identifier:
        raise ValueError("asset record requires an id or hostname")

    return Asset(
        id=identifier,
        hostname=hostname,
        fqdn=text("fqdn"),
        ip_addresses=string_list("ip_addresses") or string_list("ip"),
        asset_type=text("asset_type") or text("type"),
        environment=text("environment"),
        zone=text("zone"),
        exposure=text("exposure"),
        criticality=text("criticality"),
        business_service=text("business_service"),
        owner=text("owner"),
        operating_system=text("operating_system") or text("os"),
        services=string_list("services"),
        accounts_of_interest=string_list("accounts_of_interest"),
        data_classification=text("data_classification"),
        compliance_scope=string_list("compliance_scope"),
        backup_state=text("backup_state"),
        patch_state=text("patch_state"),
        location=text("location"),
        last_inventoried=text("last_inventoried") or text("last_seen"),
        tags=string_list("tags"),
        source=text("inventory_source") or source,
    )


class AssetInventory(Protocol):
    def lookup(self, value: str) -> Asset | None: ...
    def all_assets(self) -> list[Asset]: ...


class FileAssetInventory:
    """Asset inventory backed by JSON files in a directory.

    Each file is either a list of asset records or an object with an `assets`
    array. Unknown fields are ignored so a real CMDB export can be dropped in
    with minimal shaping.
    """

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self._assets: list[Asset] | None = None
        self._index: dict[str, Asset] = {}

    def reload(self) -> None:
        self._assets = None
        self._index = {}

    def _load(self) -> list[Asset]:
        if self._assets is not None:
            return self._assets

        assets: list[Asset] = []
        index: dict[str, Asset] = {}
        if self.root.exists():
            for path in sorted(self.root.glob("*.json")):
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    records, source = payload, path.stem
                elif isinstance(payload, dict):
                    records = payload.get("assets", [])
                    source = str(payload.get("source", path.stem))
                else:
                    continue
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    asset = asset_from_record(record, source=source)
                    assets.append(asset)
                    for identifier in asset.identifiers:
                        # First file wins so an explicit override file can be
                        # ordered ahead of a bulk export.
                        index.setdefault(identifier, asset)

        self._assets = assets
        self._index = index
        return assets

    def lookup(self, value: str) -> Asset | None:
        self._load()
        key = str(value or "").strip().lower()
        return self._index.get(key) if key else None

    def all_assets(self) -> list[Asset]:
        return list(self._load())


class NullAssetInventory:
    """Used when no inventory is configured; keeps call sites uniform."""

    def lookup(self, value: str) -> Asset | None:  # noqa: ARG002
        return None

    def all_assets(self) -> list[Asset]:
        return []


def _observed_values(event: CanonicalEvent) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    if event.host_name:
        values.append((event.host_name, ROLE_EVENT_HOST))
    if event.source_ip:
        values.append((event.source_ip, ROLE_SOURCE_IP))
    if event.destination_ip:
        values.append((event.destination_ip, ROLE_DESTINATION_IP))
    return values


def match_assets(
    inventory: AssetInventory,
    events: Iterable[CanonicalEvent],
    *,
    trigger_id: str = "",
) -> tuple[list[AssetMatch], list[str]]:
    """Resolve inventory records for hosts and addresses seen in the evidence.

    Returns the ordered matches plus the observed identifiers that have no
    inventory record — an unmanaged or unknown host is itself analytically
    relevant, so it is reported rather than silently dropped.
    """
    matches: dict[str, AssetMatch] = {}
    unresolved: dict[str, None] = {}

    for event in events:
        for value, role in _observed_values(event):
            asset = inventory.lookup(value)
            if asset is None:
                unresolved.setdefault(str(value), None)
                continue
            match = matches.get(asset.id)
            if match is None:
                match = AssetMatch(asset=asset)
                matches[asset.id] = match
            if value not in match.matched_on:
                match.matched_on.append(value)
            if role not in match.observed_roles:
                match.observed_roles.append(role)
            if event.id not in match.observed_in:
                match.observed_in.append(event.id)
            if trigger_id and event.id == trigger_id:
                match.on_trigger = True

    ordered = sorted(
        matches.values(),
        # Assets on the triggering alert first, then the most frequently seen.
        key=lambda item: (not item.on_trigger, -len(item.observed_in), item.asset.id),
    )
    return ordered, list(unresolved)
