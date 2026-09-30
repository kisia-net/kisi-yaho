"""Retrieval profiles for live alert correlation (경보 종류별 상관분석 창).

Every live alert used to get the same evidence net: the same agent, +/- 300
seconds. That net is too short for a brute-force run, which unfolds over tens
of minutes, and too narrow for a web attack, where the network sensor on a
different agent sees the same attacker address.

A profile is picked deterministically from the trigger's Wazuh rule groups and
decoder, never by the model, and it only decides *where to look*: how far back,
how far forward, and whether to look across agents for the same address. What
is kept from that window is still decided by the relevance scoring in
wazuh.get_alert_context.

The first matching profile wins, so the order below goes from most to least
specific.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CorrelationProfile:
    name: str
    description: str
    groups: frozenset[str] = frozenset()
    decoders: frozenset[str] = frozenset()
    seconds_before: int = 300
    seconds_after: int = 300
    # Also pull events from other agents that share the trigger's source
    # address (e.g. Suricata on the sensor for an nginx alert on web-01).
    cross_agent: bool = False

    def matches(self, groups: set[str], decoder: str) -> bool:
        return bool(self.groups & groups) or decoder in self.decoders

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["groups"] = sorted(self.groups)
        data["decoders"] = sorted(self.decoders)
        return data


PROFILES: tuple[CorrelationProfile, ...] = (
    CorrelationProfile(
        name="authentication",
        description=(
            "Password guessing and account abuse build up over tens of minutes; "
            "look back 30 minutes and across agents for the same source."
        ),
        groups=frozenset({
            "authentication_failed", "authentication_failures",
            "authentication_success", "invalid_login", "sshd", "pam",
            "win_authentication_failed",
        }),
        decoders=frozenset({"sshd", "pam"}),
        seconds_before=1800,
        seconds_after=300,
        cross_agent=True,
    ),
    CorrelationProfile(
        name="web_attack",
        description=(
            "Web attacks arrive as short bursts from one address; the WAF, the "
            "access log and the network sensor all see that address, often on "
            "different agents."
        ),
        groups=frozenset({"web", "accesslog", "attack", "modsecurity", "web_scan"}),
        decoders=frozenset({"web-accesslog", "nginx-errorlog", "modsecurity"}),
        seconds_before=600,
        seconds_after=300,
        cross_agent=True,
    ),
    CorrelationProfile(
        name="network_ids",
        description=(
            "An IDS signature marks one flow; the host logs around it on the "
            "target and on the sensor explain what the flow did."
        ),
        # Suricata arrives through the generic "json" decoder, which many
        # other sources share, so only the rule groups identify it.
        groups=frozenset({"ids", "suricata"}),
        seconds_before=300,
        seconds_after=300,
        cross_agent=True,
    ),
    CorrelationProfile(
        name="endpoint_process",
        description=(
            "Process, file and persistence activity on one host: the chain that "
            "led to the alert can start well before it, and it stays on the "
            "same agent."
        ),
        groups=frozenset({
            "sysmon", "sysmon_process", "windows", "syscheck", "rootcheck",
            "audit", "process_creation",
        }),
        decoders=frozenset({"windows_eventchannel", "sysmon-linux"}),
        seconds_before=900,
        seconds_after=300,
        cross_agent=False,
    ),
)


def _groups(trigger: dict[str, Any]) -> set[str]:
    rule = trigger.get("rule") if isinstance(trigger.get("rule"), dict) else {}
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    return {str(item).strip().lower() for item in groups if str(item).strip()}


def _decoder(trigger: dict[str, Any]) -> str:
    decoder = trigger.get("decoder") if isinstance(trigger.get("decoder"), dict) else {}
    # A child decoder carries its family in `parent` (e.g. sshd).
    return str(decoder.get("parent") or decoder.get("name") or "").strip().lower()


def select_profile(trigger: dict[str, Any], *, default_seconds: int) -> CorrelationProfile:
    groups = _groups(trigger)
    decoder = _decoder(trigger)
    for profile in PROFILES:
        if profile.matches(groups, decoder):
            return profile
    return CorrelationProfile(
        name="default",
        description="No specific profile matched; symmetric window on the same agent.",
        seconds_before=default_seconds,
        seconds_after=default_seconds,
        cross_agent=False,
    )
