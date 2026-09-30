"""Automatic analysis and reports for high-level Wazuh alerts (자동 보고서).

A separate worker (``flask --app app auto-report``) runs ``AutoReporter.run_cycle``
once a minute. Each cycle:

1. reads new alerts at or above AUTO_ANALYSIS_MIN_LEVEL since the saved cursor;
2. groups repeats (same rule + source address + host within
   AUTO_ANALYSIS_GROUP_SECONDS) into the report already open for them, so an
   alert storm produces one report with a count, not hundreds;
3. builds the evidence package for the first alert of a group and keeps it
   only if HAW-KI's own deterministic priority is in AUTO_ANALYSIS_BANDS
   (P1, P2) or a live threat-intelligence indicator matched;
4. writes the report at once from deterministic facts: the alert, the
   priority factors, the asset records and the indicator matches. None of it
   needs the model, so a report exists even while the GPU is off;
5. fills the AI section when the model answers, at most
   AUTO_ANALYSIS_MAX_PER_HOUR times an hour, highest priority first. While the
   model is down the section stays "pending"; after
   AUTO_ANALYSIS_PENDING_TTL_SECONDS it is marked expired.

What it never does:
- put a proposed action in the approval queue. Actions are kept in the report
  as suggestions; an analyst queues one from the report page, which goes
  through the same /api/actions/queue check as any other proposal;
- send a result to the red team runner unless AUTO_ANALYSIS_FORWARD_REDTEAM is
  on *and* the runner forwarding itself is on;
- present an AI draft as a finding. Every report starts "unreviewed" and says
  so until an analyst marks it confirmed, false positive or under investigation.

The class takes its collaborators as functions, so the tests drive it without
Wazuh, a model or Flask. app.py supplies the real ones.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .priority import SEVERITY_AS_LEVEL

try:  # POSIX (the containers). Windows development runs one process anyway.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]

AUTO_REPORT_SCHEMA = "hawki.auto-report/v1"
REPORT_ID_PATTERN = re.compile(r"^AR-\d{8}-[0-9a-f]{6}$")

REVIEW_STATUSES = ("unreviewed", "investigating", "confirmed", "false_positive")
AI_STATUSES = ("pending", "completed", "failed", "expired")
VALID_BANDS = ("P1", "P2", "P3", "P4")

# Stored sizes. A report is read on every list request; keep it small.
MAX_GROUP_ALERT_IDS = 50
MAX_EVIDENCE_INDEX = 20
MAX_ANSWER_CHARS = 20000
MAX_NOTE_CHARS = 2000
MAX_SEEN_IDS = 3000
# A storm on one rule/source/host keeps one report for at most this long.
MAX_REPORT_GROUP_SECONDS = 6 * 3600
# Model calls per cycle. A call can take minutes; polling must not wait on a
# long queue of them. The hourly cap still applies on top.
MAX_AI_PER_CYCLE = 3
# Each poll reaches this far behind the cursor: an alert indexed late, with a
# timestamp before alerts already read, is still picked up. Seen ids stop the
# overlap from producing duplicates.
OVERLAP_SECONDS = 120
MAX_STORED_REPORTS = 2000

ACTION_TYPES_FOR_SUGGESTION = {
    "velociraptor_hunt",
    "velociraptor_collection",
    "velociraptor_isolation",
    "velociraptor_remediation",
    "suricata_rule",
    "suricata_rule_disable",
}


class ModelUnavailable(Exception):
    """The model could not be reached. The report waits; nothing is lost."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Wazuh writes +0000 without the colon.
    match = re.match(r"^(.*[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2})(\d{2})$", text)
    if match:
        text = f"{match.group(1)}{match.group(2)}:{match.group(3)}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


# -- Settings -------------------------------------------------------------


def _env_bool(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(env: dict[str, str], name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(str(env.get(name, default)).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


@dataclass(frozen=True)
class AutoReportSettings:
    enabled: bool = False
    min_level: int = 8
    bands: tuple[str, ...] = ("P1", "P2")
    max_ai_per_hour: int = 20
    group_seconds: int = 600
    poll_seconds: int = 60
    lookback_seconds: int = 900
    pending_ttl_seconds: int = 86400
    forward_redteam: bool = False
    max_alerts_per_cycle: int = 200
    max_attempts: int = 3

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "AutoReportSettings":
        env = dict(os.environ if env is None else env)
        bands = tuple(
            band
            for band in (part.strip().upper() for part in str(env.get("AUTO_ANALYSIS_BANDS", "P1,P2")).split(","))
            if band in VALID_BANDS
        )
        return cls(
            enabled=_env_bool(env, "AUTO_ANALYSIS_ENABLED", False),
            min_level=_env_int(env, "AUTO_ANALYSIS_MIN_LEVEL", 8, 0, 15),
            bands=bands or ("P1", "P2"),
            max_ai_per_hour=_env_int(env, "AUTO_ANALYSIS_MAX_PER_HOUR", 20, 0, 120),
            group_seconds=_env_int(env, "AUTO_ANALYSIS_GROUP_SECONDS", 600, 60, 86400),
            poll_seconds=_env_int(env, "AUTO_ANALYSIS_POLL_SECONDS", 60, 15, 3600),
            lookback_seconds=_env_int(env, "AUTO_ANALYSIS_LOOKBACK_SECONDS", 900, 60, 7 * 86400),
            pending_ttl_seconds=_env_int(env, "AUTO_ANALYSIS_PENDING_TTL_SECONDS", 86400, 3600, 7 * 86400),
            forward_redteam=_env_bool(env, "AUTO_ANALYSIS_FORWARD_REDTEAM", False),
        )

    def public(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "min_level": self.min_level,
            "bands": list(self.bands),
            "max_ai_per_hour": self.max_ai_per_hour,
            "group_seconds": self.group_seconds,
            "poll_seconds": self.poll_seconds,
            "pending_ttl_seconds": self.pending_ttl_seconds,
            "forward_redteam": self.forward_redteam,
        }


# -- Reading an alert and its evidence -----------------------------------


def alert_level(item: dict[str, Any]) -> int | None:
    """Wazuh rule level, or the fixture severity placed on the Wazuh scale."""
    try:
        return int(item.get("rule_level"))
    except (TypeError, ValueError):
        severity = str(item.get("severity") or "").lower()
        return SEVERITY_AS_LEVEL.get(severity)


def group_key(item: dict[str, Any]) -> str:
    rule = str(item.get("rule_id") or item.get("title") or "-")[:120]
    source = str(item.get("source_ip") or "-")[:64]
    host = str(item.get("host") or "-")[:120]
    return f"{rule}|{source}|{host}"


def _indicator_expired(record: dict[str, Any], now: datetime) -> bool:
    match = record.get("match") if isinstance(record.get("match"), dict) else {}
    if match.get("indicator_expired") or record.get("expired"):
        return True
    valid_until = parse_time(record.get("valid_until"))
    return bool(valid_until and valid_until < now)


def evidence_facts(bundle: dict[str, Any], item: dict[str, Any], now: datetime) -> dict[str, Any]:
    """The deterministic part of a report, from either bundle schema."""
    schema = str(bundle.get("schema") or "")
    if schema.startswith("hawki.wazuh.live-evidence/"):
        priority = bundle.get("priority") if isinstance(bundle.get("priority"), dict) else {}
        assets = list(((bundle.get("assets") or {}).get("matches")) or [])
        intel = list(((bundle.get("threat_intelligence") or {}).get("matches")) or [])
        index = []
        trigger = bundle.get("trigger") if isinstance(bundle.get("trigger"), dict) else None
        for event in ([trigger] if trigger else []) + list(bundle.get("investigation_context") or []):
            if not isinstance(event, dict):
                continue
            rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
            agent = event.get("agent") if isinstance(event.get("agent"), dict) else {}
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            index.append({
                "evidence_id": str(event.get("evidence_id") or ""),
                "timestamp": str(event.get("timestamp") or ""),
                "host": str(agent.get("name") or ""),
                "rule": " ".join(str(part) for part in (rule.get("id"), rule.get("description")) if part)[:200],
                "level": rule.get("level"),
                "source_ip": str(data.get("srcip") or data.get("src_ip") or ""),
                "log": str(event.get("full_log") or "")[:300],
                "origin": str(((event.get("retrieval") or {}).get("origin")) or ("trigger" if event is trigger else "")),
            })
        retrieval = bundle.get("retrieval") if isinstance(bundle.get("retrieval"), dict) else {}
        profile = retrieval.get("profile") if isinstance(retrieval.get("profile"), dict) else {}
    else:
        priority = item.get("priority") if isinstance(item.get("priority"), dict) else {}
        metadata = bundle.get("metadata") if isinstance(bundle.get("metadata"), dict) else {}
        assets = list(((metadata.get("assets") or {}).get("items")) or [])
        intel = list(((metadata.get("threat_intelligence") or {}).get("items")) or [])
        index = [
            {"evidence_id": f"T{number:02d}", "log": str(line)[:300]}
            for number, line in enumerate(bundle.get("timeline") or [], start=1)
        ]
        profile = {}

    asset_rows = [
        {
            key: asset.get(key)
            for key in ("id", "hostname", "criticality", "exposure", "business_service", "data_classification", "zone")
            if asset.get(key) not in (None, "", [])
        }
        for asset in assets[:5]
        if isinstance(asset, dict)
    ]
    intel_rows = []
    for record in intel[:8]:
        if not isinstance(record, dict):
            continue
        match = record.get("match") if isinstance(record.get("match"), dict) else {}
        intel_rows.append({
            "id": record.get("id"),
            "value": record.get("value") or match.get("matched_value"),
            "type": record.get("type"),
            "verdict": str(record.get("verdict") or "").lower() or None,
            "confidence": record.get("confidence"),
            "feed": record.get("feed") or record.get("source"),
            "on_trigger": bool(match.get("on_trigger_alert", True)),
            "expired": _indicator_expired(record, now),
        })

    return {
        "bundle_schema": schema,
        "priority": {
            "score": priority.get("score"),
            "band": priority.get("band"),
            "primary_asset_id": priority.get("primary_asset_id"),
            "factors": list(priority.get("factors") or [])[:8],
        },
        "assets": asset_rows,
        "threat_intelligence": intel_rows,
        "evidence_index": index[:MAX_EVIDENCE_INDEX],
        "evidence_total": len(index),
        "correlation_profile": {
            key: profile.get(key)
            for key in ("name", "seconds_before", "seconds_after", "cross_agent")
            if key in profile
        },
    }


def selection_reasons(facts: dict[str, Any], settings: AutoReportSettings) -> list[str]:
    """Why this alert gets a report. Empty means it does not."""
    reasons = []
    band = str((facts.get("priority") or {}).get("band") or "")
    if band in settings.bands:
        reasons.append(f"priority_{band}")
    if any(
        not row.get("expired") and row.get("verdict") in {"malicious", "suspicious"}
        for row in facts.get("threat_intelligence") or []
    ):
        reasons.append("threat_intel_match")
    return reasons


def suggested_actions(actions: Any) -> list[dict[str, Any]]:
    """Model-proposed actions, kept as suggestions. Never queued here."""
    suggestions = []
    for action in actions if isinstance(actions, list) else []:
        if not isinstance(action, dict) or action.get("type") not in ACTION_TYPES_FOR_SUGGESTION:
            continue
        suggestions.append({
            "type": action["type"],
            "title": str(action.get("title") or "")[:160],
            "summary": str(action.get("summary") or "")[:1200],
            "risk": str(action.get("risk") or "unknown")[:20],
            "payload": action.get("payload") if isinstance(action.get("payload"), dict) else {},
            "requires_approval": True,
            "queued": False,
        })
    return suggestions[:6]


# -- Storage --------------------------------------------------------------


class ReportStore:
    """One JSON file per report plus the worker state, in data/auto_reports.

    The web app (review updates) and the worker (new reports, AI results) both
    write here, so every write goes through one file lock and an atomic rename.
    """

    def __init__(self, root: Path, *, max_reports: int = MAX_STORED_REPORTS):
        self.root = Path(root)
        self.max_reports = max_reports

    @contextlib.contextmanager
    def lock(self, name: str = ".store.lock", *, blocking: bool = True) -> Iterator[bool]:
        self.root.mkdir(parents=True, exist_ok=True)
        if fcntl is None:
            yield True
            return
        with open(self.root / name, "a+", encoding="utf-8") as handle:
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(handle.fileno(), flags)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _write(self, path: Path, value: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(temporary, path)

    @staticmethod
    def _read(path: Path) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def path_for(self, report_id: str) -> Path:
        if not REPORT_ID_PATTERN.match(str(report_id or "")):
            raise ValueError("Report ID is invalid.")
        return self.root / f"{report_id}.json"

    def new_id(self, now: datetime) -> str:
        return f"AR-{now.strftime('%Y%m%d')}-{secrets.token_hex(3)}"

    def save(self, report: dict[str, Any]) -> None:
        with self.lock():
            self._write(self.path_for(report["id"]), report)

    def get(self, report_id: str) -> dict[str, Any] | None:
        try:
            path = self.path_for(report_id)
        except ValueError:
            return None
        return self._read(path)

    def update(self, report_id: str, change: Callable[[dict[str, Any]], None]) -> dict[str, Any] | None:
        with self.lock():
            path = self.path_for(report_id)
            report = self._read(path)
            if report is None:
                return None
            change(report)
            self._write(path, report)
            return report

    def all(self) -> list[dict[str, Any]]:
        if not self.root.is_dir():
            return []
        reports = [
            report
            for report in (self._read(path) for path in self.root.glob("AR-*.json"))
            if report is not None
        ]
        reports.sort(key=lambda report: str(report.get("created_at") or ""), reverse=True)
        return reports

    def prune(self) -> int:
        """Drop the oldest reports beyond the stored limit."""
        reports = self.all()
        removed = 0
        with self.lock():
            for report in reports[self.max_reports:]:
                with contextlib.suppress(OSError, ValueError):
                    self.path_for(report["id"]).unlink()
                    removed += 1
        return removed

    def load_state(self) -> dict[str, Any]:
        return self._read(self.root / "state.json") or {}

    def save_state(self, state: dict[str, Any]) -> None:
        with self.lock():
            self._write(self.root / "state.json", state)


def report_summary(report: dict[str, Any]) -> dict[str, Any]:
    alert = report.get("alert") or {}
    ai = report.get("ai") or {}
    return {
        "id": report.get("id"),
        "created_at": report.get("created_at"),
        "updated_at": report.get("updated_at"),
        "alert_id": alert.get("id"),
        "alert_time": alert.get("time"),
        "title": alert.get("title"),
        "host": alert.get("host"),
        "source_ip": alert.get("source_ip"),
        "rule_id": alert.get("rule_id"),
        "level": alert.get("level"),
        "priority": {key: (report.get("priority") or {}).get(key) for key in ("score", "band")},
        "reasons": (report.get("selection") or {}).get("reasons") or [],
        "occurrences": (report.get("group") or {}).get("occurrences", 1),
        "ai_status": ai.get("status"),
        "ai_waiting": ai.get("waiting_reason"),
        "review_status": (report.get("review") or {}).get("status", "unreviewed"),
        # Indicators that count against the alert: live, malicious or suspicious.
        "intel_matches": sum(
            1
            for row in report.get("threat_intelligence") or []
            if not row.get("expired") and row.get("verdict") in {"malicious", "suspicious"}
        ),
    }


# -- The worker cycle -----------------------------------------------------


@dataclass
class AutoReporter:
    settings: AutoReportSettings
    store: ReportStore
    fetch_alerts: Callable[[datetime, int, int], list[dict[str, Any]]]
    build_bundle: Callable[[dict[str, Any]], dict[str, Any]]
    model_available: Callable[[], bool]
    analyze: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    audit: Callable[[str, dict[str, Any]], None] = lambda event, detail: None
    forward: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], str] | None = None
    clock: Callable[[], datetime] = utcnow
    _bundles: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def run_cycle(self, *, lookback_seconds: int | None = None) -> dict[str, Any]:
        with self.store.lock(".cycle.lock", blocking=False) as acquired:
            if not acquired:
                return {"skipped": "busy"}
            return self._run_cycle(lookback_seconds)

    def _run_cycle(self, lookback_seconds: int | None) -> dict[str, Any]:
        now = self.clock()
        state = self.store.load_state()
        summary: dict[str, Any] = {
            "started_at": iso(now),
            "enabled": self.settings.enabled,
            "alerts_read": 0,
            "reports_created": 0,
            "grouped": 0,
            "not_selected": 0,
            "errors": 0,
            "ai_completed": 0,
            "ai_pending": 0,
            "model_available": None,
        }
        state["heartbeat_at"] = iso(now)
        if not self.settings.enabled:
            state.update({"last_cycle_at": iso(now), "last_summary": summary})
            self.store.save_state(state)
            return summary

        self._bundles = {}
        self._collect(state, now, summary, lookback_seconds)
        # Saved before any model call: a restart during the AI step must not
        # read the same alerts again and write duplicate reports.
        self.store.save_state(state)
        self._fill_ai(state, now, summary)
        self.store.prune()

        state.update({"last_cycle_at": iso(self.clock()), "heartbeat_at": iso(self.clock()), "last_summary": summary})
        self.store.save_state(state)
        return summary

    def _fetch(self, cursor: datetime) -> list[dict[str, Any]]:
        """New alerts from the cursor on, plus a short look behind it.

        The main read starts at the cursor, so it always moves forward even
        when an alert storm fills a whole page. The second, smaller read
        catches alerts indexed late with an earlier timestamp.
        """
        limit = self.settings.max_alerts_per_cycle * 2
        fresh = self.fetch_alerts(cursor, self.settings.min_level, limit)
        late = self.fetch_alerts(cursor - timedelta(seconds=OVERLAP_SECONDS), self.settings.min_level, limit)
        merged: dict[str, dict[str, Any]] = {}
        for item in [*late, *fresh]:
            alert_id = str(item.get("id") or "")
            if alert_id:
                merged[alert_id] = item
        return sorted(merged.values(), key=lambda item: parse_time(item.get("time")) or cursor)

    # Step 1-4: read, group, select, write.
    def _collect(self, state: dict[str, Any], now: datetime, summary: dict[str, Any], lookback: int | None) -> None:
        settings = self.settings
        cursor = parse_time(state.get("cursor"))
        if cursor is None or lookback is not None:
            cursor = now - timedelta(seconds=lookback if lookback is not None else settings.lookback_seconds)
        seen = [str(value) for value in state.get("seen_ids") or []][-MAX_SEEN_IDS:]
        seen_set = set(seen)
        groups: dict[str, dict[str, Any]] = dict(state.get("groups") or {})
        occurrences: dict[str, list[tuple[dict[str, Any], datetime]]] = {}

        try:
            alerts = self._fetch(cursor)
        except Exception as exc:  # noqa: BLE001 - one bad poll must not stop the worker
            summary["errors"] += 1
            summary["fetch_error"] = str(exc)[:300]
            self.audit("auto_report_fetch_failed", {"error": str(exc)[:300]})
            return

        processed = 0
        for item in alerts:
            alert_id = str(item.get("id") or "")
            when = parse_time(item.get("time")) or now
            if not alert_id or alert_id in seen_set:
                cursor = max(cursor, when)
                continue
            if processed >= settings.max_alerts_per_cycle:
                break  # the rest are read next cycle; the cursor stays before them
            processed += 1
            seen.append(alert_id)
            seen_set.add(alert_id)
            cursor = max(cursor, when)

            level = alert_level(item)
            if level is None or level < settings.min_level:
                continue
            summary["alerts_read"] += 1

            key = group_key(item)
            group = groups.get(key)
            if group and self._joins_group(group, when):
                last_seen = parse_time(group.get("last_seen")) or when
                group["last_seen"] = iso(max(when, last_seen))
                if group.get("report_id"):
                    occurrences.setdefault(group["report_id"], []).append((item, when))
                    summary["grouped"] += 1
                else:
                    summary["not_selected"] += 1
                continue

            try:
                bundle = self.build_bundle(item)
                facts = evidence_facts(bundle, item, now)
            except Exception as exc:  # noqa: BLE001 - a bad alert must not stop the others
                summary["errors"] += 1
                self.audit("auto_report_bundle_failed", {"alert_id": alert_id, "error": str(exc)[:300]})
                continue

            reasons = selection_reasons(facts, settings)
            if not reasons:
                groups[key] = {"report_id": None, "first_seen": iso(when), "last_seen": iso(when)}
                summary["not_selected"] += 1
                continue

            report = self._new_report(item, level, facts, reasons, key, when, now)
            self.store.save(report)
            self._bundles[report["id"]] = bundle
            groups[key] = {"report_id": report["id"], "first_seen": iso(when), "last_seen": iso(when)}
            summary["reports_created"] += 1
            self.audit("auto_report_created", {
                "report_id": report["id"],
                "alert_id": alert_id,
                "priority": report["priority"].get("band"),
                "score": report["priority"].get("score"),
                "reasons": reasons,
            })

        # One write per report, however many repeats arrived.
        for report_id, items in occurrences.items():
            self._add_occurrences(report_id, items, now)

        # Groups end when their window has passed; the map stays small.
        horizon = now - timedelta(seconds=max(settings.group_seconds * 2, MAX_REPORT_GROUP_SECONDS))
        state["groups"] = {
            key: value
            for key, value in groups.items()
            if (parse_time(value.get("last_seen")) or now) >= horizon
        }
        state["cursor"] = iso(cursor)
        state["seen_ids"] = seen[-MAX_SEEN_IDS:]

    def _joins_group(self, group: dict[str, Any], when: datetime) -> bool:
        """A repeat joins while it is close to the last one.

        A reported group keeps growing for up to MAX_REPORT_GROUP_SECONDS, then
        a fresh report starts. A group that was not selected is looked at again
        after one window, since its intelligence or inventory may have changed.
        """
        last_seen = parse_time(group.get("last_seen"))
        first_seen = parse_time(group.get("first_seen")) or last_seen
        if last_seen is None or abs((when - last_seen).total_seconds()) > self.settings.group_seconds:
            return False
        lifetime = MAX_REPORT_GROUP_SECONDS if group.get("report_id") else self.settings.group_seconds
        return (when - first_seen).total_seconds() <= lifetime

    def _new_report(
        self,
        item: dict[str, Any],
        level: int,
        facts: dict[str, Any],
        reasons: list[str],
        key: str,
        when: datetime,
        now: datetime,
    ) -> dict[str, Any]:
        return {
            "schema": AUTO_REPORT_SCHEMA,
            "id": self.store.new_id(now),
            "created_at": iso(now),
            "updated_at": iso(now),
            "notice": "AI draft; an analyst has to review it before it is treated as a finding.",
            "alert": {
                "id": str(item.get("id") or ""),
                "index": str(item.get("index") or ""),
                "time": str(item.get("time") or ""),
                "title": str(item.get("title") or "")[:300],
                "summary": str(item.get("summary") or "")[:500],
                "host": str(item.get("host") or ""),
                "agent_ip": str(item.get("agent_ip") or ""),
                "source_ip": str(item.get("source_ip") or ""),
                "rule_id": str(item.get("rule_id") or ""),
                "level": level,
                "mitre": str(item.get("mitre") or ""),
                "groups": [str(value) for value in (item.get("groups") or [])][:10],
            },
            "selection": {"min_level": self.settings.min_level, "bands": list(self.settings.bands), "reasons": reasons},
            "group": {
                "key": key,
                "first_seen": iso(when),
                "last_seen": iso(when),
                "occurrences": 1,
                "alert_ids": [str(item.get("id") or "")],
            },
            "priority": facts["priority"],
            "assets": facts["assets"],
            "threat_intelligence": facts["threat_intelligence"],
            "evidence": {
                "bundle_schema": facts["bundle_schema"],
                "index": facts["evidence_index"],
                "total": facts["evidence_total"],
                "correlation_profile": facts["correlation_profile"],
            },
            "ai": {"status": "pending", "attempts": 0},
            "review": {"status": "unreviewed"},
            "redteam": "not_sent",
        }

    def _add_occurrences(
        self,
        report_id: str,
        items: list[tuple[dict[str, Any], datetime]],
        now: datetime,
    ) -> None:
        def change(report: dict[str, Any]) -> None:
            group = report.setdefault("group", {})
            group["occurrences"] = int(group.get("occurrences") or 1) + len(items)
            ids = list(group.get("alert_ids") or [])
            for item, _ in items:
                if len(ids) >= MAX_GROUP_ALERT_IDS:
                    break
                ids.append(str(item.get("id") or ""))
            group["alert_ids"] = ids
            latest = max(when for _, when in items)
            last = parse_time(group.get("last_seen"))
            group["last_seen"] = iso(max(latest, last) if last else latest)
            report["updated_at"] = iso(now)

        self.store.update(report_id, change)

    # Step 5: the AI section.
    def _fill_ai(self, state: dict[str, Any], now: datetime, summary: dict[str, Any]) -> None:
        settings = self.settings
        hour_ago = now - timedelta(hours=1)
        started = [
            moment
            for moment in (parse_time(value) for value in state.get("ai_started") or [])
            if moment and moment >= hour_ago
        ]

        pending = [report for report in self.store.all() if (report.get("ai") or {}).get("status") == "pending"]
        waiting = []
        for report in pending:
            created = parse_time(report.get("created_at")) or now
            if (now - created).total_seconds() > settings.pending_ttl_seconds:
                self.store.update(report["id"], lambda r: r["ai"].update({"status": "expired", "waiting_reason": None}))
                self.audit("auto_report_ai_expired", {"report_id": report["id"]})
            else:
                waiting.append(report)

        # Highest priority first, then oldest.
        waiting.sort(key=lambda r: (-int((r.get("priority") or {}).get("score") or 0), str(r.get("created_at") or "")))
        summary["ai_pending"] = len(waiting)
        if not waiting:
            state["ai_started"] = [iso(moment) for moment in started]
            return

        available = self._model_available()
        summary["model_available"] = available
        if not available:
            for report in waiting:
                self._set_waiting(report["id"], "model_unavailable")
            state["ai_started"] = [iso(moment) for moment in started]
            return

        this_cycle = 0
        for position, report in enumerate(waiting):
            if len(started) >= settings.max_ai_per_hour:
                self._set_waiting(report["id"], "rate_limit")
                continue
            if this_cycle >= MAX_AI_PER_CYCLE:
                self._set_waiting(report["id"], "queued")
                continue
            this_cycle += 1
            started.append(self.clock())
            outcome = self._analyze_report(report, now)
            # A model call can take minutes: record progress as it happens,
            # so the hourly count survives a restart and the worker looks alive.
            state["ai_started"] = [iso(moment) for moment in started]
            state["heartbeat_at"] = iso(self.clock())
            self.store.save_state(state)
            if outcome == "completed":
                summary["ai_completed"] += 1
                summary["ai_pending"] -= 1
            elif outcome == "model_unavailable":
                for rest in waiting[position + 1:]:
                    self._set_waiting(rest["id"], "model_unavailable")
                break
            elif outcome == "failed":
                summary["ai_pending"] -= 1

        state["ai_started"] = [iso(moment) for moment in started]

    def _model_available(self) -> bool:
        try:
            return bool(self.model_available())
        except Exception:  # noqa: BLE001
            return False

    def _set_waiting(self, report_id: str, reason: str) -> None:
        self.store.update(report_id, lambda r: r["ai"].update({"waiting_reason": reason}))

    def _analyze_report(self, report: dict[str, Any], now: datetime) -> str:
        report_id = report["id"]
        alert = report.get("alert") or {}
        attempts = int((report.get("ai") or {}).get("attempts") or 0) + 1

        try:
            bundle = self._bundles.get(report_id) or self.build_bundle(alert)
            result = self.analyze(bundle, alert)
        except ModelUnavailable as exc:
            # Counted like any failure, so one report the model keeps timing
            # out on cannot hold the queue until it expires.
            give_up = attempts >= self.settings.max_attempts
            self.store.update(report_id, lambda r: r["ai"].update({
                "status": "failed" if give_up else "pending",
                "attempts": attempts,
                "waiting_reason": None if give_up else "model_unavailable",
                "last_error": str(exc)[:300],
            }))
            if give_up:
                self.audit("auto_report_ai_failed", {"report_id": report_id, "attempts": attempts, "error": str(exc)[:300]})
            return "failed" if give_up else "model_unavailable"
        except Exception as exc:  # noqa: BLE001
            status = "failed" if attempts >= self.settings.max_attempts else "pending"
            self.store.update(report_id, lambda r: r["ai"].update({
                "status": status,
                "attempts": attempts,
                "waiting_reason": None if status == "failed" else "retry",
                "last_error": str(exc)[:300],
            }))
            self.audit("auto_report_ai_failed", {"report_id": report_id, "attempts": attempts, "error": str(exc)[:300]})
            return status

        facts = evidence_facts(bundle, alert, now)
        redteam = "not_sent"
        if self.settings.forward_redteam and self.forward is not None:
            try:
                redteam = self.forward(bundle, alert, result)
            except Exception as exc:  # noqa: BLE001
                redteam = f"error: {str(exc)[:120]}"

        def change(r: dict[str, Any]) -> None:
            r["ai"] = {
                "status": "completed",
                "attempts": attempts,
                "completed_at": iso(self.clock()),
                "model": result.get("model"),
                "analysis_id": result.get("analysis_id"),
                "hashes": result.get("hashes") or {},
                "answer": str(result.get("answer") or "")[:MAX_ANSWER_CHARS],
                "assessment": result.get("assessment") if isinstance(result.get("assessment"), dict) else None,
                "assessment_review": result.get("assessment_review") if isinstance(result.get("assessment_review"), dict) else None,
                "evidence": [str(value)[:400] for value in (result.get("evidence") or [])][:12],
                "queries": [value for value in (result.get("queries") or []) if isinstance(value, dict)][:6],
                "suggested_actions": suggested_actions(result.get("actions")),
            }
            # The evidence the model actually saw, which may be newer than at creation.
            r["evidence"] = {
                "bundle_schema": facts["bundle_schema"],
                "index": facts["evidence_index"],
                "total": facts["evidence_total"],
                "correlation_profile": facts["correlation_profile"],
            }
            r["redteam"] = redteam
            r["updated_at"] = iso(self.clock())

        self.store.update(report_id, change)
        self.audit("auto_report_analyzed", {
            "report_id": report_id,
            "alert_id": alert.get("id"),
            "analysis_id": result.get("analysis_id"),
            "model": result.get("model"),
            "redteam": redteam,
        })
        return "completed"


# -- Review and export ----------------------------------------------------


def apply_review(report: dict[str, Any], *, status: str, note: str, reviewer: str, now: datetime) -> None:
    if status not in REVIEW_STATUSES:
        raise ValueError("Review status is invalid.")
    history = list((report.get("review") or {}).get("history") or [])[-19:]
    entry = {"status": status, "note": str(note or "")[:MAX_NOTE_CHARS], "reviewer": reviewer, "at": iso(now)}
    history.append(entry)
    report["review"] = {**entry, "history": history}
    report["updated_at"] = iso(now)


FACTOR_LABELS = {
    "wazuh_rule_level": "Wazuh 룰 레벨",
    "source_severity": "원본 심각도",
    "asset_criticality": "자산 중요도",
    "asset_exposure": "자산 노출도",
    "asset_data_classification": "민감 데이터",
    "asset_not_in_inventory": "자산 목록에 없음",
    "threat_intel_match": "위협 인텔리전스 일치",
}
REASON_LABELS = {
    "priority_P1": "우선순위 P1",
    "priority_P2": "우선순위 P2",
    "priority_P3": "우선순위 P3",
    "priority_P4": "우선순위 P4",
    "threat_intel_match": "위협 인텔리전스 일치",
}
REVIEW_LABELS = {
    "unreviewed": "검토 전",
    "investigating": "추가 조사",
    "confirmed": "확인됨",
    "false_positive": "오탐",
}
AI_LABELS = {
    "pending": "AI 분석 대기",
    "completed": "AI 분석 완료",
    "failed": "AI 분석 실패",
    "expired": "AI 분석 만료",
}
VERDICT_LABELS = {"malicious": "악성", "suspicious": "의심", "benign": "정상", "unknown": "알 수 없음"}
WAITING_LABELS = {
    "model_unavailable": "모델 꺼짐",
    "rate_limit": "시간당 상한",
    "queued": "다음 차례",
    "retry": "재시도 예정",
}


def _cell(value: Any) -> str:
    return str(value if value not in (None, "") else "—").replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    """The report as a Markdown document for download or printing."""
    alert = report.get("alert") or {}
    priority = report.get("priority") or {}
    review = report.get("review") or {}
    ai = report.get("ai") or {}
    group = report.get("group") or {}
    evidence = report.get("evidence") or {}
    lines: list[str] = []
    add = lines.append

    add(f"# 자동 분석 보고서 {report.get('id')}")
    add("")
    add(f"> **AI 초안 · 분석가 검토 필요** — 검토 상태: {REVIEW_LABELS.get(review.get('status'), '검토 전')}")
    add("")
    add(f"- 작성: {report.get('created_at')} (HAW-KI 자동 분석)")
    add(f"- 우선순위: **{priority.get('band') or '—'}** ({priority.get('score') if priority.get('score') is not None else '—'}점)")
    add(f"- 선정 이유: {', '.join(REASON_LABELS.get(r, r) for r in (report.get('selection') or {}).get('reasons') or []) or '—'}")
    add("")

    add("## 1. 경보")
    add("")
    add("| 항목 | 값 |")
    add("|---|---|")
    for label, value in (
        ("경보 ID", alert.get("id")),
        ("발생 시각", alert.get("time")),
        ("룰", f"{alert.get('rule_id') or ''} {alert.get('title') or ''}".strip()),
        ("레벨", alert.get("level")),
        ("호스트", alert.get("host")),
        ("출발지 IP", alert.get("source_ip")),
        ("MITRE ATT&CK", alert.get("mitre")),
        ("요약", alert.get("summary")),
    ):
        add(f"| {label} | {_cell(value)} |")
    add("")
    if int(group.get("occurrences") or 1) > 1:
        add(f"같은 룰·출발지·호스트로 **{group.get('occurrences')}건** 반복 발생 ({group.get('first_seen')} ~ {group.get('last_seen')}).")
        add("")

    add("## 2. 우선순위 근거 (코드로 계산, 모델이 바꿀 수 없음)")
    add("")
    add("| 요인 | 값 | 점수 |")
    add("|---|---|---|")
    for factor in priority.get("factors") or []:
        add(f"| {_cell(FACTOR_LABELS.get(factor.get('factor'), factor.get('factor')))} | {_cell(factor.get('value'))} | {_cell(factor.get('points'))} |")
    add("")

    add("## 3. 자산")
    add("")
    assets = report.get("assets") or []
    if assets:
        add("| 자산 | 중요도 | 노출도 | 서비스 |")
        add("|---|---|---|---|")
        for asset in assets:
            add(f"| {_cell(asset.get('hostname') or asset.get('id'))} | {_cell(asset.get('criticality'))} | {_cell(asset.get('exposure'))} | {_cell(asset.get('business_service'))} |")
    else:
        add("자산 목록에서 찾은 기록이 없습니다. 자산 중요도는 알 수 없습니다.")
    add("")

    add("## 4. 위협 인텔리전스")
    add("")
    intel = report.get("threat_intelligence") or []
    if intel:
        add("| 지표 | 판정 | 신뢰도 | 출처 | 경보 자체 | 만료 |")
        add("|---|---|---|---|---|---|")
        for row in intel:
            add(f"| {_cell(row.get('value'))} | {_cell(VERDICT_LABELS.get(row.get('verdict'), row.get('verdict')))} | {_cell(row.get('confidence'))} | {_cell(row.get('feed'))} | {'예' if row.get('on_trigger') else '맥락에서만'} | {'예' if row.get('expired') else '아니오'} |")
        add("")
        add("지표 일치는 외부 맥락입니다. 침해를 증명하지 않습니다.")
    else:
        add("일치한 지표가 없습니다. 일치가 없다고 안전하다는 뜻은 아닙니다.")
    add("")

    add("## 5. AI 분석")
    add("")
    if ai.get("status") == "completed":
        add(f"_모델: {ai.get('model') or '—'} · 분석 ID: {ai.get('analysis_id') or '—'} · 완료: {ai.get('completed_at') or '—'}_")
        add("")
        add(str(ai.get("answer") or "반환된 분석 결과가 없습니다."))
    else:
        label = AI_LABELS.get(ai.get("status"), "AI 분석 대기")
        waiting = WAITING_LABELS.get(ai.get("waiting_reason") or "", "")
        add(f"{label}{f' ({waiting})' if waiting else ''}. 위의 1~4절은 모델 없이 계산한 사실입니다.")
    add("")

    actions = ai.get("suggested_actions") or []
    add("## 6. 제안 조치 (실행되지 않음 · 승인 필요)")
    add("")
    if actions:
        for action in actions:
            add(f"- **{action.get('title') or action.get('type')}** (`{action.get('type')}`, 위험도 {action.get('risk')}): {action.get('summary') or ''}")
    else:
        add("제안된 조치가 없습니다.")
    add("")

    add("## 7. 증거 목록")
    add("")
    index = evidence.get("index") or []
    if index:
        add("| ID | 시각 | 호스트 | 룰 | 내용 |")
        add("|---|---|---|---|---|")
        for row in index:
            add(f"| {_cell(row.get('evidence_id'))} | {_cell(row.get('timestamp'))} | {_cell(row.get('host'))} | {_cell(row.get('rule'))} | {_cell((row.get('log') or '')[:160])} |")
        if int(evidence.get("total") or 0) > len(index):
            add("")
            add(f"(전체 {evidence.get('total')}건 중 {len(index)}건 표시)")
    else:
        add("저장된 증거 목록이 없습니다.")
    add("")

    add("## 8. 검토 기록")
    add("")
    history = review.get("history") or []
    if history:
        for entry in history:
            note = f" — {entry.get('note')}" if entry.get("note") else ""
            add(f"- {entry.get('at')} · {entry.get('reviewer')} · {REVIEW_LABELS.get(entry.get('status'), entry.get('status'))}{note}")
    else:
        add("아직 검토하지 않았습니다.")
    add("")

    hashes = ai.get("hashes") or {}
    add("---")
    add("")
    add(f"추적 정보: 보고서 스키마 `{report.get('schema')}` · 증거 스키마 `{evidence.get('bundle_schema') or '—'}`"
        f" · prompt `{str(hashes.get('prompt_sha256') or '—')[:16]}` · bundle `{str(hashes.get('bundle_sha256') or '—')[:16]}`"
        f" · 레드팀 `{report.get('redteam') or 'not_sent'}`")
    add("")
    return "\n".join(lines)
