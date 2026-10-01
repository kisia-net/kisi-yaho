"""Analyst feedback (분석가 판정) and how it reaches the next analysis.

An analyst's verdict on an alert -- confirmed, false positive, or still under
investigation -- is appended to data/analyst_feedback.jsonl from two places:
the alert page after an LLM analysis, and the review of an automatic report.

When ANALYST_FEEDBACK_CONTEXT_ENABLED is on, the next analysis of a *similar*
alert carries up to three earlier verdicts in an `analyst_feedback` block:

- similar means the same rule AND the same host or the same source address;
- only settled verdicts (confirmed, false positive) are used, from the last
  FEEDBACK_MAX_AGE_DAYS days, newest and closest match first;
- the alert itself is never its own precedent.

This is retrieval into the prompt, not fine-tuning: the model's weights do not
change, and removing a record removes its influence immediately.

Guard rails, because a past "false positive" can talk a model out of a real
attack:
- the block is context, never evidence: the prompt forbids citing it and
  forbids lowering severity on precedent alone when the current evidence
  differs (new source, an indicator match, a higher level);
- the deterministic priority (P1-P4) is computed before and without it;
- notes are free text written by people and are passed as untrusted data,
  trimmed, without the reviewer's name.
"""

from __future__ import annotations

import contextlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows development
    fcntl = None  # type: ignore[assignment]

FEEDBACK_SCHEMA = "hawki.analyst-feedback/v1"
# What an analyst can choose. "withdrawn" is recorded when a report is set
# back to unreviewed, so the earlier verdict stops counting.
ANALYST_VERDICTS = ("confirmed", "false_positive", "investigating")
VERDICTS = (*ANALYST_VERDICTS, "withdrawn")
SETTLED_VERDICTS = ("confirmed", "false_positive")
FEEDBACK_MAX_AGE_DAYS = 90
MAX_CONTEXT_ITEMS = 3
MAX_NOTE_CHARS = 1000
MAX_CONTEXT_NOTE_CHARS = 300


def _parse(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def identity(rule_id: Any, host: Any, source_ip: Any) -> dict[str, str]:
    """What makes two alerts 'the same kind of thing' for feedback."""
    return {
        "rule_id": str(rule_id or "").strip()[:200],
        "host": str(host or "").strip()[:200],
        "source_ip": str(source_ip or "").strip()[:64],
    }


class FeedbackStore:
    """Append-only JSONL. The latest verdict for an alert replaces earlier ones."""

    def __init__(self, path: Path):
        self.path = Path(path)

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fcntl is None:
            yield
            return
        with open(self.path.with_suffix(".lock"), "a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def record(
        self,
        *,
        alert_id: str,
        alert: dict[str, str],
        verdict: str,
        note: str,
        reviewer: str,
        source: str,
        now: datetime,
        alert_time: str = "",
        analysis_id: str = "",
        report_id: str = "",
    ) -> dict[str, Any]:
        if verdict not in VERDICTS:
            raise ValueError("Verdict is invalid.")
        entry = {
            "schema": FEEDBACK_SCHEMA,
            "id": f"FB-{now.strftime('%Y%m%d')}-{secrets.token_hex(3)}",
            "recorded_at": now.astimezone(timezone.utc).isoformat(),
            "source": str(source)[:40],
            "alert_id": str(alert_id)[:200],
            "alert_time": str(alert_time or "")[:64],
            **identity(alert.get("rule_id"), alert.get("host"), alert.get("source_ip")),
            "verdict": verdict,
            "note": str(note or "").strip()[:MAX_NOTE_CHARS],
            "reviewer": str(reviewer)[:64],
            "analysis_id": str(analysis_id or "")[:64],
            "report_id": str(report_id or "")[:64],
        }
        with self._lock():
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and value.get("verdict") in VERDICTS:
                    records.append(value)
        return records

    def latest(self) -> list[dict[str, Any]]:
        """One record per alert: the most recent verdict."""
        by_alert: dict[str, dict[str, Any]] = {}
        for record in self.all():
            by_alert[str(record.get("alert_id") or record.get("id"))] = record
        return list(by_alert.values())

    def for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        return [record for record in self.all() if record.get("alert_id") == alert_id]

    def similar(
        self,
        alert: dict[str, str],
        *,
        exclude_alert_id: str,
        now: datetime,
        limit: int = MAX_CONTEXT_ITEMS,
        max_age_days: int = FEEDBACK_MAX_AGE_DAYS,
    ) -> list[dict[str, Any]]:
        """Settled verdicts on the same rule and the same host or source."""
        target = identity(alert.get("rule_id"), alert.get("host"), alert.get("source_ip"))
        if not target["rule_id"]:
            return []
        horizon = now - timedelta(days=max_age_days)
        scored = []
        for record in self.latest():
            if record.get("alert_id") == exclude_alert_id or record.get("verdict") not in SETTLED_VERDICTS:
                continue
            if record.get("rule_id") != target["rule_id"]:
                continue
            reasons = ["same_rule"]
            if target["host"] and record.get("host") == target["host"]:
                reasons.append("same_host")
            if target["source_ip"] and record.get("source_ip") == target["source_ip"]:
                reasons.append("same_source_ip")
            if len(reasons) == 1:
                continue
            when = _parse(record.get("recorded_at"))
            if when is None or when < horizon:
                continue
            scored.append((len(reasons), when, record, reasons))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [{**record, "match": reasons} for _, _, record, reasons in scored[:limit]]


def context_block(matches: list[dict[str, Any]]) -> dict[str, Any]:
    """The block placed in the evidence package. No reviewer names."""
    items = []
    for number, record in enumerate(matches, start=1):
        items.append({
            "feedback_id": f"FB-{number}",
            "verdict": record.get("verdict"),
            "recorded_at": record.get("recorded_at"),
            "past_alert_time": record.get("alert_time") or None,
            "match": list(record.get("match") or []),
            "past_source_ip": record.get("source_ip") or None,
            "note": str(record.get("note") or "")[:MAX_CONTEXT_NOTE_CHARS],
        })
    return {
        "schema": FEEDBACK_SCHEMA,
        "description": (
            "Earlier analyst verdicts on similar alerts (same rule and same host or source). "
            "Human context, not evidence about this alert: do not cite it, and do not lower "
            "severity on precedent alone when the current evidence differs."
        ),
        "items": items,
        "counts": {
            verdict: sum(1 for item in items if item["verdict"] == verdict)
            for verdict in SETTLED_VERDICTS
        },
    }
