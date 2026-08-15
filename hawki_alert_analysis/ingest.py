"""Turn a directory of collected logs into a scenario manifest.

This is the bridge between real collected telemetry and the alert-analysis
engine. Point it at Suricata output from a PCAP replay, an AIT-LDS host
directory, or anything else the adapters understand, and it writes the
`scenario.json` the repository already reads.

Two modes:

- auto: detect source types from filenames and contents, then select the
  highest-severity alert as the trigger.
- labelled: read a label file naming the trigger and the correlation window,
  for datasets that ship ground truth.

Detection reports what it did and what it could not classify. A file the
adapters cannot read is named in the result rather than skipped quietly,
because a source silently missing from a case looks identical to a source that
genuinely had nothing in it.

Run as:

    python -m hawki_alert_analysis.ingest <log-dir> --out data/scenarios/<name>
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import SYSLOG_LINE
from .models import CanonicalEvent
from .repository import ADAPTERS, TEXT_LINE_SOURCES

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Filename hints, checked before content sniffing. The first hint whose token
# appears in the lowercased filename wins, so producer names come before
# generic format names: apache_access.log is Apache, not "some access log".
NAME_HINTS = (
    ("eve", "suricata"),
    ("suricata", "suricata"),
    ("sysmon", "sysmon"),
    ("wazuh", "wazuh"),
    ("alerts.json", "wazuh"),
    ("apache", "apache"),
    ("httpd", "apache"),
    ("nginx", "nginx"),
    ("auth.log", "authlog"),
    ("secure", "authlog"),
    ("syslog", "syslog"),
    ("messages", "syslog"),
    ("audit", "syslog"),
    # Generic combined-format fallbacks, attributed to Nginx only because a
    # producer has to be named; the raw line is preserved either way.
    ("access.log", "nginx"),
    ("access-", "nginx"),
)

SKIP_NAMES = {"scenario.json", "labels.json", "readme", "readme.md"}


@dataclass
class DetectedSource:
    path: Path
    source_type: str
    reason: str
    sample_ok: bool = True
    detail: str = ""

    def to_manifest_entry(self, defaults: dict[str, Any]) -> dict[str, Any]:
        entry: dict[str, Any] = {"type": self.source_type, "path": self.path.name}
        if defaults:
            entry["defaults"] = dict(defaults)
        return entry


@dataclass
class IngestResult:
    sources: list[DetectedSource] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    alert_count: int = 0
    event_count: int = 0

    def summary(self) -> str:
        lines = [
            f"{len(self.sources)} source(s) detected, "
            f"{self.event_count} events, {self.alert_count} alerts"
        ]
        for source in self.sources:
            note = "" if source.sample_ok else f"  [unreadable: {source.detail}]"
            lines.append(f"  {source.path.name:<28} -> {source.source_type:<9} ({source.reason}){note}")
        for name in self.unclassified:
            lines.append(f"  {name:<28} -> skipped (no adapter matched)")
        return "\n".join(lines)


def _first_lines(path: Path, count: int = 5) -> list[str]:
    lines: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
                if len(lines) >= count:
                    break
    except OSError:
        return []
    return lines


def sniff_source_type(path: Path) -> tuple[str, str]:
    """Identify a log file's producer. Returns (source_type, reason)."""
    lowered = path.name.lower()
    for token, source_type in NAME_HINTS:
        if token in lowered:
            return source_type, f"filename contains {token!r}"

    lines = _first_lines(path)
    if not lines:
        return "", "file is empty"

    first = lines[0]
    if first.startswith("{"):
        try:
            payload = json.loads(first)
        except json.JSONDecodeError:
            return "", "first line is not valid JSON"
        if not isinstance(payload, dict):
            return "", "JSON line is not an object"
        if "event_type" in payload or "flow_id" in payload:
            return "suricata", "JSON carries Suricata EVE fields"
        if "rule" in payload and "agent" in payload:
            return "wazuh", "JSON carries Wazuh alert fields"
        # Checked before ECS: Winlogbeat-shaped Sysmon also carries @timestamp,
        # and the Sysmon adapter reads the Windows fields the ECS one drops.
        if "winlog" in payload or "EventID" in payload or "EventId" in payload:
            return "sysmon", "JSON carries Windows event fields"
        if isinstance(payload.get("Event"), dict) and "System" in payload["Event"]:
            return "sysmon", "JSON carries nested Windows Event/System fields"
        if "@timestamp" in payload or "event" in payload:
            return "ecs", "JSON looks ECS-shaped"
        return "", "JSON object matched no known producer"

    if SYSLOG_LINE.match(first):
        return "syslog", "line matches RFC 3164 syslog"
    if '"' in first and ("HTTP/" in first or " GET " in first or " POST " in first):
        return "nginx", "line matches combined access log"
    return "", "no adapter recognized the first line"


def _probe(path: Path, source_type: str) -> tuple[bool, str]:
    """Confirm the chosen adapter can actually read the file's first line."""
    adapter = ADAPTERS.get(source_type)
    if adapter is None:
        return False, f"no adapter registered for {source_type!r}"
    lines = _first_lines(path, 1)
    if not lines:
        return False, "file is empty"
    row: Any = lines[0]
    if source_type not in TEXT_LINE_SOURCES:
        try:
            row = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            return False, f"invalid JSON: {exc}"
    try:
        adapter.normalize(row, scenario_id="probe", defaults={"year": 2026})
    except Exception as exc:  # noqa: BLE001 - report any adapter rejection
        return False, str(exc)
    return True, ""


def detect_sources(log_dir: Path) -> tuple[list[DetectedSource], list[str]]:
    detected: list[DetectedSource] = []
    unclassified: list[str] = []
    for path in sorted(log_dir.iterdir()):
        if not path.is_file() or path.name.lower() in SKIP_NAMES or path.name.startswith("."):
            continue
        source_type, reason = sniff_source_type(path)
        if not source_type:
            unclassified.append(f"{path.name} ({reason})")
            continue
        ok, detail = _probe(path, source_type)
        if not ok:
            unclassified.append(f"{path.name} ({detail})")
            continue
        detected.append(DetectedSource(path=path, source_type=source_type, reason=reason))
    return detected, unclassified


def _load_labels(path: Path | None) -> dict[str, Any]:
    """Read an optional ground-truth file.

    Expected shape, which any dataset's own label format can be mapped onto:

        {
          "id": "AIT-LDS-...",
          "name": "...",
          "trigger": {"source_type": "suricata", "kind": "alert", "rule_id": "2100001"},
          "correlation_window_seconds": 300,
          "expected": {
             "attack_techniques": ["T1190"],
             "affected_hosts": ["web-01"],
             "answers": [{"question": "...", "expect": ["..."]}]
          }
        }

    Only `trigger` changes how the case is assembled. Everything under
    `expected` is carried through untouched for the evaluation harness.
    """
    if path is None:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def build_manifest(
    log_dir: Path,
    *,
    scenario_id: str,
    name: str = "",
    labels: dict[str, Any] | None = None,
    host_name: str = "",
    year: int | None = None,
    correlation_window_seconds: int = 300,
) -> IngestResult:
    labels = labels or {}
    detected, unclassified = detect_sources(log_dir)

    defaults: dict[str, Any] = {}
    if host_name:
        defaults["host_name"] = host_name
    if year:
        defaults["year"] = year

    manifest: dict[str, Any] = {
        "id": labels.get("id") or scenario_id,
        "name": labels.get("name") or name or scenario_id,
        "description": labels.get("description")
        or f"Ingested from {log_dir.name} by hawki_alert_analysis.ingest.",
        "correlation_window_seconds": int(
            labels.get("correlation_window_seconds") or correlation_window_seconds
        ),
        "minimum_correlation_score": int(labels.get("minimum_correlation_score") or 2),
        "sources": [source.to_manifest_entry(defaults) for source in detected],
    }
    if labels.get("expected"):
        manifest["expected"] = labels["expected"]

    result = IngestResult(sources=detected, unclassified=unclassified, manifest=manifest)

    trigger = labels.get("trigger")
    if isinstance(trigger, dict) and trigger:
        manifest["trigger"] = trigger
        return result

    # No ground truth: load what was detected and pick the most severe alert.
    manifest["trigger"] = {"kind": "alert"}
    events = _load_preview(log_dir, manifest)
    result.event_count = len(events)
    alerts = [event for event in events if event.kind == "alert"]
    result.alert_count = len(alerts)
    if alerts:
        # Most severe wins; ties break toward the earliest, which is the more
        # likely entry point of a sequence.
        best = max(
            alerts,
            key=lambda event: (SEVERITY_RANK.get(event.severity, 0), -event.timestamp_dt.timestamp()),
        )
        manifest["trigger"] = {
            "source_type": best.source_type,
            "kind": "alert",
            **({"rule_id": str(best.rule["id"])} if best.rule.get("id") else {}),
        }
    return result


def _load_preview(log_dir: Path, manifest: dict[str, Any]) -> list[CanonicalEvent]:
    """Normalize the detected sources once, to choose a trigger.

    Reads through the adapters directly rather than staging a scenario
    directory: the log directory may be read-only, and ingest should never
    write into the source data.
    """
    events: list[CanonicalEvent] = []
    for source in manifest.get("sources", []):
        source_type = str(source.get("type", ""))
        adapter = ADAPTERS.get(source_type)
        path = log_dir / str(source.get("path", ""))
        if adapter is None or not path.is_file():
            continue
        defaults = source.get("defaults") if isinstance(source.get("defaults"), dict) else {}
        text_mode = source_type in TEXT_LINE_SOURCES
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                row: Any = stripped
                if not text_mode:
                    try:
                        row = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(row, dict):
                        continue
                try:
                    events.append(adapter.normalize(row, scenario_id="preview", defaults=defaults))
                except (ValueError, KeyError, TypeError):
                    continue
    return events


def write_scenario(
    log_dir: Path,
    out_dir: Path,
    result: IngestResult,
    *,
    copy_logs: bool = True,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "scenario.json"
    manifest_path.write_text(
        json.dumps(result.manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if copy_logs and out_dir.resolve() != log_dir.resolve():
        for source in result.sources:
            shutil.copy2(source.path, out_dir / source.path.name)
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m hawki_alert_analysis.ingest",
        description="Build a scenario manifest from a directory of collected logs.",
    )
    parser.add_argument("log_dir", type=Path, help="Directory holding collected log files.")
    parser.add_argument("--out", type=Path, help="Scenario directory to write. Defaults to log_dir.")
    parser.add_argument("--id", dest="scenario_id", default="", help="Scenario id. Defaults to the directory name.")
    parser.add_argument("--name", default="", help="Human-readable scenario name.")
    parser.add_argument("--labels", type=Path, help="Optional ground-truth label file.")
    parser.add_argument("--host", default="", help="Host name for sources that do not carry one.")
    parser.add_argument("--year", type=int, help="Year for syslog timestamps, which omit it.")
    parser.add_argument("--window", type=int, default=300, help="Correlation window in seconds.")
    parser.add_argument("--no-copy", action="store_true", help="Write only the manifest, leave logs in place.")
    parser.add_argument("--dry-run", action="store_true", help="Report detection without writing.")
    args = parser.parse_args(argv)

    log_dir = args.log_dir
    if not log_dir.is_dir():
        parser.error(f"{log_dir} is not a directory")

    result = build_manifest(
        log_dir,
        scenario_id=args.scenario_id or log_dir.name,
        name=args.name,
        labels=_load_labels(args.labels),
        host_name=args.host,
        year=args.year,
        correlation_window_seconds=args.window,
    )

    print(result.summary())
    if not result.sources:
        print("\nNo readable sources were found; no scenario was written.")
        return 1

    trigger = result.manifest.get("trigger", {})
    print(f"\ntrigger: {json.dumps(trigger, ensure_ascii=False)}")
    if trigger == {"kind": "alert"}:
        print(
            "warning: no alert was found in the collected logs, so the trigger is unresolved. "
            "Supply --labels to name one, or include an alerting source."
        )

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        return 0

    out_dir = args.out or log_dir
    path = write_scenario(log_dir, out_dir, result, copy_logs=not args.no_copy)
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
