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

from .adapters import SYSLOG_LINE, IgnoredEvent
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
    ("modsec", "modsecurity"),
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

# A producer's own operational output, which sits in the same directory as its
# telemetry. Naming these explicitly keeps the report about the collection
# rather than about files that were never going to be events.
NON_TELEMETRY = {
    "fast.log": "Suricata's human-readable alert log; eve.json carries the same alerts with more detail",
    "stats.log": "Suricata's own performance counters",
    "suricata.log": "Suricata's operational log",
    "suricata-start.log": "Suricata's startup log",
}


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
    non_telemetry: list[str] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    alert_count: int = 0
    event_count: int = 0
    ignored_count: int = 0
    # A trigger declared in a labels file that no collected event satisfies.
    trigger_unmatched: bool = False

    def summary(self) -> str:
        lines = [
            f"{len(self.sources)} source(s) detected, "
            f"{self.event_count} events, {self.alert_count} alerts"
            + (f", {self.ignored_count} sensor self-reports ignored" if self.ignored_count else "")
        ]
        for source in self.sources:
            note = "" if source.sample_ok else f"  [unreadable: {source.detail}]"
            lines.append(f"  {source.path.name:<28} -> {source.source_type:<9} ({source.reason}){note}")
        for name in self.unclassified:
            lines.append(f"  {name:<28} -> skipped (no adapter matched)")
        for name in self.non_telemetry:
            lines.append(f"  {name:<28} -> skipped (producer's own output)")
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
        if "transaction" in payload or "audit_data" in payload:
            return "modsecurity", "JSON carries a ModSecurity audit transaction"
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
    except IgnoredEvent:
        # The first line happened to be a sensor self-report. The adapter
        # understood it perfectly well; it just is not a security event.
        return True, ""
    except Exception as exc:  # noqa: BLE001 - report any adapter rejection
        return False, str(exc)
    return True, ""


def detect_sources(log_dir: Path) -> tuple[list[DetectedSource], list[str], list[str]]:
    detected: list[DetectedSource] = []
    unclassified: list[str] = []
    non_telemetry: list[str] = []
    for path in sorted(log_dir.iterdir()):
        if not path.is_file() or path.name.lower() in SKIP_NAMES or path.name.startswith("."):
            continue
        if path.name.lower() in NON_TELEMETRY:
            non_telemetry.append(f"{path.name} ({NON_TELEMETRY[path.name.lower()]})")
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
    return detected, unclassified, non_telemetry


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
    detected, unclassified, non_telemetry = detect_sources(log_dir)

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

    result = IngestResult(
        sources=detected,
        unclassified=unclassified,
        non_telemetry=non_telemetry,
        manifest=manifest,
    )

    labelled_trigger = labels.get("trigger")
    labelled_trigger = labelled_trigger if isinstance(labelled_trigger, dict) and labelled_trigger else None
    manifest["trigger"] = dict(labelled_trigger) if labelled_trigger else {"kind": "alert"}

    # Read the sources whether or not a trigger was declared. The counts are how
    # a collection reports itself, and skipping them for a labelled run made a
    # healthy collection print "0 events" and trip the empty-collection warning.
    events, ignored = _load_preview(log_dir, manifest)
    result.event_count = len(events)
    result.ignored_count = ignored
    alerts = [event for event in events if event.kind == "alert"]
    result.alert_count = len(alerts)

    if labelled_trigger:
        # A declared trigger that matches nothing would otherwise surface as an
        # AlertNotFound at load time, far from the typo that caused it.
        result.trigger_unmatched = not any(
            _matches_trigger(event, labelled_trigger) for event in events
        )
        return result

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


def _matches_trigger(event: CanonicalEvent, selector: dict[str, Any]) -> bool:
    """Mirror of the repository's trigger selector.

    Kept in step with `FixtureEventRepository._resolve_trigger`: a selector that
    passes here must be the one that resolves at load time, or the check is
    worse than none.
    """
    if selector.get("source_type") and event.source_type != selector["source_type"]:
        return False
    if selector.get("rule_id") and str(event.rule.get("id", "")) != str(selector["rule_id"]):
        return False
    if selector.get("kind") and event.kind != selector["kind"]:
        return False
    return True


def _load_preview(log_dir: Path, manifest: dict[str, Any]) -> tuple[list[CanonicalEvent], int]:
    """Normalize the detected sources once, to choose a trigger.

    Reads through the adapters directly rather than staging a scenario
    directory: the log directory may be read-only, and ingest should never
    write into the source data.
    """
    events: list[CanonicalEvent] = []
    ignored = 0
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
                except IgnoredEvent:
                    ignored += 1
                except (ValueError, KeyError, TypeError):
                    continue
    return events, ignored


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


def verify_written_scenario(out_dir: Path, scenario_id: str) -> list[str]:
    """Read the scenario back the way the app will, and report what breaks.

    Writing a manifest and copying logs can both succeed while the result is
    still unusable — a source file that did not arrive, a trigger that resolves
    to nothing. The failure then shows up far away, as a scenario quietly
    absent from the alert list, so it is checked here instead.
    """
    from .repository import FixtureEventRepository

    problems: list[str] = []
    manifest_path = out_dir / "scenario.json"
    if not manifest_path.is_file():
        return [f"{manifest_path} does not exist."]

    # Rooted at the parent because that is what the app points at, which also
    # surfaces a scenario id that collides with an existing one.
    repository = FixtureEventRepository(out_dir.parent)
    try:
        loaded = [
            scenario
            for scenario in repository._load()
            if str(scenario.manifest.get("id", "")) == scenario_id
        ]
    except OSError as exc:
        return [f"the scenario directory could not be read: {exc}"]

    if not loaded:
        problems.append(f"no scenario with id {scenario_id!r} was found under {out_dir.parent}.")
    elif len(loaded) > 1:
        problems.append(
            f"{len(loaded)} scenarios share the id {scenario_id!r}; alert ids will collide."
        )
    elif not loaded[0].events:
        problems.append(f"scenario {scenario_id!r} loaded but holds no events.")

    for line in repository.skipped_lines[:5]:
        problems.append(f"unreadable: {line}")
    return problems


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

    try:
        labels = _load_labels(args.labels)
    except FileNotFoundError:
        parser.error(
            f"labels file not found: {args.labels}\n"
            "Create it, or drop --labels to let the most severe alert be the trigger."
        )
    except ValueError as exc:
        parser.error(f"labels file is not valid JSON: {args.labels}\n{exc}")

    result = build_manifest(
        log_dir,
        scenario_id=args.scenario_id or log_dir.name,
        name=args.name,
        labels=labels,
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

    if result.trigger_unmatched and result.event_count:
        print(
            "\nwarning: no collected event matches the trigger declared in the labels file.\n"
            "  The scenario will fail to load with AlertNotFound. Check source_type, kind, and\n"
            "  rule_id against the collected data, or drop --labels to let the most severe\n"
            "  alert be the trigger."
        )

    if result.event_count == 0:
        # Sources were readable but held nothing. Almost always the collection
        # step upstream produced no telemetry, not a problem with these files.
        print(
            "\nwarning: the sources were readable but contained no events at all.\n"
            "  The collection step upstream probably produced nothing. For a Suricata replay,\n"
            "  check its own output: 'read 0 files, 0 packets' means it never saw the capture —\n"
            "  usually the capture path is missing, or is a directory rather than the .pcap file."
        )
    elif trigger == {"kind": "alert"}:
        print(
            "warning: events were collected but none of them is an alert, so the trigger is\n"
            "  unresolved. Either the ruleset raised nothing on this traffic, or the alerting\n"
            "  source is missing. Supply --labels to name a trigger explicitly."
        )

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        return 0

    out_dir = args.out or log_dir
    path = write_scenario(log_dir, out_dir, result, copy_logs=not args.no_copy)
    print(f"\nwrote {path}")

    problems = verify_written_scenario(out_dir, str(result.manifest.get("id", "")))
    if problems:
        print("\nwarning: the scenario was written but does not load back:")
        for problem in problems:
            print(f"  {problem}")
        print(
            "  Until this is fixed the scenario is invisible to the app and to\n"
            "  tools/evaluate.py, which will list only the scenarios that do load."
        )
        return 1

    print(f"verified: reloads from {out_dir} with {result.alert_count} alert(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
