#!/usr/bin/env python3
"""List collected alerts and the id to hand to `tools/evaluate.py --alert`.

A real capture produces hundreds of alerts, most of them the same signature
firing again and again, so a flat list of 561 rows is not something anyone can
choose from. This groups by signature, shows how often each fired, and prints
one representative event id per group — which is what `--alert` wants.

    python tools/list_alerts.py                          # every scenario
    python tools/list_alerts.py --scenario MTA-2026-...  # one scenario
    python tools/list_alerts.py --all                    # every alert, ungrouped
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def report_silent_scenarios(app, contributing: list[str]) -> None:
    """Name scenarios that are on disk but contributed no alert.

    A scenario whose telemetry failed to load still parses its manifest, so it
    exists as far as the repository is concerned and simply never appears in a
    list built from alerts. That is the one failure this listing could hide,
    and it is exactly what an operator hits after a fresh ingest.
    """
    repository = app.ALERT_REPOSITORY
    load = getattr(repository, "_load", None)
    if not callable(load):  # Elasticsearch: no scenario directories to compare.
        print(f"reading from: {app.ALERT_REPOSITORY_KIND} repository\n")
        return

    # Always printed. "The scenario I just ingested is not listed" is almost
    # always a scenario written to one directory and read from another, and
    # the answer is this line.
    root = getattr(repository, "root", None)
    print(f"reading from: {root}")

    # All three collections resolve the same way, so a container path left in
    # .env silently redirects any of them. Reporting one and not the others
    # just moves the confusion to the asset or intelligence block.
    fallbacks = [
        (name, requested)
        for name, requested, effective in (
            ("ALERT_FIXTURE_ROOT", app.ALERT_FIXTURE_REQUESTED_ROOT, app.ALERT_FIXTURE_ROOT),
            ("ASSET_INVENTORY_ROOT", app.ASSET_INVENTORY_REQUESTED_ROOT, app.ASSET_INVENTORY_ROOT),
            ("THREAT_INTEL_ROOT", app.THREAT_INTEL_REQUESTED_ROOT, app.THREAT_INTEL_ROOT),
        )
        if requested != effective
    ]
    for name, requested in fallbacks:
        print(f"  note: {name}={requested} does not exist; packaged fixtures used instead.")
    if fallbacks:
        print(
            "  Data written elsewhere will not appear. These are read from the environment\n"
            "  and from .env, which is loaded natively as well as inside the container —\n"
            "  a container path (/app/data/...) resolves to nothing on the host."
        )

    silent = [
        str(scenario.manifest.get("id", "?"))
        for scenario in load()
        if str(scenario.manifest.get("id", "")) not in contributing
    ]
    skipped = list(getattr(repository, "skipped_lines", []))
    if not silent and not skipped:
        print()
        return

    for scenario_id in silent:
        print(f"  warning: scenario {scenario_id!r} loaded but produced no alerts.")
    for line in skipped[:10]:
        print(f"  unreadable: {line}")
    if len(skipped) > 10:
        print(f"  ... and {len(skipped) - 10} more unreadable lines.")
    if silent:
        print(
            "  A scenario with no alerts usually means its log file is missing from the\n"
            "  scenario directory, or holds no records the adapter recognised. Check that\n"
            "  the file named in its scenario.json 'sources' sits beside it.\n"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tools/list_alerts.py",
        description="Show collected alerts grouped by signature, with the id --alert expects.",
    )
    parser.add_argument("--scenario", default="", help="Limit to one scenario id.")
    parser.add_argument("--all", action="store_true", help="List every alert instead of grouping.")
    parser.add_argument("--limit", type=int, default=20, help="Rows to show (default 20).")
    args = parser.parse_args()

    import app  # Imported here so --help works without the app's environment.

    alerts = app.ALERT_ANALYSIS.list_alerts()
    if args.scenario:
        alerts = [item for item in alerts if item.get("scenario_id") == args.scenario]
        if not alerts:
            known = sorted({item.get("scenario_id", "") for item in app.ALERT_ANALYSIS.list_alerts()})
            print(f"No alerts in scenario {args.scenario!r}. Known scenarios: {', '.join(known)}")
            return 1

    if not alerts:
        print("No alerts found. Has a scenario been ingested into data/scenarios/?")
        return 1

    scenarios = sorted({item.get("scenario_id", "") for item in alerts})
    print(f"{len(alerts)} alert(s) across {len(scenarios)} scenario(s): {', '.join(scenarios)}\n")
    report_silent_scenarios(app, scenarios)

    if args.all:
        rows = sorted(alerts, key=lambda item: SEVERITY_ORDER.get(item.get("severity", ""), 5))
        for item in rows[: args.limit]:
            print(f"{item['severity']:<9} {item['id']:<26} {item['title'][:64]}")
        if len(rows) > args.limit:
            print(f"\n... {len(rows) - args.limit} more; raise --limit to see them.")
        return 0

    # One row per signature: the count is what tells you whether a detection is
    # a repeated beacon or a one-off, and the id is what --alert takes.
    counts = Counter(item["title"] for item in alerts)
    first: dict[str, dict] = {}
    for item in alerts:
        first.setdefault(item["title"], item)

    ranked = sorted(
        counts,
        key=lambda title: (SEVERITY_ORDER.get(first[title].get("severity", ""), 5), -counts[title]),
    )
    print(f"{'severity':<9} {'count':>6}  {'alert id (use with --alert)':<26} signature")
    for title in ranked[: args.limit]:
        item = first[title]
        print(f"{item['severity']:<9} {counts[title]:>6}  {item['id']:<26} {title[:58]}")
    if len(ranked) > args.limit:
        print(f"\n... {len(ranked) - args.limit} more signatures; raise --limit to see them.")

    top = first[ranked[0]]
    print(
        f"\nMost severe signature first. To score that one:\n"
        f"    python tools/evaluate.py --alert {top['id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
