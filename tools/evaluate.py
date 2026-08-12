#!/usr/bin/env python3
"""Score alert analyses against schema coverage, grounding, and ground truth.

Three things are measured, in decreasing order of how objectively they can be
judged:

1. schema coverage    did the model report every required section?
2. grounding          did every cited event id exist in the bundle?
3. ground truth       did it recover the expected techniques, hosts, and
                      answers declared in the scenario's `expected` block?

Only the third needs labels. The first two work on any scenario, which means
this runs against the synthetic fixture as a regression check and against
collected corpora as an evaluation.

Ground-truth matching is deliberately shallow: it looks for expected strings in
the assessment. That detects a missed technique or host, not whether the prose
reasoning is sound — no automatic check does, and reporting a keyword hit as if
it were a judgement of analytical quality would be worse than reporting nothing.

    python tools/evaluate.py                      # all scenarios, demo path
    python tools/evaluate.py --live               # call the configured LLM
    python tools/evaluate.py --alert evt-1243...  # one alert
    python tools/evaluate.py --json report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("FLASK_SECRET_KEY", "evaluation-harness-key-" + "0" * 32)
os.environ.setdefault("HAWKI_ADMIN_USERNAME", "evaluator")
os.environ.setdefault("HAWKI_ADMIN_PASSWORD", "Evaluation-Harness-Pw!1")

import requests  # noqa: E402

import app as hawki  # noqa: E402
from hawki_alert_analysis.assessment import REQUIRED_SECTIONS  # noqa: E402


def scenario_expectations() -> dict[str, dict[str, Any]]:
    """Ground-truth blocks declared in each scenario manifest, by scenario id."""
    expectations: dict[str, dict[str, Any]] = {}
    for scenario in hawki.ALERT_REPOSITORY._load():
        expected = scenario.manifest.get("expected")
        if isinstance(expected, dict):
            expectations[str(scenario.manifest.get("id", ""))] = expected
    return expectations


def analyze(alert_id: str, *, live: bool) -> dict[str, Any]:
    case = hawki.ALERT_ANALYSIS.get_case(alert_id)
    context = {"alert_id": alert_id, "alert_case": case.to_llm_context()}
    request_text = hawki.ALERT_ANALYSIS.default_analysis_request()

    if not live:
        return hawki.demo_agent_response("alert_summary", request_text, context)
    try:
        return hawki.call_llm("alert_summary", request_text, [], context)
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return {"error": str(exc), "assessment": {}, "assessment_review": {}}


def match_expected(assessment: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Shallow containment check of expected values against the assessment."""
    haystack = json.dumps(assessment, ensure_ascii=False).lower()

    def check(values: Any) -> dict[str, list[str]]:
        wanted = [str(value) for value in values] if isinstance(values, list) else []
        found = [value for value in wanted if value.lower() in haystack]
        return {"found": found, "missed": [value for value in wanted if value not in found]}

    result = {
        "attack_techniques": check(expected.get("attack_techniques")),
        "affected_hosts": check(expected.get("affected_hosts")),
        "indicators": check(expected.get("indicators")),
    }

    answers = []
    for item in expected.get("answers", []) if isinstance(expected.get("answers"), list) else []:
        if not isinstance(item, dict):
            continue
        terms = item.get("expect") if isinstance(item.get("expect"), list) else []
        hits = [str(term) for term in terms if str(term).lower() in haystack]
        answers.append(
            {
                "question": item.get("question", ""),
                "matched": hits,
                "missed": [str(term) for term in terms if str(term) not in hits],
            }
        )
    result["answers"] = answers
    return result


def evaluate_alert(alert: dict[str, Any], *, live: bool, expectations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result = analyze(alert["id"], live=live)
    assessment = result.get("assessment", {}) or {}
    review = result.get("assessment_review", {}) or {}
    reported = [section for section in REQUIRED_SECTIONS if section not in review.get("missing_sections", [])]

    record: dict[str, Any] = {
        "alert_id": alert["id"],
        "scenario_id": alert.get("scenario_id", ""),
        "title": alert.get("title", ""),
        "error": result.get("error", ""),
        "schema": {
            "reported": len(reported),
            "required": len(REQUIRED_SECTIONS),
            "missing": review.get("missing_sections", []),
            "complete": bool(review.get("complete")),
        },
        "grounding": {
            "citations": review.get("citations", 0),
            "ungrounded": review.get("ungrounded_event_ids", []),
            "clean": not review.get("ungrounded_event_ids"),
        },
        "notes": review.get("notes", []),
        "repair_attempted": bool(review.get("repair_attempted")),
    }
    expected = expectations.get(str(alert.get("scenario_id", "")))
    if expected:
        record["ground_truth"] = match_expected(assessment, expected)
    return record


def print_report(records: list[dict[str, Any]], *, live: bool) -> None:
    mode = "live LLM" if live else "demo path"
    print(f"\nAlert analysis evaluation ({mode})")
    print("=" * 78)

    for record in records:
        schema = record["schema"]
        grounding = record["grounding"]
        status = "ok" if schema["complete"] and grounding["clean"] else "review"
        print(f"\n[{status}] {record['alert_id']}  {record['title'][:52]}")
        print(
            f"  schema     {schema['reported']}/{schema['required']} sections"
            + (f"  missing: {', '.join(schema['missing'])}" if schema["missing"] else "")
        )
        print(
            f"  grounding  {grounding['citations']} citations"
            + (f"  ungrounded: {', '.join(grounding['ungrounded'])}" if grounding["ungrounded"] else "  all resolved")
        )
        if record.get("error"):
            print(f"  error      {record['error']}")
        truth = record.get("ground_truth")
        if truth:
            for key in ("attack_techniques", "affected_hosts", "indicators"):
                section = truth.get(key, {})
                if section.get("found") or section.get("missed"):
                    print(
                        f"  {key:<10} found {len(section['found'])}"
                        + (f", missed {', '.join(section['missed'])}" if section["missed"] else "")
                    )
            for answer in truth.get("answers", []):
                verdict = "hit" if answer["matched"] and not answer["missed"] else "partial" if answer["matched"] else "miss"
                print(f"  answer     [{verdict}] {answer['question'][:56]}")
        for note in record["notes"]:
            print(f"  note       {note}")

    complete = sum(1 for record in records if record["schema"]["complete"])
    clean = sum(1 for record in records if record["grounding"]["clean"])
    print("\n" + "=" * 78)
    print(f"{len(records)} alerts · {complete} schema-complete · {clean} fully grounded")
    if not live:
        print(
            "Demo path: the assessments are deterministic summaries, not model reasoning. "
            "Re-run with --live against the configured LLM for a real measurement."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tools/evaluate.py",
        description="Score alert analyses for schema coverage, grounding, and ground truth.",
    )
    parser.add_argument("--live", action="store_true", help="Call the configured LLM instead of the demo path.")
    parser.add_argument("--alert", action="append", default=[], help="Evaluate specific alert ids.")
    parser.add_argument("--scenario", default="", help="Limit to one scenario id.")
    parser.add_argument("--json", dest="json_out", type=Path, help="Write the full report as JSON.")
    args = parser.parse_args(argv)

    alerts = hawki.ALERT_ANALYSIS.list_alerts()
    if args.alert:
        wanted = set(args.alert)
        alerts = [alert for alert in alerts if alert["id"] in wanted]
    if args.scenario:
        alerts = [alert for alert in alerts if alert.get("scenario_id") == args.scenario]

    if not alerts:
        print("No alerts matched. Check the configured scenario root.", file=sys.stderr)
        return 1

    skipped = hawki.ALERT_REPOSITORY.skipped_lines
    if skipped:
        print(f"note: {len(skipped)} log line(s) were unreadable during collection:")
        for entry in skipped[:5]:
            print(f"  {entry}")

    expectations = scenario_expectations()
    records = [evaluate_alert(alert, live=args.live, expectations=expectations) for alert in alerts]
    print_report(records, live=args.live)

    if args.json_out:
        args.json_out.write_text(
            json.dumps(
                {"mode": "live" if args.live else "demo", "alerts": records},
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.json_out}")

    # Non-zero when a live run produced an incomplete or ungrounded assessment,
    # so this can gate a change to prompts or the bundle.
    if args.live and any(
        not record["schema"]["complete"] or not record["grounding"]["clean"] for record in records
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
