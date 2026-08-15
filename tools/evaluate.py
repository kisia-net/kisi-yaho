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
from hawki_alert_analysis.models import AlertCase  # noqa: E402


def scenario_expectations() -> dict[str, dict[str, Any]]:
    """Ground-truth blocks declared in each scenario manifest, by scenario id."""
    expectations: dict[str, dict[str, Any]] = {}
    for scenario in hawki.ALERT_REPOSITORY._load():
        expected = scenario.manifest.get("expected")
        if isinstance(expected, dict):
            expectations[str(scenario.manifest.get("id", ""))] = expected
    return expectations


def bare_case(case: AlertCase) -> AlertCase:
    """The same alert with enrichment switched off.

    This is the "before" side of the comparison: exactly what an un-enriched
    SIEM hands an analyst — the triggering alert and nothing else. No
    correlated events, no asset context, no threat intelligence. The task put
    to the model is identical; only the evidence differs, so any difference in
    the answer is attributable to enrichment rather than to prompting.
    """
    return AlertCase(
        id=case.id,
        scenario_id=case.scenario_id,
        title=case.trigger.rule.get("name") or case.trigger.message,
        trigger=case.trigger,
        related_events=[],
        entities=case.trigger.entity_values(),
        time_window={"start": case.trigger.timestamp, "end": case.trigger.timestamp},
    )


def run_analysis(alert_id: str, bundle: dict[str, Any], *, live: bool) -> dict[str, Any]:
    context = {"alert_id": alert_id, "alert_case": bundle}
    request_text = hawki.ALERT_ANALYSIS.default_analysis_request()

    if not live:
        return hawki.demo_agent_response("alert_summary", request_text, context)
    try:
        return hawki.call_llm("alert_summary", request_text, [], context)
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return {"error": str(exc), "assessment": {}, "assessment_review": {}}


def analyze(alert_id: str, *, live: bool, enriched: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    """Analyze one alert. Returns (result, bundle actually sent)."""
    case = hawki.ALERT_ANALYSIS.get_case(alert_id)
    bundle = (case if enriched else bare_case(case)).to_llm_context()
    return run_analysis(alert_id, bundle, live=live), bundle


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


def score(
    alert: dict[str, Any],
    result: dict[str, Any],
    bundle: dict[str, Any],
    expectations: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    assessment = result.get("assessment", {}) or {}
    review = result.get("assessment_review", {}) or {}
    reported = [section for section in REQUIRED_SECTIONS if section not in review.get("missing_sections", [])]
    counts = bundle.get("collection", {}).get("counts", {})
    entities = assessment.get("affected_entities", {}) or {}

    record: dict[str, Any] = {
        "alert_id": alert["id"],
        "scenario_id": alert.get("scenario_id", ""),
        "title": alert.get("title", ""),
        "error": result.get("error", ""),
        "evidence_supplied": {
            "security_alerts": counts.get("security_alerts", 0),
            "security_events": counts.get("security_events", 0),
            "assets": counts.get("assets", 0),
            "threat_indicators": counts.get("threat_indicators", 0),
            "sources": len(bundle.get("collection", {}).get("sources", [])),
        },
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
        "answer": {
            "entities_named": sum(len(value) for value in entities.values() if isinstance(value, list)),
            "techniques": len(assessment.get("attack_techniques", []) or []),
            "observations": len(assessment.get("confirmed_observations", []) or []),
            "severity": (assessment.get("severity", {}) or {}).get("level", ""),
            "severity_rationale": (assessment.get("severity", {}) or {}).get("rationale", ""),
            "confidence": (assessment.get("confidence", {}) or {}).get("level", ""),
            "markdown": str(result.get("answer", "")),
        },
        "notes": review.get("notes", []),
        "repair_attempted": bool(review.get("repair_attempted")),
    }
    expected = expectations.get(str(alert.get("scenario_id", "")))
    if expected:
        record["ground_truth"] = match_expected(assessment, expected)
    return record


def evaluate_alert(alert: dict[str, Any], *, live: bool, expectations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result, bundle = analyze(alert["id"], live=live)
    return score(alert, result, bundle, expectations)


def _truth_found(record: dict[str, Any]) -> int:
    truth = record.get("ground_truth") or {}
    total = 0
    for key in ("attack_techniques", "affected_hosts", "indicators"):
        total += len((truth.get(key) or {}).get("found", []))
    total += sum(1 for answer in truth.get("answers", []) if answer.get("matched"))
    return total


def compare_alert(
    alert: dict[str, Any], *, live: bool, expectations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Analyze one alert twice — without and with enrichment — and diff the two."""
    bare_result, bare_bundle = analyze(alert["id"], live=live, enriched=False)
    rich_result, rich_bundle = analyze(alert["id"], live=live, enriched=True)

    before = score(alert, bare_result, bare_bundle, expectations)
    after = score(alert, rich_result, rich_bundle, expectations)

    return {
        "alert_id": alert["id"],
        "title": alert.get("title", ""),
        "scenario_id": alert.get("scenario_id", ""),
        "before": before,
        "after": after,
        "delta": {
            "evidence_events": after["evidence_supplied"]["security_events"]
            - before["evidence_supplied"]["security_events"],
            "evidence_sources": after["evidence_supplied"]["sources"]
            - before["evidence_supplied"]["sources"],
            "assets": after["evidence_supplied"]["assets"],
            "threat_indicators": after["evidence_supplied"]["threat_indicators"],
            "entities_named": after["answer"]["entities_named"] - before["answer"]["entities_named"],
            "techniques": after["answer"]["techniques"] - before["answer"]["techniques"],
            "citations": after["grounding"]["citations"] - before["grounding"]["citations"],
            "ground_truth_found": _truth_found(after) - _truth_found(before),
        },
    }


def print_comparison(records: list[dict[str, Any]], *, live: bool) -> None:
    mode = "live LLM" if live else "demo path"
    print(f"\n증강 전/후 비교  ({mode})")
    print("=" * 78)

    for record in records:
        before, after, delta = record["before"], record["after"], record["delta"]
        print(f"\n{record['alert_id']}  {record['title'][:56]}")
        print("-" * 78)
        print(f"{'':22} {'증강 전':>12} {'증강 후':>12}   차이")

        def row(label: str, key_path: tuple[str, str], delta_key: str | None = None) -> None:
            section, key = key_path
            left, right = before[section][key], after[section][key]
            change = f"{right - left:+d}" if isinstance(left, int) else ""
            if delta_key:
                change = f"{delta[delta_key]:+d}"
            print(f"{label:22} {left:>12} {right:>12}   {change}")

        print("  [모델에 준 증거]")
        row("  경보", ("evidence_supplied", "security_alerts"))
        row("  원본 로그", ("evidence_supplied", "security_events"))
        row("  자산 정보", ("evidence_supplied", "assets"))
        row("  위협 인텔", ("evidence_supplied", "threat_indicators"))
        row("  로그 소스 수", ("evidence_supplied", "sources"))

        print("  [모델이 낸 답]")
        row("  언급한 엔티티", ("answer", "entities_named"))
        row("  ATT&CK 기법", ("answer", "techniques"))
        row("  확인된 관찰", ("answer", "observations"))
        row("  증거 인용", ("grounding", "citations"))
        row("  채운 항목", ("schema", "reported"))
        if before["schema"]["missing"]:
            print(f"{'    증강 전 미보고':22} {', '.join(before['schema']['missing'])}")
        if after["schema"]["missing"]:
            print(f"{'    증강 후 미보고':22} {', '.join(after['schema']['missing'])}")
        print(f"{'  심각도':22} {before['answer']['severity']:>12} {after['answer']['severity']:>12}")
        print(f"{'  확신도':22} {before['answer']['confidence']:>12} {after['answer']['confidence']:>12}")

        if record["before"].get("ground_truth"):
            print("  [정답 복원]")
            print(
                f"{'  맞춘 항목':22} {_truth_found(before):>12} {_truth_found(after):>12}"
                f"   {delta['ground_truth_found']:+d}"
            )

        # The rationale is where asset context shows up or fails to.
        print("\n  심각도 근거 — 증강 전:")
        print(f"    {before['answer']['severity_rationale'] or '(없음)'}")
        print("  심각도 근거 — 증강 후:")
        print(f"    {after['answer']['severity_rationale'] or '(없음)'}")

    print("\n" + "=" * 78)
    totals = {
        "entities": sum(record["delta"]["entities_named"] for record in records),
        "citations": sum(record["delta"]["citations"] for record in records),
        "truth": sum(record["delta"]["ground_truth_found"] for record in records),
    }
    print(
        f"{len(records)}건 · 엔티티 {totals['entities']:+d} · 인용 {totals['citations']:+d} · "
        f"정답 복원 {totals['truth']:+d}"
    )
    if not live:
        print(
            "데모 경로입니다. 결정론적 요약이라 모델 추론 차이는 나타나지 않습니다. "
            "--live 로 실제 모델에 붙여야 의미 있는 비교가 됩니다."
        )


def write_comparison_markdown(records: list[dict[str, Any]], path: Path, *, live: bool) -> None:
    """Write the side-by-side comparison as a shareable document."""
    lines = [
        "# 증강 전 / 증강 후 비교",
        "",
        f"- 실행 모드: {'실제 LLM' if live else '데모 경로 (결정론적 요약)'}",
        f"- 비교 건수: {len(records)}",
        "",
        "증강 전은 트리거 경보 하나만, 증강 후는 4블록 번들 전체를 같은 질문과 함께 "
        "모델에 넣은 결과입니다. 질문은 동일하고 증거만 다릅니다.",
        "",
    ]
    for record in records:
        before, after, delta = record["before"], record["after"], record["delta"]
        lines += [
            f"## {record['title']}",
            "",
            f"`{record['alert_id']}` · 시나리오 `{record['scenario_id']}`",
            "",
            "| 항목 | 증강 전 | 증강 후 |",
            "| --- | ---: | ---: |",
            f"| 경보 | {before['evidence_supplied']['security_alerts']} | {after['evidence_supplied']['security_alerts']} |",
            f"| 원본 로그 | {before['evidence_supplied']['security_events']} | {after['evidence_supplied']['security_events']} |",
            f"| 자산 정보 | {before['evidence_supplied']['assets']} | {after['evidence_supplied']['assets']} |",
            f"| 위협 인텔 | {before['evidence_supplied']['threat_indicators']} | {after['evidence_supplied']['threat_indicators']} |",
            f"| 언급한 엔티티 | {before['answer']['entities_named']} | {after['answer']['entities_named']} |",
            f"| ATT&CK 기법 | {before['answer']['techniques']} | {after['answer']['techniques']} |",
            f"| 증거 인용 | {before['grounding']['citations']} | {after['grounding']['citations']} |",
            f"| 채운 항목 | {before['schema']['reported']}/{before['schema']['required']} "
            f"| {after['schema']['reported']}/{after['schema']['required']} |",
            f"| 심각도 | {before['answer']['severity'] or '—'} | {after['answer']['severity'] or '—'} |",
            f"| 심각도 근거 | {before['answer']['severity_rationale'] or '—'} "
            f"| {after['answer']['severity_rationale'] or '—'} |",
            "",
            "### 증강 전 답변",
            "",
            before["answer"]["markdown"] or "_(없음)_",
            "",
            "### 증강 후 답변",
            "",
            after["answer"]["markdown"] or "_(없음)_",
            "",
            "---",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")


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
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Analyze each alert twice, without and with enrichment, and diff the results.",
    )
    parser.add_argument(
        "--markdown",
        dest="markdown_out",
        type=Path,
        help="With --compare, write the side-by-side comparison as a shareable document.",
    )
    args = parser.parse_args(argv)

    if args.markdown_out and not args.compare:
        parser.error("--markdown requires --compare")

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

    if args.compare:
        records = [
            compare_alert(alert, live=args.live, expectations=expectations) for alert in alerts
        ]
        print_comparison(records, live=args.live)
        payload: dict[str, Any] = {"mode": "live" if args.live else "demo", "comparisons": records}
        if args.markdown_out:
            write_comparison_markdown(records, args.markdown_out, live=args.live)
            print(f"\nwrote {args.markdown_out}")
    else:
        records = [evaluate_alert(alert, live=args.live, expectations=expectations) for alert in alerts]
        print_report(records, live=args.live)
        payload = {"mode": "live" if args.live else "demo", "alerts": records}

    if args.json_out:
        args.json_out.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.json_out}")

    # Non-zero when a live run produced an incomplete or ungrounded assessment,
    # so this can gate a change to prompts or the bundle.
    if args.live and not args.compare and any(
        not record["schema"]["complete"] or not record["grounding"]["clean"] for record in records
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
