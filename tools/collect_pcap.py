#!/usr/bin/env python3
"""Replay a PCAP through Suricata and build a scenario from the output.

This is the shortest path from a public capture to genuinely collected
telemetry: Suricata reads the capture and writes its own eve.json, which the
existing SuricataAdapter already consumes. Nothing about the resulting events
is synthetic.

    python tools/collect_pcap.py capture.pcap --out data/scenarios/mta-2026-08-11

Sources for captures with published analyses, which double as ground truth:
malware-traffic-analysis.net, the Suricata test corpus, and CTF network
forensics challenges. Add --labels to attach that ground truth for the
evaluation harness.

Suricata is not bundled. If it is missing this exits with instructions rather
than pretending to have collected anything.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hawki_alert_analysis.ingest import _load_labels, build_manifest, write_scenario  # noqa: E402

INSTALL_HINT = """Suricata was not found on PATH.

  Debian/Ubuntu   sudo apt install suricata
  macOS           brew install suricata
  container       docker run --rm -v "$PWD:/data" jasonish/suricata:latest \\
                      -r /data/capture.pcap -l /data/out

Then re-run this script, or run Suricata yourself and point
python -m hawki_alert_analysis.ingest at the directory holding eve.json."""


def run_suricata(pcap: Path, work_dir: Path, *, config: Path | None, rules: Path | None) -> Path:
    """Run Suricata over the capture and return the directory holding eve.json."""
    binary = shutil.which("suricata")
    if binary is None:
        raise FileNotFoundError(INSTALL_HINT)

    work_dir.mkdir(parents=True, exist_ok=True)
    command = [binary, "-r", str(pcap), "-l", str(work_dir)]
    if config:
        command += ["-c", str(config)]
    if rules:
        command += ["-S", str(rules)]

    print("running:", " ".join(command))
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        # Suricata reports rule-load and config problems on stderr and still
        # exits non-zero, so the message is worth showing in full.
        raise RuntimeError(
            f"suricata exited {completed.returncode}\n"
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )

    eve = work_dir / "eve.json"
    if not eve.is_file():
        raise RuntimeError(
            f"suricata produced no eve.json in {work_dir}. "
            "Check that the configuration enables the eve-log output."
        )
    if eve.stat().st_size == 0:
        raise RuntimeError(
            f"{eve} is empty: Suricata read the capture but logged nothing. "
            "Verify the capture contains traffic Suricata can decode."
        )
    return work_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tools/collect_pcap.py",
        description="Replay a PCAP through Suricata and write a HAW-KI scenario.",
    )
    parser.add_argument("pcap", type=Path, help="Capture file to replay.")
    parser.add_argument("--out", type=Path, required=True, help="Scenario directory to write.")
    parser.add_argument("--work", type=Path, help="Directory for Suricata output. Defaults to <out>/_suricata.")
    parser.add_argument("--config", type=Path, help="suricata.yaml to use.")
    parser.add_argument("--rules", type=Path, help="Rule file to load with -S.")
    parser.add_argument("--labels", type=Path, help="Ground-truth label file to attach.")
    parser.add_argument("--id", dest="scenario_id", default="", help="Scenario id. Defaults to the capture name.")
    parser.add_argument("--name", default="", help="Human-readable scenario name.")
    parser.add_argument("--host", default="", help="Host name for sources that do not carry one.")
    parser.add_argument("--keep-work", action="store_true", help="Keep the raw Suricata output directory.")
    args = parser.parse_args(argv)

    if not args.pcap.is_file():
        parser.error(f"{args.pcap} is not a file")

    work_dir = args.work or (args.out / "_suricata")
    try:
        collected = run_suricata(args.pcap, work_dir, config=args.config, rules=args.rules)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    scenario_id = args.scenario_id or args.pcap.stem
    result = build_manifest(
        collected,
        scenario_id=scenario_id,
        name=args.name or f"Suricata replay of {args.pcap.name}",
        labels=_load_labels(args.labels),
        host_name=args.host,
    )
    print()
    print(result.summary())

    if not result.sources:
        print("\nSuricata output held no readable sources; no scenario written.", file=sys.stderr)
        return 1

    manifest_path = write_scenario(collected, args.out, result)
    print(f"\ntrigger: {json.dumps(result.manifest.get('trigger', {}), ensure_ascii=False)}")
    print(f"wrote {manifest_path}")

    if not args.keep_work and work_dir.exists() and work_dir.resolve() != args.out.resolve():
        shutil.rmtree(work_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
