#!/usr/bin/env python3
"""Refresh the live threat-intelligence feed from abuse.ch Feodo Tracker.

HAW-KI looks indicators up in a local file, never in an online service, so no
address, domain or hash observed in the lab leaves the network during an
analysis. This script is the only thing that talks to the outside, and it only
downloads.

    python3 tools/import_cti.py                       # download and write
    python3 tools/import_cti.py --input feodo.json    # convert a saved copy
    python3 tools/import_cti.py --dry-run             # parse and report only

Output: data/threat_intel-live/abusech-feodo.json (HAW-KI indicator format).
The web app notices the new file within a minute; no restart is needed.

Run it daily on the frontend host, e.g. crontab:
    17 6 * * * cd /opt/hawki && python3 tools/import_cti.py >> /var/log/hawki-cti.log 2>&1

Standard library only, so it runs on the host without the app's virtualenv.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
FEED_NAME = "abuse.ch Feodo Tracker"
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1] / "data" / "threat_intel-live" / "abusech-feodo.json"
)

# Online C2 servers are strong evidence; ones the tracker has seen go offline
# are still listed as malicious but with less confidence that the address is
# hostile today.
CONFIDENCE_ONLINE = 90
CONFIDENCE_OFFLINE = 60

# Refuse to replace a working feed with an empty or truncated download.
MINIMUM_INDICATORS = 1


def fetch(url: str, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "hawki-cti-import/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def _public_ip(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # A feed entry for a private or reserved address would match lab hosts.
    if not address.is_global:
        return None
    return str(address)


def convert(records: list[dict], *, now: datetime, ttl_days: int) -> tuple[list[dict], int]:
    valid_until = (now + timedelta(days=ttl_days)).isoformat()
    indicators: dict[str, dict] = {}
    skipped = 0

    for record in records:
        if not isinstance(record, dict):
            skipped += 1
            continue
        ip = _public_ip(str(record.get("ip_address") or record.get("ip") or ""))
        if ip is None:
            skipped += 1
            continue

        status = str(record.get("status") or "").lower()
        malware = str(record.get("malware") or "").strip()
        port = record.get("port")
        indicator = {
            "id": f"feodo-{ip}",
            "type": "ipv6-addr" if ":" in ip else "ipv4-addr",
            "value": ip,
            "verdict": "malicious",
            "confidence": CONFIDENCE_ONLINE if status == "online" else CONFIDENCE_OFFLINE,
            "severity": "high" if status == "online" else "medium",
            "feed": FEED_NAME,
            "description": (
                f"Botnet C2 server ({malware or 'unknown family'})"
                f"{f' on port {port}' if port else ''}, status {status or 'unknown'}."
            ),
            "categories": ["botnet-c2"],
            "malware_families": [malware] if malware else [],
            "mitre_techniques": ["T1071"],
            "first_seen": str(record.get("first_seen") or ""),
            "last_seen": str(record.get("last_online") or record.get("first_seen") or ""),
            "valid_until": valid_until,
            "tlp": "TLP:CLEAR",
            "references": [f"https://feodotracker.abuse.ch/browse/host/{ip}/"],
        }
        # One indicator per address; keep the most confident entry.
        previous = indicators.get(ip)
        if previous is None or indicator["confidence"] > previous["confidence"]:
            indicators[ip] = indicator

    return sorted(indicators.values(), key=lambda item: item["value"]), skipped


def write_atomically(path: Path, payload: dict) -> None:
    """Write beside the target and rename, so the app never reads half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".cti-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=1)
            stream.write("\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=FEODO_URL)
    parser.add_argument("--input", type=Path, help="convert a saved feed instead of downloading")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--ttl-days", type=int, default=7,
                        help="indicators expire this many days after import unless refreshed")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        raw = args.input.read_bytes() if args.input else fetch(args.url, args.timeout)
        records = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"error: could not read the feed: {exc}", file=sys.stderr)
        return 1
    if not isinstance(records, list):
        print("error: expected a JSON array of Feodo Tracker records", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    indicators, skipped = convert(records, now=now, ttl_days=args.ttl_days)
    print(f"parsed {len(records)} records -> {len(indicators)} indicators ({skipped} skipped)")

    if len(indicators) < MINIMUM_INDICATORS:
        print("error: no usable indicators; the existing feed file was left untouched",
              file=sys.stderr)
        return 1
    if args.dry_run:
        return 0

    write_atomically(args.output, {
        "source": FEED_NAME,
        "description": (
            "Botnet C2 IP addresses from abuse.ch Feodo Tracker, imported by "
            "tools/import_cti.py. Matches are external context, not proof."
        ),
        "generated_at": now.isoformat(),
        "source_url": args.url if not args.input else f"file:{args.input.name}",
        "indicators": indicators,
    })
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
