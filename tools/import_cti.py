#!/usr/bin/env python3
"""Refresh the live threat-intelligence feeds (Feodo, blocklist.de, ThreatFox).

HAW-KI looks indicators up in a local file, never in an online service, so no
address, domain or hash observed in the lab leaves the network during an
analysis. This script is the only thing that talks to the outside, and it only
downloads.

    python3 tools/import_cti.py                       # every feed, download and write
    python3 tools/import_cti.py --feed blocklist      # one feed
    python3 tools/import_cti.py --input feodo.json    # convert a saved Feodo copy
    python3 tools/import_cti.py --dry-run             # parse and report only

Feeds (one file each in data/threat_intel-live/, HAW-KI indicator format):
- feodo      abuse.ch Feodo Tracker: botnet C2 servers         -> malicious
- blocklist  blocklist.de, last 48 h of attackers (web, login
             brute force, ssh, bots)                            -> suspicious
- threatfox  abuse.ch ThreatFox IOCs (IP, domain, URL, hash);
             needs a free Auth-Key in THREATFOX_AUTH_KEY        -> malicious
A feed that fails or has no key is skipped; the others are still written,
and data/threat_intel-live/.import-status records each outcome for the
CTI status card.
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


# -- blocklist.de ------------------------------------------------------------
#
# Addresses reported by blocklist.de's sensors in the last 48 hours. Shared and
# cloud addresses appear here too, so a listing is "suspicious", never
# "malicious": on its own it adds +6 to the priority, not enough for P1.

BLOCKLIST_URL = "https://lists.blocklist.de/lists/{name}.txt"
BLOCKLIST_LISTS = {
    "apache": "web-attack",
    "bruteforcelogin": "web-login-bruteforce",
    "bots": "web-bot",
    "ssh": "ssh-bruteforce",
}
BLOCKLIST_FEED = "blocklist.de"
BLOCKLIST_CONFIDENCE = 50
BLOCKLIST_TTL_DAYS = 3


def convert_blocklist(lists: dict[str, str], *, now: datetime) -> tuple[list[dict], int]:
    valid_until = (now + timedelta(days=BLOCKLIST_TTL_DAYS)).isoformat()
    by_ip: dict[str, set[str]] = {}
    skipped = 0
    for name, text in lists.items():
        category = BLOCKLIST_LISTS.get(name, name)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = _public_ip(line)
            if ip is None:
                skipped += 1
                continue
            by_ip.setdefault(ip, set()).add(category)
    indicators = []
    for ip, categories in sorted(by_ip.items()):
        indicators.append({
            "id": f"blocklistde-{ip}",
            "type": "ipv6-addr" if ":" in ip else "ipv4-addr",
            "value": ip,
            "verdict": "suspicious",
            "confidence": BLOCKLIST_CONFIDENCE,
            "severity": "medium",
            "feed": BLOCKLIST_FEED,
            "description": f"Reported by blocklist.de in the last 48 hours: {', '.join(sorted(categories))}.",
            "categories": sorted(categories),
            "malware_families": [],
            "mitre_techniques": ["T1595"] if "web-attack" in categories or "web-bot" in categories else ["T1110"],
            "first_seen": "",
            "last_seen": now.isoformat(),
            "valid_until": valid_until,
            "tlp": "TLP:CLEAR",
            "references": [f"https://www.blocklist.de/en/view.html?ip={ip}"],
        })
    return indicators, skipped


# -- abuse.ch ThreatFox -------------------------------------------------------
#
# Malware infrastructure (C2, payload delivery) shared by the community. The API
# needs a free Auth-Key from https://auth.abuse.ch/; without one the feed is
# skipped. The key is read from THREATFOX_AUTH_KEY, or from the repository's
# .env when cron runs this outside the container.

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_FEED = "abuse.ch ThreatFox"
THREATFOX_DAYS = 7
THREATFOX_TYPES = {
    "ip:port": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "md5_hash": "file-hash-md5",
    "sha256_hash": "file-hash-sha256",
}


def threatfox_key(env_file: Path) -> str:
    key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if key or not env_file.is_file():
        return key
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("THREATFOX_AUTH_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def fetch_threatfox(key: str, timeout: int, days: int = THREATFOX_DAYS) -> list[dict]:
    request = urllib.request.Request(
        THREATFOX_API,
        data=json.dumps({"query": "get_iocs", "days": days}).encode("utf-8"),
        headers={"Auth-Key": key, "Content-Type": "application/json", "User-Agent": "hawki-cti-import/1"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = json.loads(response.read())
    if not isinstance(payload, dict) or payload.get("query_status") not in ("ok", "no_result"):
        raise ValueError(f"ThreatFox answered {payload.get('query_status') if isinstance(payload, dict) else 'non-object'}")
    data = payload.get("data")
    return data if isinstance(data, list) else []


def convert_threatfox(records: list[dict], *, now: datetime, ttl_days: int) -> tuple[list[dict], int]:
    valid_until = (now + timedelta(days=ttl_days)).isoformat()
    indicators: dict[tuple[str, str], dict] = {}
    skipped = 0
    for record in records:
        if not isinstance(record, dict):
            skipped += 1
            continue
        kind = THREATFOX_TYPES.get(str(record.get("ioc_type") or ""))
        value = str(record.get("ioc") or "").strip()
        if not kind or not value:
            skipped += 1
            continue
        if kind == "ipv4-addr":
            ip = _public_ip(value.rsplit(":", 1)[0])
            if ip is None:
                skipped += 1
                continue
            value = ip
            kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
        elif kind.startswith("file-hash"):
            value = value.lower()
        try:
            confidence = max(0, min(int(record.get("confidence_level") or 50), 100))
        except (TypeError, ValueError):
            confidence = 50
        malware = str(record.get("malware_printable") or record.get("malware") or "").strip()
        threat = str(record.get("threat_type") or "").strip()
        indicator = {
            "id": f"threatfox-{record.get('id') or value}",
            "type": kind,
            "value": value,
            "verdict": "malicious",
            "confidence": confidence,
            "severity": "high" if confidence >= 75 else "medium",
            "feed": THREATFOX_FEED,
            "description": f"{threat or 'malware infrastructure'} ({malware or 'unknown family'}).",
            "categories": [threat] if threat else [],
            "malware_families": [malware] if malware else [],
            "mitre_techniques": ["T1071"] if threat == "botnet_cc" else [],
            "first_seen": str(record.get("first_seen") or ""),
            "last_seen": str(record.get("last_seen") or record.get("first_seen") or ""),
            "valid_until": valid_until,
            "tlp": "TLP:CLEAR",
            "references": [str(record.get("reference"))] if record.get("reference") else [],
        }
        previous = indicators.get((kind, value.lower()))
        if previous is None or confidence > previous["confidence"]:
            indicators[(kind, value.lower())] = indicator
    return sorted(indicators.values(), key=lambda item: (item["type"], item["value"])), skipped


FEED_FILES = {
    "feodo": "abusech-feodo.json",
    "blocklist": "blocklistde.json",
    "threatfox": "abusech-threatfox.json",
}
STATUS_FILE = ".import-status"  # no .json: the feed loader reads every *.json


def record_status(directory: Path, results: dict[str, dict]) -> None:
    """Merge this run's outcome per feed into the hidden status file."""
    path = directory / STATUS_FILE
    try:
        current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        current = {}
    feeds = current.get("feeds") if isinstance(current.get("feeds"), dict) else {}
    feeds.update(results)
    write_atomically(path, {"updated_at": datetime.now(timezone.utc).isoformat(), "feeds": feeds})


def run_feed(name: str, args: argparse.Namespace, now: datetime) -> dict:
    """Download, convert and write one feed; returns its status record."""
    output = args.dir / FEED_FILES[name]
    status = {"attempted_at": now.isoformat(), "file": FEED_FILES[name]}
    try:
        if name == "feodo":
            records = json.loads(fetch(FEODO_URL, args.timeout))
            if not isinstance(records, list):
                raise ValueError("expected a JSON array")
            indicators, skipped = convert(records, now=now, ttl_days=args.ttl_days)
            meta = (FEED_NAME, "Botnet C2 IP addresses from abuse.ch Feodo Tracker.", FEODO_URL)
        elif name == "blocklist":
            lists = {}
            for list_name in BLOCKLIST_LISTS:
                lists[list_name] = fetch(BLOCKLIST_URL.format(name=list_name), args.timeout).decode("utf-8", "replace")
            indicators, skipped = convert_blocklist(lists, now=now)
            meta = (BLOCKLIST_FEED, "Addresses blocklist.de saw attacking in the last 48 hours (suspicious, not proof).",
                    BLOCKLIST_URL.format(name="{" + ",".join(BLOCKLIST_LISTS) + "}"))
        else:
            key = threatfox_key(args.env_file)
            if not key:
                status.update(state="no_key", message="THREATFOX_AUTH_KEY is not set; skipped")
                print(f"{name}: skipped (no THREATFOX_AUTH_KEY)")
                return status
            indicators, skipped = convert_threatfox(fetch_threatfox(key, args.timeout), now=now, ttl_days=args.ttl_days)
            meta = (THREATFOX_FEED, f"Malware infrastructure IOCs from abuse.ch ThreatFox, last {THREATFOX_DAYS} days.",
                    THREATFOX_API)
    except (OSError, ValueError) as exc:
        status.update(state="error", message=str(exc)[:200])
        print(f"{name}: error: {exc}", file=sys.stderr)
        return status

    print(f"{name}: {len(indicators)} indicators ({skipped} skipped)")
    if len(indicators) < MINIMUM_INDICATORS:
        status.update(state="empty", message="no usable indicators; the previous file was kept")
        return status
    status.update(state="ok", indicators=len(indicators))
    if not args.dry_run:
        write_atomically(output, {
            "source": meta[0],
            "description": meta[1] + " Imported by tools/import_cti.py. Matches are external context, not proof.",
            "generated_at": now.isoformat(),
            "source_url": meta[2],
            "indicators": indicators,
        })
        print(f"wrote {output}")
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=FEODO_URL)
    parser.add_argument("--input", type=Path, help="convert a saved feed instead of downloading")
    parser.add_argument("--ttl-days", type=int, default=7,
                        help="indicators expire this many days after import unless refreshed")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--feed", choices=["all", *FEED_FILES], default="all")
    parser.add_argument("--dir", type=Path, default=DEFAULT_OUTPUT.parent,
                        help="where each feed's file is written (all-feeds mode)")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_OUTPUT.parents[2] / ".env",
                        help="read THREATFOX_AUTH_KEY from this file when it is not in the environment")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    # Several feeds, each into its own file (the daily cron job).
    if args.input is None and args.output is None:
        now = datetime.now(timezone.utc)
        names = list(FEED_FILES) if args.feed == "all" else [args.feed]
        results = {name: run_feed(name, args, now) for name in names}
        if not args.dry_run:
            record_status(args.dir, results)
        return 0 if any(result.get("state") == "ok" for result in results.values()) else 1

    # One Feodo file, from a saved copy or a given output path.
    args.output = args.output or DEFAULT_OUTPUT

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
