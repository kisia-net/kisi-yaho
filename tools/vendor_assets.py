#!/usr/bin/env python3
"""Download the browser libraries into static/vendor/.

The interface renders Markdown, sanitizes it, and highlights code with three
libraries that used to be loaded from a CDN. That does not work here: the
Content Security Policy allows scripts from 'self' only, so the browser blocks
them outright, and the deployment plan puts the web tier on an internal subnet
with no route to a CDN. Serving them from this origin fixes both.

    python tools/vendor_assets.py            # install
    python tools/vendor_assets.py --verify   # check against the lock file

Integrity: the first install records a SHA-256 for each file in
static/vendor/VENDOR.lock.json, and later runs verify against it. That detects
a file changing under you, but the first download is trust-on-first-use — it
cannot tell you the bytes were genuine to begin with. For a stronger guarantee
replace the digests with the ones published for each release and re-run
--verify; a mismatch then means the download did not match upstream.

Without these files the interface still works. Markdown degrades to escaped
plain text, which is safe but plainer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR_DIR = ROOT / "static" / "vendor"
LOCK_PATH = VENDOR_DIR / "VENDOR.lock.json"

# Pinned versions. Bumping one is a deliberate change: update the URL, delete
# its entry from the lock file, re-run, and commit the new digest.
ASSETS = {
    "marked.umd.js": {
        "url": "https://cdn.jsdelivr.net/npm/marked@18.0.7/lib/marked.umd.js",
        "purpose": "Markdown parsing",
        "license": "MIT",
    },
    "purify.min.js": {
        "url": "https://cdn.jsdelivr.net/npm/dompurify@3.4.12/dist/purify.min.js",
        "purpose": "HTML sanitization of parsed Markdown",
        "license": "Apache-2.0 OR MPL-2.0",
    },
    "highlight.min.js": {
        "url": "https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.11.1/build/highlight.min.js",
        "purpose": "Syntax highlighting in code blocks",
        "license": "BSD-3-Clause",
    },
}


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def load_lock() -> dict[str, dict[str, str]]:
    if not LOCK_PATH.is_file():
        return {}
    try:
        data = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def verify(lock: dict[str, dict[str, str]]) -> int:
    problems = 0
    for name in ASSETS:
        path = VENDOR_DIR / name
        recorded = (lock.get(name) or {}).get("sha256", "")
        if not path.is_file():
            print(f"  missing   {name}")
            problems += 1
            continue
        actual = digest(path.read_bytes())
        if not recorded:
            print(f"  unlocked  {name}  sha256={actual}")
            problems += 1
        elif actual != recorded:
            print(f"  MISMATCH  {name}")
            print(f"            expected {recorded}")
            print(f"            actual   {actual}")
            problems += 1
        else:
            print(f"  ok        {name}  ({len(path.read_bytes())} bytes)")
    return problems


def fetch(name: str, url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "hawki-vendor-assets"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - pinned https URLs
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return response.read()


def install(force: bool) -> int:
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    lock = load_lock()
    failures = 0

    for name, meta in ASSETS.items():
        path = VENDOR_DIR / name
        recorded = (lock.get(name) or {}).get("sha256", "")

        if path.is_file() and not force:
            actual = digest(path.read_bytes())
            if recorded and actual != recorded:
                print(f"  MISMATCH  {name} — delete it and re-run to reinstall")
                failures += 1
            else:
                print(f"  present   {name}")
                lock.setdefault(name, {"url": meta["url"], "sha256": actual})
            continue

        print(f"  fetching  {name}  <- {meta['url']}")
        try:
            payload = fetch(name, meta["url"])
        except (urllib.error.URLError, RuntimeError, OSError) as exc:
            print(f"  FAILED    {name}: {exc}")
            failures += 1
            continue

        actual = digest(payload)
        if recorded and actual != recorded:
            # The pinned URL returned different bytes than last time.
            print(f"  REFUSED   {name}: digest changed since the lock file was written")
            print(f"            expected {recorded}")
            print(f"            actual   {actual}")
            failures += 1
            continue

        path.write_bytes(payload)
        lock[name] = {"url": meta["url"], "sha256": actual, "license": meta["license"]}
        print(f"  installed {name}  ({len(payload)} bytes)")

    LOCK_PATH.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tools/vendor_assets.py",
        description="Install the browser libraries the interface loads from this origin.",
    )
    parser.add_argument("--verify", action="store_true", help="Check installed files against the lock file.")
    parser.add_argument("--force", action="store_true", help="Re-download even if a file is present.")
    args = parser.parse_args(argv)

    print(f"vendor directory: {VENDOR_DIR}")

    if args.verify:
        problems = verify(load_lock())
        if problems:
            print(f"\n{problems} problem(s). Run without --verify to install.")
            return 1
        print("\nAll vendored assets match the lock file.")
        return 0

    failures = install(args.force)
    print(f"\nlock file: {LOCK_PATH}")
    if failures:
        print(
            f"{failures} asset(s) could not be installed. The interface still runs — "
            "Markdown falls back to escaped plain text."
        )
        return 1
    print("Done. Restart the app so it picks up the new files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
