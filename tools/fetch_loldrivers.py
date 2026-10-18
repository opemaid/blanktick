#!/usr/bin/env python3
"""Fetch the LOLDrivers corpus for the BYOVD check (DSK-DRV-001).

This is a BUILD-TIME tool and the one place a network call is allowed: Blanktick
itself never touches the network, but the bundled threat data has to come from
somewhere, exactly as the password and domain corpora do. It downloads the
community LOLDrivers list and caches it under tools/seeds/, which
`build_intel.py --drivers` then turns into the offline `drivers.mus` hash set.

    python tools/fetch_loldrivers.py
    python tools/build_intel.py --demo --drivers tools/seeds/loldrivers.json \
        --out desktop/src/main/resources/intel

Source: https://www.loldrivers.io/api/drivers.json  (magicsword-io/LOLDrivers).
The file is a JSON array of driver entries; each entry's KnownVulnerableSamples
carry the SHA256 of every known sample. We cache the raw JSON verbatim so the
exact provenance is auditable, and build_intel.py does the extraction.
"""
from __future__ import annotations

import pathlib
import sys
import urllib.request

URL = "https://www.loldrivers.io/api/drivers.json"
SEEDS = pathlib.Path(__file__).resolve().parent / "seeds"
OUT = SEEDS / "loldrivers.json"


def main() -> int:
    SEEDS.mkdir(parents=True, exist_ok=True)
    print(f"Fetching {URL} ...")
    req = urllib.request.Request(URL, headers={"User-Agent": "blanktick-intel-build"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
    except Exception as exc:  # noqa: BLE001 - a build tool, report and stop
        print(f"  failed: {exc}", file=sys.stderr)
        return 1

    # Sanity-check it parses and looks like the corpus before overwriting.
    import json

    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as exc:
        print(f"  not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(parsed, list) or not parsed:
        print("  unexpected shape: expected a non-empty JSON array", file=sys.stderr)
        return 1

    samples = sum(len(e.get("KnownVulnerableSamples") or []) for e in parsed)
    OUT.write_bytes(data)
    print(f"  {len(parsed):,} driver entries, {samples:,} samples -> {OUT}")
    print(f"  {len(data) / 1_048_576:.1f} MiB cached")
    print("Next: python tools/build_intel.py --demo --drivers "
          f"{OUT} --out desktop/src/main/resources/intel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
