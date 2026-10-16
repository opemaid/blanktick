#!/usr/bin/env python3
"""
Builds the intel bundle that ships inside the Blanktick APK.

    python tools/build_intel.py --demo
    python tools/build_intel.py --passwords pwned-top10m.txt --domains hosts.txt

Build-time only. The app never runs this and never fetches its output -- the
files land in `app/src/main/assets/intel/` and are packaged uncompressed so the
device can map them rather than copy 20 MB onto the heap.

Sizing
------
    passwords.mub    2,000,000 entries, Bloom, p=0.1%    3.4 MiB
    blocklist.mus    2,000,000 domains, exact u64       15.3 MiB
    allowlist.mus      200,000 domains, exact u64        1.5 MiB
    signers.txt         known-good signing certs         0.3 MiB
                                                        --------
                                                        ~20.5 MiB

Breached-password reuse is brutally long-tailed, so the top 2M covers
essentially every real case; raising it to 10M costs 14 MiB and buys very
little. It also does nothing about the actual limitation, which is freshness --
it just makes the install heavier for people on expensive mobile data. For a
free consumer app that is the wrong trade.

Both limits are flags, so the decision is one line either way:

    python tools/build_intel.py --password-limit 10000000 --domain-limit 4000000

Two structures, on purpose
--------------------------
Passwords use a Bloom filter because its only error is a FALSE POSITIVE -- we
tell someone to change a password that was actually fine. Annoying, harmless,
and the advice is still good. False negatives are impossible, so a breached
password can never be reported as safe.

Domains use an EXACT sorted-hash table because there the error runs the other
way: a false positive blocks a site the user needs, the feature looks broken,
they turn it off, and they lose all of its protection. There is no safe
direction to be wrong in, so we do not approximate.
"""

from __future__ import annotations

import argparse
import math
import pathlib
import random
import struct
import sys
from datetime import date

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from blanktick_hash import digest, h1, h2, normalize_domain, to_punycode  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "app" / "src" / "main" / "assets" / "intel"
SEEDS = ROOT / "tools" / "seeds"

MASK64 = 0xFFFFFFFFFFFFFFFF
LN2 = math.log(2)

DEFAULT_PASSWORD_FPR = 0.001


# --------------------------------------------------------------------- Bloom

class BloomBuilder:
    """Writes the `MUB1` format that `BloomFilter.parse` reads."""

    MAGIC = b"MUB1"
    VERSION = 1
    HEADER = 40

    def __init__(self, n: int, p: float) -> None:
        self.bit_count = max(1, round(math.ceil(-n * math.log(p) / (LN2 ** 2))))
        self.hash_count = max(1, min(64, round(self.bit_count / n * LN2)))
        self.words = (self.bit_count + 63) // 64
        self.bits = bytearray(self.words * 8)
        self.inserted = 0

    def add(self, value: str) -> None:
        a, b = h1(value), h2(value)
        probe = a
        m = self.bit_count
        for _ in range(self.hash_count):
            index = probe % m
            word, bit = divmod(index, 64)
            off = word * 8
            current = int.from_bytes(self.bits[off:off + 8], "little")
            self.bits[off:off + 8] = (current | (1 << bit)).to_bytes(8, "little")
            probe = (probe + b) & MASK64
        self.inserted += 1

    def serialize(self) -> bytes:
        checksum = _checksum(self.bits)
        header = (
            self.MAGIC
            + struct.pack("<I", self.VERSION)
            + struct.pack("<I", self.hash_count)
            + struct.pack("<I", 0)
            + struct.pack("<Q", self.bit_count)
            + struct.pack("<Q", self.inserted)
            + struct.pack("<Q", checksum)
        )
        assert len(header) == self.HEADER, len(header)
        return bytes(header) + bytes(self.bits)


# ---------------------------------------------------------- exact hash table

def build_sorted_set(values, *, normalize=True) -> bytes:
    """Writes the `MUS1` format that `SortedHashSet64.parse` reads."""
    seen = set()
    for raw in values:
        key = to_punycode(normalize_domain(raw)) if normalize else raw
        if key:
            seen.add(digest(key))
    ordered = sorted(seen)

    payload = bytearray()
    for d in ordered:
        payload += d.to_bytes(8, "little")

    header = (
        b"MUS1"
        + struct.pack("<I", 1)
        + struct.pack("<Q", len(ordered))
        + struct.pack("<Q", _checksum(payload))
    )
    assert len(header) == 24, len(header)
    return bytes(header) + bytes(payload)


def _checksum(payload: bytes | bytearray) -> int:
    """FNV-1a over the payload bytes. Mirrors `BloomFilter.checksumOf`."""
    h = 0xCBF29CE484222325
    for b in payload:
        h = ((h ^ b) * 0x100000001B3) & MASK64
    return h


# ------------------------------------------------------------------- sources

def read_lines(path: pathlib.Path):
    """
    Reads a source list, tolerating the formats these actually ship in:
    plain lists, `hosts` files (`0.0.0.0 domain`), and `#` comments.
    """
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith(("#", "!", ";")):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1"):
                yield parts[1]
            else:
                yield parts[0]


_HEX = set("0123456789abcdef")


def _looks_like_loldrivers(path: pathlib.Path) -> bool:
    """True when the file is the LOLDrivers JSON corpus rather than a hash list.

    Checked by content, not just suffix, so a `.txt` export of the JSON or a
    `.json` of bare hashes are both handled correctly: a LOLDrivers dump starts
    with a JSON array/object, a hash list starts with hex.
    """
    if path.suffix.lower() == ".json":
        return True
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(256).lstrip()
    return head.startswith(("[", "{"))


def loldrivers_hashes(path: pathlib.Path) -> list[str]:
    """Every valid SHA-256 in a LOLDrivers `drivers.json` corpus, lowercased.

    Pulls `KnownVulnerableSamples[].SHA256` from each driver entry. Both the
    "vulnerable" and "malicious" categories are kept: a loaded driver matching
    either is worth telling the user about. Non-64-hex values (blanks, the
    occasional SHA1/MD5 landing in the wrong field) are dropped.
    """
    import json

    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    out: list[str] = []
    for entry in data if isinstance(data, list) else []:
        for sample in (entry.get("KnownVulnerableSamples") or []):
            h = str(sample.get("SHA256") or "").strip().lower()
            if len(h) == 64 and all(c in _HEX for c in h):
                out.append(h)
    return out


def synthetic_passwords(count: int, seed: int = 20260828):
    """
    Deterministic filler so the pipeline can be built and measured end to end
    without a 10 GB corpus present.

    These are NOT real breached passwords and the manifest records that the
    bundle is synthetic, so a demo build cannot be mistaken for a shipping one.
    """
    rng = random.Random(seed)
    words = ["love", "dragon", "qwerty", "summer", "monkey", "shadow", "master",
             "letmein", "sunshine", "princess", "football", "welcome", "admin",
             "soccer", "iloveyou", "trustno1", "batman", "superman", "hello"]
    for i in range(count):
        w = rng.choice(words)
        yield f"{w}{rng.randint(0, 9999)}{rng.choice(['', '!', '#', '@', '1'])}{i % 7 or ''}"


def synthetic_domains(count: int, seed: int = 828):
    rng = random.Random(seed)
    tlds = ["com", "net", "info", "top", "xyz", "click", "ru", "cn", "tk"]
    parts = ["ads", "track", "pixel", "metric", "click", "banner", "promo",
             "secure", "verify", "login", "account", "update", "billing"]
    for i in range(count):
        label = f"{rng.choice(parts)}{rng.choice(parts)}{i}"
        yield f"{label}.{rng.choice(tlds)}"


# ---------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--passwords", type=pathlib.Path,
                    help="one password per line, most common first")
    ap.add_argument("--domains", type=pathlib.Path,
                    help="blocklist: plain list or hosts-file format")
    ap.add_argument("--malware", type=pathlib.Path,
                    help="file of SHA-256 hashes, one per line, of known-malicious "
                         "files. Lines may be bare hex or CSV with the hash first; "
                         "anything that is not 64 hex characters is skipped.")
    ap.add_argument("--allowlist", type=pathlib.Path,
                    help="domains that must never be blocked")
    ap.add_argument("--drivers", type=pathlib.Path,
                    help="known-vulnerable kernel driver corpus (BYOVD). Accepts "
                         "EITHER the LOLDrivers drivers.json (fetch with "
                         "tools/fetch_loldrivers.py) — every KnownVulnerableSamples "
                         "SHA256 is pulled — OR a plain list of SHA-256 hashes, one "
                         "per line (bare hex or CSV, hash first). Omitted => no "
                         "drivers.mus is written and DSK-DRV-001 reports 'not "
                         "checkable' rather than a false pass.")
    ap.add_argument("--password-limit", type=int, default=2_000_000)
    ap.add_argument("--domain-limit", type=int, default=2_000_000)
    ap.add_argument("--fpr", type=float, default=DEFAULT_PASSWORD_FPR)
    ap.add_argument("--demo", action="store_true",
                    help="build a small synthetic bundle to prove the pipeline")
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    args = ap.parse_args()

    out: pathlib.Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    synthetic = False

    # ---- passwords -------------------------------------------------------
    if args.passwords and args.passwords.exists():
        source = read_lines(args.passwords)
        limit = args.password_limit
    elif args.demo:
        synthetic = True
        limit = 200_000
        source = synthetic_passwords(limit)
    else:
        print("error: --passwords is required (or use --demo)", file=sys.stderr)
        return 2

    # The seed list is always folded in, whatever the source. It gives a
    # developer build real entries and gives the cross-language parity test
    # deterministic vectors to assert on.
    seed_pw = SEEDS / "passwords-seed.txt"
    seeded = list(read_lines(seed_pw)) if seed_pw.exists() else []

    print(f"Building password filter (n<={limit:,}, p={args.fpr})…")
    bloom = BloomBuilder(limit + len(seeded), args.fpr)
    for pw in seeded:
        bloom.add(pw)
    for i, pw in enumerate(source):
        if i >= limit:
            break
        bloom.add(pw)
    blob = bloom.serialize()
    (out / "passwords.mub").write_bytes(blob)
    print(f"  {bloom.inserted:,} entries · k={bloom.hash_count} · "
          f"{bloom.bit_count:,} bits · {len(blob) / 1048576:.2f} MiB")

    # ---- blocklist -------------------------------------------------------
    if args.domains and args.domains.exists():
        domains = list(_take(read_lines(args.domains), args.domain_limit))
    elif args.demo:
        synthetic = True
        domains = list(synthetic_domains(50_000))
    else:
        domains = []

    seed_block = SEEDS / "blocklist-seed.txt"
    if seed_block.exists():
        domains += list(read_lines(seed_block))

    blob = build_sorted_set(domains)
    (out / "blocklist.mus").write_bytes(blob)
    print(f"Blocklist: {len(domains):,} input · {len(blob) / 1048576:.2f} MiB")

    # ---- allowlist -------------------------------------------------------
    allow = []
    if args.allowlist and args.allowlist.exists():
        allow = list(read_lines(args.allowlist))
    seed_allow = SEEDS / "allowlist-seed.txt"
    if seed_allow.exists():
        allow += list(read_lines(seed_allow))

    blob = build_sorted_set(allow)
    (out / "allowlist.mus").write_bytes(blob)
    print(f"Allowlist: {len(allow):,} input · {len(blob) / 1024:.1f} KiB")

    # ---- known-malware hashes --------------------------------------------
    #
    # ## Why an exact table and not a Bloom filter
    #
    # Passwords use a Bloom filter because its only error mode is a false
    # positive, and a false positive there says "change a password that was
    # actually fine" -- harmless. Here a false positive accuses a legitimate
    # program on someone's computer of being malware. That is the one output
    # this product must never produce by accident, so the same exact sorted-u64
    # table the domain blocklist uses is the right structure: no false
    # positives at all, at roughly 8 bytes per entry.
    #
    # 64-bit truncation is not a meaningful risk here. The chance that any
    # given legitimate file collides with any of a million entries is about
    # one in twenty trillion.
    #
    # ## The corpus is nobody's competitive advantage
    #
    # It is stale the moment it ships and it will never approach a real
    # antivirus. It is worth having because it costs 8 MiB and catches the
    # commodity case -- a file that has been sitting on disk unchanged since
    # somebody else already identified it. Recompiled or packed malware walks
    # straight past, and the app says so rather than implying coverage it does
    # not have.
    hashes = []
    if args.malware and args.malware.exists():
        for line in read_lines(args.malware):
            candidate = line.split(",")[0].strip().strip('"').lower()
            if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                hashes.append(candidate)

    # The EICAR test file, always. Not malware -- a 68-byte string every
    # scanner has agreed to recognise since 1991 -- and its presence means the
    # feature can be proven to work end to end by anyone, on any machine, with
    # no corpus and nothing dangerous on disk. A detection feature nobody can
    # verify is indistinguishable from one that does nothing.
    #
    # This value was computed from the published signature rather than copied:
    #   python -c "import hashlib;print(hashlib.sha256(EICAR.encode()).hexdigest())"
    hashes.append("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

    # normalize=False: these are already canonical lowercase hex, and the
    # domain normaliser would mangle them. The Kotlin side queries with
    # SortedHashSet64.contains(hex), which does not normalise either -- the two
    # have to agree, and this is the pair that agrees.
    blob = build_sorted_set(hashes, normalize=False)
    (out / "malware.mus").write_bytes(blob)
    print(f"Malware:   {len(hashes):,} hashes · {len(blob) / 1024:.1f} KiB"
          + ("  (EICAR only -- pass --malware to add a real corpus)"
             if len(hashes) == 1 else ""))

    # ---- known-vulnerable driver hashes (BYOVD) --------------------------
    #
    # Same exact-table structure and the same no-false-positive discipline as
    # the malware list, for the same reason: a false positive here calls a
    # legitimately signed driver on someone's machine exploitable.
    #
    # Unlike malware there is no universal benign test value (no "EICAR for
    # drivers"), so a synthetic build writes NOTHING here. An empty-but-present
    # corpus would make DSK-DRV-001 answer "no vulnerable drivers found" on a
    # machine where nothing was actually checked -- the false reassurance this
    # product exists to avoid. No file => the rule reports *not checkable*.
    driver_hashes = []
    if args.drivers and args.drivers.exists():
        if _looks_like_loldrivers(args.drivers):
            # The LOLDrivers corpus itself: a JSON array of drivers, each with a
            # KnownVulnerableSamples list carrying the SHA256 of every known
            # sample. Pull them all; dedup happens in build_sorted_set.
            driver_hashes = loldrivers_hashes(args.drivers)
            print(f"Drivers:   LOLDrivers corpus -> {len(driver_hashes):,} sample hashes")
        else:
            for line in read_lines(args.drivers):
                candidate = line.split(",")[0].strip().strip('"').lower()
                if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                    driver_hashes.append(candidate)
    if driver_hashes:
        dblob = build_sorted_set(driver_hashes, normalize=False)
        (out / "drivers.mus").write_bytes(dblob)
        print(f"Drivers:   {len(driver_hashes):,} hashes · {len(dblob) / 1024:.1f} KiB")
    else:
        # Remove any stale file so a demo build never ships a usable-looking
        # but empty corpus.
        (out / "drivers.mus").unlink(missing_ok=True)
        print("Drivers:   none (pass --drivers to add a BYOVD corpus; "
              "DSK-DRV-001 reports 'not checkable' without one)")

    # ---- signers ---------------------------------------------------------
    seed_signers = SEEDS / "signers-seed.txt"
    if seed_signers.exists():
        (out / "signers.txt").write_bytes(seed_signers.read_bytes())
        lines = sum(1 for line in seed_signers.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#"))
        print(f"Signers: {lines:,} packages")

    # ---- manifest --------------------------------------------------------
    #
    # A synthetic bundle is labelled as such. The app surfaces the build date
    # on every scan, and a demo build must not be able to masquerade as one
    # carrying real threat data.
    manifest = "\n".join([
        "# Generated by tools/build_intel.py. Do not edit.",
        f"builtOn={date.today().isoformat()}",
        f"passwords={bloom.inserted}",
        f"domains={len(domains)}",
        f"malware={len(hashes)}",
        f"drivers={len(driver_hashes)}",
        "version=1",
        f"synthetic={'true' if synthetic else 'false'}",
        "",
    ])
    (out / "manifest.txt").write_text(manifest, encoding="utf-8", newline="\n")

    total = sum(p.stat().st_size for p in out.iterdir() if p.is_file())
    print(f"\nBundle written to {out.relative_to(ROOT)}")
    print(f"Total: {total / 1048576:.2f} MiB")
    if synthetic:
        print("\n  NOTE: this bundle is SYNTHETIC. manifest.txt records synthetic=true.")
        print("  Supply --passwords and --domains with real corpora for a shipping build.")
    return 0


def _take(iterable, n):
    for i, v in enumerate(iterable):
        if i >= n:
            return
        yield v


if __name__ == "__main__":
    sys.exit(main())
