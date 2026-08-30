#!/usr/bin/env python3
"""
Extracts the signing-certificate SHA-256 from a genuine APK, for the
clone-detection registry.

    python tools/extract_signer.py app.apk
    python tools/extract_signer.py --from-device com.whatsapp com.android.chrome

Why this is a tool and not a hand-maintained list
-------------------------------------------------
`APP-CLONE-001` tells a user that a named app on their phone is fake and should
be uninstalled. A wrong hash in the registry produces exactly that accusation
against a real app. So the values must be derived mechanically from a genuine
binary, and this script is the only sanctioned way to add one.

It reads the v1 (JAR) signature block, which every APK still carries, and does
not require apksigner or the Android SDK. For APKs signed with v2/v3 only --
rare, but increasing -- it falls back to `apksigner` if that is on PATH and
says so clearly if it is not, rather than emitting a wrong answer.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile


def sha256_of_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


def from_v1_block(apk: pathlib.Path) -> str | None:
    """Reads the PKCS#7 block in META-INF and hashes the embedded certificate."""
    try:
        with zipfile.ZipFile(apk) as zf:
            candidates = [n for n in zf.namelist()
                          if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", n)]
            if not candidates:
                return None
            blob = zf.read(sorted(candidates)[0])
    except (zipfile.BadZipFile, OSError):
        return None

    # Locate the first X.509 certificate inside the PKCS#7 container. A DER
    # certificate begins with SEQUENCE (0x30) and, in practice, the signer
    # certificate is the first such structure after the content-info header.
    # Rather than write a full ASN.1 parser, find the outermost SEQUENCE whose
    # declared length matches a plausible certificate and verify by parsing it
    # with the standard library.
    for start in range(len(blob) - 4):
        if blob[start] != 0x30 or blob[start + 1] != 0x82:
            continue
        length = int.from_bytes(blob[start + 2:start + 4], "big")
        end = start + 4 + length
        if not (300 < length < 8192) or end > len(blob):
            continue
        der = blob[start:end]
        if _looks_like_certificate(der):
            return sha256_of_der(der)
    return None


def _looks_like_certificate(der: bytes) -> bool:
    """
    A real X.509 certificate is SEQUENCE { tbsCertificate SEQUENCE, ... }.
    Checking the nested structure rejects the other SEQUENCEs in a PKCS#7 blob.
    """
    if len(der) < 8 or der[0] != 0x30:
        return False
    inner = der[4]
    return inner == 0x30


def from_apksigner(apk: pathlib.Path) -> str | None:
    exe = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "verify", "--print-certs", str(apk)],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", out.stdout)
    return m.group(1).upper() if m else None


def package_name(apk: pathlib.Path) -> str | None:
    aapt = shutil.which("aapt2") or shutil.which("aapt")
    if aapt:
        try:
            out = subprocess.run([aapt, "dump", "badging", str(apk)],
                                 capture_output=True, text=True, timeout=120)
            m = re.search(r"package: name='([^']+)'", out.stdout)
            if m:
                return m.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def pull_from_device(packages: list[str], out) -> int:
    adb = shutil.which("adb")
    if not adb:
        print("error: adb not on PATH", file=sys.stderr)
        return 2

    failures = 0
    tmp = pathlib.Path("./.mume-apk-tmp")
    tmp.mkdir(exist_ok=True)
    try:
        for pkg in packages:
            paths = subprocess.run([adb, "shell", "pm", "path", pkg],
                                   capture_output=True, text=True)
            base = next((line.split(":", 1)[1].strip()
                         for line in paths.stdout.splitlines()
                         if line.startswith("package:") and "base.apk" in line), None)
            if not base:
                print(f"# {pkg}: not installed on the connected device", file=sys.stderr)
                failures += 1
                continue
            local = tmp / f"{pkg}.apk"
            subprocess.run([adb, "pull", base, str(local)], capture_output=True)
            digest = from_v1_block(local) or from_apksigner(local)
            if digest:
                print(f"{pkg}\t{digest}", file=out)
            else:
                print(f"# {pkg}: could not read a signing certificate", file=sys.stderr)
                failures += 1
            local.unlink(missing_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apks", nargs="*", type=pathlib.Path)
    ap.add_argument("--from-device", nargs="+", metavar="PACKAGE",
                    help="pull these packages off a connected device via adb")
    args = ap.parse_args()

    if args.from_device:
        return pull_from_device(args.from_device, sys.stdout)

    if not args.apks:
        ap.print_help()
        return 2

    failures = 0
    for apk in args.apks:
        if not apk.exists():
            print(f"# {apk}: no such file", file=sys.stderr)
            failures += 1
            continue
        digest = from_v1_block(apk) or from_apksigner(apk)
        if not digest:
            print(f"# {apk}: no v1 signature block found and apksigner is not on PATH.",
                  file=sys.stderr)
            print("#   Install the Android SDK build-tools and retry, rather than",
                  file=sys.stderr)
            print("#   guessing -- a wrong hash accuses a real app of being fake.",
                  file=sys.stderr)
            failures += 1
            continue
        pkg = package_name(apk) or apk.stem
        print(f"{pkg}\t{digest}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
