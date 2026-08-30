#!/usr/bin/env python3
"""
Fails if any CSS custom property the site uses is never defined.

    python tools/check_css_vars.py

## Why this exists

CSS custom properties are case-sensitive and `var(--missing)` is not an error.
It silently falls back to the inherited or initial value, so the page renders --
just with the wrong grey, or the wrong font -- and nothing anywhere says so.

The site was hand-written against camelCase names (`--inkMuted`,
`--surfaceSunk`, `--type-family-bodyWeb`) in some places and kebab-case
(`--ink-muted`, `--text-footnote`, `--font-mono`, `--pass-on-dark`) in others,
while `gen_tokens.py` emitted only one of the two spellings. Ten variables were
undefined from the day the site was built. Nobody noticed, because there is
nothing to notice: no console warning, no build failure, no visual glitch
obvious enough to chase.

This is the same failure the design panel found in the Kotlin emitter, where the
entire `elevation` group was generated to CSS and silently dropped from Kotlin.
A generator and its consumer disagreeing is not a rare accident -- it is the
default outcome unless something checks. So this checks.

Exit code 1 on any undefined variable, so it can gate a release.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Files that USE variables.
CONSUMERS = [
    ROOT / "web" / "styles.css",
    ROOT / "web" / "index.html",
    ROOT / "design" / "prototype.html",
]

# Files that DEFINE them. tokens.css is generated; the others may declare local
# ones inline.
DEFINERS = [
    ROOT / "design" / "tokens.css",
    ROOT / "web" / "styles.css",
    ROOT / "web" / "index.html",
    ROOT / "design" / "prototype.html",
]

# Set at runtime by script rather than declared in a stylesheet. Each entry needs
# a reason, so the allowlist cannot quietly become the place bugs go to hide.
RUNTIME_DEFINED = {
    "--scale": "prototype.html sets it from the text-size slider via JS",
}

USE = re.compile(r"var\(\s*(--[A-Za-z0-9_-]+)")
DEF = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def main() -> int:
    defined: set[str] = set()
    for path in DEFINERS:
        defined.update(DEF.findall(read(path)))

    missing: dict[str, list[str]] = {}
    for path in CONSUMERS:
        text = read(path)
        for name in USE.findall(text):
            if name in defined or name in RUNTIME_DEFINED:
                continue
            missing.setdefault(name, []).append(path.relative_to(ROOT).as_posix())

    total_used = len({n for p in CONSUMERS for n in USE.findall(read(p))})
    print(f"Checked {total_used} distinct custom properties across {len(CONSUMERS)} files.")

    if not missing:
        print(f"  all resolve ({len(RUNTIME_DEFINED)} allowed as runtime-defined)")
        return 0

    print(f"\n{len(missing)} used but never defined:\n")
    for name, files in sorted(missing.items()):
        print(f"  {name}")
        for f in sorted(set(files)):
            print(f"      used in {f}")
    print(
        "\nvar(--undefined) does not error -- it falls back to the inherited or\n"
        "initial value, so the page renders with the wrong colour or font and\n"
        "says nothing. Either add the token to design/tokens.json and re-run\n"
        "tools/gen_tokens.py, or fix the spelling at the call site."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
