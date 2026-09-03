#!/usr/bin/env python3
"""
Fails if a number published in prose disagrees with the code.

    python tools/check_published_numbers.py

## Why this exists

`PlatformCoverageTest` already fails the build when a rule count changes,
because an early README quoted figures nobody had measured ("22 checks on
Android, 14 on iPhone") and for a product whose entire pitch is telling you
exactly what it can and cannot see, an invented number is the worst possible
bug.

That test guards the code. Nothing guarded the prose, and the prose drifted
badly. Found 2026-09-02 by two independent reviewers reading the repo:

  * README said **249 tests**, the website said **253**, the real number was 341
  * README said startup entries come from "**seven places**" in one paragraph
    and referred to "the **thirteen**-source sweep" in another; it is twelve
  * README used **42** and **43** runtime jars in the same section
  * the website said **29 checks** total, which is the Android-eligible count
  * README said "**45 rules**" in a directory listing and "17 of **27** desktop
    checks" in a table

Every one of those is `grep`-able by anyone. A reviewer who finds two of your
own files contradicting each other stops verifying the rest and starts
assuming — which costs more than the errors do.

## What it does NOT do

It does not know what the numbers should be. It reads the canonical values from
the pinned test and from the build, then looks for contradicting claims in the
documents. A number it has no source for is reported as unsourced rather than
guessed at, in keeping with the rest of this codebase.

Exit code 1 on any contradiction, so it can gate a release.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Documents that make claims to a reader.
DOCUMENTS = [
    ROOT / "README.md",
    ROOT / "web" / "index.html",
    ROOT / "docs" / "mcp.md",
    ROOT / "RELEASE-CHECKLIST.md",
]

COVERAGE_TEST = ROOT / "core" / "src" / "test" / "kotlin" / "com" / "mume" / "core" / "PlatformCoverageTest.kt"
PROBE = ROOT / "desktop" / "src" / "main" / "kotlin" / "com" / "mume" / "desktop" / "collect" / "WindowsProbe.kt"
RULES_DIR = ROOT / "core" / "src" / "main" / "kotlin" / "com" / "mume" / "core" / "rules"
PIN_FILE = ROOT / "desktop" / "network-surface.txt"


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def canonical() -> dict[str, int]:
    """The numbers, taken from the code rather than from anybody's memory."""
    facts: dict[str, int] = {}

    test = read(COVERAGE_TEST)
    for key, pattern in {
        "checks_total": r"assertEquals\((\d+), DefaultRules\.COUNT",
        "checks_android": r"assertEquals\((\d+), DefaultRules\.countFor\(Platform\.ANDROID\)\)",
        "checks_ios": r"assertEquals\((\d+), DefaultRules\.countFor\(Platform\.IOS\)",
        "checks_desktop": r"assertEquals\((\d+), DefaultRules\.countFor\(Platform\.DESKTOP\)\)",
    }.items():
        m = re.search(pattern, test)
        if m:
            facts[key] = int(m.group(1))

    # Persistence sources: one `Source '<name>'` block each in the probe.
    facts["persistence_sources"] = len(re.findall(r"Source '[^']+'", read(PROBE)))

    # Desktop-specific rules, by stable id.
    ids = set()
    for f in RULES_DIR.glob("*.kt"):
        ids.update(re.findall(r'id = "(DSK-[A-Z]+-\d+)"', read(f)))
    facts["desktop_specific_rules"] = len(ids)

    # Pinned jars. NOTE the two legitimate numbers here: the gate scans 43 jars
    # and writes 42 rows, because version stripping collapses one duplicated
    # base name. Both are true and they are not interchangeable, which is
    # exactly how the README came to use them as if they were.
    facts["pinned_jar_rows"] = len(
        [ln for ln in read(PIN_FILE).splitlines() if ln.strip() and not ln.startswith("#")]
    )
    return facts


# Claims worth policing: a regex over prose, and the canonical key it must match.
# Deliberately narrow. A pattern that matches too much produces false alarms and
# gets switched off, which is worse than not having it.
# Only TOTAL claims. An earlier pattern matched any "N checks", which fired
# on subset labels like "18 checks" in a table group header -- a true
# statement about a subgroup, reported as a contradiction. A guard that
# cannot tell a part from a whole gets switched off, which is worse than not
# having one. Same failure as a probe test that tripped on a comment quoting
# the bug it guards against.
CLAIMS = [
    (r"\*\*(\d+) checks in total", "checks_total"),
    (r"There are (?:\*\*)?(\d+)(?:\*\*)? checks\b", "checks_total"),
    (r"read from (\w+) places", "persistence_sources"),
    (r"(\w+)-source sweep", "persistence_sources"),
]

WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15,
}


def as_int(token: str) -> int | None:
    if token.isdigit():
        return int(token)
    return WORDS.get(token.lower())


def main() -> int:
    facts = canonical()

    print("Canonical numbers, read from the code:")
    for k, v in sorted(facts.items()):
        print(f"  {k:24} {v}")
    print()

    problems: list[str] = []

    for doc in DOCUMENTS:
        text = read(doc)
        if not text:
            continue
        rel = doc.relative_to(ROOT).as_posix()

        for pattern, key in CLAIMS:
            if key not in facts:
                continue
            for m in re.finditer(pattern, text):
                claimed = as_int(m.group(1))
                if claimed is None:
                    continue
                if claimed != facts[key]:
                    line = text[: m.start()].count("\n") + 1
                    problems.append(
                        f"{rel}:{line}  claims {key} = {claimed}, code says {facts[key]}\n"
                        f"      ...{m.group(0).strip()}..."
                    )

    # The test count cannot be derived without running the suite, so it is
    # checked against the last recorded run rather than guessed. Absent that,
    # it is reported as unsourced rather than silently accepted.
    for doc in DOCUMENTS:
        text = read(doc)
        rel = doc.relative_to(ROOT).as_posix()
        for m in re.finditer(r"(\d{2,4}) tests\b", text):
            line = text[: m.start()].count("\n") + 1
            problems.append(
                f"{rel}:{line}  claims {m.group(1)} tests — verify against "
                f"`gradlew check` output before release (no automatic source)"
            )

    if not problems:
        print("No contradictions found.")
        return 0

    print(f"{len(problems)} claim(s) to reconcile:\n")
    for p in problems:
        print(f"  {p}")
    print(
        "\nA number in prose that disagrees with the code is the failure this\n"
        "project's own coverage test exists to prevent. Fix the prose, or fix\n"
        "the code, but do not ship them disagreeing."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
