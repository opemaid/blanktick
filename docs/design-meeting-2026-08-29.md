# Design panel — desktop dashboard

**Date:** 2026-08-29
**Panel:** information architecture · visual craft · accessibility & honesty · desktop platform reality
**Process:** `ui-design-gate` first, then four parallel reviewers each held to one lens, each required to invoke their specialist skills, be decisive with exact values, and **flag cross-lane collisions rather than resolve them**. The lead adjudicated on evidence.

Decisions DD-01…DD-13 (2026-08-28) were **not** reopened. The question put to the panel was narrower and harder: *does the shipped implementation actually deliver them?*

Mostly, it did not.

---

## What the panel found, and how it was verified

Every claim below was checked by the lead before being accepted. Two were rejected.

| # | Finding | How it was verified |
|---|---|---|
| 1 | **The severity rail never rendered.** `Modifier.width(3.dp).fillMaxSize()` on a `Row` child inside a `LazyColumn` item measures **3dp × 0dp** — the incoming `maxHeight` is `Constraints.Infinity` and Compose's fill modifiers no-op on an unbounded axis. | Cropped the shipped screenshot and sampled pixels along the card's left edge: pure `#FFFFFF` at every x. The only saturated pixel on the card was the `■` glyph. Present in **both** the desktop and Android builds. |
| 2 | **The whole `elevation` token group never reached Kotlin.** It is in `tokens.json`, generates 7 CSS variables, and the HTML prototype uses it correctly. The Kotlin emitter silently omitted it. | `grep -r 'shadowElevation\|tonalElevation\|Modifier.shadow' --include=*.kt` → **0 hits**. Same for `Radius.shell`, `Radius.core`, `TypeScale.display`, `TypeScale.title2`: generated, referenced nowhere. |
| 3 | **`tokens.json` asserted a contrast property it did not have.** The severity block claimed *"Every value below clears 4.5:1 on its paper."* `notChecked` measured **3.05:1** on paper and **2.79:1** on the nav rail. | Recomputed all 47 pairings independently. The accessibility reviewer reproduced the same numbers from the same formula. |
| 4 | **The ledger showed categories, not findings.** Both findings on the test machine are `NETWORK`, so DD-06's inspectable arithmetic rendered as a single row `Network −14` above two cards reading `−9` and `−5`. It also `return`ed early when there were no findings — deleting the arithmetic exactly when a user is most entitled to check nothing was hidden. | Read `Ledger()`: `result.categories.forEach`, and `if (result.actionableFindings.isEmpty()) return`. |
| 5 | **`LedgerNumberStyle`'s doc comment was false.** *"Monospaced, tabular style for anything the user might add up"* sat above `bodyMedium.copy(fontWeight = Bold)`. | `grep 'FontFamily.Monospace\|tnum\|tabular'` → the only hit was the comment. |
| 6 | **`▲` meant two opposite things.** `severityGlyph(HIGH)` returns `▲`; the score delta rendered `"▲ up $delta since last scan"`. Danger and improvement, same mark, 200px apart. | Read both. |
| 7 | **The dark ledger panel was invisible.** `kelpTint` was aliased to `Dark.surface`, and the reconciliation panel drew `kelpTint` on a card that was also `surface`. | Read `Theme.kt:116`. |
| 8 | **Finding detail rendered at 13.3sp** against a 16sp base — the exact temptation DD-09 refuses by name. | Read `Components.kt`. |
| 9 | **Hover and keyboard focus were pixel-identical.** Compose's default `LocalIndication` is `DefaultDebugIndication`, which draws the same black-10% rectangle for both, outside `Surface`'s clip layer, and invisible on dark. | Platform reviewer decompiled `foundation-desktop-1.9.0`; lead confirmed the class exists by name via `javap`. |
| 10 | **No scrollbar, no pointer cursor, no text selection, no window minimum.** The window could be dragged to 420×400 with the primary action off-screen. | Platform reviewer drove the running app with Win32 calls. |
| 11 | **The brief's "19 not checkable" was wrong — it is 28.** 19 came from an idealised test fixture; a real machine has more nulls. | The lead's own screenshot: *"2 of 17 checks"* and *"Passed 15 checks"*, and 45 − 17 = 28. |

---

## Adjudications

### DD-14 — `inkFaint` / `notChecked` is a split decision

The lead solved against three backgrounds; the accessibility reviewer solved against four and caught `kelpTint`. **Light takes their value.** For dark, a pure contrast solve lands at 5.84–6.33 against `inkMuted`'s 6.78 — a 0.94 gap that erases the ink hierarchy. **Dark takes the lead's value**, which passes everywhere at 4.53+ and keeps a 2.25 gap.

| | was | now | paper / surface / sunk |
|---|---|---|---|
| light | `#8B918F` | **`#666D6B`** | 5.03 / 5.30 / 4.61 |
| dark | `#6B726F` | **`#7A827E`** | 4.91 / 4.53 / 4.74 |

This matters beyond compliance: that grey carries the **null contract**. A product whose pitch is *"you can tell checked-and-fine from never-looked"* was rendering "never looked" as the faintest text on the page. Visual hierarchy is an assertion, and that one asserted the honest answer mattered least.

### DD-15 — The dark severity ramp is NOT re-spread. Rejected.

The accessibility reviewer reported 14 of 15 pairs collapsing under deuteranopia and proposed new `onDark` values for all six severities. The lead's independent Viénot simulation gave **7 of 15**, and their proposed ramp measured **worse** for deuteranopia (7 → 9) while improving protanopia (7 → 2).

Two simulation methods disagreeing is contested evidence, and DD-03 already makes colour the **third** channel behind label and glyph. A calm ramp and a dichromacy-legible one are not both achievable on near-black — the reviewer said so themselves. So the ramp stands and `tokens.json` now states plainly that in dark mode colour is decorative and label plus glyph carry severity.

**What was taken:** the token file must stop claiming properties nobody measured.

### DD-16 — Three regions, surplus width to the outer margin

Findings column capped at **680dp** (~85 characters; it was running ~180 at 1920). Coverage column 400dp at ≥1320dp, otherwise folded into the findings scroll. **Status sidebar 300–320dp that does not scroll**, carrying score, census, the full ledger and "Scan again".

First attempt gave the findings region `weight(1f)`, which put ~210dp of dead space between the last word of a finding and the ledger — the same empty-middle problem, moved. Surplus now goes to the outer margin.

### DD-17 — The score is a 270° gauge, not a ring

168dp box (was 200), 2.5dp stroke (was 6), open at the bottom, numeral up one rung to 99.1sp. The numeral now occupies ~71% of the dial rather than ~50%, which makes DD-05's "numeral primary, arc secondary" a measurement instead of an assertion. A *closed* ring reads as a task nearing completion; a security posture is not a task you finish.

Animation drops 700ms → **320ms** on DD-10's spring — which was defined in `tokens.json` and never generated, so every animation had silently been running Compose's default easing.

### DD-18 — "Not checkable" is split by cause

`RuleReport` now carries `eligibleOnPlatform`, so the UI can separate:

- **Written for a phone — 18.** Permanent, identical on every scan of every computer. Collapsed, count always on the header.
- **This computer wouldn't answer — 10.** Machine-specific, can change. Always expanded and itemised.

Reporting 28 checks as one undifferentiated "could not run" was the honest floor. This is the honest answer. The count stays in the announced sentence — the null contract must not be dropped from the audio channel the way it was from the visual one.

### DD-19 — Hover is a fill, focus is an outline

Not a style preference: the framework default makes them byte-identical, so a keyboard user cannot locate focus while a mouse is on screen. Indication is disabled and replaced with two channels that cannot be confused, plus `pointerHoverIcon(Hand)`. New tokens `light/dark.focus`. The nav rail's selected state gains a 3dp kelp leading bar (8.49:1) because the white-on-`surfaceSunk` fill alone was **1.15:1** against 1.4.11's 3:1.

### DD-20 — The desktop display face is resolved at runtime, not hard-coded

The panel recommended binding `Segoe UI Variable Display`. `GraphicsEnvironment` on the development machine lists `Segoe UI Variable` but **not** that name — Windows exposes optical sizes as named instances inside one variable family and AWT surfaces only the family. Asking for a missing family gets silently substituted, so hard-coding it would have produced a *different* font from the one intended with nothing reporting it. The list is probed at runtime and the first installed entry wins.

The reviewer had flagged their own claim as inferred from a screenshot. It was, and it did not survive.

---

## Corrections to things previously stated

**The dependency gate did not do what the README said it did.** `auditDependencyNetworkSurface` recorded only jars *containing* networking code, so a new dependency with none produced an identical file and passed silently. "The gate will catch it" was a false assurance for exactly the case a human should review. It now pins **all 42** runtime jars and flags the networking ones separately. Caught by the platform reviewer.

**The window opened 26% shorter than intended.** `GraphicsEnvironment.maximumWindowBounds` is already in logical units (1536×816 here, not 1920×1080); dividing by `scaleY` applied the DPI scale twice. 613dp of usable height instead of 776.

---

## Still open

- **A three-column layout does not fit a 1920×1080 display at 125% scaling.** Content width after the rail is ~1232dp; three columns need ~1480dp. Two-column is correct there, and coverage folds into the findings scroll. The 1320dp branch is written and only engages on a wider display — **it has not been seen rendering.**
- **Reduce-motion cannot be read on Compose Desktop.** Verified two ways: `AccessibilityManager` exposes only `calculateRecommendedTimeoutMillis`, and AWT surfaces no animation desktop property on Windows. `REDUCED_MS` is now generated, but nothing can consult the OS preference. Mitigated by keeping animation at 320ms and non-positional; a future in-app switch is the honest alternative. **Gate checklist line 5 should be untucked until then.**
- **200% text scaling is unverified on desktop.** The gate checklist ticks it on evidence from the HTML prototype, not the Compose app. `LocalDensity.fontScale` is 1.0 and nothing sets it.
- **Mixed Compose versions:** `ui`/`foundation` resolve to 1.9.0, `material3` to 1.8.2.
- The macOS and Linux collectors remain written-but-unrun; none of this changes that.
