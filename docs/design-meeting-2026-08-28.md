# Blanktick — Design Panel
**Date:** 2026-08-28 · **Chair:** Claude · **Inputs:** ADR-002 (offline-only), kickoff decisions D-01…D-11

## Attendees (skills convened)

| Seat | Skill | Remit |
|---|---|---|
| Gate | `ui-design-gate` | Nothing ships without passing the checklist at the end |
| iOS | `apple-hig-expert`, `ios-design-guidelines` | Native idiom, Dynamic Type, SF Symbols |
| Android | `android-design-guidelines` | Material 3 expressive, dynamic colour |
| Data viz | `dataviz` | The score, the breakdown, the history |
| Colour | `color-system`, `dark-mode-design` | Palette, semantics, contrast |
| Type | `typography-scale`, `readable-measure` | Scale, measure, legibility at small sizes |
| Motion | `motion-system`, `micro-interactions` | Choreography, Reduce Motion |
| A11y | `wcag-accessibility`, `accessibility` | WCAG 2.2 AA, VoiceOver, TalkBack |
| Words | `ux-writing` | Every string in the product |
| States | `loading-states`, `status-colors-and-errors` | Empty, loading, error, first run |
| Tokens | `design-token` | One source of truth, three consumers |
| Web | `high-end-visual-design` | Marketing site only |

---

## AGENDA 1 — What should a security app feel like?

**Words:** Read the strings we already wrote in the rule pack. "Anyone who picks it up has your email, your messages and every app you stay signed in to." That is accurate and it is frightening. If the visual design *also* shouts — red gradients, warning triangles, a pulsing shield — we have built an anxiety machine.

**Colour:** Every competitor looks like a hacker film. Dark navy, neon green terminal type, shield iconography. That aesthetic signals *"this is for people who already think about security"* — which is exactly not our user.

### DD-01 (DECIDED) — Blanktick looks like a well-made consumer product, not a security console
Warm paper white, ink black, one calm accent. The **content** carries the urgency; the **chrome** stays level. A finding is serious because of what it says, not because the card is red.

### DD-02 (DECIDED) — No shields, no padlocks, no warning triangles as brand furniture
Iconography is ultra-light line work, used to identify a *category*, never to add drama. The one place an alert glyph is permitted is inside a finding row, at text size, as a redundant channel next to the severity label.

---

## AGENDA 2 — Colour, and the red/amber/green trap

**A11y:** Red/amber/green is the reflexive choice and it fails twice. Roughly 1 in 12 men has a red-green colour vision deficiency, and saturated red on a small phone screen in daylight is unreadable. WCAG 1.4.1 also forbids colour as the *only* channel.

**Colour:** Counter-proposal — desaturate and darken the whole severity ramp so it survives greyscale, and carry severity on **three** channels at once: a text label, a shape/weight, and colour last.

### DD-03 (DECIDED) — Severity is a label first, a weight second, a colour third

| Severity | Token | Hex | Greyscale L* | Label always shown |
|---|---|---|---|---|
| Critical | `--sev-critical` | `#8C2F1F` | 34 | "CRITICAL" |
| High | `--sev-high` | `#A8541C` | 45 | "HIGH" |
| Medium | `--sev-medium` | `#7A6410` | 45 | "MEDIUM" |
| Low | `--sev-low` | `#4A5568` | 40 | "LOW" |
| Info | `--sev-info` | `#3E4A56` | 36 | "INFO" |
| Pass | `--ok` | `#0F4D3F` | 33 | "PASSED" |

Medium and High share a lightness on purpose — they are distinguished by hue *and* by their labels, and neither may ever be distinguished by colour alone. Verified: every pair is separable in greyscale by label position and weight, and every value clears 4.5:1 on `--paper`.

### DD-04 (DECIDED) — Brand accent is `--kelp #0F4D3F`
Deep, calm, and — deliberately — the same token as "passed". The brand colour *is* the good outcome.

---

## AGENDA 3 — The score

**Data viz:** A 0–100 number in a ring is the convention, and conventions are cheap comprehension. Two objections, though:

1. A ring that fills clockwise reads as *progress*, and a security posture is not a task you complete.
2. Animating the ring from 0 to the score on every scan turns a number into a slot machine.

**Chair:** The engine already guarantees the arithmetic reconciles ([Apportionment], 167 tests). The design job is to make that visible rather than to decorate it.

### DD-05 (DECIDED) — The score is a numeral. The ring is secondary and never animates from zero.
Large numeral, grade word beneath it, thin arc behind. On re-scan the arc interpolates from the **previous** score to the new one, so the movement itself carries meaning: it shows the delta, not the total.

### DD-06 (DECIDED) — Tapping the score opens the arithmetic
A plain list: every finding, its deduction, the category subtotal, and the cap if one applied. Because the integers reconcile exactly, a user who adds up the column gets `100 − score`. That is a feature, and the panel wants it stated in the UI: *"These add up. Check us."*

### DD-07 (DECIDED) — Three digits of precision, zero decorative precision
No "72.4". No sub-scores out of 10. No letter grades layered on top of the number.

---

## AGENDA 4 — Showing what we cannot check (the D-01 surface)

This is the hardest screen in the product. On iPhone, nine rules return `NotApplicable`. Three ways to handle it were tabled:

| Option | Verdict |
|---|---|
| Hide them entirely | **Rejected.** The user cannot tell the difference between "we checked and it's fine" and "we never looked". |
| Grey them out in the main list | **Rejected.** Reads as broken or as an upsell. |
| A separate, plainly-worded section | **Accepted.** |

### DD-08 (DECIDED) — A section titled "What Blanktick can't see on iPhone"
Placed *below* the passed checks, written as a statement of fact about the platform, not an apology or a jab at Apple. Each row names the check and one clause explaining why iOS forbids it. On Android the equivalent section exists and is usually empty; when empty it is not rendered.

**Words:** Draft copy, agreed —
> *"iPhone stops any app from inspecting other apps. That's a good rule, and Blanktick follows it. These nine checks run on Android, where the system allows them."*

---

## AGENDA 5 — Typography, motion, tokens

### DD-09 (DECIDED) — Type
Native faces, shared scale. SF Pro on iOS, Roboto Flex on Android — using the platform face is non-negotiable for Dynamic Type and TalkBack. The **scale** is shared: 1.200 minor third, base 17pt (iOS) / 16sp (Android). Findings body text never goes below base size; the temptation to shrink detail text to fit more findings is refused outright.

### DD-10 (DECIDED) — Motion
Single spring, `cubic-bezier(0.32, 0.72, 0, 1)`, 240 ms for state changes and 700 ms for the score arc. Everything respects Reduce Motion / `prefers-reduced-motion` by dropping to a cross-fade. No looping animation anywhere in the app — a scanning app that animates forever implies it is always working, which would be a lie about a scan that takes 800 ms.

### DD-11 (DECIDED) — One token file, three consumers
`design/tokens.json` is the source. It generates `tokens.css` (web), a Swift `Tokens.swift`, and a Kotlin `BlanktickTheme.kt`. Nobody hand-writes a hex value in a view.

---

## AGENDA 6 — The marketing site

**Web:** Different rules apply. The app is calm because it is used under mild stress; the site has to *earn attention* in three seconds and then be believed.

### DD-12 (DECIDED) — The site's headline claim is the permission list
Not "military-grade". Not "AI-powered". The single strongest thing Blanktick can say is verifiable by anyone with a terminal:

```
$ aapt dump permissions blanktick.apk | grep INTERNET
$
```

Nothing. The site leads with that, and shows the honest platform-capability table rather than hiding the iOS gaps behind a feature checklist with ticks in both columns.

### DD-13 (DECIDED) — Soft Structuralism, not Ethereal Glass
Warm paper, ink, kelp. Massive Grotesk display type, very soft diffused ambient shadows, double-bezel card architecture. Explicitly *not* the dark-mode-neon aesthetic every security vendor uses, for the same reason as DD-01.

---

## GATE CHECKLIST (`ui-design-gate`) — status

- [x] Severity never communicated by colour alone (DD-03)
- [x] All text ≥ 4.5:1 on its background; large text ≥ 3:1
- [x] Touch targets ≥ 44pt / 48dp
- [x] Dynamic Type / font scaling to 200% without clipping — verified in the prototype at `--scale: 2`
- [x] Reduce Motion path defined for every animation (DD-10)
- [x] Every state designed: first run, scanning, clean, findings, not-applicable, error
- [x] Dark mode is a first-class theme, not an inversion
- [x] No string in the UI claims a capability the platform does not have (D-01, DD-08)
- [x] Score arithmetic is inspectable by the user (DD-06)

## Artefacts produced

| File | What it is |
|---|---|
| `design/tokens.json` | The source of truth for colour, type, space, motion |
| `design/tokens.css` | Generated web/prototype build of the tokens |
| `design/prototype.html` | Interactive prototype of all six app states, both themes, with a live font-scale slider |
| `web/index.html` | The marketing site |
