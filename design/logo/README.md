# Blanktick logo

**Concept.** A checkmark that passes a security check, with the long arm
deliberately **severed**. The gap *is* the air gap — the product's one promise
(no network) drawn into the mark. Brutalist, matching the existing brand: sharp
butt-cap strokes, no radius, no shadow; the acid accent appears only on the
verified mark, never on type.

**Palette** (from `design/tokens`):
- Background `#0A0A0A` · Ink `#FFFFFF` · Accent `#D6FF3F`
- Wordmark uses the grey ramp, not colour: `blank` muted, `tick` full ink.

## Files

| File | Use |
|---|---|
| `blanktick-icon.svg` | App icon / favicon — solid dark square + accent tick. Master. |
| `blanktick-mark-accent.svg` | Mark only, accent, transparent — for dark surfaces. |
| `blanktick-mark-ink.svg` | Mark only, ink — for light surfaces. |
| `blanktick-mark-mono.svg` | Mark in `currentColor` — recolours when **inlined** (not via `<img>`). |
| `blanktick-lockup-dark.svg` | Mark + wordmark, for dark. |
| `blanktick-lockup-light.svg` | Mark + wordmark, for light. |
| `blanktick-icon-512.png` | 512 raster (stores, social). |
| `blanktick-icon-180.png` | Apple touch icon. |
| `blanktick-favicon-32.png` | Favicon. |
| `preview.html` | Open to review every variant on light/dark at real sizes. |

## Notes
- **Outline the wordmark** (convert text to paths) before shipping the lockups,
  so rendering does not depend on Inter being installed.
- At 16px the severed gap is barely visible; that is expected. Use the solid
  `blanktick-icon.svg` for favicons, not the bare mark.
- Need more PNG sizes or an `.ico`? Re-render from `blanktick-icon.svg`.

Generated 2026-10-01. AI image generation was not used (its API keys were absent,
and a geometric mark is better authored as exact vector anyway).
