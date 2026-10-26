# Blanktick — "Which tick?" (30 s, 16:9, for Google Veo / Flow)

Replaces `Downloads\Untitled video (3).mp4`.

## Why the old video has to go

- **The logo is wrong.** It shows a blue shield. The brand is the broken (severed) tick in dark green on cream. The brand rules say no shield.
- **The on-screen words are gibberish.** The generator invented them: "Blanking your fesakt!" and "Honting four lerne!".
- **It makes claims the website says are false.**
  - "Protected — all threats neutralized". Blanktick is not an antivirus. It removes nothing and never changes a setting.
  - Monsters being blasted away. Blanktick reports what it finds; it doesn't fight anything.
- **It's a generic neon cyber look.** The website and app are now warm paper, ink and kelp green.

## Visual rules for every shot (paste into every prompt)

> Style: calm, premium, editorial product film. Warm cream paper background (#FBFAF6), near-black ink (#17191B), one brand colour: deep kelp green (#0F4D3F). Soft natural daylight, matte paper textures, fine dot-grid like engineering paper, crisp shadows, shallow depth of field. No neon, no glow, no blue, no shields, no monsters, no padlocks, no hackers in hoodies. Avoid all readable text and logos in the image.

**Rule:** leave all words to the edit (Google Vids, CapCut or similar). Veo garbles lettering, so never ask it to write the brand name or the URL. That is exactly how "Honting four lerne!" happened.

**Brand assets in this folder:**

| File | Use it for |
|---|---|
| `logo-1024.png` | The severed tick. Use it as the reference image in Flow (Ingredients / Frames). |
| `endcard-1920x1080.png` | The final frame with the correct wordmark and "Download free at blanktick.org". Use it as the last 4 seconds, or as the end frame of shot 4. |

---

## Shot 1 — "We checked, it's fine" (0:00–0:08)

**Veo prompt**
> Close-up on a laptop screen in a dim, anonymous office. The screen shows a large glossy green checkmark on a plain background, gently pulsing, reassuring. Slow push-in toward the checkmark. Then the camera drifts past the edge of the laptop and reveals the back of the screen: the checkmark is just a sticker on an empty cardboard box — nothing is behind it. Subtle, wry, cinematic. Muted colours except the green tick. No readable text. Audio: quiet room tone, a soft "ding" when the tick appears, then silence on the reveal. A calm, warm narrator (male or female, mid-tempo, understated) says: "A green tick can mean 'we checked, it's fine.'… Or it can mean 'we never looked.'"

**On-screen text (add in the edit)**

| Time | Text |
|---|---|
| 0:01 | *"we checked, it's fine."* |
| 0:05 | *"we never looked."* |

Set both in italic serif, ink on cream.

---

## Shot 2 — The receipt (0:08–0:16)

**Veo prompt**
> Overhead shot of a warm cream paper desk with a faint dot grid. A long paper receipt slowly feeds out across the desk from the top of the frame, like a printout from a precise instrument. Printed on it, in neat rows, is a grid of small squares: the top rows are solid deep kelp-green squares each containing a white checkmark; the lower rows are empty squares outlined in black ink containing a hollow, broken checkmark with a gap in its long arm. Both kinds of square are the same size and equally sharp — neither is faded. Camera glides slowly along the receipt. Editorial, tactile, calm. No readable text. Audio: soft paper feed sound, a quiet mechanical tick for each row. Narrator: "Blanktick tells you which one you're looking at. What it checked — and, just as clearly, what it couldn't check, and why."

**On-screen text (add in the edit)**

| Time | Text |
|---|---|
| 0:10 | **50** checked |
| 0:10 | **31** couldn't be checked |

- Show the two figures side by side at **the same size**. Equal weight is the product's whole point.
- These are the numbers on the website's receipt (a real scan of the developer's laptop). Keep them identical to the site.

---

## Shot 3 — Offline, hands-off (0:16–0:24)

**Veo prompt**
> A clean Windows laptop on the same cream paper desk, morning light. A hand unplugs a network cable from the laptop and sets it neatly aside; the laptop keeps working calmly, a progress line moving on screen. Then the camera tilts down to the desk where the same broken kelp-green checkmark from the reference image is drawn in thick ink — the small gap in its long arm clearly visible, like an air gap. Slow, steady, reassuring. No readable text, no glow. Audio: the soft click of the cable, room tone, a single low piano note. Narrator: "It runs entirely on your computer. Nothing is uploaded. No account. And it never changes a setting — it just tells you the truth."

- **Reference image:** `logo-1024.png`
- **On-screen text (add in the edit), at 0:18:** OFFLINE · NO ACCOUNT · NEVER CHANGES A SETTING (mono caps, small)

---

## Shot 4 — End card (0:24–0:30)

**Option A (recommended): no generation.** Put `endcard-1920x1080.png` on screen for 6 s with a slow 3% zoom-in. It already carries the correct logo, "Download free at blanktick.org" and "Free · Open source · Offline · Windows".

**Option B:** use the end card as the **end frame** in Flow's Frames-to-Video with this prompt:
> The broken kelp-green checkmark draws itself stroke by stroke on cream paper with a dot grid, then settles beside the wordmark. Minimal, calm, premium. Camera locked off. Audio: one soft "tick" sound as the second stroke lands.

**Narrator (over either option):** "Blanktick. Free and open source, for Windows. Download free at blanktick.org."

---

## Full voice-over (about 28 s at a calm pace)

> A green tick can mean "we checked, it's fine." Or it can mean "we never looked."
> Blanktick tells you which one you're looking at. What it checked — and, just as clearly, what it couldn't check, and why.
> It runs entirely on your computer. Nothing is uploaded. No account. And it never changes a setting — it just tells you the truth.
> Blanktick. Free and open source, for Windows. Download free at blanktick.org.

To get one consistent voice, you can record or generate the voice-over separately (e.g. Google Vids' voice-over feature) and mute Veo's narration.

## Claims check — every line is on the live website

| Claim in the ad | Where the website says it |
|---|---|
| "free" | About section and footer: "Free. No ads, no account" |
| "open source" | AGPL-3.0, About and Terms |
| "for Windows" | Download section. Android is source-only and Mac/Linux aren't offered, so don't say "any device". |
| "Nothing is uploaded" | "Offline by construction" section, and the privacy policy |
| "never changes a setting" | "Blanktick reports; it never changes anything." |

**Do NOT say:** protects, blocks, removes, neutralizes, antivirus, "100% safe". The site explicitly says Blanktick is not an antivirus.

## Music

Sparse and warm, about 80–90 bpm: soft felt piano or plucked strings with a light ticking pulse. No EDM drops and no "cyber" synth risers.
