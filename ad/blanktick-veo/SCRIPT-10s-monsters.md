# Blanktick — "Monsters" (10 s) — shot-for-shot remake in the new colours

Source: `Downloads\Untitled video (3).mp4` (1920×1080, 30 fps, 10.0 s). Every shot below matches
the original second by second. Only three things change:

1. **The logo.** The blue shield with "Blanktick" becomes a thick **cream tile (#FBFAF6)** with the
   **kelp-green (#0F4D3F) broken tick** — `logo-1024.png`. No shield, no blue.
2. **The energy.** Electric-blue lightning becomes **cream-white energy with kelp-green edges**.
3. **The words.** The garbled captions ("Blanking your fesakt!", "Honting four lerne!") and the
   on-screen "Protected / All threats neutralized" are removed. Correct captions go in the edit.

Monsters, desk, PC, camera moves, pacing and the blast-them-away ending all stay the same.

## Shot list (matches the original)

| Sec | Original | Remake | Caption (edit) |
|---|---|---|---|
| 0 | Monsters swarm the gaming PC, red warnings on screen | Same | **Something's hiding on your PC.** |
| 1 | Orange monster leaps toward camera | Same | ↑ (hold) |
| 2 | Blue shield appears right, crackling | Cream tile with kelp tick appears right, glowing warm | **Blanktick** |
| 3 | Shield beside the PC, monsters still on it | Tile beside the PC | ↑ (hold) |
| 4 | Close-up: shield charging with lightning | Close-up: tile charging with cream-and-kelp energy | **Catches ransomware & hackers.** |
| 5 | Beams sweep out from the shield | Cream-and-kelp beams sweep out from the tile | ↑ (hold) |
| 6 | Beam blasts across the PC | Same blast, new colours | ↑ (hold) |
| 7 | Monsters blown off, breaking into pixels | Same | ↑ (hold) |
| 8 | Monitor: green "Protected" screen | Monitor turns cream with rows of kelp ticks — **no words on it** | **No fake green ticks.** |
| 9 | Shield logo end card | `endcard-1920x1080.png` | **Download free · blanktick.org** |

**Voice-over (optional, ~9 s):**
> Something's hiding on your PC. Blanktick catches ransomware and hackers. Download free at blanktick.org.

## How to make it in Google Flow / Veo

Veo makes 8-second clips, so build it as **clip A (0–8 s) + end card (8–10 s)**. Seconds 8 and 9 of the
original (monitor + logo) become: monitor in the last second of clip A, end card for 2 s.

**Best method — Frames to Video:** take the first frame of the original video as the start frame,
so Veo keeps the same room, PC and monsters:

```
ffmpeg -i "Untitled video (3).mp4" -frames:v 1 start-frame.png
```

Upload `start-frame.png` as the start frame and `logo-1024.png` as an Ingredient, then paste:

### Clip A prompt (8 s)

> Continue this exact scene. Dark gaming-desk room at night. Dozens of cute, fluffy, colourful cartoon monsters — orange, pink, purple, teal, lime — swarm the glowing gaming PC, monitor and keyboard, giggling, red warning triangles flashing on the monitor. At 1 second an orange furry monster leaps toward the camera. Pixar-style 3D.
>
> At 2 seconds, Blanktick's logo appears on the right of frame: a thick, matte cream-coloured square tile (#FBFAF6) with a bold deep kelp-green (#0F4D3F) checkmark whose long arm is broken by a small clean gap, exactly as in the reference image. Flat, sharp corners, not a shield, no blue. It glows with warm cream light.
>
> At 4 seconds, close-up on the tile as it charges with crackling cream-white energy with kelp-green edges. At 5 seconds it fires sweeping beams of that cream-and-kelp energy across the desk; at 6 seconds the blast hits the PC; at 7 seconds the monsters are blown off, tumbling and breaking apart into sparkling pixels, the red warnings switching off. In the final second, the monitor turns warm cream and shows neat rows of small kelp-green checkmarks.
>
> Camera: push-in, close-up on the tile, whip-pan along the blast — same moves as the original. Lighting: cool dark room; Blanktick's cream-and-green light is the only warm light. No readable text, no letters anywhere.
>
> Audio: monster giggles and chaos, a bright "ting" as the tile appears, rising energy hum, a big whoosh-boom for the blast, pops as monsters vanish, a calm resolved chord.
>
> Negative: shield, blue light, blue lightning, neon blue, padlock, text, letters, words, logo lettering.

Generate 3–4 takes. Keep the one where the tile is cream, the tick is green and nothing is blue.

### End card (8–10 s)

`endcard-1920x1080.png`, slow 3% zoom-in, one soft "tick" sound.
For 9:16 (TikTok / Reels / Shorts) centre it on a cream (#FBFAF6) background.

## Captions style

Bold white sans with a soft shadow, top-centre (same spot as the original captions). Spell-checked,
added in the editor — never typed into the Veo prompt.

## Words that stay out

"All threats neutralized", "Protected", "100% protected", "removes viruses", "replaces your antivirus".
The blast is the picture; the caption carries the true claim: **catches ransomware & hackers**.
