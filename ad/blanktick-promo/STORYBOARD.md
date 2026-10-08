---
format: 1920x1080
duration: 30s
message: "Not every green tick means safe — Blanktick shows what it checked, what it couldn't, and why."
arc: Hook → Problem (one tick, three meanings) → Reveal → Proof → Proof in numbers → CTA
audience: "Windows PC users who already trust a security dashboard's green ticks"
mode: autonomous
music: calm minimal ambient underscore, soft piano and warm pads, unhurried
---

## Video direction

- **palette system** (frame.md, Blanktick light tokens): ground `bg` #FAF9F6 cream paper; text `text` #0B0D0C; kelp `primary` #0F4D3F is BOTH the brand accent and the "passed" state (DD-04 — never use kelp for anything that is not passed/brand); grey `text-light` #666D6B is the "not checked / wouldn't answer" state. No red, no alarm colours: this is not a threat ad. Cards use `card-bg` tint + `border` hairline, no shadows.
- **type**: display/numerals by the frame.md display role (Segoe UI, heavy weight for hooks), body by body role; state labels in tracked uppercase like the app ("PASSED", "NOT CHECKABLE").
- **motion grammar + reveal model**: smooth long-tail `power3` settles, no bounce anywhere. Every piece reveals on the word that names it; at t=0 only what the VO is saying is on screen. Holds are still — subtle jitter is the only permitted aliveness.
- **rhythm**: F1 sparse and still (one tick) → F2 the busiest text beat → F3 the reveal is the climax of the idea → F4–F5 real-product proof, calmer → F6 is the deliberately HELD breather/end card.
- **the tick motif**: one tick shape (a checkmark drawn as an SVG stroke) is the recurring object. It self-draws in F1, triples in F2, and in F3 two of the three copies MORPH into a dash and a ring while the first stays a kelp tick. Same stroke weight throughout.
- **real screenshots** (F4, F5) are shown as a framed app window on the cream ground — never full-bleed, never tilted into fake 3D — with a thin kelp or grey highlight ring drawn on the row/tile the VO names. The screenshots are dark theme; the ring and a soft cream vignette bridge them to the light film.
- **negative list**: no shields, padlocks, hoodies, matrix code, neon, navy-and-green hacker look, glitch, scanlines, red alerts, bokeh, purple AI gradients; no URL, store badge, price or competitor; no invented numbers. Both motion failure modes forbidden: slideshow (front-load then freeze) and screensaver (everything floating).
- **caption band**: all content in the top ~83%.


## Frame 1 — One green tick

- scene: A single large kelp-green tick sits alone on cream paper
- voiceover: "Not every green tick means safe."
- duration: 3s
- transition_in: cut
- status: animated
- src: compositions/frames/01-one-tick.html
- type: hook
- persuasion: Pattern interrupt — doubt planted in the most trusted symbol
- beat: curiosity + unease
- blueprint: kinetic-type-beats
- asset_candidates:
- blueprint: kinetic-type-beats (Adapt)
- focal: the drawn tick
- roles:
- sfx: click-soft

Adapt: keep the single-beat centre anchor; the "type" is one glyph — a tick — then one line.
Scene 1 (0.00–0.79s): cream field, nothing else. A large kelp tick SELF-DRAWS dead-centre (`svg-path-draw`), ~35% of frame height, long-tail settle.
Scene 2 (0.79–1.47s): as the VO reaches "means safe", the line "Not every green tick means safe." reveals word-by-word beneath the tick (`dynamic-content-sequencing`), display role, ink; "safe" set in kelp. Centered, tick upper third.
Scene 3 (1.47–1.98s): hold still; subtle jitter on the tick only.

narrativeRole: plant the doubt in the viewer's own language — the tick they already trust.
keyMessage: a green tick is not automatically a result.

## Frame 2 — Three meanings

- scene: The tick triples into three identical ticks; under each, a different meaning types in
- voiceover: "One means we checked. One means we never looked. One means your computer wouldn't answer."
- duration: 6s
- transition_in: crossfade
- status: animated
- src: compositions/frames/02-three-meanings.html
- type: pain_point
- persuasion: Rule of three — three identical marks, three different truths
- beat: tension
- blueprint: kinetic-type-beats
- asset_candidates:
- blueprint: kinetic-type-beats (Adapt)
- focal: three identical ticks
- roles:
- sfx: click-soft

Adapt: keep beats landing one at a time; instead of replacing in place they accumulate across a triptych, so the viewer sees three identical marks with three different captions.
Scene 1 (0.00–0.74s): the F1 tick slides left as two identical copies appear to its right (`center-outward-expansion`) — triptych, three equal columns, ticks in the upper third, all kelp.
Scene 2 (0.74–2.03s): on "we checked", caption 1 types under tick 1 (`discrete-text-sequence`): "we checked".
Scene 3 (2.03–3.51s): on "never looked", caption 2 types under tick 2: "we never looked".
Scene 4 (3.51–4.99s): on "wouldn't answer", caption 3 types under tick 3: "your computer wouldn't answer".
Scene 5 (4.99–5.55s): hold — three identical ticks, three contradictory captions. Stillness is the point.

narrativeRole: name the problem — identical ticks hide three different states.
keyMessage: you cannot tell them apart.

## Frame 3 — Blanktick tells them apart

- scene: The three ticks split into three distinct states — PASSED (kelp tick), NOT CHECKED (grey dash), WOULDN'T ANSWER (grey ring) — and the lower-case wordmark "blanktick" lands
- voiceover: "Blanktick tells them apart."
- duration: 3s
- transition_in: zoom-through
- status: animated
- src: compositions/frames/03-tells-apart.html
- type: product_intro
- persuasion: Negative contrast resolved — the product is the act of separating
- beat: clarity + relief
- blueprint: titlecard-reveal
- asset_candidates:
- blueprint: titlecard-reveal (Adapt)
- focal: the three separating marks + wordmark
- roles:
- sfx: chime

Adapt: keep the ONE restrained move then a held card; the one move is the separation.
Scene 1 (0.00–0.20s): the F2 triptych, captions gone, three kelp ticks.
Scene 2 (0.20–0.88s): on "tells them apart" — tick 1 stays a kelp tick labelled PASSED; tick 2 redraws into a grey dash labelled NOT CHECKED; tick 3 redraws into a grey ring labelled WOULDN'T ANSWER (`svg-path-draw` morph, labels in tracked uppercase). The three spread apart slightly.
Scene 3 (0.88–1.71s): the lower-case wordmark "blanktick" resolves beneath (per-word reveal), ink, heavy weight; hold still.

narrativeRole: land the promise (message) by beat 3 and name the product.
keyMessage: Blanktick separates checked from unchecked.

## Frame 4 — A result, or a reason

- scene: The real Policy page — "Device storage is encrypted: PASSED" sits between rows reading "NOT CHECKABLE · this computer wouldn't answer"; each state is picked out as the VO names it
- voiceover: "Every check ends in a result — or the reason it couldn't run. Never a quiet pass."
- duration: 6s
- transition_in: blur-crossfade
- status: animated
- src: compositions/frames/04-result-or-reason.html
- type: feature_showcase
- persuasion: Show-don't-tell proof — the real app, unedited
- beat: trust
- blueprint: device-surface-showcase
- asset_candidates: assets/app-policy-accounts.png — real Policy page, Access & accounts: PASSED next to NOT CHECKABLE rows with their reasons
- blueprint: device-surface-showcase (Adapt)
- focal: assets/app-policy-accounts.png
- roles: app-policy-accounts = supporting (framed window, ~70% width, centred, cream vignette around it)
- sfx: none

Adapt: keep "the real surface is the hero"; a still screenshot, so the flow advances by highlighting rows, not changing screens.
Scene 1 (0.00–0.90s): the framed Policy screenshot rises into place (smooth long-tail), centred, ~70% width.
Scene 2 (0.90–2.33s): on "a result", a kelp highlight ring draws around the "Device storage is encrypted — PASSED" row (`css-marker-patterns`); the rest dims slightly (`depth-of-field-blur`, gentle).
Scene 3 (2.33–3.94s): on "the reason it couldn't run", a grey ring draws around a "NOT CHECKABLE · this computer wouldn't answer" row; focus shifts to it.
Scene 4 (3.94–5.38s): on "Never a quiet pass", the line appears as a kelp-on-cream caption card upper-right of the window; hold.

narrativeRole: prove the promise inside the real product.
keyMessage: not-checked is shown and explained, never counted as a pass.

## Frame 5 — Fifty ran, thirty-one named

- scene: The real dashboard; the "Checks ran 50" and "Not checkable 31" tiles are lifted forward and count up
- voiceover: "On a real laptop: fifty checks ran. Thirty-one couldn't — and every one is named."
- duration: 6s
- transition_in: crossfade
- status: animated
- src: compositions/frames/05-fifty-thirty-one.html
- type: benefit_highlight
- persuasion: Statistical proof — the product's own real scan numbers, including the unflattering one
- beat: confidence
- blueprint: dataviz-countup
- asset_candidates: assets/app-dashboard.png — real dashboard from a real scan: Rules 81, Checks ran 50, Not checkable 31, score 81
- blueprint: dataviz-countup (Adapt)
- focal: assets/app-dashboard.png
- roles: app-dashboard = supporting (framed window, left 55%); the two counters = cutout foreground (right 45%)
- sfx: none

Adapt: keep the count-up as the signature; no push-through (the doctrine forbids back-half pushes) — the numbers lift out of the real tiles instead.
Scene 1 (0.00–0.97s): framed dashboard window settles left, asymmetric 55/45.
Scene 2 (0.97–2.71s): on "fifty checks ran", a kelp ring marks the "Checks ran 50" tile and a large kelp "50" counts up on the right (`counting-dynamic-scale`), label "ran".
Scene 3 (2.71–4.46s): on "thirty-one couldn't", a grey ring marks "Not checkable 31" and a same-size grey "31" counts up beneath the 50, label "couldn't — each one named". Equal size: the gap is not hidden.
Scene 4 (4.46–5.33s): hold still.

narrativeRole: quantify honesty with a real scan — the gap is shown at full size, not hidden.
keyMessage: it tells you exactly how much it looked at.

## Frame 6 — Offline, free, open

- scene: Calm end card — "blanktick" wordmark, line "A security scanner that tells you what it could not check.", then three short facts: Offline · Nothing leaves your computer · Free and open source
- voiceover: "Blanktick. It works offline, nothing leaves your computer, and it's free and open source."
- duration: 6s
- transition_in: crossfade
- status: animated
- src: compositions/frames/06-end-card.html
- type: cta
- persuasion: Risk reversal — no account, no upload, no cost
- beat: peace of mind
- blueprint: titlecard-reveal
- asset_candidates:
- blueprint: titlecard-reveal (Reproduce)
- focal: wordmark
- roles:
- sfx: none

Scene 1 (0.00–0.48s): cream field; the kelp tick from F1 draws small, upper third.
Scene 2 (0.48–1.94s): "blanktick" wordmark resolves under it (ink, heavy), then the line "A security scanner that tells you what it could not check." in body role, text-muted.
Scene 3 (1.94–4.36s): on each spoken phrase, three facts appear in one row of pill chips: "Offline" · "Nothing leaves your computer" · "Free and open source" (sequential reveal, kelp outline chips).
Scene 4 (4.36–5.33s): held end card — the only frame with a real exit: a gentle fade to cream in the last 0.4s.

narrativeRole: close on the brand and remove every reason not to try it. No URL — there is no public download address yet.
keyMessage: safe to try — it can't send anything anywhere.
