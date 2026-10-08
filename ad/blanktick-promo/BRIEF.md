---
workflow: product-launch-video
flow: automation
storyboard: no
message: "Not every green tick means safe — Blanktick shows what it checked, what it couldn't, and why."
destination: youtube-embed
aspect: 1920x1080
language: en
audience: "Windows PC users who already trust a security dashboard's green ticks"
length: 30s
angle: "The Tick That Lies"
---

## Intent

Concept #2, chosen from a five-pitch round: **The Tick That Lies.** Three identical
green ticks mean three different things — "passed", "never checked", "this
computer wouldn't answer". Blanktick splits them apart. Opening hook: "Not every
green tick means safe." Calm and honest, deliberately NOT the hacker-film look
(navy, neon, shields, hoodies) every security ad uses — Blanktick's own design
notes reject it.

## Customizations

- The single tick visibly splits into three labelled states (passed / not checked /
  wouldn't answer), and a "not checked" list with reasons slides in.
- Real counts from a real scan count up: 50 ran, 31 could not be checked, score 81.

## Notes

Every claim must be true of the shipped app (branch blanktick-policy-and-fixes,
2026-09-25). Allowed claims, with their source:

- 81 checks; 63 apply to a Windows PC (PlatformCoverageTest).
- A real scan of the developer's Windows 11 laptop: 50 ran, 31 could not be
  checked (18 written for a phone, 13 the computer wouldn't answer), score 81,
  5 findings. Each not-checked item is named with its reason (web/index.html).
- A not-checked item is never counted as a pass; an unfinished scan gets no score.
- Every point off the score traces to one named finding.
- Works entirely offline; nothing leaves the computer; the build fails if
  networking code is ever added (README, NoNetwork gate).
- Never changes a setting — it tells you what to change.
- Checks things Windows Security doesn't show: open network ports, remote-access
  services, startup programs, unsupported software, USB history, AI keys in plain
  text, an antivirus quietly switched off in part.
- Free and open source (AGPL-3.0).

Forbidden: "antivirus", "blocks/removes malware", "protects you in real time",
any number not above, any URL or store badge (no public download yet), any
competitor named or shown.
Brand: kelp #0F4D3F (= "passed"), paper #FAF9F6, ink #0B0D0C, notChecked #666D6B;
system fonts only (the website loads no font service). Wordmark: lower-case
"blanktick". Tagline source: "a security scanner that tells you what it could not check".
