---
name: security-checkup
description: Check this Windows PC's security posture with Blanktick's read-only MCP tools and explain it honestly. Use when the user asks how secure their computer is, what changed since the last scan, whether a specific setting or finding applies, or wants a Wireshark capture reviewed.
---

# Security check-up with Blanktick

Blanktick reads this machine and reports. **It changes nothing, and neither do you.**
Every tool is a question. If something should be fixed, say what and why, and let
the user do it.

## Pick the cheapest tool that answers the question

| The user wants | Call |
|---|---|
| A full picture | `blanktick_scan` (about 100 s — tell the user it is running) |
| "What changed?" | `blanktick_changes`, then `blanktick_history` for the trend |
| "Have I ever had X?" | `blanktick_search` with `severity` / `rule` / `category` / `since` |
| The raw readings behind a finding | `blanktick_facts` |
| "What exactly does it run?" | `blanktick_probe_script` |
| What can't be checked here | `blanktick_coverage` |
| A network capture reviewed | `blanktick_netlog` with the path to their exported Wireshark CSV |

`blanktick_coverage` reuses the session's scan, so after one `blanktick_scan` it
answers instantly; called first, it runs the scan itself — budget the same ~100 s.
`blanktick_facts` reads the machine fresh on every call, so call it once and reuse
the answer.

History, search and changes read a stored record that is **empty until the user
sets `keepHistory=true`** in `%APPDATA%\Blanktick\settings.conf`. If they come back
empty, say that, and offer a live scan instead.

## Two rules for every summary

1. **"Could not check" is not "fine".** A null fact or an unobservable rule means the
   machine would not answer. List those separately; never fold them into the passes.
2. **The score only means something next to coverage.** It is 100 minus deductions,
   so a machine where little could be checked scores high. Always give the number of
   checks that ran and the number that could not, alongside the score. When two
   scans ran different numbers of checks, say so before comparing their scores.

## How to report

- Lead with the findings that matter most (Critical, then High), each with Blanktick's
  own fix text and the rule id.
- Then what could not be checked, and why.
- Stored results are dated: say how old they are. A day-old record is not a live reading.
- Do not run shell commands to "fix" anything on the user's behalf. Offer the steps.
