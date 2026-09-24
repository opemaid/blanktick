# ADR-004 — A searchable scan history, and a conscious revision of D-05

**Date:** 2026-09-23
**Status:** Accepted (owner-requested)
**Supersedes in part:** the derived "persist nothing" reading of
[D-05](kickoff-meeting-2026-08-28.md) — *not* its letter.

## Context

The MCP server (ADR in `docs/mcp.md`) lets a model ask about this machine, but
every question ran a fresh ~100-second scan, and the result lived only in memory
for the life of one `--mcp` process. The owner asked for the obvious next thing:
*"Claude connects to the database and runs searches on it. The app never
connects to the internet."* — i.e. a persisted store the model can query across
sessions instead of re-scanning.

## The tension

D-05 as written says **"findings never leave the device."** A local history
file does not violate that: nothing is transmitted, the app still opens no
socket, and the bytecode gate still forbids one. The clarification worth stating
is that *"the app never connects to the internet"* was never the same claim as
*"nothing is written"* — a file on disk that lists a machine's weaknesses is a
map for whatever runs on that machine next, regardless of the network.

The codebase had extended D-05 into a stricter posture — "persist no scan
history at all" — recorded in `ScanViewModel.kt` and enforced by
`Settings.kt`'s rule that the settings file may hold UI preferences and nothing
else. **That stricter posture is what this ADR revises**, deliberately and with
the owner's decision, keeping the reason it existed intact.

## Decision

Add an append-only local store, `history.jsonl`, next to `settings.conf`, and
three read-only MCP tools (`blanktick_history`, `blanktick_search`,
`blanktick_changes`) that read it and never scan. Four constraints keep it
faithful to why D-05's stricter reading existed:

1. **Off by default.** Nothing is recorded unless the user sets
   `keepHistory=true`. The default posture stays "keep nothing"; enabling it is
   an explicit act. The toggle is a *preference* (so it lives in `settings.conf`);
   the scan data it gates is not (so it lives in a separate file).

2. **Summary, never snapshot.** Only rule outcomes are stored — id, subjectId,
   severity, category, the on-screen title, points. The specifics that would
   make the file a target map — the actual DNS address, account names, open
   ports, full paths — live in `Finding.detail` / `Finding.evidence` and the raw
   `DeviceSnapshot`, and none of them reach the file. `ScanHistoryTest` asserts
   the omission against real-shaped data.

3. **Dated, and declared stale.** Every stored scan carries its timestamp; every
   tool prints the age and says in words that it is a stored record, not a live
   reading — because a model summarising history is exactly where a day-old
   "clear" gets read as "fine now".

4. **Never a partial scan.** Recording is gated on `collectionCompleted`. A scan
   that could not read the machine is never stored, for the same reason the
   score is suppressed for it: an unfinished read must not become a stored
   "all clear".

## Consequences

- A model can now answer "what changed since last week" and "have I ever had a
  CRITICAL finding" from the store, in milliseconds, with no scan.
- There is now a file on disk describing this machine's past weaknesses when the
  feature is on. That is a real, if reduced, exposure — reduced by constraint 2,
  bounded by constraint 1, and deletable at any time (`history.jsonl`, or
  `keepHistory=false`). It is not encrypted at rest; encrypting it (or scoping it
  to the OS user profile) is the obvious next hardening step and is **not yet
  done** — noted here rather than left implicit.
- `McpServerTest` still fails the build if any tool is named as if it changes the
  machine; the three new tools are questions, like the rest.

## Not done

- At-rest encryption of `history.jsonl`.
- An Android equivalent (this store is desktop-only; the phone app still keeps
  nothing, per the unrevised stricter D-05 there).
