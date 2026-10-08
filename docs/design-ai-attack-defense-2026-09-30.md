# Blanktick vs AI-driven attacks — the honest build plan

Status: design + in-progress, 2026-09-30. Extends
`design-paid-dynamic-tier-2026-09-27.md`; does not replace it.
Trigger: "lets make it block against ai attacks" + "use the ant, go all out."

## What "AI attack" actually means at the endpoint

AI does not create new *execution* primitives on the victim machine. An
AI-assisted attack still lands as one of a small set of concrete behaviours:
a process starts, code is injected, a script runs (PowerShell/VBA/JS), files
are mass-rewritten, a handle is opened to lsass, a service or WMI consumer is
created. AI mostly lowers the skill bar and raises the *volume and speed* of
those same attacks. So "block AI attacks" decomposes into two honest jobs:

1. **Harden the openings AI-assisted attackers automate** (config/posture — the
   free product already does much of this).
2. **Detect and block the behaviours in flight** (needs the resident sensor —
   the Pro tier in the dynamic-tier doc).

Plus one surface that is genuinely *new* with AI and is our differentiator:

3. **Defend the local AI/MCP layer itself** — the model runner, the tool
   configuration, and the agent that can act. This is where prompt-injection,
   rogue/over-permissioned MCP tools, and agent-driven command execution live.

## What the ant (fly-brain) said, and how it steered this

Two honest signals from the local brain (67,732 docs, 36,328 code files):

- **`brain_recall` top match 0.607, "covered": true.** The classic behavioural
  detections (fileless, LOLBins, WMI-persistence, ransomware, suspicious
  PowerShell) are well-trodden prior art. There are on-disk how-to skills for
  each (`detecting-fileless-attacks-on-endpoints`, `detecting-wmi-persistence`,
  `detecting-living-off-the-land-attacks`, `detecting-suspicious-powershell-
  execution`, `securing-agentic-ai-tool-invocation`). Build the classic engine
  to *their* spec rather than from memory; do not claim novelty there.
- **`brain_novelty` = 0.437 (moderate); every nearest neighbour is a generic
  endpoint detector.** Nothing near the query defends the **AI/MCP agent layer**.
  That is the differentiated ground and the honest lead for both the product and
  the marketing.

Steer: classic behavioural engine = table-stakes, built to known standards;
**AI/MCP-layer defence = the edge, built first and led on.** The ant is a
novelty/dedup/QA instrument here, not the detector — it does not run the
detection ML (CPU NumPy). Used for what it is good at.

## Two honest lines that stay true through every phase

- **Harden vs block are different verbs.** The free tier and the new static AI
  rules *harden* — they remove openings before an attack. They do not *block* a
  live attack. Only the resident sensor (Pro) blocks in flight. Marketing must
  not let "protects against AI attacks" imply the free tier stops a running one.
- **The no-network gate stays sacred.** Everything below is local ETW/AMSI/file
  reads or static config parsing. Reputation/phishing intel, if ever needed,
  arrives as a user-imported signed bundle (dynamic-tier doc, option A), never a
  socket. The elevated resident sensor is opt-in Pro; the free tier stays
  elevation-free and unchanged.

## Phases (novelty-ordered, honesty-gated)

### Phase 1 — static AI-surface hardening (free tier, no sensor, shippable now)
Closes the openings AI-assisted attackers go looking for, at the config layer,
with pure `Rule`s over the existing snapshot. No elevation, gate intact.

- [x] **DSK-AI-005 — tool started through a package runner** (`npx`/`uvx`/
  `bunx`/`pipx`). Fetches and runs code from a public registry as you, silently
  at latest — the main way a rogue MCP tool arrives. MEDIUM, framed as context,
  not accusation. *Shipped 2026-09-30.*
- [x] **DSK-AI-006 — the prompt-injection reach.** Flags when one agent config
  grants *both* an untrusted-content intake tool (web/fetch/email/browse) *and*
  a tool that can act (shell / filesystem / exec / db). That is the condition
  that makes indirect prompt injection actionable. *Shipped 2026-09-30* as a
  **name-heuristic** version (classifies each MCP server by its configured name,
  plus shell-launcher = action) — no model/probe change, so it stays additive
  and the old suite is untouched. Fires only when *both* halves are present, so a
  single mislabel is silent. MEDIUM, framed as "here is the combination," not an
  accusation. **Refinement deferred:** add `McpServer.args` + a coarse capability
  tag on the probe to catch runner-wrapped tools (`npx some-fetch-server`) and
  cut heuristic error.
- [ ] **DSK-AI-007 — MCP server writable by others / from a user-writable path.**
  A tool definition or its binary that a non-admin can rewrite is an injection
  point into the agent. Reuses the existing user-writable-path machinery.

### Phase 2 — the resident sensor (`sensor/` module, Pro, opt-in, elevated)
Per the dynamic-tier doc. This is where "block" becomes literal. Build order
lifted from that doc; detection logic taken from the on-disk `detecting-*`
skills the ant surfaced.

**The engine is built and green (2026-09-30).** New `sensor/` module: the pure,
deterministic core — `SensorEvent` (sealed), bounded `RollingWindow`,
`BehaviorRule` (`DYN-*`), `BehaviorEngine` (drives rules, suppresses repeats),
and a working offline `ReplayProvider`. It depends only on `:core` for the
shared `Finding` model, opens no socket, and is **inside the no-network gate**:
`assertNoNetworkBytecode` now scans `sensor/` and passes, and its self-test still
fails on a planted violation. 18 unit tests, all green; `./gradlew test` green
across every module (the old suite untouched).

- [x] `sensor/` scaffold: `SensorEvent`, `RollingWindow`, `BehaviorRule`,
  `BehaviorEngine`, gate extended over the module.
- [x] First behaviour rules: **DYN-OFFICE-001** (Office → shell child),
  **DYN-CRED-001** (non-system process opens an lsass handle),
  **DYN-RANSOM-001** (high-entropy write burst **or** shadow-copy delete).
- [x] **The AI-layer behaviour rules — our differentiator:**
  - **DYN-AI-001** — an MCP/agent process spawns a shell or LOLBin (tool-abuse /
    injected tool call in flight).
  - **DYN-AI-003** — an agent acts (file write / process launch) within seconds
    of ingesting external content (prompt-injection → action, correlated).
- [x] Block **intent** modelled: each `Detection` carries a `Response`
  (OBSERVE/ALERT/SUSPEND/KILL). Enforcement is the provider's job, kept in one
  consented, elevated place — not inside a pure rule.
- [x] "Not observed ≠ clean" carried in via `ProviderStatus`.

**First live provider built and proven (2026-09-30).** `WindowsProcessProvider`
runs a bundled PowerShell tap (`process-provider.ps1`) that polls `Win32_Process`
and emits each new start; the class parses it to `SensorEvent.ProcessStart` and
feeds the engine. It spawns a child process and reads its output — no socket —
so the gate still passes with it present. `SensorMain` + `gradlew :sensor:runSensor`
ran it live for 30s and captured real starts with correct lineage
(`cmd.exe <- powershell.exe`, `conhost.exe <- cmd.exe`, `dllhost.exe <- svchost.exe`),
firing zero false alerts on a benign session. This is the **user-level fallback**:
`privilege = USER`, and it can miss a process that lives and dies between polls.

**Privileged ETW tap built (2026-09-30).** `WindowsProcessProvider.etw()` runs
`process-provider-etw.ps1`, which subscribes to `Win32_ProcessStartTrace` — the
WMI surface of the NT kernel's process ETW trace: push-based (no poll gap) and
machine-wide. Native-free (pure PowerShell over stdio, no JNA), so the gate still
passes. It needs admin: the script reports `#elevated=false` and stops if not.
`SensorMain` now auto-selects `etw()` when elevated, `poll()` otherwise, and
prints the real elevation state (fixing the old fixed `[USER]` label). Compiles
and the parse path is the shared tested code; a live elevated run is the user's
(can't elevate unattended here).

**Safe demo mode built (2026-09-30).** `-Dblanktick.sensor.demo=true` injects a
few clearly-labelled synthetic events (Word→PowerShell, MCP→shell) into the same
engine, so a detection can be watched firing without any real malware. Verified
locally: fired `DYN-OFFICE-001 [KILL]` and `DYN-AI-001 [SUSPEND]`, each tagged
`[DEMO]`.

**Network + DNS providers built (2026-09-30).** `NetworkProvider` polls
`Get-NetTCPConnection` and emits new established outbound connections
(`SensorEvent.NetworkConnect`); `DnsProvider` polls `Get-DnsClientCache` and
emits newly resolved names (`SensorEvent.DnsQuery`). Both are native-free poll
taps on the shared `ScriptTapProvider` base, gate still passes. Two rules use
them: **DYN-C2-001** (a process calling one destination on a regular, low-jitter
beat — flags the *pattern*, says naming the host needs the offline intel bundle)
and **DYN-DNS-001** (a DNS name shaped like tunneling — over-long, or an
over-long label). `SensorMain` now runs all three taps into one engine (made
thread-safe with `@Synchronized`), with a window wide enough for slow beacons.
Verified: 31 sensor tests green, gate clean; the demo fired all four of
DYN-OFFICE-001, DYN-AI-001, DYN-DNS-001, DYN-C2-001. ETW `Kernel-Network`/
`DNS-Client` (admin, live, per-query with process) remain the fidelity upgrade.

**Still to build (needs elevated hardware, cannot be unit-tested off it):**
- [ ] The **AMSI** provider (fileless/macro content → `ScriptExecution`) and WMI
  watchers; the ETW upgrades of the network and DNS taps.
- [ ] Richer actor tagging: mark `node`/`python` started by an MCP config as
  `MCP_SERVER` (lineage from the AI/MCP config the free tier already reads), so
  DYN-AI-001/003 catch injected tool calls, not just named model runners.
**Live-protection screen built into the app (2026-09-30).** The desktop app now
depends on `:sensor`; a `LiveProtectionController` bridges the engine and taps to
the UI as StateFlows, and `LiveProtectionScreen` (nav entry "Live protection",
badged Pro · preview) shows a Start/Stop control, live process/connection/DNS
counts, the elevation state, and each detection as a card with its recommended
action. Honest throughout: leads with "not a full antivirus, detects and warns,
does not yet stop a process," and treats an empty list as the sensor working,
not a clean bill of health. Verified: `gradlew check` green (gate clean, dep
audit re-pinned to 44 jars incl. clean sensor.jar); opened in the preview app,
navigated to the screen, Started it, and watched real counts populate (19
processes, 39 connections) with zero false alerts. Closing calls `stop()`
(both windows) and the taps use `destroyForcibly()` so a poller never orphans.

**Enforcement built (2026-09-30).** A detection now carries its `targetPid`, and
`Enforcer` actually stops a flagged process via the JVM's own `ProcessHandle`
(native-free, gate intact). Guarded: it refuses system pids (<=4) and Blanktick
itself, only acts on KILL/SUSPEND responses, and is **off by default** — the
`LiveProtectionController` only enforces when the user turns on the screen's
"Stop flagged processes" switch, which shows a destructive-action warning.
Tested: a real spawned process is actually stopped; advisory/no-target/protected
cases are refused. Honest limit: both KILL and SUSPEND terminate — a true
forensic suspend (freeze) needs native code and is future work; the UI says
"stopped," not "suspended."

- [ ] A true forensic suspend (freeze, not terminate), the **AMSI** provider,
  an optional tray icon, and the signed local license that gates the Pro tier.
- [ ] **DYN-AI-002** — agent process opens an lsass handle / injects (trivial
  once the Threat-Intel provider emits `HandleOpen` with an actor tag; the rule
  is a two-line variant of DYN-CRED-001 gated on `AGENT_ACTORS`).
- [ ] Enforcement of SUSPEND/KILL, the tray surface, and the signed local
  license gate for the Pro tier.

### Phase 3 — optional, only if demanded
Offline signed intel bundle importer (names C2/phishing destinations without a
socket). A separate networked edition stays a separate SKU and a separate
marketing frame — never folded into the gated build.

## Honesty carried in (unchanged ethos)
- A resident offline sensor is a behavioural detector, not a full EDR; ETW can
  be unhooked by kernel-level malware. State the evasion class, do not imply
  total coverage.
- Licensing for Pro is a signed local file, not a phone-home — a validation call
  would break the gate through the back door.
- "Not observed" is the dynamic analogue of NotApplicable, never a pass.
