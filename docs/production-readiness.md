# Blanktick production-readiness roadmap

Consolidated from a five-track audit (code, tests, security guarantees, docs,
release) on 2026-10-17. Status key: **[x] done** · **[~] in progress** ·
**[ ] todo** · **[HUMAN] needs a person / hardware / money** (cannot be done by
code review alone).

The codebase is mature — 438 tests, a bytecode no-network gate, MSI packaging,
and a disciplined null contract. The work below is hardening, validation, and
release, not construction.

---

## P0 — Security & correctness (fix before any release)

- [x] **AskDefender spawns one `MpCmdRun.exe` scan per file, uncapped** (WindowsProbe.kt ~1126/1135). `scanTargets` includes every AppData process (Discord/Slack/Teams/VS Code/browsers), so on a normal machine this fires dozens of multi-second scans and can push the probe past its 240s ceiling → PowerShell killed → whole scan discarded. Same class as the driver-hash bug already fixed. Fix: cap to top-N by risk + cumulative time budget + per-call timeout, or one batched MpCmdRun call.
- [x] **Sensor `ScriptTapProvider` launches `powershell` via PATH, not `Shell.resolve`** (ScriptTapProvider.kt:45-47) — HKCU `%PATH%` injection, and the ETW tap runs elevated → RCE. Fix: resolve through the hardened trusted-dir logic.
- [x] **Sensor tap `.ps1` written to shared temp (TOCTOU)** (ScriptTapProvider.kt:41-42) — swappable between write and elevated execution → LPE. Fix: mirror `Shell.powershell`'s private random dir + immediate delete.
- [x] **Sensor tap stderr never drained** (ScriptTapProvider.kt:47,52) — pipe fills, child blocks, live protection silently stops. Fix: drain stderr on its own daemon thread.
- [x] **`WindowsElevation` PATH-based powershell + no timeout** (WindowsElevation.kt:12-18) — same injection class; unbounded blocking on startup. Fix: hardened Shell + bounded timeout.
- [x] **`Enforcer.isProtected` only guards pid ≤ 4** (critical-image refusal done; pid-reuse-to-benign re-verification still needs the detection to carry its recorded image) (Enforcer.kt:37-40) — a misfired `destroyForcibly()` on a real system process (csrss/wininit/services, pid > 4) can crash Windows; also a PID-reuse race. The one irreversible action in the app. Fix: refuse by image path / known-critical set and re-verify the image at enforce time. **[HUMAN review recommended — irreversible, elevated.]**

## P1 — Robustness & honesty (locale, consistency, silent failures)

- [ ] **Defender exclusions matched by English literal** (WindowsProbe.kt ~1348) — on non-English Windows the "must be an administrator" blind-spot message doesn't match → a localized sentence is emitted as a fabricated "exclusion configured" finding. Fix: detect the blind spot structurally, not by English text.
- [x] **AskDefender parses English MpCmdRun output** (WindowsProbe.kt ~1126) — non-English → every file reads not-checkable while paying full scan cost. Fix: use exit code / numeric parse.
- [ ] **CLI and GUI disagree on score trust** (Main.kt:506 vs Dashboard.kt:428) — CLI suppresses only on `collectionCompleted==false`; GUI suppresses on any caveat. Same scan → full score in `--cli`, "No score this time" in the GUI. Fix: one shared threshold.
- [x] **`DesktopIntel` swallows corpus parse failures** (DesktopIntel.kt:79-87) — `runCatching{…}.getOrNull()` makes a *corrupt* (not absent) bundled corpus degrade silently to "not checkable". Fix: distinguish absent from present-but-unparseable and surface the latter.

## P2 — Test coverage (17 untested rules + a structural seam)

- [x] **Add a parse seam to `WindowsCollector`** — it ran PowerShell in a field initializer, so NO test exercised key=value→DesktopFacts parsing. Added an `internal constructor(Map<String,List<String>>?)` seam.
  - [x] Parse tests for the 3 new facts (`WindowsCollectorParseTest`): `driver.loaded`→vulnerableDriversLoaded (sentinel/corpus/hex gating + de-dup), `office.macroWeak`→officeMacroSecurityWeak (null-vs-empty), `cred.savedRdp`→savedRemoteDesktopCredentials (null-vs-0). The seam now also enables the broader parse tests in item P2.
- [~] **Fail-path tests for 17 rules** — DONE (13): DSK-AV-001, DSK-USB-001, DSK-BOOT-001, DSK-UPD-001, DSK-LOCK-001, DSK-ACC-002, ACC-CRYPT-001, ACC-PWD-002, ACC-LOCK-002, DSK-PS-001 (triads in DesktopRulesTest/RulesTest/HardeningRulesTest). REMAINING (4): DSK-MAL-005 (AV-verdict fixture), DSK-SW-001/DSK-SW-002 (EoL intel), NET-DNS-002/APP-SDK-001 (mobile). Added bootloader/dev-options/VPN. OLD-REMAINING DSK-MAL-005 (needs AV-verdict fixture), DSK-SW-001/DSK-SW-002 (need EoL intel), and the mobile-only NET-DNS-002, NET-VPN-001, APP-SDK-001, DEV-DEVOPT-001, DEV-BOOT-001 (low priority under Windows-only scope).
- [ ] **Sensor provider parse tests** for the 3 DYN rules whose source events have no provider test (DYN-CRED-001/HandleOpen, DYN-RANSOM-001/ShadowCopy+FileModify, DYN-AI-003/ContentIntake). **[partly HUMAN — the OS taps are hardware-gated; add stub parseLine tests.]**

## P3 — Docs & claims alignment

- [x] Headline counts synced to 88 / 70 / 69 (README, web).
- [x] README "Four tools" → Eight; `docs/mcp.md` already correct.
- [x] README/web/arch-docs stale rule counts (81/67/45/25/16/"eleven") → 88 / 70 / 59 desktop-only.
- [x] web hero "50+31=81 every check" → honest "50 answered, 31 not checkable".
- [ ] **README autorun source list understates the code** — says WMI/COM "are not read"; the probe reads all 12 sources incl. WMI subscriptions, COM, AppInit, Active Setup. Fix the list + delete the false sentence (README contradicts web).
- [ ] README "50 of 81" dev-machine measurement reads as the current total — re-measure on 88 or label historical.
- [ ] Reconcile "42 vs 43 third-party jars" (README :35/:44/:46 vs web :305).
- [ ] Optional: add "superseded" notes to dated meeting-minute docs carrying old counts.

## Release engineering

- [x] `release.yml` drafted — builds the MSI (`:desktop:packageMsi`) on a `v*` tag, publishes a GitHub Release + SHA-256. **(draft — review before use.)**
- [x] `docs/release.md` runbook drafted.
- [ ] Bump `packageVersion` 0.1.0 → the intended release version. **[HUMAN decision.]**
- [ ] A production release must build the MSI from the **real** LOLDrivers corpus (`tools/fetch_loldrivers.py`), not the CI test seed.
- [ ] Bump deprecated CI actions (`setup-java@v5`, Node 20→24).

## HUMAN / hardware / $-gated (no code can close these)

- [HUMAN] **Code-sign the MSI** — EV cert or Azure Trusted Signing; without it SmartScreen warns "Unknown publisher".
- [HUMAN] **Live positive-case validation** — load a real vulnerable driver / set a weak macro key / save a real RDP cred and confirm the scan fires.
- [HUMAN] **Run on Pro/Enterprise, Windows 10, and a non-English locale** (several P1 locale bugs only manifest there).
- [HUMAN] **Multi-day sensor soak** on real hardware; Sysmon provisioning path; final support-claim sign-off.

---

## Security guarantees — re-audited, all HOLD

no-network · read-only · no-probe-injection · MCP-question-only · build-time
network isolated to `fetch_loldrivers.py`. Two guard gaps found **and fixed**
this pass: the probe's mutation fence now covers native executables
(`cmdkey /add`, `reg add`, …) and the one unsanitized Office emit is now
`San`-wrapped.
