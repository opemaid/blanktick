# Blanktick Pro — the dynamic-threat tier

Status: design proposal, 2026-09-27. Not implemented.
Author seat: security architecture review following the 81-rule coverage review.

## The problem this tier solves

The free product is a **snapshot posture auditor**: `DesktopCollector.collect()`
builds one `DeviceSnapshot`, `BlanktickScanner.scan()` runs rules that are pure
functions of that snapshot (no clock, no filesystem, no network — enforced by
the module having no dependency that would allow it). That design is excellent
at *configuration and attack-surface* questions and structurally blind to
*anything that happens over time*: a fileless implant already running, a C2
beacon, a malicious macro spawning PowerShell, an infostealer browser
extension. Those are events, not settings, and a point-in-time snapshot cannot
see an event it did not happen to catch mid-flight.

Blanktick Pro adds a **resident local sensor** that watches the machine
continuously and a **behavioral engine** that reasons over the event stream.

## Two values this must not casually break

1. **The no-network guarantee.** `assertNoNetworkBytecode` fails the build if any
   Blanktick class references a networking API; `NoNetwork.kt` locks the sockets
   it can at runtime; the marketing, the competitor differentiation, and the
   About screen all rest on this. **The resident sensor stays fully offline and
   stays inside the gate.** Everything it needs — process/network/DNS events,
   script content, file and registry activity — is available locally on Windows
   without opening a socket.

2. **"Needs no elevation."** Today a test asserts no probe requires admin. The
   resident sensor **does** need elevation (ETW kernel providers, the AMSI
   provider, and the Threat-Intelligence provider are privileged). This is a
   real trade. Resolution: the **free tier stays elevation-free and unchanged**;
   the Pro sensor is a separate, opt-in Windows service the user knowingly
   installs. The purity claim is preserved *for the product the free user runs*.

## Architecture

```
 free (unchanged)                 Pro adds
 ────────────────                 ────────────────────────────────────────
 DesktopCollector.collect()       BlanktickSensor  (Windows service, SYSTEM)
   -> DeviceSnapshot                 ETW sessions ─┐
 BlanktickScanner.scan()             AMSI provider ─┼─> normalised EventStream
   -> ScanReport                     WMI watchers  ─┘        │
 (pure Rule set)                                              v
                                                     BehaviorEngine (stateful)
                                                       rolling window + rules
                                                              │
                                                              v
                                                     Finding stream -> tray
                                                     alerts + ScanHistory
```

New gradle module `sensor/` (desktop-only). It must **also** pass
`assertNoNetworkBytecode` — it is all local ETW/AMSI/file reads, so it can.
The pure `Rule` set in `core/` is untouched; dynamic detections use a new,
separate interface so the static engine stays provably pure.

### New rule interface (do not overload the pure `Rule`)

```kotlin
// sensor/  — parallel to core.rules.Rule, never mixed with it
interface BehaviorRule {
    val id: String            // "DYN-<TOPIC>-NNN", new namespace
    val category: Category
    fun onEvent(e: SensorEvent, w: RollingWindow): List<Finding>
}
```

`RollingWindow` is a bounded (time- and size-capped) in-memory history so
correlation rules can ask "did winword.exe spawn this powershell in the last
5s?" without unbounded memory. Keeping this out of `core.rules.Rule` means the
free engine's "pure function of a snapshot" invariant and its golden fixtures
never change.

## The offline sensor primitives (all local, no socket)

| Primitive | What it sees | Privilege |
|---|---|---|
| ETW `Microsoft-Windows-Kernel-Process` | process start/stop, full command line, parent PID | admin |
| ETW `Microsoft-Windows-Kernel-Network` | this machine's own TCP/UDP connections | admin |
| ETW `Microsoft-Windows-DNS-Client` | every DNS name this machine resolves | admin |
| ETW Threat-Intelligence provider | remote-thread injection, LSASS handle opens, VirtualAllocEx | PPL/admin |
| AMSI provider | PowerShell / VBA / JS / in-memory .NET **content** at execution | admin |
| WMI `__InstanceCreationEvent` watchers | new services, new WMI event subscriptions | admin |

Reading the machine's *own* network events via ETW is not "using the network" —
no socket is opened, nothing is sent. The bytecode gate still holds.

## Each dynamic threat -> concrete offline detection

| Threat (from the coverage review) | Offline mechanism | Offline verdict quality |
|---|---|---|
| Fileless / in-memory malware | AMSI script content + ETW Threat-Intel injection events + process-tree anomaly | strong |
| Malicious documents | AMSI (macro execution) + parent-child (Office -> powershell/cmd/mshta) | strong |
| Browser extensions / infostealers | periodic enumeration of Chrome/Edge/Firefox extension manifests; flag new, over-permissioned, side-loaded, or unpacked | strong, and easy — do this first |
| C2 beaconing | ETW network+DNS: detect periodic connections to a stable destination (regular interval, low jitter) from one process | pattern: strong; **naming the destination bad: needs intel** |
| Ransomware behavior | ETW file events: mass rename/rewrite + entropy jump + shadow-copy deletion (vssadmin/wmic) in a short window | strong |
| Credential theft | Threat-Intel provider: non-system process opening a handle to lsass | strong |
| Live persistence | WMI watcher: new service / scheduled task / **WMI event-consumer** appearing while running (closes the WMI-persistence gap the static review flagged) | strong |
| Phishing | only downstream effects (the payload executing) are visible offline | **weak offline — needs intel** |

## What genuinely needs the network, and how to serve it without lying

Two things are degraded offline: **global reputation** (is this hash/domain
known-bad worldwide) and **phishing/URL intel**. Two ways to provide them,
in increasing commitment:

- **A. Offline intel bundle (recommended default, stays inside the gate).**
  Ship a signed threat-intel pack (malware hashes, C2 domains/IPs, phishing
  domains) and refresh it the same way `blanktick_netlog` already takes a
  user-exported Wireshark CSV: the **user** imports an updated pack; the app
  never fetches. Fresher than build time, still zero sockets, still passes the
  gate. This is the on-brand answer and it makes the C2/phishing rows above go
  from "pattern only" to "named."

- **B. A separate network-enabled edition (only if you decide to).** A distinct
  `intel-net/` module and a distinct build **not** covered by the bytecode gate,
  for live cloud reputation and document detonation. This edition **cannot**
  carry the no-network claim, and its marketing must be kept in a separate frame
  from the free product (the two-frames rule). My recommendation: do A, and only
  do B as an explicitly separate SKU if customers demand cloud-grade — never
  fold a socket into the gated build.

## Product decision you own

The one thing I did not decide for you: **does Blanktick Pro ship option A only
(offline, gate intact) or also option B (a separate networked edition)?** My
recommendation is **A now** — it delivers almost all the dynamic value, keeps
the identity that differentiates you, and the resident sensor is the hard part
either way. B can follow as a clearly-separated edition if there is demand.

## Honesty carried into the new tier (keep the ethos)

- **"Not observed" is not "clean."** If the sensor was not running for a window,
  the timeline says so — the dynamic analogue of NotApplicable.
- **A resident offline sensor is a behavioral detector, not a full EDR.** ETW can
  be patched/unhooked by kernel-level malware; the Threat-Intel provider can be
  tampered with. State the evasion class rather than imply total coverage, the
  same way `NoNetwork.kt` states its NIO/JNI gaps.
- **Licensing stays offline too.** Gate Pro behind a signed local license file,
  not a phone-home check — a network call to validate a license would break the
  same promise through the back door.

## Rough build order

1. Browser-extension inventory rule — fully offline, high value, no service yet
   (can even run as a new static rule in the existing snapshot model first).
2. `sensor/` module scaffold + one ETW process session + the normalised
   `SensorEvent` / `RollingWindow` + `BehaviorRule` interface + the no-network
   bytecode gate extended over it.
3. First behavior rules: Office-spawns-shell, lsass-handle, ransomware mass-write.
4. AMSI provider (fileless/macro content).
5. Network/DNS beaconing detector (pattern) + the offline intel bundle importer.
6. Tray/notification surface + license gate + the Pro/free tier split in the UI.
