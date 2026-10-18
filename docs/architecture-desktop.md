# ADR-003 — The desktop build

**Date:** 2026-08-29
**Status:** Accepted, implemented
**Supersedes nothing. Extends:** ADR-002 (the zero-network architecture)

---

## Context

Blanktick shipped as a phone product. The scoring engine, the rule set and the intel
bundle are pure Kotlin/JVM with no Android dependency, which meant a desktop
build was mostly a matter of writing collectors — but the product's central
claim does not survive the move unchanged, and pretending otherwise would have
been the worst possible outcome for an app whose entire pitch is knowing the
difference between *checked* and *assumed*.

Three decisions had to be made before any code:

1. Is a desktop a third platform, or a variant of an existing one?
2. What happens to "this app cannot reach the internet"?
3. Which desktop operating systems do we claim to support, and what do we say
   about the ones we cannot test?

---

## Decision D-13 — Desktop is a sibling platform, not a variant

`Platform` gains `DESKTOP` alongside `ANDROID` and `IOS`.

A laptop and a phone fail in different places. The phone's threat model is a
malicious app inside a sandbox; the laptop's is an account with administrator
rights, a program that starts itself at login, and a service listening on every
interface. Sixteen new rules (`DSK-*`) cover the second set. Eleven existing
rules — disk encryption, screen lock, passwords, DNS, proxy, photo metadata,
extra certificate authorities — apply to both and were enrolled explicitly.

**The safety property:** `BaseRule` defaults to `Platforms.MOBILE`. Adding the
enum constant therefore enrolled *no* existing rule on desktop by accident;
every one of the 59 desktop-only rules had to be edited by name.
`PlatformCoverageTest` asserts that the Android (29) and iOS (15) counts did not
move, so a careless `Platforms.EVERYWHERE` on an Android-only rule fails the
build rather than silently handing iOS a check it cannot perform.

Measured coverage: **88 rules total — 29 eligible on Android, 15 on iOS, 70 on
desktop.** On a healthy Windows machine 69 of the 70 run; SIP is macOS-only.

### Rejected: reuse `OS-EOL-001` on desktop

It reads `referencePatchDates`, a table keyed by *Android* major version. A
Windows 11 machine reports `osMajor = 11`, which would have been compared
against the Android 11 patch date. The rule stayed mobile-only and desktops got
`DSK-UPD-001/002/003` instead.

---

## Decision D-14 — The desktop network guarantee is narrower, and says so

On Android the promise is enforced by the kernel: no `INTERNET` permission, no
sockets, end of discussion. **A desktop JVM has no equivalent.** A process
started by the user can open sockets and nothing inside that process can make
that untrue.

So the desktop claim is deliberately smaller, and enforced statically:

| Mechanism | What it actually proves |
|---|---|
| `assertNoNetworkBytecode` | No compiled Blanktick class references a networking API. Zero tolerance; one class exempt by exact name. **This is the claim.** |
| `auditDependencyNetworkSurface` | Pins the set of third-party jars containing networking code. Measured 2026-08-29: 0 of 43. The build fails if that set changes. |
| `NoNetwork` runtime blocks | Blocks `java.net.Socket` and http/https URLs. Defence in depth. |

**The gaps are stated, in the code and on the About screen:**
`java.nio.channels` cannot be intercepted after startup, and native code and
child processes are out of reach. Anyone wanting a hard guarantee is told to add
an OS-level egress rule — enforced by their operating system, not by us, which
is the only kind of guarantee worth having.

### Rejected: a `SecurityManager`

It would close both gaps on JDK 17. It is also deprecated for removal,
`System.setSecurityManager` throws unless the JVM was started with
`-Djava.security.manager=allow`, and it is gone in JDK 24. Building the headline
claim on a mechanism that disappears at the next LTS means the claim quietly
stops being true after a routine JDK bump, with nothing failing to say so. A
narrower guarantee that keeps working beats a broad one with an expiry date.

### The scanner is positive-controlled

A broken scanner and a clean codebase produce identical output. `-PblanktickNetworkGateSelfTest`
drops the `NoNetwork` exemption; the gate must then fail. If it passes, its
silence means nothing.

---

## Decision D-15 — Three operating systems, with their status stated per OS

| OS | Status | Why it is written down |
|---|---|---|
| Windows | Runs on real hardware; 17 checks answered on the dev machine | Testable here |
| macOS | Compiles, parsers tested against captured output, **never executed** | No Mac available |
| Linux | Compiles, exercised only under WSL | WSL is not a desktop session |

This is survivable rather than dangerous because of the null contract: every
query in every collector returns `null` on anything unexpected, so a wrong guess
about a tool's output format produces *"not checkable"*, never a false green
tick. A Mac user running this today sees a short list of checks and a long list
of things Blanktick says it could not determine — honest, if not yet useful.

An OS that is none of the three is reported as unsupported and no score is
shown. Falling through to the Linux collector would produce a confident-looking
screen from an app with no idea what it is looking at.

---

## Two findings that changed the implementation

Both were discovered by running the thing on real hardware, and both are the
kind of bug that a passing test suite would never have caught.

### `powershell -EncodedCommand` gets the app killed by Defender

The first Windows collector passed each query as a `-Command` argument.
`ProcessBuilder` re-quotes arguments on Windows, so any script containing quotes
or `$_` arrived subtly different from what was written — the symptom was not an
error but *silence*, and seventeen checks reported as not-checkable.

`-EncodedCommand` fixed the quoting completely and introduced a far worse
problem: **Microsoft Defender terminated the entire application.** Spawning
base64-encoded PowerShell is behaviour signature `Behavior:Win32/PShellEnc.A`;
Defender killed the parent `java.exe` silently, with exit code 0 and no stack
trace, which took a bisect of the probe script to find.

Defender is right. Encoded PowerShell issued by another program is a malware
technique and a security product has no business using one. The script is now
written to a temp file and run with `-File`: no quoting layer, no signature
match, and the most auditable of the three options — while a scan runs, the
exact script is a readable file on disk.

### `Cert:\CurrentUser\Root` is not "certificates the user installed"

Windows mirrors the machine root store into every user's store. Listing the user
store returned 52 certificates on the development machine, all legitimate, and
the app would have reported **52 critical TLS-interception findings on a
perfectly healthy computer** — precisely the false alarm that teaches people to
ignore a security tool.

The collector now reports the *difference* between the user and machine stores
(0 on that machine, correctly). The cost is stated rather than hidden:
machine-wide interception certificates are not detected on Windows in this
build. Telling them apart from Microsoft's own roots needs a bundled list of
pinned thumbprints; distinguishing them by subject name would be worse than
useless, since the name is the one part an attacker controls.

---

## Consequences

**Gained.** A real desktop product sharing one scoring engine, one rule ID
namespace and one intel format with the phone apps. The desktop build can
inspect the network it is on, which the Android build currently cannot.

**Cost.** A third UI to keep in step. `desktop/ui/Theme.kt` is a copy of the
Android file differing only in its package declaration — kept as a copy rather
than extracted, because `:core` must stay free of any UI dependency for the
Swift mirror comparison to mean anything. `tools/gen_tokens.py` now emits four
targets from `design/tokens.json`, so colours and spacing cannot drift.

**Newly visible.** Android's `ACCESS_NETWORK_STATE` ban means four network rules
never run on the phone. That was always true; writing the desktop collector,
where they do run, is what made it obvious. It is now documented in
`AndroidCollector.kt` as a product decision to revisit rather than a bug —
`ACCESS_NETWORK_STATE` grants no ability to send anything, since without
`INTERNET` the kernel still refuses every socket.
