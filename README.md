# Mume

A security checkup for your phone and your computer that runs entirely on the
device it is checking.

**The app has no `INTERNET` permission.** Not "we choose not to send data" — the
operating system will not let it open a socket, because it never asked for one.
That is verifiable in ten seconds against any build:

```
$ aapt dump permissions app-debug.apk
package: com.mume.app.debug
uses-permission: name='android.permission.READ_MEDIA_IMAGES'
uses-permission: name='android.permission.READ_EXTERNAL_STORAGE' maxSdkVersion='32'
uses-permission: name='android.permission.PACKAGE_USAGE_STATS'

$ aapt dump permissions app-debug.apk | grep INTERNET
$
```

The build enforces it: `assertNoNetworkPermissionDebug` reads the **merged**
manifest and fails if any network permission appears — including one injected by
a transitive dependency, which is the realistic way it would happen.

### On desktop, the same promise is weaker, and we say so

A desktop JVM has no permission model to opt out of. A process started by the
user can open sockets and nothing inside that process can make that untrue. So
the desktop build makes a narrower claim and enforces it differently:

```
$ gradlew :desktop:check
  Mume: no Mume class references a networking API.
  Mume: scanned 43 runtime jars, 0 contain networking code.
  Mume: dependency network surface unchanged (0 jars).
```

- **`assertNoNetworkBytecode`** scans the compiled classes of `:core` and
  `:desktop` for any reference to `java.net.Socket`, `HttpURLConnection`,
  `SocketChannel` and friends, and fails the build if one appears. Exactly one
  class is exempt, by exact name: `NoNetwork`, whose job is to break them.
- **`auditDependencyNetworkSurface`** pins **every** third-party jar on the
  runtime classpath — 42 of them — and flags those containing networking code.
  As measured on 2026-08-29, **none of the 43 runtime jars (Compose
  Multiplatform, Skiko, coroutines, the Kotlin stdlib) contains a single
  reference to a networking API.** The build fails if the set changes.
  *An earlier version recorded only the jars that did contain networking code,
  which meant a new clean dependency passed silently. That was a false assurance
  and is fixed.*
- **`NoNetwork`** additionally blocks `java.net.Socket` and `http`/`https` URLs
  at runtime. This is defence in depth, not the guarantee: `java.nio.channels`
  cannot be intercepted after startup and native code is out of reach. The
  About screen lists both gaps rather than implying total coverage.

The scanner is positive-controlled, because a broken scanner and a clean
codebase produce identical output:

```
$ gradlew :desktop:assertNoNetworkBytecode -PmumeNetworkGateSelfTest
> Task :desktop:assertNoNetworkBytecode FAILED
      com/mume/desktop/NoNetwork$BlockedSocketImpl.class -> java/net/Socket, java/net/InetAddress
```

If that *passes*, the gate is dead and its silence means nothing.

---

## Status

| Component | State |
|---|---|
| `core/` — scoring engine, rules, filters, URL analysis, EXIF | **Builds. 208 tests, 0 failures.** |
| `app/` — Android, Compose | **Builds. 26.6 MB APK produced. 30 tests, 0 failures.** |
| `desktop/` — Compose Multiplatform | **Builds and runs. `Mume.exe` produced. 11 tests, 0 failures.** |
| Windows collector | **Runs on real hardware.** 17 of 27 desktop checks answered on the dev machine. |
| macOS collector | **Written, never executed.** No Mac available. |
| Linux collector | **Written, exercised only under WSL.** Not a real desktop session. |
| Intel bundle pipeline (Python → Kotlin ×2) | **Working. Cross-language parity proven.** |
| `web/` — marketing site + live link checker | **Working. 30/30 logic parity tests.** |
| `design/` — tokens, interactive prototype | **Working.** |
| `ios/MumeCore/` — Swift mirror | **Written, not compiled.** No Swift toolchain on Windows. |

**249 tests across the three JVM modules, 0 failures.** `gradlew check` is green, including both network gates and Android lint.

**Honest caveats.** The Swift sources mirror the Kotlin line for line and pin the
identical hash vectors, but have never been through a compiler — a reviewed
draft, not working code. The macOS collector is in the same position: it
compiles, its parsers are tested against captured output, and no one has watched
it run on real hardware. Both fail safe rather than fail silent: every query
returns `null` on anything unexpected, so an untested guess produces "not
checkable", never a green tick.

The intel bundle currently shipping is **synthetic placeholder data**
(`synthetic=true` in `manifest.txt`). Both apps detect this and say so on screen
rather than presenting meaningless password and link verdicts as findings.

---

## What it checks

**62 checks in total.** Coverage per platform, measured by `PlatformCoverageTest`
rather than estimated:

| Platform | Eligible | Run on an *idealised* device | Not checkable |
|---|---|---|---|
| Android | 29 | 29 | 33 (the desktop-only rules) |
| iPhone | 15 | 12 | 50 |
| Desktop | 44 | 43 | 19 |

Those are fixture numbers — a device that answers every question it can. **A real
machine answers fewer.** On the development laptop (Windows 11, standard user, no
elevation) the desktop build runs **17 of 45** and reports **28 as not
checkable**: 18 written for a phone, 10 that this computer declined to answer.
The dashboard states both numbers and separates the two causes, because
"permanent" and "might change next scan" are not the same fact.

The asymmetry is real and every app says so on screen — listing what it could
*not* look at — rather than showing ticks in every column.

**Highest-value, and impossible on iOS:**

- **Cloned / repackaged apps.** An app claiming `com.whatsapp` but signed with a
  different key is not that app. Detected against a bundled registry of genuine
  signing certificates — no server has an advantage here, and cloud scanners
  routinely miss it because they match file hashes, which a repacker changes for
  free.
- **Dangerous permission *combinations*.** Reading SMS is what a messaging app
  does. Drawing over other apps is what a chat head does. Driving the UI through
  the accessibility API is what a screen reader does. All three together is a
  banking trojan, and almost nothing legitimate needs them at once.
- **Extra certificate authorities.** An interception proxy has to install its own
  root CA. We enumerate every CA the OS did not ship — and say when it was an
  employer's MDM rather than an attacker.

**Desktop only — 16 rules that have no phone equivalent:**

- **Host firewall**, per profile. The common failure is not "firewall off", it is
  "Public profile off since that printer thing", which disarms it precisely when
  the laptop leaves the house.
- **Services listening on every interface**, with the ports the OS always binds
  (SMB, mDNS) excluded — a rule that fires on every machine is a rule people
  learn to dismiss.
- **Inbound remote control** (RDP, SSH, Screen Sharing), scored lower when it is
  hardened, because a considered choice is not an accident.
- **Real-time malware protection and definition age**, attributed to whichever
  product is actually active rather than assuming Defender.
- **Secure Boot**, **SIP** on macOS, **automatic updates**, **update staleness**.
- **Accounts**: passwordless sign-in (critical), the guest account, and whether
  your everyday account holds administrator rights.
- **Programs that start themselves**, read from seven places: the Run and
  RunOnce keys (per-user, machine, and the 32-bit views of both), the Startup
  folders, Winlogon's `Shell` and `Userinit`, Image File Execution Options
  debugger hijacks, scheduled tasks, and auto-start services outside the system
  directories. Reported as unsigned only when the platform positively says so —
  an unverifiable signature is *not* an unsigned one, and a binary inside a
  Store package carries the package's signature rather than its own.

  Each source reports its own coverage. If one cannot be read — several Image
  File Execution Options subkeys are ACL'd against a normal user, which is
  ordinary — the app names it rather than quietly returning a shorter list.
  Still not everything: WMI event subscriptions and COM hijacks are not read,
  and the finding says "starts automatically", never "this is everything that
  does".
- **Removable media.** Two things about a USB stick are answerable offline and
  Mume checks exactly those: whether the AutoRun policy has been *explicitly
  weakened* from the Windows default (absent means hardened — Microsoft turned
  autorun off for removable drives in 2011, so a rule that warned about plain
  AutoPlay would fire on every machine alive), and whether a drive that is
  attached right now is encrypted. Nothing plugged in reports as *not checkable*,
  never as a pass. It also shows every drive and phone the computer still
  remembers — not a finding, never scored, just your machine's memory of you.
- **Programs pretending to be Windows.** A real `svchost.exe` lives in the
  system folder. Anything else with that name, running out of your personal
  folders, is not a borderline case — there is no innocent reason to do it.
  Mume checks the programs running right now against a per-binary table of where
  each one actually belongs. That table has to be per binary: a single "must be
  in System32" rule reports `explorer.exe` on every Windows machine alive,
  because Explorer genuinely lives in `C:\Windows`.

  This is the one part of Mume that looks for malware, and it is worth being
  precise about what it means. It does not scan your disk, hash your files or
  carry signatures — that is the antivirus you already have, and it needs a
  server Mume does not talk to. What it detects is a *technique*, which is a
  property of your machine rather than a fact someone else has to tell you
  about a file. A dormant installer sitting in a downloads folder will not be
  found here, and nothing in this section should be read as "your computer is
  clean".

  Roughly a third of running processes will not reveal their path to a program
  without administrator rights — 179 of them on the development machine. That
  number is shown, because "I checked everything" would not be true.
- **A bundled list of known-malicious files.** The closest thing here to
  conventional antivirus, and worth being exact about. Mume ships a table of
  SHA-256 hashes and compares it against the programs that start themselves and
  the ones running from your personal folders — about sixty files, not your
  whole disk.

  It is **stale the day it is built**, it will never approach a real scanner,
  and **it is defeated by recompiling the file**: one changed byte, different
  hash. It earns its place because it costs about eight bytes an entry and
  catches the commodity case — a file that has been sitting unchanged on a disk
  since somebody else already identified it.

  The table is an exact sorted set rather than a Bloom filter, unlike the
  password corpus. A false positive there means "change a password that was
  fine"; a false positive here tells someone a legitimate program on their
  computer is malware, which is the one output this product must never produce
  by accident.

  It ships containing the EICAR test signature — a 68-byte string every scanner
  has recognised since 1991, and not malware — so the feature can be proven to
  work by anyone, on any machine, with nothing dangerous on disk. To load a real
  corpus: `python tools/build_intel.py --malware hashes.txt`, where the file
  holds one SHA-256 per line (or CSV with the hash first). Any line that is not
  64 hex characters is skipped.
- **Machine hardening**: User Account Control, whether sign-in credentials are
  left readable in memory, SMBv1, LLMNR, remote-administration services, and
  whether an auto-logon password is sitting in the registry in cleartext. Mume
  never reads that password — only whether one exists. An app that copied a
  stored credential into its own report would have made the problem worse in
  the course of describing it.
- **An audit of the antivirus you already have.** Mume is not an antivirus and
  cannot become one: no network means no reputation lookup, and it has no file
  scanner. What it can do is check whether the scanner already installed has
  been quietly switched off in part — a disabled behaviour monitor, tamper
  protection off, or a threat the product found and never resolved. Malware
  disables one component rather than the whole suite, because the whole suite
  going dark gets noticed, and from the outside a partly-disabled antivirus
  looks exactly like a working one.
- **Installed software**, read from the OS's own uninstall registry. Two things
  are checkable offline and Mume checks exactly those: software **past its
  vendor's security support** (matched against a catalogue of products whose EOL
  has already happened and is final, so the list can go stale by becoming
  incomplete but never by becoming wrong), and software installed **somewhere it
  needed no permission to reach while naming no publisher**. Neither half is a
  finding alone — measured on the development machine, 11 programs live in
  user-writable folders and all 11 name a publisher, so this fires zero times
  there while a naive "installed under AppData" rule would fire seven.

**Everywhere:** screen-lock strength, disk encryption (named per OS — BitLocker,
FileVault, LUKS), lock timeout, breached and reused passwords, photo GPS
metadata, extra certificate authorities, DNS and proxy inspection, and an
offline phishing-link checker.

---

## Architecture

```
core/                Pure Kotlin/JVM · no I/O · no Android · no network
  model/             DeviceSnapshot, DesktopFacts, Finding, Severity, Category
  scoring/           ScoringEngine + ScoringPolicy  (the normative one)
  rules/             45 rules, stable IDs, platform-gated
  filters/           BloomFilter, SortedHashSet64, Hashing
  analysis/          UrlAnalyzer, Punycode, Confusables, PublicSuffix, ExifGps
app/                 Android · Compose · collectors only
desktop/             Compose Multiplatform · Windows/macOS/Linux collectors
  collect/           Shell, WindowsProbe (one readable script), 3 collectors
  NoNetwork.kt       Runtime socket + URL blocks, with their gaps documented
ios/MumeCore/        Swift mirror — same rule IDs, same vectors
design/              tokens.json (source of truth) + interactive prototype
web/                 Marketing site with a live, offline link checker
tools/               Python, build-time only — bundle builder, token codegen
docs/                Kickoff panel, ADR-002 (offline), design panel
```

### The `null` contract

Every observable field on `DeviceSnapshot` is nullable, and **`null` means "this
platform cannot observe this"** — never `false`, never a guess. A rule whose
inputs are `null` returns `NotApplicable` and is shown to the user as *not
checkable*, never as a passing check.

That one convention is what stops the iPhone build from displaying green ticks
for things iOS is incapable of inspecting. It is enforced by tests
(`NullContractTest`, `DesktopRulesTest`), not by discipline.

It earned its keep during the desktop build. Half the Windows queries in the
first version were returning nothing because of a shell-quoting bug — and the
app dutifully reported seventeen checks as "not checkable" instead of inventing
answers. The bug cost coverage. It could not cost correctness.

### Adding a platform cannot silently change an old one

`BaseRule` defaults to the two mobile platforms. Adding `Platform.DESKTOP` to the
enum therefore enrolled **no** existing rule automatically; each of the eleven
that now run on a desktop had to opt in by name, and
`PlatformCoverageTest` asserts that the Android and iOS numbers did not move.

### Two data structures, on purpose

| Data | Structure | Why |
|---|---|---|
| 2M breached passwords | Bloom filter, p=0.1%, 3.4 MiB | Its only error is a **false positive** — telling someone to change a safe password. Annoying, harmless. False negatives are impossible, so a breached password can never be reported as safe. |
| 2M blocked domains | Exact sorted `u64` + prefix index, 15.3 MiB | A false positive **blocks a site the user needs**. The feature looks broken, they switch it off, and lose all its protection. There is no safe direction to be wrong in. |

### A score you can audit

Every point traces to one finding, per-finding integers sum exactly to
`100 − score` (largest-remainder apportionment, so the column on screen really
adds up), categories are capped so one bad area cannot dominate, and repeat
findings decay geometrically so ten small issues never outweigh one serious one.

---

## Build

Requires JDK 17 and the Android SDK (platform 35, build-tools 35).

```bash
# 1. Generate design tokens for every platform
python tools/gen_tokens.py

# 2. Build the intel bundle. --demo makes a small synthetic one;
#    supply real corpora for a shipping build.
python tools/build_intel.py --demo
python tools/build_intel.py --passwords pwned-top2m.txt --domains hosts.txt

# 3. Build and test everything, including both network gates
gradlew check

# 4. Android APK
gradlew :app:assembleDebug

# 5. Desktop app
gradlew :desktop:run                  # run it
gradlew :desktop:createDistributable  # native app + bundled JRE
gradlew :desktop:packageMsi           # or packageDmg / packageDeb
```

On a machine where `JAVA_HOME` points at a JDK older than 17 (Gradle 9 needs
17+), set it for the invocation rather than globally:

```bash
JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-17.0.20.8-hotspot" ./gradlew check
```

Bundle sizing is a flag, not an architecture decision:

```bash
python tools/build_intel.py --password-limit 10000000 --domain-limit 4000000
```

The default is 2M/2M (~20 MiB). Breached-password reuse is brutally long-tailed,
so the top 2M covers essentially every real case; 10M costs 14 extra MiB, does
nothing about the actual limitation (freshness), and makes the install heavier
for people on expensive mobile data.

### Clone-detection registry

`tools/seeds/signers-seed.txt` ships **empty on purpose**. A wrong entry there
tells someone their real banking app is malware. Populate it mechanically:

```bash
python tools/extract_signer.py /path/to/genuine.apk >> tools/seeds/signers-seed.txt
python tools/extract_signer.py --from-device com.whatsapp com.android.chrome
```

With no entries, `APP-CLONE-001` reports *not checkable* — the correct behaviour
for a check we have no data to run.

### The one file Mume writes

The desktop build wrote **nothing** to disk until Settings existed — no config,
no cache, no history. Settings spends part of that deliberately, and is bounded
by rule: `settings.conf` may hold UI preferences and nothing else. No scan
results, no scores, no findings, no machine identifiers. The Settings screen
prints the file's full path and its entire contents, because *"nothing leaves
this computer"* was never the same claim as *"nothing is written"* and the
difference should be visible rather than argued.

It also carries the **Reduce motion** switch, which exists because Compose
Desktop exposes no API for the OS preference — verified against the toolkit and
against Windows itself — so a manual switch is the only way to honour DD-10 at
all.


---

## Reading over the desktop app's shoulder

The desktop build ships two modes whose only purpose is to let you check it:

```bash
Mume --script    # prints the exact PowerShell it runs on your machine
Mume --probe     # prints every field it read, including the nulls
```

`--script` output is one readable block you can paste into a terminal and
compare against what the app displayed. `WindowsProbeTest` asserts that the
script contains no mutating cmdlet, no network cmdlet, and no cmdlet needing
elevation — **Mume reports, you decide and act.** It never changes a setting.

`--probe` is how a "not checkable" is diagnosed: a field printed as `null` is
either an honest platform limit or a collector bug, and this is how the two are
told apart.

### Two things the Windows collector learned the hard way

**Do not use `powershell -EncodedCommand`.** It solves the argument-quoting
problem perfectly and gets the entire application killed by Microsoft Defender:
spawning encoded PowerShell is behaviour signature `Behavior:Win32/PShellEnc.A`,
and Defender terminates the *parent* process silently with exit code 0. Which is
fair. Base64ed PowerShell issued by another program is a malware technique, and
a security product has no business using one. The script goes in a temp file and
runs with `-File`.

**Do not list `Cert:\CurrentUser\Root` and call it "user-installed".** Windows
mirrors the machine root store into every user, so that query returned 52
certificates on the development machine — all legitimate — and the app would
have reported 52 critical TLS-interception findings on a healthy computer. The
collector now reports the *difference* between the user and machine stores.
Machine-wide interception certificates are consequently **not** detected on
Windows in this build; that gap needs a bundled list of Microsoft root
thumbprints and is stated in the About screen rather than papered over.

---

## The three-language hash contract

Python writes the intel bundle. Kotlin reads it on Android. Swift reads it on
iOS. All three implement one specification:

```
h1(x) = splitmix64( fnv1a64(utf8(x), OFFSET_A) )
h2(x) = splitmix64( fnv1a64(utf8(x), OFFSET_B) ^ 0xD6E8FEB86659FD93 )
```

A one-bit divergence in any of them does not crash. It silently returns wrong
membership answers — and for the password filter, "silently wrong" means telling
someone a compromised password is safe.

So the agreement is tested two ways:

1. **Pinned vectors** (`shared/hash-vectors.json`, generated by
   `tools/gen_hash_vectors.py`) asserted identically in `HashVectorsTest.kt` and
   `HashParityTests.swift`. The `🔒emoji` vector is the important one: it is a
   surrogate pair in UTF-16, so an implementation that hashed UTF-16 code units
   instead of UTF-8 bytes fails on that line and passes every other.
2. **Bundle round-trip** (`IntelBundleParityTest.kt`): Kotlin opens the file
   Python wrote and looks up values Python inserted.

If these fail, do not "fix" the test. Find out which implementation moved.

---

## Run the site and prototype locally

```bash
python -m http.server 8910
```

- <http://127.0.0.1:8910/web/index.html> — marketing site, with a link checker
  that runs the real analyzer in the page. Open the network tab: there is no
  request to make.
- <http://127.0.0.1:8910/design/prototype.html> — every app state, both themes,
  and a text-size slider that goes to 200% (nothing may clip). States are
  deep-linkable: `?screen=ios`, `?screen=ledger`, `?theme=dark`.

```bash
node web/verify.mjs      # 30 tests: the site's checker matches UrlAnalyzer.kt
```

---

## What Mume deliberately cannot do

Stated here because the app says the same thing on screen:

- **Email breach monitoring.** Genuinely impossible offline without shipping
  corpora of other people's personal data. Dropped, not faked.
- **Expanding shortened links.** `bit.ly/…` is reported **unknown**, never *safe*.
- **Live threat feeds.** Blocklists refresh when the app updates. The build date
  is shown on every scan.
- **Tracker/DNS blocking.** Requires network capability, so it cannot exist in
  this build. Deferred to a separate, separately-installable module.
- **Any product analytics.** We do not know how many people use which feature,
  and cannot find out.
- **Scan the contents of a USB stick.** Mume never opens files on a drive,
  hashes them, or checks them against anything. That is an antivirus and it
  needs a server.
- **Tell you whether a program is malware.** The desktop lists what is installed
  and checks two offline properties of it. Hashing files and asking a reputation
  service is what an antivirus does, and it needs a server.
- **Tell you your browser is out of date.** Knowing what "current" is requires a
  network. A bundled "latest version" table would start rotting the day it
  shipped and eventually call every up-to-date browser stale.
- **Read your saved passwords.** On desktop it could — the vaults are on the
  disk and decryptable by that user — and it deliberately does not. You type in
  what you want checked. An app that can silently decrypt your password store is
  one you have to take on trust.
- **Count pending OS updates.** On both Windows and macOS that means asking the
  vendor's servers. Reported as not performed, never as "nothing pending".
- **See the Wi-Fi network on Android.** `ACCESS_NETWORK_STATE` is on the
  forbidden-permission list, so `NET-WIFI-001`, `NET-PROXY-001`, `NET-VPN-001`
  and `NET-DNS-001` report *not checkable* on the phone. The desktop build does
  run them. This is a real cost of the permission policy and is written down in
  `AndroidCollector.kt` rather than left to be rediscovered.
- **Change anything.** Mume tells you what to fix and lets you fix it. A security
  tool that silently reconfigures a machine is one nobody can audit.

Passing every check does not mean you are safe. It means these particular
problems are not present. The app says that too.

---

## Documents

| File | What it is |
|---|---|
| `docs/kickoff-meeting-2026-08-28.md` | Cross-functional panel; decisions D-01…D-12 |
| `docs/architecture-offline.md` | ADR-002 — the zero-network architecture |
| `docs/architecture-desktop.md` | ADR-003 — the desktop build; D-13…D-15 |
| `docs/design-meeting-2026-08-28.md` | Design panel; decisions DD-01…DD-13 |
| `docs/design-meeting-2026-08-29.md` | Desktop dashboard panel; DD-14…DD-20, and what the shipped code was not delivering |
