# How Blanktick works — the full story

This is the complete text of blanktick.org as it stood on 26 October 2026, before
the homepage was simplified. The website now keeps the short version; this page
keeps the detail. The same long page is also still online at
[blanktick.org/details.html](https://blanktick.org/details.html).

> **Out of date since this text was written:** the old site said Blanktick has
> "no real-time protection". The desktop app now has **Live protection**, a
> behaviour sensor that watches for ransomware, harmful Office macros, password
> theft, web shells, hacker remote control and risky AI-tool activity as it
> happens, and can stop the process if you switch that on. It still has no
> signature-based file scanner of its own; for files it asks Microsoft Defender.

---

## A green tick can mean "we checked, it's fine." Or it can mean "we never looked."

Blanktick is a free, open-source security scanner for Windows and Android. It
tells you which one you are looking at.

### The scan receipt

A real scan of the developer's own Windows 11 laptop, unedited: 50 answered,
31 reported not checkable.

| | |
|---|---|
| **50 — Checks ran** | Score 81 out of 100, from five findings. The 81 is computed over the 50 that ran — it is not a percentage of your security, it is a percentage of what was looked at. |
| **31 — Could not be checked** | 18 are written for a phone and will never apply to a laptop. 13 are questions this computer declined to answer. All 31 are named on screen, each with its reason. |

---

## 01 · The gap — Your antivirus watches files. Nothing is watching your settings.

Defender is good at malware. It will not tell you that Remote Desktop is on,
that a root certificate was added after your laptop left the factory, or that a
program you uninstalled in 2023 still starts at boot.

That gap is the product. Most of Blanktick's **70 desktop checks** have no
counterpart in Windows Security, because they are configuration questions — and
configuration is what an attacker changes once they are already in.

**It asks the scanner you already have.** Blanktick shortlists roughly seventy
files — the ones that start automatically, and the ones running from your own
folders — and hands that list to Defender's own command-line scanner with
`-DisableRemediation` set, so it asks the question without changing the answer.

| Measured | Submitted | Flagged |
|---|---|---|
| on the developer's laptop on 2026-09-07 | 67 files | 0 |

> **It is not an antivirus and does not replace one.** Blanktick has no file
> scanner, no signatures and no real-time protection, and the offline design
> means it never will. If you turn Defender off to run this instead, you have
> made your computer worse. Run both. Blanktick reports; it never changes
> anything.
>
> *(See the note at the top: Live protection has since been added. The advice
> to keep Defender on still stands.)*

Prefer text? `gradlew :desktop:run --args="--scan"` prints the whole report —
findings and the not-checked list — to your terminal.

---

## 02 · Coverage — Every scanner tells you what it found. Blanktick also tells you what it never saw.

A list of green ticks is only useful if the ticks all mean the same thing, and
usually they do not. Some mean "we looked, it is fine." Some mean "this does not
apply on your device." A few mean "we asked and got nothing back." All three
print as a tick and you cannot tell them apart.

Blanktick splits them. There are **88 checks**. Every one ends in a result, or in
the not-checked list with a reason attached to it. Not all 88 are eligible
everywhere: **29 can run on Android, 15 on an iPhone, 70 on a desktop.** On any
particular machine, fewer than that will actually answer.

| Platform | Eligible checks |
|---|---|
| All checks | 88 |
| Desktop | 70 |
| Android | 29 |
| iPhone | 15 |

> It is the difference between a mechanic who hands your keys back and says
> "all fine", and one who says "brakes and tyres are good, I could not get the
> gearbox up on the ramp." The second gives you worse news and a more useful day.

**Table 2.1 — Why 30 checks did not run on the developer's Windows 11 machine.**
Grouped by reason, because eighteen rows saying the same thing is the point:
that is a platform boundary, not eighteen separate failures.

**Written for a phone (18 checks)**

| Check | Result |
|---|---|
| Root / jailbreak detection | Not checked — a laptop cannot be rooted |
| USB debugging & developer options | Not checked — written for a phone |
| Cloned / repackaged app detection | Not checked — there is no installed-app list in the Android sense |
| Android security-patch level | Not checked — a desktop uses a different update model |
| Lock-screen notification previews | Not checked — a phone concept |

**This computer would not answer (12 checks)**

| Check | Result |
|---|---|
| System Integrity Protection | Not checked — macOS only; this machine is Windows |
| Password required when the screen wakes | Not checked — Windows will not tell an unprivileged app |
| Downloaded programs are checked before they run | Not checked — the setting is absent, which is both the default and what a failed read looks like |
| Attached removable drives are encrypted | Not checked — nothing was plugged in, which is not the same as nothing being wrong |
| Saved passwords appear in known breaches | Not checked — the scan never harvests saved passwords; paste one into the password tool and it is matched offline |

Ten of the thirty shown. The app lists all of them, by name, on screen.

---

## 03 · The refusal — If the scan does not finish, there is no score.

An interrupted scan still has real findings in it, and it would be easy to
average what we got and print a number anyway. Blanktick does not. A score
calculated over an unknown fraction of the checks is a number that looks like
information and is not — and it is worse than no number, because you would act
on it.

So an unfinished scan shows the findings it has, the checks it got through, and
a blank where the score goes. This is the one place a security app is supposed
to look unfinished, because it is.

This is not hypothetical. It was found by a scan that overran its own time limit
and reported 100 out of 100 from two checks of sixty-eight, because a score is
deductions subtracted from a hundred and almost nothing had been deducted. That
build never shipped.

---

## 04 · What it checks — What it actually looks at

Six areas, chosen because they are where an attacker who is already in makes
changes, and where the usual tools do not look. Every check is read-only. None
of them changes a setting.

**4.1 Programs that start themselves.** Twelve places, not the four most tools
check: Run and RunOnce keys in both registry views, Startup folders, Winlogon,
Image File Execution Options, scheduled tasks, services, WMI subscriptions, COM
hijacks, AppInit DLLs, Active Setup and three system DLL lists. On the
development machine that found **47 entries**. The four usual locations found
nine.

**4.2 The verdict of the antivirus you already have.** Blanktick hands the
roughly seventy files it considers worth asking about to the scanner already on
your machine — read-only, with remediation switched off, so nothing is
quarantined or moved. Its signatures are hours old. Anything Blanktick could
bundle would be stale the day it shipped.

**4.3 The AI surface.** A local model server listening on every interface
rather than just your machine. The programs an AI tool-config file has been
granted permission to run — a grant that executes commands and appears in no
Run key, no scheduled task and no service, so every startup checker ever written
looks past it, including Blanktick's own. API keys sitting in those files,
counted and never read. And whether Windows Recall has been switched off, and
whether its snapshot store is on disk.

**4.4 Certificate authorities your machine trusts.** Windows records which roots
it delivered and when each one was written. A root that appeared after the
operating system was installed, did not arrive through Microsoft's update
channel and was not deployed by workplace policy was put there by somebody.

**4.5 What is reachable, asked of the firewall.** "Twenty-five things are
listening" is true on a stock Windows machine and tells you almost nothing,
because Windows blocks inbound by default. The firewall knows which programs it
permits, so Blanktick asks it. On the development machine: two, and both were
the developer's own web servers.

**4.6 Machine hardening.** User Account Control, whether sign-in credentials are
left readable in memory, SMBv1, LLMNR, remote-administration services, and
whether an auto-logon password is sitting in the registry in cleartext.
Blanktick never reads that password — only whether one exists.

---

## 05 · Offline — Offline by construction, not by promise

**Android — permission absent.** The Android build never declares
`android.permission.INTERNET`, so the kernel refuses it a socket. You do not
have to believe that:

```
$ aapt dump permissions blanktick.apk | grep INTERNET
(no output)
```

**Desktop — build gate.** On desktop there is no permission to give up, so the
guarantee is a build gate instead. `assertNoNetworkBytecode` fails the build if
any Blanktick class references a networking API, and all 42 third-party jars on
the runtime classpath are pinned and contain none either. The gate is
positive-controlled: run it with `-PblanktickNetworkGateSelfTest` and it must
*fail*, or its silence means nothing.

> **One thing we would rather say than have pointed out.** Blanktick opens no
> network connection. But "nothing on your computer touches the network because
> of Blanktick" would be false. On Windows it asks the Defender that is already
> running about roughly seventy files, and Defender then does what Defender
> always does — which, depending on the cloud-protection setting *you* chose,
> may include contacting Microsoft. That is Defender's connection, made under
> your settings. But it happens because Blanktick asked.

The website makes no third-party request either. No third-party fonts, no
analytics, no embeds.

---

## 06 · By hand — Two checks you run by hand, and the data behind them

Alongside the scan, Blanktick has two tools you drive yourself: paste in a
password, or paste in a link.

- **Password — 1,000,000.** The password is compared — on your machine, never
  sent anywhere — against the one million most common and breached passwords.
- **Link — ~72,000.** The link is checked against a bundled list of about
  72,000 domains known for malware and phishing, built from the StevenBlack host
  list and abuse.ch's URLhaus feed.

Both lists are snapshots baked into the download. That makes them offline by
construction and, like every other list here, exactly as current as the day you
downloaded the file — a known trade for never phoning home. Earlier builds
shipped these two lists as synthetic placeholders and said so on screen; this
build carries the real data — the bundle is flagged `synthetic=false`, so the
app stops showing the placeholder notice and the two tools return real verdicts.

Neither tool reads anything you did not type in. The automatic scan never
harvests your saved passwords — which is why "saved passwords in known
breaches" stays on the not-checked list: it is a question you ask on purpose,
one password at a time, not something scraped from your browser behind your
back.

---

## 07 · About the project — Why Blanktick exists

*Our mission: security tools that are honest about their own limits, so a tick
on your screen always means somebody actually looked.*

Blanktick started in August 2026 as a side project with a narrow complaint:
security apps show the same reassuring green tick for "checked and fine" and
for "never checked at all". Its working name was Mume. It was renamed Blanktick
in September 2026, after the thing it refuses to print.

The project has three rules that are not up for negotiation.

1. It runs entirely on your device and never sends anything anywhere.
2. It reports and never changes your settings.
3. And it costs nothing: no ads, no account, no paid tier holding back the useful part.

| Founded | Founder | Based in | Licence | Price |
|---|---|---|---|---|
| August 2026 | Simphiwe Damoyi | South Africa | Open source, AGPL-3.0 | Free. No ads, no account |

---

## 08 · Download — Download it, then check what you downloaded

| Version | Platform | Formats | Code-signed | Admin rights | Price |
|---|---|---|---|---|---|
| 0.1.2 | Windows · x64 | .msi installer · portable .zip | No | Not needed | Free |

> **Windows will warn you. That is correct.** You will see *"Windows protected
> your PC"* and you will need *More info → Run anyway*. That is SmartScreen,
> working. This build is **not code-signed** — a certificate costs a few hundred
> pounds a year and Blanktick, which is free and has no revenue, has not bought
> one. Every unsigned program gets that warning, harmless or not, which is also
> why the warning by itself does not tell you much in either direction.

We are not going to tell you to click past a security warning — that is the
habit every piece of malware relies on. Here is what to do instead.

**Step 1 — Download.**
[Blanktick 0.1.2 for Windows (x64 installer)](https://dl.blanktick.org/Blanktick-0.1.2-win-x64.msi).
Installs for your account only, so it needs no administrator rights. Adds
Blanktick to the Start menu and to Installed apps, where it uninstalls like
anything else. No service is registered.

Would rather not install anything?
[Get the portable .zip](https://dl.blanktick.org/Blanktick-0.1.2-win-x64.zip) —
extract the whole folder first (right-click → Extract All), then run
`Blanktick\Blanktick.exe`. Running it from inside the zip will fail.

**Step 2 — Then check the hash.**

```
PS> Get-FileHash .\Blanktick-0.1.2-win-x64.msi -Algorithm SHA256
```

It should print, exactly:

```
C30CFFA64C61678DF5B70211878D80AD1BC182154FC4CAC229234A5923EB1023
```

For the portable .zip: `7DEAA7097BD4ACAC66D0E967359628AF6AD3D8E2BE7E84E72D34EFADC761DD23`

> **This proves less than it looks like it does.** The file and the hash are
> served by the same website. Anyone who can replace the download can replace
> the hash next to it, and you would find them in perfect agreement. What the
> hash rules out is a corrupted or intercepted download. It does not rule out
> this site being compromised — for that, compare against the release tag in the
> repository, which is a second host an attacker would also have to own.

**Or — build it and trust none of this.**

```
git clone https://github.com/opemaid/blanktick && cd blanktick
gradlew check                       # the full test suite, including both network gates
gradlew :desktop:createDistributable
```

Needs JDK 17. This is the only option on this page that does not require
trusting us, and it is the one we would use.

**macOS, Linux and Android.** Not offered yet, deliberately. The macOS collector
has never been run on a Mac and the Linux one has only run under WSL — both
would report almost everything as not checkable, which is safe and nearly
useless. The Android build is not on Google Play; build it from source.

---

*Blanktick is free and open source under AGPL-3.0. It has had no third-party
security audit; it is one person's code, and the build gates exist so you do not
have to take our word for the part that matters. Passing every check is not the
same as being safe. It means the checks that ran, ran clean — and the list of
the ones that did not is on the same screen, at the same size, on purpose.*
