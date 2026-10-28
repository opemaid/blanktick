# Microsoft Store submission — Blanktick 0.1.1

Package: `desktop/build/msix/Blanktick-0.1.1.0-x64.msix`, built by `tools/build-msix.sh`.
It is unsigned on purpose: the Store signs MSIX packages when they are certified.

## 1. One-time account setup (the owner does this)

1. Go to https://storedeveloper.microsoft.com and register as an **Individual** developer
   (free for individuals; identity check with ID + selfie).
2. Partner Center → Apps and games → **New product → MSIX or PWA app** → reserve the name **Blanktick**.
3. Product → Product management → **Product identity**. Copy three values and rebuild:

```bash
MSIX_NAME="<Package/Identity/Name>" \
MSIX_PUBLISHER="<Package/Identity/Publisher, starts CN=>" \
MSIX_PUBLISHER_DISPLAY="<Package/Properties/PublisherDisplayName>" \
tools/build-msix.sh
```

The Store rejects any upload whose identity doesn't match these three values exactly.

## 2. Submission fields

| Field | Value |
|---|---|
| Pricing | Free |
| Markets | All |
| Category | Security (if not offered: Utilities & tools) |
| Privacy policy URL | https://blanktick.org/privacy |
| Website | https://blanktick.org |
| Support contact | hello@blanktick.org |
| Age rating (IARC) | Utility app: no violence, no user-generated content, no sharing, no purchases → 3+ / Everyone |
| System requirements | Windows 10 version 1809 or later, x64 (the manifest minimum; only tested on Windows 11) |

**Restricted capability justification (runFullTrust):**
> Blanktick is a desktop (Win32/Java) app packaged as MSIX. It reads Windows security
> settings with built-in tools (PowerShell, Get-MpComputerStatus, registry reads) to report
> what is and is not protected. It runs as the signed-in user, never asks for elevation,
> makes no network requests, and changes no system settings unless the user turns on
> "Stop flagged processes" in Live protection.

**Notes for certification:**
> No account or sign-in is needed. Open the app and click "Run the first scan"; a full scan
> takes about one minute. The app has no network code, so it works offline and has no
> online features to test.

## 3. Listing (English)

**Product name:** Blanktick

**Short description (≤ 100 characters):**
Free security check-up for Windows that tells you what it could not check.

**Description:**
Most security apps show a green tick even when they never looked. Blanktick shows you both: what it checked, and what it couldn't check, each with a reason.

Blanktick checks 70 settings that attackers change on Windows PCs, and watches for ransomware, password theft and hackers taking control while it is open. When it can't check something, it says so. If a scan doesn't finish, you get no score at all instead of a made-up one.

What it does:
• Full PC check-up: firewall, Windows Security, updates, BitLocker, remote access, risky startup items and more
• Live protection (preview): flags ransomware-style file changes, credential theft, programs beaconing out and AI assistants being driven to run commands, while the app is open
• Virus scan using Windows' own Microsoft Defender engine
• Check a link before you open it: spots look-alike sites such as "paypa1"
• Check a password against a built-in list of breached passwords; nothing is sent anywhere
• Installed software: programs past security support and programs installed where anyone can change them
• USB & drives, AI tool safety, and a plain-English list of every rule it ran

Private by design: Blanktick has no network code. Nothing is uploaded, there's no account and there are no ads.

Blanktick works alongside Windows Security. Keep Windows Security switched on.

**What's new in this version:** First Microsoft Store release.

**Features (up to 20, ≤ 200 chars each):**
- Shows what it checked and what it couldn't check, each with a reason
- 70 Windows security settings checked offline
- Live protection preview for ransomware, credential theft and hacker remote control
- Virus scan with Microsoft Defender's engine
- Link checker for look-alike and phishing addresses
- Breached-password checker that never sends your password anywhere
- No account, no ads, nothing uploaded

**Search terms (max 7):** security scan, privacy, ransomware, phishing link checker, password checker, windows security check, offline security

**Copyright:** © 2026 Blanktick

**Screenshots (1440×980, in this order):** `desktop/msix/screenshots/`
1. `01-this-computer.png` — "See what was checked, and what couldn't be"
2. `04-check-a-link.png` — "Check a link before you open it"
3. `06-check-a-password.png` — "Check a password without sending it anywhere"
4. `02-threats.png` — "Every finding, sorted by how much it matters"
5. `05-installed-software.png` — "Spot software past its security support"
6. `03-live-protection.png` — "Live protection while the app is open"

Screenshots come from the app's `--preview` mode (sample data, not a real machine).

**Store logos:** `desktop/msix/Assets/` (already inside the package). Optional 1:1 box art 1080×1080: `design/social/avatar-1024x1024.png` scaled up, or skip.

## 4. Claims kept out of the listing

"Antivirus", "100% protection", "removes viruses", "replaces Windows Security", "blocks all".
Live protection is described as a preview that runs while the app is open, because that is what the code does.
