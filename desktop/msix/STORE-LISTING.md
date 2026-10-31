# Microsoft Store submission — Blanktick 0.1.2

Package: `desktop/build/msix/Blanktick-0.1.2.0-x64.msix`, built by `tools/build-msix.sh`.
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
> what is and is not protected, and runs Microsoft Defender's own command-line scanner
> (MpCmdRun.exe, report-only) for the optional whole-PC scan. It runs as the signed-in user, never asks for elevation,
> makes no network requests, and changes no system settings unless the user turns on
> "Stop flagged processes" in Live protection.

**Notes for certification:**
> No account or sign-in is needed. Open the app and click "Run the first scan"; a full scan
> takes about one minute. "Scan whole PC" runs Microsoft Defender over every local drive and can
> take 30 minutes or more; it can be stopped at any time. The app has no network code, so it works offline and has no
> online features to test.

## 3. Listing (English)

**Product name:** Blanktick

**Short description:**
Blanktick, your antivirus built for AI. It finds where bad AI can get into your PC (hijacked agents, exposed AI models, leaked AI keys) and lets your own AI agent help you shut the gaps. Free, offline, no account.

**Description:**
Blanktick, your antivirus built for AI.

Bad AI can now get into your PC in ways normal antivirus never looks at: AI agents that outside content can hijack, AI model servers open to your whole network, AI keys saved in plain text, AI tools that download and run code. Blanktick finds these, watches for AI being driven to run commands while it is open, and lets your own AI agent help you shut the gaps.

What it does:
• Bad AI: hijackable AI agents (prompt injection), exposed AI model servers, plaintext AI keys, which tools your AI assistant may run, AI tools that download code, Windows Recall
• Your AI on your side: a read-only MCP server lets Claude or another agent explain your results and help you secure your PC. It can explain, never change anything
• Live protection (preview): flags AI assistants being driven to run commands, ransomware-style file changes, credential theft and programs beaconing out, while the app is open
• Scan your whole PC: every file on every drive, using Windows' own Microsoft Defender engine. Nothing is moved or deleted; you get the list and decide
• 70 Windows settings attackers change: firewall, Windows Security, updates, BitLocker, remote access, risky startup items and more
• Check a link before you open it, and check a password against a built-in list of breached passwords; nothing is sent anywhere

When Blanktick can't check something, it says so, with a reason. If a scan doesn't finish, you get no score instead of a made-up one.

Private by design: Blanktick has no network code. Nothing is uploaded, there's no account and there are no ads.

Blanktick works alongside Windows Security. Keep Windows Security switched on.

**What's new in this version:** Clearer focus on AI threats: hijackable AI agents, exposed AI models and leaked AI keys come first. Includes "Scan whole PC", which checks every file on every drive with Microsoft Defender's engine.

**Features (up to 20, ≤ 200 chars each):**
- Finds where bad AI can get into your PC: hijackable agents, exposed AI models, leaked AI keys
- Read-only MCP server so your own AI agent can explain your results
- Shows what it checked and what it couldn't check, each with a reason
- 70 Windows security settings checked offline
- Live protection preview for ransomware, credential theft and hacker remote control
- Scans your whole PC: every file on every drive, with Microsoft Defender's engine
- Read-only MCP server so your AI agent can explain your results
- Link checker for look-alike and phishing addresses
- Breached-password checker that never sends your password anywhere
- No account, no ads, nothing uploaded

**Search terms (max 7):** full pc scan, security scan, ransomware, phishing link checker, password checker, windows security check, offline security

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
