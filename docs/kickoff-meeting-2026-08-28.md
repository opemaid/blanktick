# MUME — Product Kickoff Panel
**Date:** 2026-08-28 · **Chair:** Claude · **Codename:** MUME (not cleared, see D-12)

## Brief
Consumer device-security app. Native Swift + Kotlin. Full feature set. **Free** — no paywall, no ads.
Ship to Apple App Store and Google Play.

---

## ATTENDEES (skills convened)

| Seat | Skill | Brought to the table |
|---|---|---|
| Threat model | `security-threat-model`, `master-ethical-hacker` | Who we actually defend against |
| Detection design | `detecting-mobile-malware-behavior`, `conducting-mobile-app-penetration-test` | Which signals are real vs theatre |
| Our own hardening | `exploiting-insecure-data-storage-in-mobile`, `implementing-aes-encryption-for-data-at-rest`, `zeroize-audit` | We must not be the vulnerability |
| iOS eng | `ios-application-dev`, `swift`, `swiftui-expert-skill`, `xcode-project-setup` | Sandbox reality check |
| Android eng | `android-native-dev` | Signal richness, Play policy limits |
| Design | `ui-design-gate`, `apple-hig-expert`, `ios-design-guidelines`, `android-design-guidelines`, `dataviz` | Risk-score UI, cross-platform idiom |
| Accessibility | `wcag-accessibility`, `accessibility` | WCAG 2.2 AA target |
| Apple release | `app-store-preflight-skills`, `asc-workflow`, `asc-signing-setup`, `asc-submission-health`, `asc-testflight-orchestration` | Entitlements + review survival |
| Store growth | `aso`, `android-aso`, `app-store-optimization` | Listing that does not trip review |
| Legal / privacy | `privacy-policy`, `gdpr-compliance`, `ccpa`, `lgpd`, `dpdpa` | Data Safety + POPIA (ZA) |
| Product | `product-strategy`, `positioning-statement`, `lean-canvas` | Scope discipline on a free build |
| QA | `xcuitest-skill`, `espresso-skill` | Regression on security logic |
| Launch | `launch-plan`, `producthunt` | Distribution without ad spend |
| Naming | `trademark-search-robb-miller` | Name clearance |

---

## AGENDA ITEM 1 — The blocking constraint (raised first, deliberately)

**iOS eng:** The mockup that was approved is not buildable on iOS. Specifically:

| Mockup line | iOS reality |
|---|---|
| "4 apps read clipboard" | Impossible. No app can observe another app's pasteboard access. iOS 14+ shows the system banner itself. |
| "12 trackers blocked" | Possible ONLY via Network Extension (DNS proxy / content filter) or Safari Content Blocker. |
| "Wi-Fi Free_WiFi is open" | Possible, but needs `NEHotspotNetwork` + Location permission + entitlement. |
| "No breached passwords" | Cannot read other apps' or Keychain credentials. Only user-entered email/password checks. |
| App permission audit | Impossible. No API enumerates other apps' granted permissions. |

**Apple release:** Additionally — App Review rejects apps claiming to scan for viruses/malware on iOS. Any listing copy with "antivirus", "malware scan", "virus" is a rejection risk on its own.

**Chair — disclosure:** Store policy wording changes often and my knowledge has a cutoff. Treat every policy citation here as *must be re-verified against live docs before build*, not as fact. The sandbox constraints above are architectural and stable; the review-policy specifics are the volatile part.

### D-01 (DECIDED) — Asymmetric-by-design, honest-by-default
Build one product with a **shared scoring engine** and **platform-specific signal providers**. The UI never renders a check the platform cannot actually perform. No greyed-out teases, no "upgrade to Android" nags. Each platform's checklist is complete *for that platform*.

---

## AGENDA ITEM 2 — Feature matrix (what actually ships)

Legend: full / partial-coached / not-possible

| Capability | iOS | Android | Notes |
|---|:--:|:--:|---|
| **Network & Wi-Fi** ||||
| Open / unencrypted Wi-Fi warning | full | full | iOS needs Location + hotspot entitlement |
| DNS-hijack + captive-portal detection | full | full | Probe our own known-good resolver, compare |
| MITM / TLS-interception detection | full | full | Pin our own cert, detect a substituted chain |
| Tracker + phishing domain blocking | full | full | iOS: NE DNS proxy. Android: local `VpnService` DNS-only |
| Safari/browser tracker blocking | full | partial | iOS Content Blocker ext is strong; Android via the same DNS layer |
| Rogue-AP / ARP-spoof heuristics | none | partial | Android scan throttling limits this badly |
| **App hygiene** ||||
| Installed-app permission audit | none | full | The single biggest Android-only win |
| Dangerous-permission cluster scoring | none | full | SMS-read + notification-listener + overlay = trojan shape |
| Accessibility / DeviceAdmin / overlay holders | none | full | Banking-trojan detection. We *read* this; we never *use* a11y ourselves |
| Sideload + installer-source flagging | none | full | `getInstallSourceInfo` |
| Signature / repack check on installed apps | none | partial | Cert hash vs known-good set |
| Clipboard-access attribution | none | partial | OS-mediated only, Android 12+ |
| **Device posture** ||||
| Jailbreak / root / bootloader-unlock | full | full | Plus Play Integrity attestation on Android |
| OS patch level vs known-CVE window | full | full | Local CVE window table, CDN-refreshed |
| Screen-lock strength, disk encryption | partial | full | iOS: passcode-set only, via `LAContext` |
| Guided hardening (2FA, ADP, Lockdown Mode) | full | full | Deep-link into Settings + verify-after |
| **Personal data** ||||
| Email/phone breach monitoring | full | full | HIBP, k-anonymity prefix — plaintext never leaves device |
| Password exposure check | full | full | SHA-1 prefix range API, offline suffix compare |
| Photo EXIF/GPS privacy scan | full | full | On-device only. Strong, underused feature |
| Link / QR phishing scanner (share sheet) | full | full | Share Extension / Intent filter |

**Product:** Android ships ~22 checks, iOS ~14. That asymmetry is a positioning asset, not an embarrassment — the iOS build is a *privacy checkup + network shield*; the Android build is that **plus** an app auditor.

---

## AGENDA ITEM 3 — The Risk Score (design panel)

**dataviz + ui-design-gate:** A 0-100 score with no traceable arithmetic is anxiety-generation, not security. Two hard rules:

1. **Every point is attributable.** Tapping the score decomposes it into weighted findings.
2. **Every finding has an action.** No finding may exist that the user cannot act on. If we cannot offer a fix, it is *information*, not a *deduction*.

Proposed home screen:

```
+----------------------------------+
|  Mume                      (o) |
|                                  |
|         .-----------.            |
|         |    72     |  Fair      |
|         |  -------  |            |
|         '-----------'            |
|    ##############......          |
|                                  |
|  3 things need attention         |
| -------------------------------- |
| [!] HIGH   -14                   |
|     "QuickScan" can read your SMS|
|     and draw over other apps     |
|                     [ Review > ] |
|                                  |
| [!] MED    -9                    |
|     Wi-Fi "CoffeeShop" is open   |
|                 [ Turn on VPN > ]|
|                                  |
| [!] MED    -5                    |
|     2 photos share your home GPS |
|                [ Strip data >  ] |
| -------------------------------- |
| (v) 19 checks passed      [see]  |
|                                  |
|      [   Run Full Scan   ]       |
+----------------------------------+
```

**Accessibility:** score is never colour-only — always numeral + label + icon + text. Ring animation respects Reduce Motion. All actions >=44pt/48dp. VoiceOver reads "Security score 72 of 100, Fair, 3 issues need attention."

**HIG:** score ring + SF Symbols + Dynamic Type on iOS; Material 3 expressive + dynamic colour on Android. **Shared design tokens, native components** — no cross-platform UI mimicry in either direction.

### D-02 (DECIDED) — Scoring engine is a pure, testable, platform-agnostic module
Signals in → findings out. Zero I/O, zero platform types. Written twice (Swift/Kotlin) against **one shared spec + one shared JSON fixture suite** so both platforms must produce identical scores for identical inputs. This is the thing that must never regress.

---

## AGENDA ITEM 4 — Privacy architecture (the hardest debate)

**Crash analytics seat proposed Crashlytics/Sentry. Rejected.**

**Privacy counsel:** A security app that ships a Google or third-party telemetry SDK has lost the argument before it starts, and the Data Safety form will say so in public.

**Our-own-hardening seat:** Worse — our findings *are* the sensitive data. A crash payload could carry the user's installed-app list.

### D-03 (DECIDED) — Zero third-party SDKs in the client. None.
### D-04 (DECIDED) — No accounts, no user IDs, no server-side profile in v1
### D-05 (DECIDED) — Findings never leave the device
### D-06 (DECIDED) — Crash handling: on-device log, user-initiated share only, with a rendered preview of the exact bytes before sending
### D-07 (DECIDED) — Breach check uses k-anonymity only (SHA-1 5-char prefix); the email/password never transits
### D-08 (DECIDED) — Local store: SQLCipher / Keystore-Keychain-wrapped key, `.completeFileProtection`, no cloud backup, scrubbed on background

**Consequence — accepted:** we will have almost no product analytics. The panel accepts flying blind in exchange for a claim we can defend absolutely. Aggregate, opt-in, differentially-private counters may be revisited post-launch — as an explicit opt-*in*, never opt-out.

---

## AGENDA ITEM 5 — Backend

**Constraint: free product must have near-zero marginal cost per user.**

| Component | Approach | Cost shape |
|---|---|---|
| Blocklists (tracker/phishing/malware domains) | Static signed bundles + daily deltas on CDN | Flat, cache-friendly |
| CVE/patch-window table | Same static bundle | Flat |
| Known-good app signature set (Android) | Same static bundle | Flat |
| Password breach lookup | HIBP range API direct from device | Free tier |
| Email breach lookup | HIBP paid API — **needs a proxy to hold the key** | Only recurring cost |
| TLS-MITM probe endpoint | Tiny pinned edge endpoint | Negligible |

### D-09 (DECIDED) — No application backend. Signed static bundles on a CDN + one thin edge worker.
The edge worker holds only the HIBP key and forwards; it logs nothing, stores nothing, sets no cookie.

**Uncertainty flagged:** HIBP's email-breach API is paid and I do not know its current price or terms. Verify before committing to email monitoring — if the economics do not work for a free app, ship password-only breach checking (which is free) and drop email monitoring rather than compromising D-03/D-04.

**Sustainability, stated once and then dropped:** "full-featured + free + no ads + no telemetry" has a real running cost (Apple Developer $99/yr, Play $25 one-off, CDN, possibly HIBP). If the intent is a credibility/portfolio asset alongside the bug-bounty work, that is coherent and the panel proceeds on that basis. Architecture keeps a Pro tier *possible* via feature flags without rework — but nothing paywalled ships in v1.

---

## AGENDA ITEM 6 — Store survival

### Apple
- **CRITICAL PATH:** Network Extension entitlement (`packet-tunnel` / `dns-proxy` / `content-filter`) requires a request to Apple with justification and has **multi-week lead time**. File in **week 1** or it becomes the launch blocker.
- Guideline 5.1.1 — every permission needs a purpose string that names the concrete user benefit. Location for Wi-Fi assessment is the one most likely to be challenged; the string must say exactly why.
- **Listing language ban:** never "antivirus", "virus", "malware scanner", "removes threats". Use "privacy checkup", "security checkup", "network protection", "breach monitoring".
- VPN-capable apps must be published under an **organisation** account, not an individual one. Verify — this materially affects account setup and possibly requires a registered entity.
- Full App Privacy nutrition labels.

### Google Play
- `VpnService` → Play declaration; DNS-only, no traffic inspection, no logging. Must be core functionality (it is).
- `QUERY_ALL_PACKAGES` is a restricted permission. **Avoid it.** Use `<queries>` with a launcher intent filter — covers user-visible apps, which is what the audit actually needs, and sidesteps the whole review category.
- `PACKAGE_USAGE_STATS` is special-access; request in-context with a clear rationale screen.
- **We never register an AccessibilityService.** We only read which *other* apps hold one. Registering one for a security app is a well-known ban vector.
- Data Safety form + privacy policy URL.

### D-10 (DECIDED) — Week-1 tasks, before any feature code
1. Apple Developer org enrolment + Network Extension entitlement request filed
2. Play Console account + policy pre-read
3. Privacy policy drafted (GDPR + CCPA + POPIA + LGPD + DPDPA) — it gates both store listings
4. Name trademark clearance

---

## AGENDA ITEM 7 — Roadmap (~5 months, native, both platforms)

| Phase | Weeks | Output |
|---|---|---|
| **0 — Unblock** | 1 | Entitlement filed, accounts live, privacy policy v1, name cleared, repo + CI + signing |
| **1 — Core** | 2-5 | Scoring engine (both langs, shared fixtures), design system + tokens, device-posture checks, home screen. First TestFlight + internal Play track. |
| **2 — Network shield** | 6-10 | NE DNS proxy (iOS), VpnService DNS resolver (Android), blocklist bundle + delta updater, Wi-Fi assessment, MITM/DNS-hijack probes, Safari content blocker |
| **3 — Android app auditor** | 11-14 | Permission audit, dangerous-permission clustering, a11y/overlay/DeviceAdmin holders, installer-source + signature checks |
| **4 — Personal data** | 15-17 | Breach monitoring (k-anonymity), photo EXIF scan, link/QR phishing scanner extensions |
| **5 — Harden & polish** | 18-20 | Self-pentest, accessibility audit, localisation, onboarding, empty/error states, store assets |
| **6 — Submit** | 21-22 | Preflight checklists, phased rollout, review-response readiness |

### D-11 (DECIDED) — Ship iOS and Android on the same day, but build Android-first per feature
Android surfaces the signal, then we port whatever iOS permits. Prevents designing to the lowest common denominator.

---

## AGENDA ITEM 8 — Quality gates

- **Scoring engine:** shared JSON fixtures; both platforms must match exactly. Fails CI otherwise.
- **Security regressions:** a suite of synthetic "malicious app" manifests that must always be flagged, plus a benign set that must never be. Both directions tested — a detector that never false-negatives by flagging everything is worthless.
- **Self-pentest before submission:** run `conducting-mobile-app-penetration-test` + `exploiting-insecure-data-storage-in-mobile` against our own build. A security app failing MASVS is the only truly fatal bug class here.
- **Accessibility:** WCAG 2.2 AA, VoiceOver + TalkBack pass on every screen.
- **XCUITest + Espresso** on the critical flows: onboarding, scan, remediate, re-scan.

---

## OPEN ITEMS

| # | Item | Owner | Blocking? |
|---|---|---|---|
| D-12 | Name clearance — "Mume" is a working codename only | Naming | Yes, before store listing |
| O-01 | Verify HIBP email API pricing/terms → email monitoring in or out | Backend | Phase 4 |
| O-02 | Confirm whether VPN-capable apps still require an org account on Apple | Apple release | Yes, week 1 |
| O-03 | Re-verify all cited store policy text against live docs | Apple + Play | Yes, week 1 |
| O-04 | Entity registration if org account is required | — | Depends on O-02 |
| O-05 | Launch surfaces (Product Hunt, r/privacy, HN) — no ad budget | Launch | Phase 6 |

---

## DECISION LOG (summary)

- **D-01** Asymmetric-by-design; never show a check the platform cannot run
- **D-02** Pure, shared-spec scoring engine with cross-platform fixture parity
- **D-03** Zero third-party SDKs in the client
- **D-04** No accounts, no user IDs, no server profile
- **D-05** Findings never leave the device
- **D-06** Crash logs on-device, user-initiated share with byte preview
- **D-07** Breach checks via k-anonymity only
- **D-08** Encrypted local store, no cloud backup
- **D-09** No app backend — signed CDN bundles + one thin edge worker
- **D-10** Week-1 unblock tasks precede all feature code
- **D-11** Same-day dual launch, Android-first per feature
- **D-12** Name unresolved
