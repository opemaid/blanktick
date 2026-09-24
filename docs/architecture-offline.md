# BLANKTICK — Offline-Only Architecture (ADR-002)

**Status:** Accepted, 2026-08-28 · **Supersedes:** D-07, D-09 from the kickoff panel
**Constraint from owner:** *"build everything locally, it must run on the app, no api calls"*

---

## 1. The rule

> **The Blanktick app makes zero outbound requests to any server — ours or anyone else's — for the entire duration of a scan.**

Enforced structurally, not by discipline:

| Layer | Enforcement |
|---|---|
| Android manifest | **`android.permission.INTERNET` is NOT declared** in `:app`. The OS makes network access impossible, not merely unused. |
| Android CI | `assertNoInternetPermission` unit test parses the merged manifest and fails the build if `INTERNET`, `ACCESS_NETWORK_STATE` for egress, or any socket permission appears. |
| iOS | No `NSAppTransportSecurity` exceptions; no `URLSession` symbol anywhere in the target. CI greps the linked binary. |
| Core module | `:core` is a pure Kotlin/JVM module with **no I/O dependencies at all** — it cannot open a socket because nothing on its classpath can. |

This is the strongest privacy claim a security app can make and it is *checkable by anyone*: install the APK, run `aapt dump permissions`, observe no INTERNET.

### 1.1 The one honest exception (deferred to v2, not in this build)
The DNS shield (tracker/phishing blocking) intrinsically requires forwarding non-blocked queries to the user's own resolver. That is pass-through of the user's own traffic, not an API call — but it is still network capability, so it lives in a **separate, separately-installable module with its own permission surface**, and the core app ships without it. v1 core = zero network. Stated plainly rather than blurred.

---

## 2. What changed from the kickoff decisions

| Was | Now | Why it is better |
|---|---|---|
| **D-07** Breach check via HIBP k-anonymity (5-char SHA-1 prefix sent to API) | **Bundled Bloom filter** over the top 2M breached passwords. Nothing transmitted, not even a prefix. | k-anonymity leaks a 5-hex-char bucket + timing + IP. A bundled filter leaks *nothing*. Strictly stronger. |
| **D-09** Signed CDN bundles + one thin edge worker holding an HIBP key | **No backend of any kind.** All intel ships inside the app binary; refreshed via normal app-store updates. | Removes the only recurring cost, the only key to protect, the only server to breach, and the O-01 pricing risk entirely. |
| Blocklists delta-updated daily | Bundled, versioned, with **honest staleness reporting** | The UI states "intel dated 2026-08-14" rather than implying live coverage. |

**O-01 (HIBP pricing) is now closed — not applicable.**
**O-02/O-04 (Apple org account for VPN apps) is deferred to v2** along with the DNS shield. v1 has no Network Extension, so the entitlement leaves the critical path. **This removes the single biggest launch blocker.**

---

## 3. Intel bundle: choosing the right data structure

Two membership problems, opposite failure costs. They get different structures — this is the central design decision.

### 3.1 Breached passwords → **Bloom filter** (approximate is *correct* here)

A false positive tells a user to change a password that was actually safe: mildly annoying, harmless.
A false negative would tell a user a breached password is safe: dangerous.
**Bloom filters have zero false negatives.** The error mode points the safe way.

Sizing, `m = -n·ln(p) / (ln2)²`, `k = (m/n)·ln2`:

| n (passwords) | p (FPR) | m (bits) | Size | k |
|---|---|---|---|---|
| 1,000,000 | 0.1% | 14,377,588 | **1.71 MiB** | 10 |
| 2,000,000 | 0.1% | 28,755,176 | **3.43 MiB** | 10 |
| 2,000,000 | 1.0% | 19,170,117 | 2.29 MiB | 7 |
| 10,000,000 | 0.1% | 143,775,876 | 17.1 MiB | 10 |

**Chosen: n = 2,000,000, p = 0.1%, k = 10 → 3.43 MiB (3.59 MB).** The top 2M breached passwords cover the overwhelming majority of real-world reuse; 3.4 MiB is an acceptable slice of an app bundle. Hashing is Kirsch-Mitzenmacher double hashing over two independent 64-bit hashes, so we compute two hashes, not ten.

*Considered and rejected:* binary fuse / xor filters give ~9.84 bits/key vs Bloom's ~14.4 at similar FPR — roughly 30% smaller. Rejected for v1 because the peeling construction has failure-retry paths I cannot verify to the same standard here. Documented as a v2 optimisation with a measured target of 2.46 MB.

### 3.2 Blocked domains → **exact sorted 64-bit hash table** (approximate is *wrong* here)

A false positive blocks a legitimate site the user needs. That is a broken product, not an annoyance. So domains get exactness:

- Each domain normalised (lowercase, IDN→punycode, trailing dot stripped, `www.` retained as-is) then hashed to `u64`.
- Hashes stored in a **sorted `LongArray`**, plus a 65,536-entry `IntArray` prefix index on the top 16 bits.
- Lookup: index the prefix bucket, binary-search the (tiny) range. ~1–2 cache lines.
- Collision probability for 2M keys in 2^64 by birthday bound ≈ `2M² / 2^65` ≈ **1.1 × 10⁻⁷**. Effectively exact.
- Parent-domain walk: `a.b.example.com` probes `a.b.example.com`, `b.example.com`, `example.com` — capped at 5 labels.
- **Allowlist override**: a bundled set of high-traffic domains that can never be blocked, checked first. Belt and braces.

Cost: 8 bytes/domain + 256 KB index. 2M domains = **16.3 MB**.

### 3.3 Full bundle budget

| Asset | Structure | Size |
|---|---|---|
| Breached passwords (2M) | Bloom, p=0.1% | 3.43 MB |
| Blocked domains (2M) | Sorted u64 + index | 16.3 MB |
| Allowlist (top 100k) | Sorted u64 | 0.8 MB |
| Brand domains for typosquat distance (10k) | Plain sorted strings | 0.2 MB |
| Known-good signer certs (5k packages) | Map pkg→SHA-256 | 0.3 MB |
| Malicious signer certs | Sorted u64 | 0.1 MB |
| OS patch-window table | JSON | < 0.1 MB |
| Permission-cluster rule pack | JSON | < 0.1 MB |
| **Total intel** | | **≈ 21.4 MB** |

Well inside both stores' limits. Android ships them as uncompressed assets so they can be `mmap`ed; iOS as on-demand-resource-free bundle files.

---

## 4. Replacing every feature that used to need a server

| Feature | Old (network) | New (fully local) |
|---|---|---|
| Breached password | HIBP range API | Bloom filter lookup, `< 1 µs` |
| Breached email | HIBP paid API | **Dropped.** Cannot be done offline without shipping breach corpora containing other people's PII — which would be both enormous and unethical. Stated in-app, not silently omitted. |
| Tracker/phishing domain block | CDN blocklist + DNS proxy | Bundled exact table; used by the **link scanner** in v1, by the DNS shield in v2 |
| Phishing URL verdict | Reputation API | **Local heuristic engine** (§5) |
| MITM / interception detection | Probe our pinned endpoint | **User-installed CA enumeration**, proxy config, VPN owner, DNS server inspection — all local and *stronger* than a probe |
| OS CVE exposure | CVE feed | Bundled patch-window table + honest staleness |
| Malware / clone detection | Cloud hash lookup | **Signer-certificate mismatch** against bundled known-good registry + permission-cluster rules |

### 4.1 A feature that got *better* offline

Detecting a **repackaged clone** — an app that claims `com.whatsapp` but is signed by a different key — needs only the bundled known-good signer registry and `PackageManager`. No server ever had an advantage here, and it is one of the highest-signal malware indicators on Android. Cloud-based scanners routinely miss it.

Likewise, enumerating **user-installed CA certificates** catches an active Burp/mitmproxy interception setup on the device itself. A network probe to our own server can be defeated by an attacker who simply allows that one host; the trust-store check cannot.

---

## 5. Local phishing engine (no reputation API)

Ten independent offline signals, weighted and summed:

1. Exact hit in the bundled blocklist → immediate CRITICAL
2. **IDN homoglyph / mixed-script** detection (Cyrillic `а` in `pаypal.com`) via Unicode script-run analysis
3. **Typosquat distance** — Damerau-Levenshtein ≤ 2 against the 10k brand list, with keyboard-adjacency weighting so `gooogle`/`gogle` rank above coincidental matches
4. **Brand-in-subdomain** — `paypal.com.secure-login.ru` (registrable domain is `secure-login.ru`, brand appears left of it)
5. Credentials in URL — `https://paypal.com@evil.ru/`
6. Raw IP host, or non-standard port
7. Excessive subdomain depth / excessive URL length / heavy percent-encoding
8. High-risk TLD set (bundled, weighted by observed abuse rate)
9. Known URL-shortener host (cannot be resolved offline — reported as *unknown*, never as *safe*)
10. Dangerous scheme (`javascript:`, `data:`, `intent:`)

Verdicts are **SAFE / SUSPICIOUS / DANGEROUS / UNKNOWN**. `UNKNOWN` is a first-class verdict — the engine never claims a link is safe when it genuinely cannot tell. This matters: an offline scanner that says "safe" for an unshortened, unlisted, structurally-clean phishing URL would be lying.

---

## 6. Module layout

```
blanktick/
├── core/                    Pure Kotlin/JVM · no I/O · no Android · no network
│   ├── model/               DeviceSnapshot, Finding, Severity, Category
│   ├── scoring/             ScoringEngine + ScoringPolicy  (the normative one)
│   ├── rules/               25 rules, stable IDs, platform-gated
│   ├── filters/             BloomFilter, SortedHashSet64, Hashing
│   ├── intel/               IntelBundle readers + staleness
│   └── analysis/            UrlAnalyzer, PermissionClusterAnalyzer, ExifAnalyzer
├── app/                     Android · Compose · collectors only
├── ios/BlanktickCore/          Swift mirror of core/ — same rule IDs, same fixtures
├── ios/Blanktick/              SwiftUI · collectors only
├── shared/fixtures/         Golden JSON — both platforms must produce identical scores
└── tools/                   Python · BUILD TIME ONLY · generates the intel bundle
```

**The `null` contract (implements D-01):** every field on `DeviceSnapshot` is nullable. `null` means *"this platform cannot observe this"* — and a rule whose inputs are `null` emits **no finding at all**, not a passing one and not a failing one. That single convention is what stops the iOS build from showing hollow checks, and it is enforced by fixture tests.

---

## 7. Trade-offs accepted

1. **Intel goes stale between app updates.** Mitigated by displaying the bundle date on every scan and degrading confidence, never by pretending.
2. **~21 MB of assets.** Accepted; it buys the zero-network claim.
3. **Email breach monitoring is gone.** Genuinely impossible offline. Not faked.
4. **URL shorteners cannot be expanded.** Reported as `UNKNOWN`, never `SAFE`.
5. **No product analytics whatsoever.** Already accepted in D-03; now structurally guaranteed rather than promised.
