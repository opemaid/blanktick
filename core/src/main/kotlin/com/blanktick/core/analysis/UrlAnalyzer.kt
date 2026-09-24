package com.blanktick.core.analysis

import com.blanktick.core.filters.DomainNormalizer
import com.blanktick.core.filters.SortedHashSet64
import com.blanktick.core.model.LinkVerdict
import kotlin.math.abs
import kotlin.math.min

/** One reason contributing to a link's risk score. */
data class UrlSignal(
    val id: String,
    val weight: Int,
    val explanation: String
)

/**
 * The result of analysing a link.
 *
 * @param verdict see [LinkVerdict]. Note that [LinkVerdict.SAFE] is only ever
 *   returned for a domain on the bundled allowlist. Everything else that looks
 *   clean returns [LinkVerdict.UNKNOWN] — Blanktick works offline and cannot verify
 *   that an arbitrary site is genuinely safe, so it does not claim to.
 * @param displayHost the Unicode form of the host, so the UI can show the user
 *   what the address *actually* says rather than its `xn--` encoding.
 */
data class UrlAnalysis(
    val url: String,
    val verdict: LinkVerdict,
    val riskScore: Int,
    val signals: List<UrlSignal>,
    val host: String?,
    val displayHost: String?,
    val registrableDomain: String?,
    val impersonatedBrand: String?
) {
    val topReason: String? get() = signals.maxByOrNull { it.weight }?.explanation
}

/**
 * Offline phishing analysis for a single URL.
 *
 * ## The design constraint
 *
 * With no network there is no reputation lookup, no WHOIS age, no certificate
 * fetch and no redirect following. Everything must come from the string itself
 * plus data bundled in the app. That rules out some checks entirely — and the
 * honest response is to *say so* in the verdict rather than to quietly downgrade
 * `UNKNOWN` to `SAFE`.
 *
 * What remains is stronger than it first appears. The overwhelming majority of
 * phishing URLs give themselves away structurally: a brand name in a subdomain
 * of an unrelated registrable domain, a homoglyph, credentials in the authority,
 * a raw IP, or a hostname one edit away from a bank's. All of that is decidable
 * from the string.
 */
class UrlAnalyzer(
    /** Exact blocklist of known-bad domains, from the bundled intel. */
    private val blocklist: SortedHashSet64? = null,
    /** Domains that must never be flagged, checked before anything else. */
    private val allowlist: SortedHashSet64? = null,
    /** Brand names for typosquat comparison, as registrable domains. */
    private val brands: Set<String> = DEFAULT_BRANDS,
    /** Hosts known to hide their destination. */
    private val shorteners: Set<String> = DEFAULT_SHORTENERS
) {

    fun analyze(input: String): UrlAnalysis {
        val parsed = UrlParser.parse(input)
            ?: return UrlAnalysis(
                url = input,
                verdict = LinkVerdict.SUSPICIOUS,
                riskScore = 45,
                signals = listOf(
                    UrlSignal(
                        "URL-MALFORMED", 45,
                        "This does not look like a valid web address, which is itself unusual in a " +
                            "message asking you to click something."
                    )
                ),
                host = null, displayHost = null, registrableDomain = null, impersonatedBrand = null
            )

        val signals = mutableListOf<UrlSignal>()
        val host = parsed.host
        val displayHost = Punycode.decodeHostname(host)
        val registrable = PublicSuffix.registrableDomain(host)
        var impersonated: String? = null

        // ---- Executable schemes: never a link you should follow ------------
        if (parsed.scheme != null && parsed.scheme in UrlParser.EXECUTABLE_SCHEMES) {
            return UrlAnalysis(
                url = input,
                verdict = LinkVerdict.DANGEROUS,
                riskScore = 95,
                signals = listOf(
                    UrlSignal(
                        "URL-SCHEME-EXEC", 95,
                        "This is not a web address — it is a command (\"${parsed.scheme}:\"). " +
                            "Opening it runs code rather than visiting a page."
                    )
                ),
                host = null, displayHost = null, registrableDomain = null, impersonatedBrand = null
            )
        }

        // ---- Allowlist short-circuit ---------------------------------------
        val allowlisted = allowlist?.let { list ->
            DomainNormalizer.parentChain(host).any { list.contains(it) }
        } ?: false

        // ---- Bundled blocklist ---------------------------------------------
        val blocked = blocklist?.matchDomain(host)
        if (blocked != null && !allowlisted) {
            signals += UrlSignal(
                "URL-BLOCKLIST", 100,
                "This address is on Blanktick's list of known malicious and tracking domains" +
                    if (blocked != host) " (matched \"$blocked\")." else "."
            )
        }

        // ---- Credentials in the authority -----------------------------------
        if (parsed.hasCredentials) {
            signals += UrlSignal(
                "URL-USERINFO", 60,
                "Everything before the \"@\" is ignored by the browser. This link actually goes to " +
                    "\"$displayHost\", not to what it appears to say."
            )
        }

        // ---- Raw IP address --------------------------------------------------
        if (parsed.isIpLiteral) {
            signals += UrlSignal(
                "URL-IP-HOST", 45,
                "This link points at a bare numeric address rather than a domain name. Legitimate " +
                    "businesses do not send links like this."
            )
        }

        // ---- Homoglyph / script analysis -------------------------------------
        if (!parsed.isIpLiteral) {
            val labels = displayHost.split('.')
            val mixedScriptLabel = labels.firstOrNull { Confusables.hasSuspiciousScriptMix(it) }
            if (mixedScriptLabel != null) {
                signals += UrlSignal(
                    "URL-MIXED-SCRIPT", 75,
                    "The address mixes alphabets inside \"$mixedScriptLabel\" — for example a " +
                        "Cyrillic letter among Latin ones. This is done to make a fake address look " +
                        "identical to a real one."
                )
            }

            // Whole-script imitation: fold to a Latin skeleton and see whether the
            // result *is* a brand while the actual host is not.
            if (!Confusables.isPureAscii(displayHost)) {
                val skeletonHost = displayHost.split('.')
                    .joinToString(".") { Confusables.skeleton(it) }
                val skeletonRegistrable = PublicSuffix.registrableDomain(skeletonHost)
                if (skeletonRegistrable != registrable && skeletonRegistrable in brands) {
                    impersonated = skeletonRegistrable
                    signals += UrlSignal(
                        "URL-HOMOGLYPH", 100,
                        "This address is built from letters that look like \"$skeletonRegistrable\" " +
                            "but are different characters. It is a deliberate imitation."
                    )
                }
            } else if (Punycode.hasAceLabel(host) && displayHost == host) {
                // An `xn--` label we could not decode.
                signals += UrlSignal(
                    "URL-PUNYCODE-BAD", 50,
                    "Part of this address is encoded in a way Blanktick could not decode, which is not " +
                        "how ordinary international domains behave."
                )
            }
        }

        // ---- Brand in a subdomain of an unrelated domain ----------------------
        if (!parsed.isIpLiteral && registrable !in brands) {
            val subLabels = PublicSuffix.subdomainLabels(displayHost)
            val brandInSub = subLabels.firstNotNullOfOrNull { label ->
                val skeleton = Confusables.skeleton(label)
                brands.firstOrNull { brand -> brand.substringBefore('.') == skeleton }
            }
            if (brandInSub != null) {
                impersonated = impersonated ?: brandInSub
                signals += UrlSignal(
                    "URL-BRAND-SUBDOMAIN", 85,
                    "\"${brandInSub.substringBefore('.')}\" appears in this address, but the site it " +
                        "actually goes to is \"$registrable\". The part that matters is the one just " +
                        "before the first single slash."
                )
            }
        }

        // ---- Typosquatting ----------------------------------------------------
        if (!parsed.isIpLiteral && registrable !in brands && !allowlisted) {
            val nearest = nearestBrand(Confusables.skeleton(registrable))
            if (nearest != null) {
                impersonated = impersonated ?: nearest.first
                signals += UrlSignal(
                    "URL-TYPOSQUAT", 70,
                    "\"$registrable\" is only ${nearest.second} character(s) away from " +
                        "\"${nearest.first}\". Misspelled lookalike domains are registered " +
                        "specifically to catch people who mistype or skim."
                )
            }
        }

        // ---- Combosquatting: a brand as one word of a hyphenated name --------
        // "paypa1-secure-login.xyz" slipped past everything above: the whole name
        // is far more than two edits from "paypal", and the brand is in the
        // registrable domain, not a subdomain. Brand-plus-words is the most
        // common phishing shape there is, so each hyphen-separated word is
        // compared on its own.
        //
        // Digits are folded HERE ONLY ('1'->'l', '0'->'o', ...). Globally that
        // fold is refused (see Confusables) for false positives; here a folded
        // word must then EQUAL a brand name, which is narrow enough to be safe.
        if (!parsed.isIpLiteral && registrable !in brands && !allowlisted &&
            signals.none { it.id == "URL-TYPOSQUAT" || it.id == "URL-HOMOGLYPH" }
        ) {
            val words = Confusables.skeleton(registrable.substringBefore('.')).split('-')
            if (words.size >= 2) {
                val brandNames = brands.associateBy { it.substringBefore('.') }
                var hit: Triple<String, String, Boolean>? = null   // brand, word, exact
                for (w in words) {
                    if (w.length < 4) continue
                    brandNames[w]?.let { hit = Triple(it, w, true) }
                    if (hit != null) break
                    // Digit swaps only, NOT edit distance: a one-letter slack on a
                    // single word flags "apples-and-pears.com" as Apple. A word
                    // that becomes a brand only once its digits are read as
                    // letters has no such innocent reading.
                    val folded = foldDigits(w)
                    val misspelt = if (folded != w) brandNames[folded] else null
                    if (misspelt != null) { hit = Triple(misspelt, w, false); break }
                }
                hit?.let { (brand, word, exact) ->
                    impersonated = impersonated ?: brand
                    val brandName = brand.substringBefore('.')
                    signals += if (exact) UrlSignal(
                        "URL-COMBOSQUAT", 55,
                        "\"$registrable\" is not $brand — it is \"$brandName\" with other words " +
                            "attached. Scam sites are very often built this way, because the brand " +
                            "name is what people check for."
                    ) else UrlSignal(
                        "URL-COMBOSQUAT", 70,
                        "\"$word\" in \"$registrable\" is a misspelling of \"$brandName\", with other " +
                            "words attached. A brand name spelled almost right is made to be skimmed " +
                            "past, and has no innocent reason to exist."
                    )
                }
            }
        }

        // ---- Structural oddities ----------------------------------------------
        val subdomainDepth = PublicSuffix.subdomainLabels(host).size
        if (subdomainDepth >= 4) {
            signals += UrlSignal(
                "URL-DEEP-SUBDOMAIN", 30,
                "This address has $subdomainDepth levels of subdomain, which is a common way to " +
                    "push the real destination out of sight on a phone screen."
            )
        }

        if (parsed.port != null && parsed.port !in setOf(80, 443, 8443)) {
            signals += UrlSignal(
                "URL-ODD-PORT", 35,
                "This link connects on port ${parsed.port} instead of the normal web ports."
            )
        }

        if (input.length > 150) {
            signals += UrlSignal(
                "URL-LENGTH", 15,
                "This address is unusually long (${input.length} characters), which is often used to " +
                    "hide the real destination."
            )
        }

        val encodedRatio = percentEncodedRatio(input)
        if (encodedRatio > 0.15) {
            signals += UrlSignal(
                "URL-ENCODED", 40,
                "A large part of this address is written in escape codes rather than plain text, " +
                    "which is normally done to disguise it."
            )
        }

        if (parsed.scheme == "http") {
            signals += UrlSignal(
                "URL-NO-TLS", 20,
                "This link is not encrypted. Anything you type into the page can be read in transit."
            )
        }

        val riskyTld = RISKY_TLDS.firstOrNull { host.endsWith(".$it") }
        if (riskyTld != null) {
            signals += UrlSignal(
                "URL-RISKY-TLD", 25,
                "\".$riskyTld\" addresses are given away cheaply or free and are used " +
                    "disproportionately for scams."
            )
        }

        // ---- Shorteners: an honest unknown -------------------------------------
        val isShortener = registrable in shorteners || host in shorteners
        if (isShortener) {
            signals += UrlSignal(
                "URL-SHORTENER", 0,
                "This is a shortened link. Blanktick works offline and cannot follow it to see where it " +
                    "really goes, so it cannot tell you whether the destination is safe."
            )
        }

        // ---- Verdict -------------------------------------------------------------
        val riskScore = min(100, signals.sumOf { it.weight })

        val verdict = when {
            allowlisted && riskScore < 70 -> LinkVerdict.SAFE
            riskScore >= 70 -> LinkVerdict.DANGEROUS
            riskScore >= 35 -> LinkVerdict.SUSPICIOUS
            isShortener -> LinkVerdict.UNKNOWN
            // Deliberately NOT `SAFE`. Nothing was found wrong, but with no
            // network Blanktick cannot confirm a site is good — only that it does not
            // look bad. Saying "safe" here would be the one dishonest thing this
            // engine could do.
            else -> LinkVerdict.UNKNOWN
        }

        return UrlAnalysis(
            url = input,
            verdict = verdict,
            riskScore = riskScore,
            signals = signals.sortedByDescending { it.weight },
            host = host,
            displayHost = displayHost,
            registrableDomain = registrable,
            impersonatedBrand = impersonated
        )
    }

    /** @return brand and edit distance, if any brand is within [MAX_TYPO_DISTANCE]. */
    private fun nearestBrand(registrable: String): Pair<String, Int>? {
        // Very short names produce meaningless matches — "a.com" is within two
        // edits of half the internet.
        val name = registrable.substringBefore('.')
        if (name.length < 5) return null

        var best: Pair<String, Int>? = null
        for (brand in brands) {
            val brandName = brand.substringBefore('.')
            if (brandName == name) return null      // exact brand, different TLD: handled elsewhere
            if (abs(brandName.length - name.length) > MAX_TYPO_DISTANCE) continue
            val d = boundedDamerauLevenshtein(name, brandName, MAX_TYPO_DISTANCE)
            if (d in 1..MAX_TYPO_DISTANCE && (best == null || d < best.second)) {
                best = brand to d
            }
        }
        return best
    }

    /** Digit-for-letter swaps used in lookalike names. Only for [URL-COMBOSQUAT]. */
    private fun foldDigits(s: String): String = s.map {
        when (it) { '0' -> 'o'; '1' -> 'l'; '3' -> 'e'; '4' -> 'a'; '5' -> 's'; '7' -> 't'; else -> it }
    }.joinToString("")

    private fun percentEncodedRatio(s: String): Double {
        if (s.isEmpty()) return 0.0
        val encoded = s.count { it == '%' } * 3
        return encoded.toDouble() / s.length
    }

    companion object {
        const val MAX_TYPO_DISTANCE = 2

        /**
         * Optimal string alignment distance with an early exit.
         *
         * Bounded so that comparing one host against a few thousand brands stays
         * cheap enough to run on the UI thread of a budget phone: the moment an
         * entire row exceeds [limit], no completion can be within the bound and
         * we stop.
         */
        fun boundedDamerauLevenshtein(a: String, b: String, limit: Int): Int {
            if (a == b) return 0
            if (abs(a.length - b.length) > limit) return limit + 1
            if (a.isEmpty()) return b.length
            if (b.isEmpty()) return a.length

            var prevPrev = IntArray(b.length + 1)
            var prev = IntArray(b.length + 1) { it }
            var current = IntArray(b.length + 1)

            for (i in 1..a.length) {
                current[0] = i
                var rowMin = current[0]
                for (j in 1..b.length) {
                    val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                    var value = minOf(
                        current[j - 1] + 1,      // insertion
                        prev[j] + 1,             // deletion
                        prev[j - 1] + cost       // substitution
                    )
                    // Transposition of two adjacent characters.
                    if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) {
                        value = minOf(value, prevPrev[j - 2] + cost)
                    }
                    current[j] = value
                    if (value < rowMin) rowMin = value
                }
                if (rowMin > limit) return limit + 1

                val spare = prevPrev
                prevPrev = prev
                prev = current
                current = spare
            }
            return prev[b.length]
        }

        /**
         * Brands most often impersonated, as registrable domains.
         *
         * Weighted toward the products people are actually phished for, plus the
         * South African banking and retail names that global lists omit entirely.
         * The shipping build replaces this with the bundled 10,000-entry list;
         * this constant is the fallback and the test fixture.
         */
        val DEFAULT_BRANDS: Set<String> = setOf(
            // Platforms and mail
            "google.com", "gmail.com", "youtube.com", "microsoft.com", "outlook.com",
            "office.com", "live.com", "apple.com", "icloud.com", "amazon.com",
            "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "twitter.com",
            "netflix.com", "spotify.com", "dropbox.com", "adobe.com", "zoom.us",
            "github.com", "gitlab.com", "slack.com", "atlassian.com", "salesforce.com",
            // Payments and crypto
            "paypal.com", "stripe.com", "wise.com", "revolut.com", "coinbase.com",
            "binance.com", "kraken.com", "blockchain.com", "metamask.io", "ledger.com",
            // Global banks
            "hsbc.com", "barclays.co.uk", "santander.com", "citi.com", "chase.com",
            "wellsfargo.com", "bankofamerica.com", "natwest.com", "lloydsbank.com",
            // South Africa
            "standardbank.co.za", "fnb.co.za", "absa.co.za", "nedbank.co.za",
            "capitecbank.co.za", "discovery.co.za", "investec.com", "tymebank.co.za",
            "sars.gov.za", "takealot.com", "vodacom.co.za", "mtn.co.za", "telkom.co.za",
            "checkers.co.za", "woolworths.co.za", "makro.co.za",
            // Logistics and government, the classic lure categories
            "dhl.com", "fedex.com", "ups.com", "usps.com", "royalmail.com",
            "postoffice.co.za", "aramex.com"
        )

        val DEFAULT_SHORTENERS: Set<String> = setOf(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "t.ly",
            "short.io", "bl.ink", "lnkd.in", "youtu.be", "amzn.to", "fb.me", "wa.me"
        )

        /** TLDs with a disproportionate share of abuse relative to their size. */
        val RISKY_TLDS: Set<String> = setOf(
            "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work",
            "zip", "mov", "country", "kim", "loan", "date", "racing", "download",
            "review", "stream", "science", "party", "gdn", "bid", "trade", "win",
            "rest", "quest", "cyou", "sbs", "cfd"
        )
    }
}
