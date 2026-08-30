package com.mume.core.analysis

/**
 * A tolerant URL decomposition.
 *
 * Deliberately *not* `java.net.URI` / `URL`, for three reasons: those types
 * reject the malformed input we most want to analyse, they resolve DNS in some
 * code paths, and their behaviour differs from Swift's `URLComponents` in ways
 * that would break Kotlin/Swift parity. Attacker-controlled strings are exactly
 * where standard parsers disagree, so we specify our own and test it.
 */
data class ParsedUrl(
    val raw: String,
    val scheme: String?,
    val userInfo: String?,
    val host: String,
    val port: Int?,
    val path: String,
    val query: String?,
    val fragment: String?
) {
    val hasCredentials: Boolean get() = !userInfo.isNullOrEmpty()
    val isIpLiteral: Boolean get() = UrlParser.isIpLiteral(host)
    val labels: List<String> get() = host.split('.').filter { it.isNotEmpty() }
}

object UrlParser {

    /** Schemes that execute rather than navigate. */
    val EXECUTABLE_SCHEMES = setOf("javascript", "data", "vbscript", "file", "intent", "jar")

    private val DEFAULT_PORTS = mapOf(
        "http" to 80, "https" to 443, "ftp" to 21, "ws" to 80, "wss" to 443
    )

    /**
     * @return the decomposed URL, or null when there is no host to analyse
     *   (which is itself reported by [UrlAnalyzer] rather than swallowed).
     */
    fun parse(input: String): ParsedUrl? {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return null

        var rest = trimmed
        var scheme: String? = null

        val schemeEnd = rest.indexOf(':')
        if (schemeEnd > 0 && rest.take(schemeEnd).all { it.isLetterOrDigit() || it in "+-." }) {
            val candidate = rest.take(schemeEnd).lowercase()
            if (candidate.first().isLetter()) {
                scheme = candidate
                rest = rest.substring(schemeEnd + 1)
                if (rest.startsWith("//")) rest = rest.substring(2)
            }
        }

        // Executable schemes have no authority; everything after the colon is payload.
        if (scheme != null && scheme in EXECUTABLE_SCHEMES) {
            return ParsedUrl(trimmed, scheme, null, "", null, rest, null, null)
        }

        var fragment: String? = null
        val hash = rest.indexOf('#')
        if (hash >= 0) {
            fragment = rest.substring(hash + 1)
            rest = rest.substring(0, hash)
        }

        var query: String? = null
        val questionMark = rest.indexOf('?')
        if (questionMark >= 0) {
            query = rest.substring(questionMark + 1)
            rest = rest.substring(0, questionMark)
        }

        var path = "/"
        val slash = rest.indexOf('/')
        if (slash >= 0) {
            path = rest.substring(slash)
            rest = rest.substring(0, slash)
        }

        // Authority. Split on the LAST '@' — an attacker puts extra '@' in the
        // userinfo precisely to make naive parsers pick the wrong host.
        var userInfo: String? = null
        val at = rest.lastIndexOf('@')
        if (at >= 0) {
            userInfo = rest.substring(0, at)
            rest = rest.substring(at + 1)
        }

        var port: Int? = null
        var host = rest
        if (host.startsWith("[")) {
            // IPv6 literal.
            val close = host.indexOf(']')
            if (close < 0) return null
            val afterBracket = host.substring(close + 1)
            if (afterBracket.startsWith(":")) {
                port = afterBracket.substring(1).toIntOrNull()
            }
            host = host.substring(0, close + 1)
        } else {
            val colon = host.lastIndexOf(':')
            if (colon >= 0) {
                val portPart = host.substring(colon + 1)
                if (portPart.isNotEmpty() && portPart.all { it.isDigit() }) {
                    port = portPart.toIntOrNull()
                    host = host.substring(0, colon)
                }
            }
        }

        host = host.lowercase().removeSuffix(".")
        if (host.isEmpty()) return null

        // Normalise away a default port so `https://x.com:443` and `https://x.com`
        // are not scored differently.
        if (scheme != null && port != null && DEFAULT_PORTS[scheme] == port) port = null

        return ParsedUrl(trimmed, scheme, userInfo, host, port, path, query, fragment)
    }

    fun isIpLiteral(host: String): Boolean {
        if (host.startsWith("[") && host.endsWith("]")) return true
        val parts = host.split('.')
        if (parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } }) {
            return parts.all { (it.toIntOrNull() ?: 256) in 0..255 }
        }
        // Decimal, octal and hex forms of an IPv4 address all resolve, and all
        // are used to disguise one. e.g. http://2130706433/ is 127.0.0.1
        if (parts.size == 1) {
            if (host.all { it.isDigit() } && host.length in 8..10) return true
            if (host.startsWith("0x") && host.drop(2).all { it.isDigit() || it in "abcdefABCDEF" }) return true
        }
        return false
    }
}

/**
 * Registrable-domain extraction from a bundled suffix list.
 *
 * ## An honest approximation
 *
 * The full Public Suffix List is ~15,000 rules and changes weekly. Bundling it
 * would be fine on size but it would go stale between releases, and the parts
 * that matter for phishing detection are dominated by a few hundred entries.
 *
 * So we ship the common multi-label suffixes and fall back to "last label" for
 * everything else. Where that guess is wrong the effect is bounded: brand-in-
 * subdomain detection may split the name one label off, which changes a score
 * slightly and never causes a block on its own.
 *
 * That trade-off is documented rather than hidden, because a user who ends up
 * reading this should be able to tell what the tool actually knows.
 */
object PublicSuffix {

    private val MULTI_LABEL_SUFFIXES: Set<String> = setOf(
        // United Kingdom
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
        // Australia / New Zealand
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        // Southern Africa
        "co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za",
        "co.zw", "co.mz", "co.bw", "co.na",
        // Brazil / Latin America
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.ar", "com.mx", "com.co", "com.pe", "com.uy", "com.ve", "com.ec",
        // Asia
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "go.kr",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "org.hk", "net.hk", "com.tw", "com.sg", "com.my", "com.ph",
        "com.vn", "co.th", "co.id", "co.il", "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.pk", "com.bd", "com.np", "com.sa", "com.eg", "com.tr", "com.kw", "com.qa",
        // Europe
        "co.at", "or.at", "com.es", "com.pl", "com.pt", "com.gr", "com.hr", "com.ua",
        "com.ru", "org.ru", "net.ru", "com.ro", "co.rs", "com.cy", "com.mt",
        // Africa (rest)
        "com.ng", "com.gh", "co.ke", "co.tz", "co.ug", "com.et",
        // Generic hosting suffixes that behave as public suffixes for our purposes
        "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
        "herokuapp.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com",
        "firebaseapp.com", "web.app", "appspot.com", "blogspot.com", "wordpress.com",
        "weebly.com", "wixsite.com", "myshopify.com", "square.site", "glitch.me",
        "repl.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
        "no-ip.org", "hopto.org", "serveo.net", "loca.lt", "onrender.com"
    )

    /**
     * @return `example.co.uk` for `a.b.example.co.uk`; the host itself when it is
     *   already at or below the registrable level.
     */
    fun registrableDomain(host: String): String {
        if (UrlParser.isIpLiteral(host)) return host
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return host

        val lastTwo = labels.takeLast(2).joinToString(".")
        return if (lastTwo in MULTI_LABEL_SUFFIXES) {
            labels.takeLast(3).joinToString(".")
        } else {
            lastTwo
        }
    }

    /** Labels to the left of the registrable domain. */
    fun subdomainLabels(host: String): List<String> {
        val registrable = registrableDomain(host)
        if (host == registrable) return emptyList()
        return host.removeSuffix(".$registrable").split('.').filter { it.isNotEmpty() }
    }
}
