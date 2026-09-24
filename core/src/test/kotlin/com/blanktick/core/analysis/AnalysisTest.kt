package com.blanktick.core.analysis

import com.blanktick.core.filters.SortedHashSet64
import com.blanktick.core.model.LinkVerdict
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PunycodeTest {

    @Test
    fun `decodes the standard textbook labels`() {
        assertEquals("bücher", Punycode.decodeLabel("bcher-kva"))
        assertEquals("münchen", Punycode.decodeLabel("mnchen-3ya"))
        assertEquals("café", Punycode.decodeLabel("caf-dma"))
    }

    @Test
    fun `decodes a hostname leaving ascii labels alone`() {
        assertEquals("bücher.example.com", Punycode.decodeHostname("xn--bcher-kva.example.com"))
        assertEquals("plain.example.com", Punycode.decodeHostname("plain.example.com"))
    }

    @Test
    fun `decoding is case-insensitive on the ACE prefix`() {
        assertEquals("bücher.com", Punycode.decodeHostname("XN--BCHER-KVA.com").lowercase())
    }

    @Test
    fun `a label with no basic characters decodes`() {
        // No delimiter at all: the whole label is encoded code points.
        val decoded = Punycode.decodeLabel("80ak6aa92e")
        assertNotNull(decoded)
        assertTrue(decoded.all { it.code > 0x7F }, "expected an all-Cyrillic label, got '$decoded'")
    }

    @Test
    fun `invalid input returns null rather than throwing`() {
        assertNull(Punycode.decodeLabel(""))
        assertNull(Punycode.decodeLabel("!!!"))
        assertNull(Punycode.decodeLabel("zzzzzzzzzzzzzzzzzzzzzzzzz"))
    }

    @Test
    fun `undecodable labels are left intact rather than corrupting the host`() {
        val host = "xn--!!!.example.com"
        assertEquals(host, Punycode.decodeHostname(host))
    }

    @Test
    fun `has ACE label detects the prefix`() {
        assertTrue(Punycode.hasAceLabel("xn--bcher-kva.com"))
        assertFalse(Punycode.hasAceLabel("bucher.com"))
    }
}

class ConfusablesTest {

    @Test
    fun `cyrillic lookalikes fold to their latin shapes`() {
        // "раураl" — every letter Cyrillic.
        val cyrillicPaypal = "раураӏ"
        assertEquals("paypal", Confusables.skeleton(cyrillicPaypal))
    }

    @Test
    fun `a single cyrillic character among latin is a script mix`() {
        val mixed = "pаypal"    // Cyrillic 'а'
        assertTrue(Confusables.hasSuspiciousScriptMix(mixed))
    }

    @Test
    fun `an all-latin label is not a script mix`() {
        assertFalse(Confusables.hasSuspiciousScriptMix("paypal"))
        assertFalse(Confusables.hasSuspiciousScriptMix("my-bank-123"))
    }

    @Test
    fun `wholly non-latin labels are not flagged as mixed`() {
        // Ordinary Russian, Greek and Japanese domains must not be treated as
        // attacks. Flagging them would make Blanktick useless outside Latin script.
        assertFalse(Confusables.hasSuspiciousScriptMix("почта"))   // почта
        assertFalse(Confusables.hasSuspiciousScriptMix("ελλαδα")) // ελλαδα
        assertFalse(Confusables.hasSuspiciousScriptMix("日本"))                      // 日本
    }

    @Test
    fun `digits are deliberately not folded to letters`() {
        // '0'->'o' would match half the internet against "google".
        assertEquals("g00gle", Confusables.skeleton("g00gle"))
        assertEquals("paypa1", Confusables.skeleton("paypa1"))
    }

    @Test
    fun `full width latin folds`() {
        assertEquals("paypal", Confusables.skeleton("ｐａｙｐａｌ"))
    }

    @Test
    fun `script classification covers the main confusable ranges`() {
        assertEquals(Confusables.Script.LATIN, Confusables.scriptOf('a'.code))
        assertEquals(Confusables.Script.CYRILLIC, Confusables.scriptOf(0x0430))
        assertEquals(Confusables.Script.GREEK, Confusables.scriptOf(0x03B1))
        assertEquals(Confusables.Script.COMMON, Confusables.scriptOf('-'.code))
        assertEquals(Confusables.Script.COMMON, Confusables.scriptOf('5'.code))
    }
}

class UrlParserTest {

    @Test
    fun `basic decomposition`() {
        val u = UrlParser.parse("https://www.example.com:8443/path/a?b=c#frag")!!
        assertEquals("https", u.scheme)
        assertEquals("www.example.com", u.host)
        assertEquals(8443, u.port)
        assertEquals("/path/a", u.path)
        assertEquals("b=c", u.query)
        assertEquals("frag", u.fragment)
    }

    @Test
    fun `default ports are normalized away`() {
        assertNull(UrlParser.parse("https://example.com:443/")!!.port)
        assertNull(UrlParser.parse("http://example.com:80/")!!.port)
    }

    @Test
    fun `the last at-sign wins`() {
        // A naive parser picks paypal.com here; browsers pick evil.ru.
        val u = UrlParser.parse("https://paypal.com@evil.ru/login")!!
        assertEquals("evil.ru", u.host)
        assertEquals("paypal.com", u.userInfo)
        assertTrue(u.hasCredentials)
    }

    @Test
    fun `multiple at-signs still resolve to the real host`() {
        val u = UrlParser.parse("https://a@b@c@real-host.example/x")!!
        assertEquals("real-host.example", u.host)
    }

    @Test
    fun `ipv6 literals parse with a port`() {
        val u = UrlParser.parse("https://[2001:db8::1]:8080/x")!!
        assertEquals("[2001:db8::1]", u.host)
        assertEquals(8080, u.port)
        assertTrue(u.isIpLiteral)
    }

    @Test
    fun `ip literals in all the disguises`() {
        assertTrue(UrlParser.isIpLiteral("192.168.1.1"))
        assertTrue(UrlParser.isIpLiteral("[::1]"))
        assertTrue(UrlParser.isIpLiteral("2130706433"))     // decimal 127.0.0.1
        assertTrue(UrlParser.isIpLiteral("0x7f000001"))     // hex 127.0.0.1
        assertFalse(UrlParser.isIpLiteral("example.com"))
        assertFalse(UrlParser.isIpLiteral("999.1.1.1"))
    }

    @Test
    fun `schemeless input still yields a host`() {
        assertEquals("example.com", UrlParser.parse("example.com/path")!!.host)
    }

    @Test
    fun `executable schemes carry no authority`() {
        val u = UrlParser.parse("javascript:alert(1)")!!
        assertEquals("javascript", u.scheme)
        assertEquals("", u.host)
    }

    @Test
    fun `empty and whitespace input is rejected`() {
        assertNull(UrlParser.parse(""))
        assertNull(UrlParser.parse("   "))
    }

    @Test
    fun `trailing dot is stripped from the host`() {
        assertEquals("example.com", UrlParser.parse("https://example.com./x")!!.host)
    }
}

class PublicSuffixTest {

    @Test
    fun `single-label suffixes`() {
        assertEquals("example.com", PublicSuffix.registrableDomain("www.example.com"))
        assertEquals("example.com", PublicSuffix.registrableDomain("a.b.c.example.com"))
        assertEquals("example.com", PublicSuffix.registrableDomain("example.com"))
    }

    @Test
    fun `multi-label suffixes`() {
        assertEquals("standardbank.co.za", PublicSuffix.registrableDomain("www.standardbank.co.za"))
        assertEquals("bbc.co.uk", PublicSuffix.registrableDomain("news.bbc.co.uk"))
        assertEquals("foo.com.au", PublicSuffix.registrableDomain("a.b.foo.com.au"))
    }

    @Test
    fun `hosting platforms behave as public suffixes`() {
        assertEquals("myapp.github.io", PublicSuffix.registrableDomain("myapp.github.io"))
        assertEquals("evil.vercel.app", PublicSuffix.registrableDomain("login.evil.vercel.app"))
    }

    @Test
    fun `subdomain labels are everything to the left`() {
        assertEquals(listOf("a", "b"), PublicSuffix.subdomainLabels("a.b.example.com"))
        assertEquals(emptyList(), PublicSuffix.subdomainLabels("example.com"))
        assertEquals(listOf("news"), PublicSuffix.subdomainLabels("news.bbc.co.uk"))
    }

    @Test
    fun `ip literals are returned untouched`() {
        assertEquals("192.168.1.1", PublicSuffix.registrableDomain("192.168.1.1"))
    }
}

class UrlAnalyzerTest {

    private val blocklist = SortedHashSet64.build(listOf("known-bad.example", "ads.tracker.test"))
    private val allowlist = SortedHashSet64.build(listOf("google.com", "standardbank.co.za"))
    private val analyzer = UrlAnalyzer(blocklist = blocklist, allowlist = allowlist)

    @Test
    fun `a blocklisted domain is dangerous`() {
        val r = analyzer.analyze("https://known-bad.example/login")
        assertEquals(LinkVerdict.DANGEROUS, r.verdict)
        assertTrue(r.signals.any { it.id == "URL-BLOCKLIST" })
    }

    @Test
    fun `blocklist matches subdomains of a listed domain`() {
        val r = analyzer.analyze("https://a.b.known-bad.example/")
        assertEquals(LinkVerdict.DANGEROUS, r.verdict)
    }

    @Test
    fun `an allowlisted domain is the only thing reported SAFE`() {
        assertEquals(LinkVerdict.SAFE, analyzer.analyze("https://www.google.com/search?q=a").verdict)
        assertEquals(LinkVerdict.SAFE, analyzer.analyze("https://standardbank.co.za").verdict)
    }

    @Test
    fun `a clean unlisted link is UNKNOWN and never SAFE`() {
        // The central honesty property of the offline engine: finding nothing
        // wrong is not the same as verifying something is right.
        val r = analyzer.analyze("https://some-small-business.co.za/contact")
        assertEquals(LinkVerdict.UNKNOWN, r.verdict)
        assertTrue(r.signals.none { it.weight > 0 })
    }

    @Test
    fun `credentials in the authority are caught`() {
        val r = analyzer.analyze("https://paypal.com@evil.ru/login")
        assertTrue(r.signals.any { it.id == "URL-USERINFO" })
        assertEquals("evil.ru", r.host)
        assertTrue(r.verdict == LinkVerdict.DANGEROUS || r.verdict == LinkVerdict.SUSPICIOUS)
    }

    @Test
    fun `brand in a subdomain of an unrelated domain is dangerous`() {
        val r = analyzer.analyze("https://paypal.com.secure-login.ru/verify")
        assertEquals(LinkVerdict.DANGEROUS, r.verdict)
        assertTrue(r.signals.any { it.id == "URL-BRAND-SUBDOMAIN" })
        assertEquals("secure-login.ru", r.registrableDomain)
        assertEquals("paypal.com", r.impersonatedBrand)
    }

    @Test
    fun `south african bank impersonation is caught`() {
        val r = analyzer.analyze("https://standardbank.co.za.verify-account.top/login")
        assertEquals(LinkVerdict.DANGEROUS, r.verdict)
        assertNotNull(r.impersonatedBrand)
    }

    @Test
    fun `typosquats within two edits are caught`() {
        assertTrue(analyzer.analyze("https://paypa1.com/").riskScore > 0)
        val r = analyzer.analyze("https://gogle.com/")
        assertTrue(r.signals.any { it.id == "URL-TYPOSQUAT" }, "signals: ${r.signals.map { it.id }}")
    }

    @Test
    fun `a digit-swapped brand with words attached is dangerous`() {
        // Found by visual test: this scored 45 "suspicious" on the TLD and http
        // alone, with no mention of PayPal at all.
        val r = analyzer.analyze("http://paypa1-secure-login.xyz/verify")
        assertTrue(r.signals.any { it.id == "URL-COMBOSQUAT" }, "signals: ${r.signals.map { it.id }}")
        assertEquals("paypal.com", r.impersonatedBrand)
        assertEquals(LinkVerdict.DANGEROUS, r.verdict)
    }

    @Test
    fun `an exact brand with words attached is flagged but not alone dangerous`() {
        val r = analyzer.analyze("https://paypal-secure-login.com/")
        val combo = r.signals.single { it.id == "URL-COMBOSQUAT" }
        assertEquals(55, combo.weight)
        assertEquals("paypal.com", r.impersonatedBrand)
    }

    @Test
    fun `ordinary hyphenated names are not mistaken for brands`() {
        // The other polarity: the edit-distance route this check deliberately
        // does NOT use would have called "apples" a misspelt Apple.
        for (url in listOf(
            "https://apples-and-pears.com/", "https://my-garden-blog.com/",
            "https://secure-login-help.com/", "https://top-10-recipes.com/"
        )) {
            val r = analyzer.analyze(url)
            assertTrue(r.signals.none { it.id == "URL-COMBOSQUAT" }, "$url: ${r.signals.map { it.id }}")
        }
    }

    @Test
    fun `the real brand is never a combosquat of itself`() {
        val r = UrlAnalyzer().analyze("https://www.paypal.com/signin")
        assertTrue(r.signals.none { it.id == "URL-COMBOSQUAT" })
    }

    @Test
    fun `short names do not produce spurious typosquat matches`() {
        // "abc.com" is within two edits of far too much to be meaningful.
        val r = analyzer.analyze("https://abc.com/")
        assertTrue(r.signals.none { it.id == "URL-TYPOSQUAT" })
    }

    @Test
    fun `the real brand itself is never flagged as a typosquat of itself`() {
        val r = UrlAnalyzer().analyze("https://www.paypal.com/signin")
        assertTrue(r.signals.none { it.id == "URL-TYPOSQUAT" })
        assertTrue(r.signals.none { it.id == "URL-BRAND-SUBDOMAIN" })
    }

    @Test
    fun `homoglyph domains are decoded and identified`() {
        // xn--pypal-4ve.com decodes to "pаypal.com" with a Cyrillic 'а'.
        val r = analyzer.analyze("https://xn--pypal-4ve.com/login")
        assertTrue(
            r.signals.any { it.id == "URL-HOMOGLYPH" || it.id == "URL-MIXED-SCRIPT" },
            "expected a homoglyph signal, got ${r.signals.map { it.id }}"
        )
        assertEquals(LinkVerdict.DANGEROUS, r.verdict)
        assertTrue(r.displayHost!!.any { it.code > 0x7F }, "display host must show the real characters")
    }

    @Test
    fun `raw ip hosts are suspicious`() {
        val r = analyzer.analyze("http://192.168.4.20/bank/login")
        assertTrue(r.signals.any { it.id == "URL-IP-HOST" })
    }

    @Test
    fun `executable schemes are dangerous immediately`() {
        assertEquals(LinkVerdict.DANGEROUS, analyzer.analyze("javascript:alert(1)").verdict)
        assertEquals(LinkVerdict.DANGEROUS, analyzer.analyze("data:text/html,<script>").verdict)
    }

    @Test
    fun `shorteners are UNKNOWN and say why`() {
        val r = analyzer.analyze("https://bit.ly/3xYzAbC")
        assertEquals(LinkVerdict.UNKNOWN, r.verdict)
        val signal = r.signals.single { it.id == "URL-SHORTENER" }
        assertTrue(
            signal.explanation.contains("cannot", ignoreCase = true),
            "the user must be told we cannot follow it, not that it is fine"
        )
    }

    @Test
    fun `risky TLDs contribute`() {
        val r = analyzer.analyze("http://free-money.tk/claim")
        assertTrue(r.signals.any { it.id == "URL-RISKY-TLD" })
    }

    @Test
    fun `plain http is noted`() {
        assertTrue(analyzer.analyze("http://example.org/").signals.any { it.id == "URL-NO-TLS" })
    }

    @Test
    fun `deep subdomains contribute`() {
        val r = analyzer.analyze("https://a.b.c.d.e.example.org/")
        assertTrue(r.signals.any { it.id == "URL-DEEP-SUBDOMAIN" })
    }

    @Test
    fun `heavy percent-encoding contributes`() {
        val r = analyzer.analyze("https://example.org/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e")
        assertTrue(r.signals.any { it.id == "URL-ENCODED" })
    }

    @Test
    fun `malformed input is reported rather than swallowed`() {
        val r = analyzer.analyze("   ")
        assertEquals(LinkVerdict.SUSPICIOUS, r.verdict)
        assertTrue(r.signals.any { it.id == "URL-MALFORMED" })
    }

    @Test
    fun `signals are ordered by weight so the UI can show the top reason`() {
        val r = analyzer.analyze("http://paypal.com.evil.tk/login")
        assertEquals(r.signals.maxByOrNull { it.weight }!!.explanation, r.topReason)
        assertEquals(r.signals.sortedByDescending { it.weight }, r.signals)
    }

    @Test
    fun `risk score is bounded`() {
        val r = analyzer.analyze("http://paypal.com@known-bad.example:1337/%2e%2e%2e%2e%2e%2e")
        assertTrue(r.riskScore in 0..100)
    }

    @Test
    fun `bounded edit distance agrees with the classic definition`() {
        val d = UrlAnalyzer.Companion::boundedDamerauLevenshtein
        assertEquals(0, d("abc", "abc", 2))
        assertEquals(1, d("abc", "abd", 2))
        assertEquals(1, d("abc", "ab", 2))
        assertEquals(1, d("ab", "ba", 2))          // transposition
        assertEquals(2, d("google", "gogle1", 2))
        assertTrue(d("aaaaaa", "bbbbbb", 2) > 2)   // early exit path
    }
}
