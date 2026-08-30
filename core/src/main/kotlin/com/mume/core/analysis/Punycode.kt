package com.mume.core.analysis

/**
 * RFC 3492 Punycode decoder.
 *
 * ## Why we implement this rather than skip it
 *
 * Homoglyph attacks — `pаypal.com` with a Cyrillic `а` — reach the device as
 * `xn--pypal-4ve.com`. Without decoding, the best an offline scanner can say is
 * "this is an internationalised domain", which is useless: millions of
 * legitimate domains are.
 *
 * Decoding is about sixty lines of integer arithmetic with no tables and no
 * network, after which [Confusables] can fold the result to a Latin skeleton and
 * compare it against the bundled brand list. That turns a vague warning into a
 * specific one: *"this looks like paypal.com but is not"*.
 *
 * Only decoding is implemented; Mume never needs to encode.
 */
object Punycode {

    private const val BASE = 36
    private const val TMIN = 1
    private const val TMAX = 26
    private const val SKEW = 38
    private const val DAMP = 700
    private const val INITIAL_BIAS = 72
    private const val INITIAL_N = 128
    private const val DELIMITER = '-'
    private const val ACE_PREFIX = "xn--"

    /** Guards against decoding bombs: a short label cannot expand without bound. */
    private const val MAX_OUTPUT_LENGTH = 256

    /**
     * Decodes every `xn--` label in a hostname, leaving other labels untouched.
     *
     * @return the Unicode form, or the input unchanged if it contains no ACE
     *   labels or if any label fails to decode. Decoding failure is treated as
     *   "leave it alone" rather than an error: a malformed label is itself
     *   suspicious and [UrlAnalyzer] scores it separately.
     */
    fun decodeHostname(host: String): String {
        if (!host.contains(ACE_PREFIX, ignoreCase = true)) return host
        return host.split('.').joinToString(".") { label ->
            if (label.startsWith(ACE_PREFIX, ignoreCase = true)) {
                decodeLabel(label.substring(ACE_PREFIX.length)) ?: label
            } else {
                label
            }
        }
    }

    fun hasAceLabel(host: String): Boolean =
        host.split('.').any { it.startsWith(ACE_PREFIX, ignoreCase = true) }

    /** @return the decoded label, or null if [encoded] is not valid Punycode. */
    fun decodeLabel(encoded: String): String? {
        if (encoded.isEmpty()) return null

        val output = ArrayList<Int>(encoded.length)

        // Everything before the last delimiter is literal ASCII.
        val lastDelimiter = encoded.lastIndexOf(DELIMITER)
        var inputIndex = 0
        if (lastDelimiter > 0) {
            for (i in 0 until lastDelimiter) {
                val c = encoded[i]
                if (c.code >= 0x80) return null
                output.add(c.code)
            }
            inputIndex = lastDelimiter + 1
        }

        var n = INITIAL_N
        var i = 0
        var bias = INITIAL_BIAS

        while (inputIndex < encoded.length) {
            val oldI = i
            var w = 1
            var k = BASE
            while (true) {
                if (inputIndex >= encoded.length) return null
                val digit = decodeDigit(encoded[inputIndex]) ?: return null
                inputIndex++

                // Overflow guards. The values here cannot legitimately approach
                // Int.MAX_VALUE for any real domain label.
                if (digit > (Int.MAX_VALUE - i) / w) return null
                i += digit * w

                val t = when {
                    k <= bias -> TMIN
                    k >= bias + TMAX -> TMAX
                    else -> k - bias
                }
                if (digit < t) break
                if (w > Int.MAX_VALUE / (BASE - t)) return null
                w *= (BASE - t)
                k += BASE
            }

            val outLength = output.size + 1
            if (outLength > MAX_OUTPUT_LENGTH) return null
            bias = adapt(i - oldI, outLength, oldI == 0)

            if (i / outLength > Int.MAX_VALUE - n) return null
            n += i / outLength
            i %= outLength

            if (n < 0 || n > 0x10FFFF) return null
            // Surrogate range is not a valid scalar value.
            if (n in 0xD800..0xDFFF) return null

            output.add(i, n)
            i++
        }

        val sb = StringBuilder(output.size)
        for (cp in output) sb.appendCodePoint(cp)
        return sb.toString()
    }

    private fun adapt(delta: Int, numPoints: Int, firstTime: Boolean): Int {
        var d = if (firstTime) delta / DAMP else delta / 2
        d += d / numPoints
        var k = 0
        while (d > ((BASE - TMIN) * TMAX) / 2) {
            d /= (BASE - TMIN)
            k += BASE
        }
        return k + (BASE - TMIN + 1) * d / (d + SKEW)
    }

    private fun decodeDigit(c: Char): Int? = when (c) {
        in 'a'..'z' -> c - 'a'
        in 'A'..'Z' -> c - 'A'
        in '0'..'9' -> c - '0' + 26
        else -> null
    }
}
