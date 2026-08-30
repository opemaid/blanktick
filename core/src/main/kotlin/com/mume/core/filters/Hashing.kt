package com.mume.core.filters

/**
 * Deterministic 64-bit hashing, identical in Kotlin and Swift.
 *
 * ## Why hand-rolled
 *
 * The bundled intel files are built once by a Python tool and read by both a
 * Kotlin and a Swift implementation. All three must agree on every bit, forever
 * — a mismatch would silently turn a breached-password lookup into a coin flip.
 *
 * `String.hashCode()`, `hashValue` and `hash(into:)` are all unsuitable: the JVM
 * one is 32-bit and weak, and Swift's is deliberately randomised per process.
 * So we specify the algorithm ourselves:
 *
 * - **FNV-1a (64-bit)** over the UTF-8 bytes, using two different offset bases
 *   to produce two independent digests.
 * - **SplitMix64** finalisation on each, because FNV-1a alone has poor avalanche
 *   in the low bits, which is exactly where a modulo lands.
 *
 * Both are a handful of integer operations with no lookup tables, and both are
 * trivially portable. The test suite pins known vectors so a future refactor
 * cannot quietly change the output.
 */
object Hashing {

    private const val FNV_PRIME = 0x100000001b3uL
    private const val FNV_OFFSET_A = 0xcbf29ce484222325uL
    private const val FNV_OFFSET_B = 0x9e3779b97f4a7c15uL

    /** SplitMix64 mixer. Strong avalanche, invertible, no bad seeds. */
    fun mix(value: ULong): ULong {
        var z = value + 0x9E3779B97F4A7C15uL
        z = (z xor (z shr 30)) * 0xBF58476D1CE4E5B9uL
        z = (z xor (z shr 27)) * 0x94D049BB133111EBuL
        return z xor (z shr 31)
    }

    private fun fnv1a(bytes: ByteArray, offset: ULong): ULong {
        var h = offset
        for (b in bytes) {
            h = h xor (b.toUByte().toULong())
            h *= FNV_PRIME
        }
        return h
    }

    /** Primary 64-bit digest. */
    fun h1(bytes: ByteArray): ULong = mix(fnv1a(bytes, FNV_OFFSET_A))

    /** Secondary digest, independent of [h1] by using a different offset basis. */
    fun h2(bytes: ByteArray): ULong = mix(fnv1a(bytes, FNV_OFFSET_B) xor 0xD6E8FEB86659FD93uL)

    fun h1(s: String): ULong = h1(s.encodeToByteArray())
    fun h2(s: String): ULong = h2(s.encodeToByteArray())

    /** Single 64-bit digest, for the exact-membership tables. */
    fun digest(s: String): ULong = h1(s)
}

/**
 * Canonicalisation applied before hashing, so that the Python builder, the
 * Kotlin reader and the Swift reader all agree on what "the same domain" means.
 */
object DomainNormalizer {

    /**
     * Lowercases, strips a trailing dot, strips any leading `*.`, and removes a
     * port if one was appended. Does **not** strip `www.` — `www.example.com`
     * and `example.com` are different names and the parent-domain walk in
     * [SortedHashSet64] handles the relationship.
     *
     * Unicode domains must already be punycode when they reach here; the
     * platform layer converts, since IDN mapping tables are large and both
     * platforms ship one.
     */
    fun normalize(input: String): String {
        var s = input.trim().lowercase()
        if (s.startsWith("*.")) s = s.substring(2)
        s = s.removeSuffix(".")
        val colon = s.lastIndexOf(':')
        if (colon > 0 && s.substring(colon + 1).all { it.isDigit() }) {
            s = s.substring(0, colon)
        }
        return s
    }

    /**
     * Yields the domain then each parent, most specific first, capped at
     * [maxLabels] probes.
     *
     * `a.b.example.com` -> `a.b.example.com`, `b.example.com`, `example.com`.
     *
     * The cap exists because a blocklist hit on a public suffix such as `com`
     * would be catastrophic, and because an attacker can otherwise force
     * unbounded work with a 200-label hostname.
     */
    fun parentChain(domain: String, maxLabels: Int = 5): List<String> {
        val normalized = normalize(domain)
        if (normalized.isEmpty()) return emptyList()
        val labels = normalized.split('.')
        // A bare hostname or a TLD is never a useful lookup key.
        if (labels.size < 2) return listOf(normalized)

        val out = ArrayList<String>(minOf(maxLabels, labels.size - 1))
        var start = 0
        // Stop before the last label so we never probe a bare TLD.
        while (start <= labels.size - 2 && out.size < maxLabels) {
            out.add(labels.subList(start, labels.size).joinToString("."))
            start++
        }
        return out
    }
}
