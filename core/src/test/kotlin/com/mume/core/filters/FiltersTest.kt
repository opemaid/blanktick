package com.mume.core.filters

import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HashingTest {

    @Test
    fun `hashing is deterministic`() {
        repeat(500) { i ->
            val s = "candidate-$i"
            assertEquals(Hashing.h1(s), Hashing.h1(s))
            assertEquals(Hashing.h2(s), Hashing.h2(s))
        }
    }

    @Test
    fun `the two hash functions are independent`() {
        var equalCount = 0
        repeat(10_000) { i ->
            if (Hashing.h1("v$i") == Hashing.h2("v$i")) equalCount++
        }
        assertEquals(0, equalCount, "h1 and h2 must not collide with each other")
    }

    @Test
    fun `similar inputs produce dissimilar hashes`() {
        // FNV-1a alone has poor avalanche in the low bits; SplitMix64 fixes it.
        // This asserts the fix is actually applied, because a regression here
        // would quietly wreck the Bloom filter's false-positive rate.
        val a = Hashing.h1("password1")
        val b = Hashing.h1("password2")
        val differingBits = java.lang.Long.bitCount((a xor b).toLong())
        assertTrue(
            differingBits in 20..44,
            "expected roughly half the bits to differ, got $differingBits"
        )
    }

    @Test
    fun `low bits are well distributed`() {
        // The modulo in a Bloom probe lands on the low bits, so they must be
        // uniform. Chi-square across 64 buckets over 64k samples.
        val buckets = IntArray(64)
        val n = 64_000
        repeat(n) { i -> buckets[(Hashing.h1("sample:$i") % 64uL).toInt()]++ }
        val expected = n.toDouble() / 64
        val chiSquare = buckets.sumOf { val d = it - expected; d * d / expected }
        // 63 degrees of freedom: the 0.999 critical value is ~112.
        assertTrue(chiSquare < 112.0, "low bits are not uniform, chi-square = $chiSquare")
    }

    @Test
    fun `empty string hashes without error`() {
        assertNotEquals(0uL, Hashing.h1(""))
        assertNotEquals(Hashing.h1(""), Hashing.h2(""))
    }

    @Test
    fun `hashing is byte-exact for non-ascii input`() {
        // The Swift mirror hashes UTF-8 bytes too; if either side ever hashed
        // UTF-16 code units instead, this value would change.
        val a = Hashing.h1("münchen")
        val b = Hashing.h1(byteArrayOf(0x6D, 0xC3.toByte(), 0xBC.toByte(), 0x6E, 0x63, 0x68, 0x65, 0x6E))
        assertEquals(a, b, "hashing must operate on UTF-8 bytes")
    }
}

class DomainNormalizerTest {

    @Test
    fun `normalization is idempotent and case-insensitive`() {
        assertEquals("example.com", DomainNormalizer.normalize("EXAMPLE.com"))
        assertEquals("example.com", DomainNormalizer.normalize("example.com."))
        assertEquals("example.com", DomainNormalizer.normalize("  Example.Com  "))
        assertEquals("example.com", DomainNormalizer.normalize("*.example.com"))
        assertEquals("example.com", DomainNormalizer.normalize("example.com:8080"))
    }

    @Test
    fun `www is preserved as a distinct name`() {
        assertEquals("www.example.com", DomainNormalizer.normalize("www.example.com"))
    }

    @Test
    fun `parent chain walks up but never reaches a bare TLD`() {
        assertEquals(
            listOf("a.b.example.com", "b.example.com", "example.com"),
            DomainNormalizer.parentChain("a.b.example.com")
        )
        assertFalse(
            DomainNormalizer.parentChain("a.b.example.com").contains("com"),
            "probing a bare TLD would let one blocklist entry break the internet"
        )
    }

    @Test
    fun `parent chain is capped`() {
        val deep = (1..40).joinToString(".") { "l$it" } + ".example.com"
        assertEquals(5, DomainNormalizer.parentChain(deep, maxLabels = 5).size)
    }

    @Test
    fun `two-label and single-label hosts behave`() {
        assertEquals(listOf("example.com"), DomainNormalizer.parentChain("example.com"))
        assertEquals(listOf("localhost"), DomainNormalizer.parentChain("localhost"))
        assertEquals(emptyList(), DomainNormalizer.parentChain(""))
    }
}

class BloomFilterTest {

    @Test
    fun `sizing matches the published formula`() {
        // n = 2,000,000, p = 0.001 -> m ~= 28,755,176 bits, k = 10.
        // That is 3.43 MiB / 3.59 MB. The architecture note quotes MiB; this
        // test pins both so the two can never drift apart again.
        val m = BloomFilter.optimalBitCount(2_000_000, 0.001)
        assertTrue(abs(m - 28_755_176L) < 100, "m was $m")
        assertEquals(10, BloomFilter.optimalHashCount(m, 2_000_000))

        val mebibytes = m / 8.0 / 1_048_576
        assertTrue(abs(mebibytes - 3.43) < 0.02, "size was $mebibytes MiB")

        val megabytes = m / 8.0 / 1_000_000
        assertTrue(abs(megabytes - 3.59) < 0.02, "size was $megabytes MB")
    }

    @Test
    fun `there are never false negatives`() {
        val n = 50_000L
        val builder = BloomFilter.create(n, 0.001)
        val inserted = (1..n.toInt()).map { "password-$it" }
        inserted.forEach { builder.add(it) }
        val filter = builder.build()

        // This is the property the whole design rests on: a breached password
        // must never be reported as safe.
        inserted.forEach {
            assertTrue(it in filter, "false negative on '$it' — this must be impossible")
        }
    }

    @Test
    fun `measured false-positive rate is close to the target`() {
        val n = 50_000L
        val target = 0.01
        val builder = BloomFilter.create(n, target)
        (1..n.toInt()).forEach { builder.add("in-$it") }
        val filter = builder.build()

        var falsePositives = 0
        val trials = 100_000
        repeat(trials) { i -> if ("out-$i" in filter) falsePositives++ }

        val measured = falsePositives.toDouble() / trials
        assertTrue(
            measured < target * 2,
            "measured FPR $measured is more than twice the $target target"
        )
        assertTrue(
            abs(filter.estimatedFalsePositiveRate() - measured) < target,
            "the self-reported estimate must track reality"
        )
    }

    @Test
    fun `serialization round-trips exactly`() {
        val builder = BloomFilter.create(1_000, 0.01)
        val words = (1..1_000).map { "word-$it" }
        words.forEach { builder.add(it) }

        val bytes = builder.serialize()
        val parsed = BloomFilter.parse(bytes)

        assertEquals(builder.build().bitCount, parsed.bitCount)
        assertEquals(builder.build().hashCount, parsed.hashCount)
        assertEquals(1_000L, parsed.insertedCount)
        words.forEach { assertTrue(it in parsed) }
    }

    @Test
    fun `header is the documented size and magic`() {
        val bytes = BloomFilter.create(10, 0.01).serialize()
        assertEquals("MUB1", bytes.decodeToString(0, 4))
        assertTrue(bytes.size > BloomFilter.HEADER_BYTES)
    }

    @Test
    fun `corruption is detected`() {
        val builder = BloomFilter.create(1_000, 0.01)
        (1..1_000).forEach { builder.add("w$it") }
        val bytes = builder.serialize()

        // Flip a bit in the payload, well past the header.
        bytes[BloomFilter.HEADER_BYTES + 32] = (bytes[BloomFilter.HEADER_BYTES + 32].toInt() xor 0x40).toByte()

        assertFailsWith<IllegalArgumentException> { BloomFilter.parse(bytes) }
    }

    @Test
    fun `bad magic is rejected`() {
        val bytes = BloomFilter.create(10, 0.01).serialize()
        bytes[0] = 'X'.code.toByte()
        assertFailsWith<IllegalArgumentException> { BloomFilter.parse(bytes) }
    }

    @Test
    fun `truncated input is rejected rather than read out of bounds`() {
        val bytes = BloomFilter.create(1_000, 0.01).serialize()
        assertFailsWith<IllegalArgumentException> { BloomFilter.parse(bytes.copyOf(bytes.size / 2)) }
        assertFailsWith<IllegalArgumentException> { BloomFilter.parse(ByteArray(4)) }
    }

    @Test
    fun `an empty filter matches nothing`() {
        val filter = BloomFilter.create(1_000, 0.01).build()
        assertFalse("anything" in filter)
        assertEquals(0.0, filter.fillRatio())
    }
}

class SortedHashSet64Test {

    private val domains = listOf(
        "ads.example.com", "tracker.net", "evil.co.za", "malware.test", "phish.example.org"
    )

    @Test
    fun `membership is exact`() {
        val set = SortedHashSet64.build(domains)
        domains.forEach { assertTrue(it in set, "missing $it") }
        assertFalse("google.com" in set)
        assertFalse("example.com" in set)
    }

    @Test
    fun `no false positives across a large probe`() {
        // The reason this structure exists rather than a second Bloom filter:
        // a false positive here would block a site the user needs.
        val set = SortedHashSet64.build((1..20_000).map { "blocked-$it.example" })
        var falsePositives = 0
        repeat(200_000) { i -> if ("clean-$i.example" in set) falsePositives++ }
        assertEquals(0, falsePositives, "the blocklist must not block innocent domains")
    }

    @Test
    fun `parent domain matching finds the registrable entry`() {
        val set = SortedHashSet64.build(listOf("evil.com"))
        assertEquals("evil.com", set.matchDomain("a.b.c.evil.com"))
        assertEquals("evil.com", set.matchDomain("evil.com"))
        assertNull(set.matchDomain("notevil.com"))
    }

    @Test
    fun `parent matching stops before a bare TLD`() {
        val set = SortedHashSet64.build(listOf("com"))
        assertNull(
            set.matchDomain("www.google.com"),
            "a TLD entry must never match, or one bad line breaks everything"
        )
    }

    @Test
    fun `normalization is applied on both build and query`() {
        val set = SortedHashSet64.build(listOf("EVIL.COM."))
        assertTrue("evil.com" in set)
        assertEquals("evil.com", set.matchDomain("A.EVIL.COM"))
    }

    @Test
    fun `duplicates collapse`() {
        val set = SortedHashSet64.build(listOf("a.com", "a.com", "A.COM", "a.com."))
        assertEquals(1, set.size)
    }

    @Test
    fun `serialization round-trips`() {
        val set = SortedHashSet64.build((1..5_000).map { "d$it.example" })
        val parsed = SortedHashSet64.parse(SortedHashSet64.serialize(set))
        assertEquals(set.size, parsed.size)
        (1..5_000).forEach { assertTrue("d$it.example" in parsed) }
    }

    @Test
    fun `header magic is checked`() {
        val bytes = SortedHashSet64.serialize(SortedHashSet64.build(listOf("a.com")))
        assertEquals("MUS1", bytes.decodeToString(0, 4))
        bytes[1] = 'X'.code.toByte()
        assertFailsWith<IllegalArgumentException> { SortedHashSet64.parse(bytes) }
    }

    @Test
    fun `corruption is detected`() {
        val set = SortedHashSet64.build((1..500).map { "d$it.example" })
        val bytes = SortedHashSet64.serialize(set)
        bytes[SortedHashSet64.HEADER_BYTES + 8] =
            (bytes[SortedHashSet64.HEADER_BYTES + 8].toInt() xor 0xFF).toByte()
        assertFailsWith<IllegalArgumentException> { SortedHashSet64.parse(bytes) }
    }

    @Test
    fun `an empty set is valid and matches nothing`() {
        val set = SortedHashSet64.build(emptyList())
        assertEquals(0, set.size)
        assertFalse("anything.com" in set)
        assertEquals(0, SortedHashSet64.parse(SortedHashSet64.serialize(set)).size)
    }

    @Test
    fun `index buckets cover the whole unsigned range`() {
        // Digests are unsigned; a signed comparison anywhere would corrupt the
        // ordering for roughly half of all keys. Exercise enough entries that
        // both halves of the range are certainly populated.
        val values = (1..30_000).map { "bucket-probe-$it.example" }
        val set = SortedHashSet64.build(values)
        val rng = Random(7)
        repeat(3_000) {
            val v = values[rng.nextInt(values.size)]
            assertTrue(v in set, "unsigned ordering is broken for $v")
        }
    }
}
