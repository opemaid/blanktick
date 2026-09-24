package com.blanktick.app

import com.blanktick.core.filters.BloomFilter
import com.blanktick.core.filters.DomainNormalizer
import com.blanktick.core.filters.SortedHashSet64
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Cross-language parity: Kotlin reads a bundle that Python wrote.
 *
 * ## Why this is the most important test in the project
 *
 * The same hash specification is implemented three times — in Python
 * (`tools/blanktick_hash.py`), in Kotlin (`Hashing.kt`) and in Swift
 * (`Hashing.swift`). If any one of them drifts by a single bit, the failure is
 * not a crash. It is **silently wrong membership answers**: the app would tell
 * someone a breached password is safe, which is the exact outcome the whole
 * architecture exists to prevent.
 *
 * Nothing about that drift is visible from reading either side. The only way to
 * know is to have one language read what another wrote and check real values.
 * That is what this does.
 *
 * The test skips (rather than fails) when the bundle has not been generated, so
 * a fresh clone builds green; CI runs `tools/build_intel.py --demo` first.
 */
class IntelBundleParityTest {

    private val intelDir: File? by lazy {
        listOf(
            File("src/main/assets/intel"),
            File("app/src/main/assets/intel")
        ).firstOrNull { it.isDirectory }
    }

    private fun bundlePresent(): Boolean =
        intelDir?.let { File(it, "passwords.mub").exists() } == true

    // Passwords from tools/seeds/passwords-seed.txt. The builder always folds
    // the seed list in, so these are guaranteed present in any bundle.
    private val knownBreached = listOf(
        "123456", "password", "qwerty", "letmein", "iloveyou",
        "trustno1", "sunshine", "qwertyuiop", "1q2w3e4r"
    )

    // Domains from tools/seeds/blocklist-seed.txt.
    private val knownBlocked = listOf(
        "doubleclick.net", "google-analytics.com", "criteo.com", "adnxs.com", "taboola.com"
    )

    // Domains from tools/seeds/allowlist-seed.txt.
    private val knownAllowed = listOf(
        "google.com", "standardbank.co.za", "cloudflare.com", "whatsapp.com"
    )

    @Test
    fun `the python-written bloom filter parses in kotlin`() {
        if (!bundlePresent()) return
        val bytes = File(intelDir, "passwords.mub").readBytes()

        // parse() verifies the checksum, so this passing already proves Python
        // and Kotlin agree on the byte layout AND on the FNV-1a checksum.
        val filter = BloomFilter.parse(bytes)

        assertEquals("MUB1", bytes.decodeToString(0, 4))
        assertTrue(filter.bitCount > 0)
        assertTrue(filter.hashCount in 1..64)
        assertTrue(filter.insertedCount > 0)
    }

    @Test
    fun `passwords python inserted are found by kotlin`() {
        if (!bundlePresent()) return
        val filter = BloomFilter.parse(File(intelDir, "passwords.mub").readBytes())

        // THE parity assertion. Each of these was hashed by blanktick_hash.py at
        // build time and is being hashed by Hashing.kt now. A one-bit
        // difference in either implementation and these fail.
        knownBreached.forEach {
            assertTrue(
                it in filter,
                "'$it' was inserted by tools/build_intel.py but Kotlin cannot find it — " +
                    "the Python and Kotlin hash implementations have diverged"
            )
        }
    }

    @Test
    fun `the filter does not match arbitrary strings`() {
        if (!bundlePresent()) return
        val filter = BloomFilter.parse(File(intelDir, "passwords.mub").readBytes())

        // Guards against the degenerate pass: a filter with every bit set would
        // satisfy the test above and be useless.
        val misses = (1..2_000).count { "not-a-real-password-$it-Zq9" !in filter }
        assertTrue(misses > 1_900, "only $misses/2000 absent strings missed; filter looks saturated")
        assertTrue(filter.fillRatio() < 0.9, "fill ratio ${filter.fillRatio()} is implausible")
    }

    @Test
    fun `the python-written domain table parses and matches in kotlin`() {
        if (!bundlePresent()) return
        val blocklist = SortedHashSet64.parse(File(intelDir, "blocklist.mus").readBytes())

        knownBlocked.forEach {
            assertTrue(it in blocklist, "'$it' is in the seed blocklist but Kotlin cannot find it")
        }
    }

    @Test
    fun `subdomains of a blocked domain match through the parent walk`() {
        if (!bundlePresent()) return
        val blocklist = SortedHashSet64.parse(File(intelDir, "blocklist.mus").readBytes())
        assertEquals("doubleclick.net", blocklist.matchDomain("stats.g.doubleclick.net"))
    }

    @Test
    fun `the allowlist protects the domains a false block would hurt most`() {
        if (!bundlePresent()) return
        val allowlist = SortedHashSet64.parse(File(intelDir, "allowlist.mus").readBytes())
        val blocklist = SortedHashSet64.parse(File(intelDir, "blocklist.mus").readBytes())

        knownAllowed.forEach {
            assertTrue(it in allowlist, "'$it' must be on the allowlist")
            assertFalse(it in blocklist, "'$it' must never appear on the blocklist")
        }
    }

    @Test
    fun `domain normalization agrees across the language boundary`() {
        if (!bundlePresent()) return
        val blocklist = SortedHashSet64.parse(File(intelDir, "blocklist.mus").readBytes())

        // Python normalises before hashing; Kotlin normalises before querying.
        // If the two rules differed — say one stripped `www.` — these would miss.
        listOf("DOUBLECLICK.NET", "doubleclick.net.", " doubleclick.net ", "doubleclick.net:443")
            .forEach {
                assertTrue(
                    DomainNormalizer.normalize(it) in blocklist,
                    "normalisation of '$it' does not agree with the builder"
                )
            }
    }

    @Test
    fun `the manifest is readable and declares whether the bundle is synthetic`() {
        if (!bundlePresent()) return
        val text = File(intelDir, "manifest.txt").readText()
        assertTrue(text.contains("builtOn="))
        assertTrue(text.contains("version="))
        assertTrue(
            text.contains("synthetic="),
            "a demo bundle must be labelled so it cannot masquerade as real threat data"
        )
    }

    @Test
    fun `a corrupt bundle is rejected rather than silently misread`() {
        if (!bundlePresent()) return
        val bytes = File(intelDir, "passwords.mub").readBytes()
        val corrupted = bytes.copyOf()
        corrupted[BloomFilter.HEADER_BYTES + 100] =
            (corrupted[BloomFilter.HEADER_BYTES + 100].toInt() xor 0x20).toByte()

        val thrown = runCatching { BloomFilter.parse(corrupted) }.exceptionOrNull()
        assertNotNull(thrown, "a flipped payload bit must fail the checksum")
    }
}
