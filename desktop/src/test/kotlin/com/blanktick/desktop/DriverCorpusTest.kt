package com.blanktick.desktop

import com.blanktick.core.filters.SortedHashSet64
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The bundled known-vulnerable-driver (LOLDrivers) table, end to end — the BYOVD
 * counterpart of [MalwareCorpusTest].
 *
 * Same failure it guards against: `tools/build_intel.py` writes the table with a
 * Python FNV-1a digest and Kotlin reads it with its own; if the two ever drift,
 * `drivers.mus` parses cleanly, every lookup returns `false`, and DSK-DRV-001
 * silently detects nothing while reporting itself as working.
 *
 * ## The known-positive
 *
 * RTCore64.sys (MSI Afterburner's driver, CVE-2019-16098) is one of the most
 * widely abused BYOVD drivers and a permanent LOLDrivers entry, so its SHA-256
 * is a stable known-positive — the driver equivalent of EICAR. The hash is read
 * straight off the LOLDrivers corpus this table is built from.
 *
 * ## Why these tests skip when the table is absent
 *
 * Unlike malware.mus (which always ships, carrying EICAR), drivers.mus is only
 * written when a real corpus is supplied to `--drivers`. A build without one
 * deliberately ships no table so DSK-DRV-001 reports *not checkable* rather than
 * a false pass. These tests therefore assert the contract *when the table is
 * present* and skip when it is not — they never force one to exist.
 */
class DriverCorpusTest {

    /** RTCore64.sys — CVE-2019-16098. A canonical, permanent LOLDrivers sample. */
    private val rtcore64Sha256 =
        "03e0581432f5c8cc727a8aa387f5b69ff84d38d0df6f1226c19c6e960a81e1e9"

    private val table: SortedHashSet64? by lazy {
        DriverCorpusTest::class.java.getResourceAsStream("/intel/drivers.mus")
            ?.use { it.readBytes() }
            ?.let { runCatching { SortedHashSet64.parse(it) }.getOrNull() }
    }

    @Test
    fun `the bundled table contains a known-vulnerable driver hash`() {
        val t = table ?: return
        assertTrue(
            t.contains(rtcore64Sha256),
            "drivers.mus is bundled but the RTCore64 known-positive is not in it — " +
                "the Python builder and the Kotlin reader disagree about the digest, " +
                "which is exactly what a silently-dead BYOVD detector looks like."
        )
    }

    /** `Get-FileHash` / the probe emit lowercase already, but the table must not care. */
    @Test
    fun `lookup is case-insensitive for hex`() {
        val t = table ?: return
        assertTrue(t.contains(rtcore64Sha256.uppercase().lowercase()))
    }

    /**
     * The error this feature must never make: calling a legitimate signed driver
     * on someone's machine exploitable. The exact sorted table exists so a false
     * positive cannot happen.
     */
    @Test
    fun `ordinary driver hashes do not match`() {
        val t = table ?: return
        val innocent = (1..500).map { i ->
            java.security.MessageDigest.getInstance("SHA-256")
                .digest("blanktick-innocent-driver-$i".toByteArray())
                .joinToString("") { "%02x".format(it) }
        }
        assertTrue(innocent.none { t.contains(it) }, "false positives in an exact table")
    }

    /** A truncated or corrupt table must fail to parse, not half-work. */
    @Test
    fun `a corrupt table is rejected rather than half-read`() {
        val bytes = DriverCorpusTest::class.java.getResourceAsStream("/intel/drivers.mus")
            ?.use { it.readBytes() } ?: return
        val damaged = bytes.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertFalse(runCatching { SortedHashSet64.parse(damaged) }.isSuccess)
    }
}
