package com.blanktick.desktop.collect

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Parse-correctness tests for the three facts added for the new rules, over the
 * `WindowsCollector(probeMap)` seam — no PowerShell.
 *
 * `WindowsProbeTest` proves every emitted key is consumed; this proves the
 * key=value → `DesktopFacts` parsing is right. The load-bearing part is the
 * null-vs-empty / null-vs-zero gating: that is exactly where a "a failed query
 * read as clean" bug would hide, and nothing exercised it before.
 */
class WindowsCollectorParseTest {

    private val knownBad = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    private fun intel(vuln: ((String) -> Boolean?)? = null) = DesktopIntelSnapshot(
        builtOn = "2026-10-17", stalenessDays = 0, isKnownMalware = null, isVulnerableDriver = vuln
    )

    private fun facts(probe: Map<String, List<String>>, vuln: ((String) -> Boolean?)? = null) =
        WindowsCollector(probe).collect(intel(vuln))

    // Hardening facts are only built when the probe reached the end of that block.
    private val hardRead = mapOf("hard.settingsRead" to listOf("True"))

    // ---------------------------------------------------- driver.loaded (BYOVD)

    @Test
    fun `vulnerable drivers keeps only hash-confirmed rows`() {
        val d = facts(
            mapOf(
                "driver.enumerated" to listOf("True"),
                "driver.loaded" to listOf(
                    "rtcore64.sys\t$knownBad",            // confirmed vulnerable
                    "benign.sys\t${"a".repeat(64)}",      // valid hash, not on the list
                    "rtcore64.sys\t$knownBad",            // duplicate -> de-duped
                    "junk.sys\tnothex"                    // 2nd field not 64 hex -> dropped
                )
            ),
            vuln = { it == knownBad }
        )
        assertEquals(listOf("rtcore64.sys"), d.vulnerableDriversLoaded)
    }

    @Test
    fun `no driver sentinel means not-checkable, never empty`() {
        val d = facts(mapOf("driver.loaded" to listOf("rtcore64.sys\t$knownBad")), vuln = { true })
        assertNull(d.vulnerableDriversLoaded)
    }

    @Test
    fun `no bundled corpus means not-checkable`() {
        val d = facts(
            mapOf("driver.enumerated" to listOf("True"), "driver.loaded" to listOf("x.sys\t$knownBad")),
            vuln = null
        )
        assertNull(d.vulnerableDriversLoaded)
    }

    @Test
    fun `drivers enumerated with no match is a pass, not not-checkable`() {
        val d = facts(mapOf("driver.enumerated" to listOf("True")), vuln = { false })
        assertEquals(emptyList(), d.vulnerableDriversLoaded)
    }

    // ------------------------------------------------- office.macroWeak

    @Test
    fun `office macro weakenings are parsed when Office was found`() {
        val d = facts(hardRead + mapOf(
            "office.read" to listOf("True"),
            "office.macroWeak" to listOf("Excel: internet macros unblocked")
        ))
        assertEquals(listOf("Excel: internet macros unblocked"), d.hardening?.officeMacroSecurityWeak)
    }

    @Test
    fun `office found with no weakening is an empty list, not null`() {
        val d = facts(hardRead + mapOf("office.read" to listOf("True")))
        assertEquals(emptyList(), d.hardening?.officeMacroSecurityWeak)
    }

    @Test
    fun `no Office found is not-checkable`() {
        val d = facts(hardRead)
        assertNull(d.hardening?.officeMacroSecurityWeak)
    }

    // ------------------------------------------------- cred.savedRdp

    @Test
    fun `saved RDP count is parsed, and zero is a real reading`() {
        assertEquals(2, facts(hardRead + mapOf("cred.savedRdp" to listOf("2"))).hardening?.savedRemoteDesktopCredentials)
        assertEquals(0, facts(hardRead + mapOf("cred.savedRdp" to listOf("0"))).hardening?.savedRemoteDesktopCredentials)
    }

    @Test
    fun `unreadable credential store is not-checkable, never zero`() {
        assertNull(facts(hardRead).hardening?.savedRemoteDesktopCredentials)
    }

    @Test
    fun `the seam does not run PowerShell`() {
        // A sanity check that the canned map is what is parsed: an empty probe
        // yields a DesktopFacts with the new facts all not-checkable.
        val d = facts(emptyMap())
        assertNull(d.vulnerableDriversLoaded)
        assertTrue(d.hardening == null)
    }
}
