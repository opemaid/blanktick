package com.blanktick.desktop

import com.blanktick.core.ScanReport
import com.blanktick.core.model.Category
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Grade
import com.blanktick.core.model.Platform
import com.blanktick.core.model.ScanResult
import com.blanktick.core.model.ScoredFinding
import com.blanktick.core.model.Severity
import com.blanktick.desktop.history.ScanHistory
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The searchable scan history, tested at its two load-bearing promises: it does
 * not write unless asked, and what it writes is a summary — never the sensitive
 * specifics the rest of the app is built to protect.
 */
class ScanHistoryTest {

    private val tmp = File.createTempFile("bt-history", ".jsonl").also { it.delete() }

    @AfterTest fun cleanup() { tmp.delete() }

    private val on = Settings(keepHistory = true)
    private val off = Settings(keepHistory = false)

    /** A finding whose specifics (a DNS address) live only in detail/evidence. */
    private fun dnsFinding() = ScoredFinding(
        Finding(
            ruleId = "NET-DNS-001",
            category = Category.NETWORK,
            severity = Severity.MEDIUM,
            title = "Name lookups go to an unrecognised server",
            detail = "The resolver is 40.33.1.55, which is not a known provider.",
            remediation = "Set DNS to a known resolver in network settings.",
            evidence = mapOf("resolver" to "40.33.1.55")
        ),
        deduction = 9,
        rawDeduction = 9.0
    )

    private fun malFinding() = ScoredFinding(
        Finding(
            ruleId = "DSK-MAL-003",
            category = Category.DEVICE_INTEGRITY,
            severity = Severity.LOW,
            title = "A program is running from a personal folder, unsigned",
            detail = "C:\\Users\\someone\\tool.exe",
            remediation = "Confirm you installed it.",
            subjectId = "tool.exe"
        ),
        deduction = 2,
        rawDeduction = 2.0
    )

    private fun report(
        scannedAt: Long,
        score: Int,
        findings: List<ScoredFinding>
    ) = ScanReport(
        ScanResult(
            score = score,
            grade = Grade.GOOD,
            findings = findings,
            categories = emptyList(),
            checksRun = 38,
            checksPassed = 34,
            checksSkipped = 30,
            platform = Platform.DESKTOP,
            intelBundleDate = "2026-09-02",
            intelStalenessDays = 21,
            scannedAt = scannedAt
        ),
        rules = emptyList()
    )

    @Test
    fun `nothing is written unless history is turned on`() {
        ScanHistory.record(report(1_000, 82, listOf(dnsFinding())), settings = off, at = tmp)
        assertFalse(tmp.exists() && tmp.length() > 0, "a scan was stored while history was off")
        assertTrue(ScanHistory.all(tmp).isEmpty())
    }

    @Test
    fun `a recorded scan round-trips`() {
        ScanHistory.record(report(1_700_000_000_000, 82, listOf(dnsFinding(), malFinding())), settings = on, at = tmp)
        val snaps = ScanHistory.all(tmp)
        assertEquals(1, snaps.size)
        val s = snaps.single()
        assertEquals(1_700_000_000_000, s.scannedAt)
        assertEquals(82, s.score)
        assertEquals("DESKTOP", s.platform)
        assertEquals(38, s.checksRun)
        assertEquals("2026-09-02", s.intelBundleDate)
        assertEquals(21, s.intelStalenessDays)
        assertEquals(2, s.findings.size)
        val dns = s.findings.first { it.ruleId == "NET-DNS-001" }
        assertEquals("MEDIUM", dns.severity)
        assertEquals(9, dns.deduction)
        assertEquals("Name lookups go to an unrecognised server", dns.title)
    }

    /**
     * The whole reason this store is allowed to exist. The specifics that make a
     * scan a target map — the DNS address, the account name, the full path — live
     * in detail/evidence, and none of them may reach disk.
     */
    @Test
    fun `the stored form omits the sensitive specifics`() {
        ScanHistory.record(report(1_000, 82, listOf(dnsFinding(), malFinding())), settings = on, at = tmp)
        val raw = tmp.readText()

        // The values themselves.
        assertFalse(raw.contains("40.33.1.55"), "a DNS address reached the history file")
        assertFalse(raw.contains("C:\\\\Users"), "a full user path reached the history file")
        assertFalse(raw.contains("Set DNS to a known resolver"), "a remediation reached the history file")

        // And the keys that carry them, so a future field cannot smuggle them in.
        ScanHistory.historyOmits.forEach { key ->
            assertFalse(raw.contains("\"$key\""), "the history file carries a forbidden field: $key")
        }
    }

    @Test
    fun `search filters by severity, rule and date`() {
        val day = 86_400_000L
        ScanHistory.record(report(day * 10, 90, listOf(malFinding())), settings = on, at = tmp)
        ScanHistory.record(report(day * 20, 82, listOf(dnsFinding(), malFinding())), settings = on, at = tmp)
        val all = ScanHistory.all(tmp)

        assertEquals(1, ScanHistory.search(all, severity = "MEDIUM").size)
        assertEquals(2, ScanHistory.search(all, ruleId = "DSK-MAL-003").size)
        assertEquals(1, ScanHistory.search(all, ruleId = "DSK-MAL-003", sinceEpochMillis = day * 15).size)
        assertTrue(ScanHistory.search(all, severity = "CRITICAL").isEmpty())
    }

    @Test
    fun `changes reports what resolved and what appeared`() {
        ScanHistory.record(report(1_000, 90, listOf(malFinding())), settings = on, at = tmp)
        ScanHistory.record(report(2_000, 82, listOf(dnsFinding())), settings = on, at = tmp)
        val scans = ScanHistory.all(tmp)
        val change = ScanHistory.changesBetween(scans[scans.size - 2], scans.last())

        assertEquals(setOf("DSK-MAL-003"), change.resolved.map { it.ruleId }.toSet())
        assertEquals(setOf("NET-DNS-001"), change.appeared.map { it.ruleId }.toSet())
    }

    @Test
    fun `history rendering flags staleness`() {
        ScanHistory.record(report(1_000, 82, listOf(dnsFinding())), settings = on, at = tmp)
        val text = ScanHistory.renderHistory(ScanHistory.all(tmp), now = 1_000 + 3 * 3_600_000L)
        assertTrue(text.contains("stored record, not a live"), "history must say it is not live")
        assertTrue(text.contains("3 h ago"), "staleness age missing: $text")
    }
}
