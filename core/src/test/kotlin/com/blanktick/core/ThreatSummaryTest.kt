package com.blanktick.core

import com.blanktick.core.model.Category
import com.blanktick.core.model.Platform
import com.blanktick.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The summary's whole job is to be *total*: every rule the scanner considered has
 * to land in exactly one bucket of exactly one level. A threat dashboard that
 * loses rules is worse than no dashboard, because it reads as reassurance.
 *
 * These assertions are on concrete category names and reconciled sums rather than
 * on a count of levels, so a new [Category] cannot pass by arriving unnoticed.
 */
class ThreatSummaryTest {

    private fun snapshotFor(platform: Platform) = when (platform) {
        Platform.ANDROID -> Snapshots.healthyAndroid()
        Platform.IOS -> Snapshots.healthyIos()
        Platform.DESKTOP -> Snapshots.healthyDesktop()
    }

    private fun summaryFor(platform: Platform): ThreatSummary =
        ThreatSummary.from(BlanktickScanner().scan(snapshotFor(platform)))

    @Test
    fun `every category appears, in enum order, even when it holds no rules`() {
        val summary = summaryFor(Platform.DESKTOP)
        assertEquals(
            Category.entries.toList(),
            summary.levels.map { it.category },
            "levels must mirror Category exactly — a level with no rules on this " +
                "device is information, not a row to drop"
        )
    }

    @Test
    fun `no rule is lost or double counted on any platform`() {
        for (platform in Platform.entries) {
            val report = BlanktickScanner().scan(snapshotFor(platform))
            val summary = ThreatSummary.from(report)

            assertEquals(
                report.rules.size,
                summary.totalRules,
                "on $platform the summary must account for every rule the scanner ran"
            )
            assertEquals(
                DefaultRules.ALL.size,
                summary.totalRules,
                "on $platform every rule in the catalogue must appear exactly once"
            )
        }
    }

    @Test
    fun `each level's buckets sum to its own total`() {
        val summary = summaryFor(Platform.DESKTOP)
        for (level in summary.levels) {
            assertEquals(
                level.total,
                level.found + level.clear + level.unobservable + level.wrongPlatform,
                "${level.category.displayName} must reconcile"
            )
            assertEquals(
                level.notCheckable,
                level.unobservable + level.wrongPlatform,
                "${level.category.displayName}: notCheckable is the two skip reasons"
            )
        }
    }

    @Test
    fun `not-checkable is never folded into clear`() {
        val report = BlanktickScanner().scan(Snapshots.healthyDesktop())
        val summary = ThreatSummary.from(report)

        assertEquals(
            report.rules.count { it.outcome == RuleReport.Outcome.PASSED },
            summary.totalClear,
            "clear must count only rules that actually ran and passed"
        )
        assertEquals(
            report.notApplicable.size,
            summary.totalNotCheckable,
            "every skipped rule must be reported as not-checkable somewhere"
        )
        assertTrue(
            summary.totalNotCheckable > 0,
            "the desktop fixture is expected to skip the phone-only rules; if this " +
                "fails the fixture changed and the screen's premise needs rechecking"
        )
    }

    @Test
    fun `findings are grouped under their own level and none escape`() {
        val report = BlanktickScanner().scan(Snapshots.healthyDesktop())
        val summary = ThreatSummary.from(report)

        assertEquals(
            report.result.findings.size,
            summary.allFindings.size,
            "every finding must surface on exactly one level"
        )
        for (level in summary.levels) {
            assertTrue(
                level.findings.all { it.finding.category == level.category },
                "${level.category.displayName} holds a finding from another category"
            )
        }
    }

    @Test
    fun `a level with findings reports found greater than zero`() {
        val summary = summaryFor(Platform.DESKTOP)
        for (level in summary.levels.filter { it.findings.any { f -> f.finding.severity.isActionable } }) {
            assertTrue(
                level.found > 0,
                "${level.category.displayName} shows findings but claims 0 rules found them"
            )
        }
    }

    @Test
    fun `findings sort most severe first`() {
        val summary = summaryFor(Platform.DESKTOP)
        val ordinals = summary.allFindings.map { it.finding.severity.ordinal }
        assertEquals(
            ordinals.sortedDescending(), ordinals,
            "the reader's eye starts at the top; the worst thing must be there"
        )
    }

    @Test
    fun `severity counts across levels equal the report's own`() {
        val report = BlanktickScanner().scan(Snapshots.healthyDesktop())
        val summary = ThreatSummary.from(report)
        for (severity in Severity.entries) {
            assertEquals(
                report.result.findings.count { it.finding.severity == severity },
                summary.countOf(severity),
                "$severity count drifted between the report and the summary"
            )
        }
    }

    @Test
    fun `incomplete is off by default and carried when set`() {
        val report = BlanktickScanner().scan(Snapshots.healthyDesktop())
        assertFalse(ThreatSummary.from(report).incomplete)
        assertTrue(
            ThreatSummary.from(report, incomplete = true).incomplete,
            "the UI suppresses headline arithmetic off this flag; it must survive"
        )
    }

    @Test
    fun `a level nothing answered is reported as unmonitored, not as clear`() {
        val summary = summaryFor(Platform.DESKTOP)
        for (level in summary.unmonitoredLevels) {
            assertEquals(
                0, level.answered,
                "${level.category.displayName} was listed unmonitored but something answered"
            )
            assertEquals(
                0, level.clear,
                "${level.category.displayName}: an unmonitored level must never show a clear count"
            )
        }
    }
}
