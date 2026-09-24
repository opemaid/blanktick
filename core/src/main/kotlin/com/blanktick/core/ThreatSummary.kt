package com.blanktick.core

import com.blanktick.core.model.Category
import com.blanktick.core.model.ScoredFinding
import com.blanktick.core.model.Severity

/**
 * The threat picture for one monitored level, summarised.
 *
 * ## Why every field is a count and none is a percentage
 *
 * A percentage needs a denominator, and the honest denominator here is contested:
 * "80% clear" could mean 8 of 10 rules passed, or 8 passed and 2 were never asked.
 * Those are different machines. The four counts below are reported raw and always
 * sum to [total], so the reader does the arithmetic they choose rather than
 * inheriting ours.
 *
 * [notCheckable] is deliberately a first-class field beside [found] and [clear]
 * rather than a footnote. On this product a check that did not run is the thing
 * most likely to be mistaken for good news, so it is never folded into "clear"
 * and never omitted because it is zero.
 */
data class LevelSummary(
    val category: Category,
    /** Rules that ran and produced at least one actionable finding. */
    val found: Int,
    /** Rules that ran and found nothing wrong. */
    val clear: Int,
    /** Eligible here, but this device did not supply the inputs. May change. */
    val unobservable: Int,
    /** Not written for this kind of device. Permanent, and not a gap in cover. */
    val wrongPlatform: Int,
    /**
     * Findings from this level, most severe first.
     *
     * Scored rather than bare so the row can show what each one actually cost.
     * A severity label alone invites "how bad is that really?"; the deduction
     * answers it in the same units as the score.
     */
    val findings: List<ScoredFinding>
) {
    /** Every rule in this category, however it ended. */
    val total: Int get() = found + clear + unobservable + wrongPlatform

    /** The two skip reasons together — what the level could not tell you. */
    val notCheckable: Int get() = unobservable + wrongPlatform

    /**
     * Rules that actually answered. The denominator a coverage claim may use.
     *
     * Zero is a real value and means the level is unmonitored on this device —
     * which is a *stronger* statement than "nothing found here", and the UI is
     * required to say so rather than render an empty bar.
     */
    val answered: Int get() = found + clear

    /** Highest severity present, or null when the level produced no findings. */
    val worst: Severity? get() = findings.maxByOrNull { it.finding.severity.ordinal }?.finding?.severity

    fun countOf(severity: Severity): Int = findings.count { it.finding.severity == severity }

    init {
        require(found >= 0 && clear >= 0 && unobservable >= 0 && wrongPlatform >= 0) {
            "counts must not be negative"
        }
    }
}

/**
 * Threat posture across every monitored level.
 *
 * Built from a [ScanReport] and nothing else, so it cannot disagree with the
 * scan it describes — the failure mode that a separately-collected "threat
 * dashboard" would invite.
 */
data class ThreatSummary(
    val levels: List<LevelSummary>,
    /**
     * True when the collector did not finish.
     *
     * The UI must suppress any headline number while this is set. An interrupted
     * scan still contains real findings and it would be easy to total what
     * arrived and print it; a total over an unknown fraction is not a total.
     * Findings stay visible — they are true. Only the summary arithmetic hides.
     */
    val incomplete: Boolean
) {
    val allFindings: List<ScoredFinding>
        get() = levels.flatMap { it.findings }.sortedWith(FINDING_ORDER)

    /** Total points these findings cost, for the row-level ledger. */
    val totalDeduction: Int get() = allFindings.sumOf { it.deduction }

    val totalFound: Int get() = levels.sumOf { it.found }
    val totalClear: Int get() = levels.sumOf { it.clear }
    val totalNotCheckable: Int get() = levels.sumOf { it.notCheckable }
    val totalRules: Int get() = levels.sumOf { it.total }

    fun countOf(severity: Severity): Int = levels.sumOf { it.countOf(severity) }

    /** Levels where nothing answered at all — reported, never quietly dropped. */
    val unmonitoredLevels: List<LevelSummary> get() = levels.filter { it.answered == 0 }

    companion object {
        /** Worst first, then by rule id so the order is stable between scans. */
        private val FINDING_ORDER =
            compareByDescending<ScoredFinding> { it.finding.severity.ordinal }
                .thenBy { it.finding.ruleId }

        /**
         * Every [Category] appears in the output, in enum order, including the
         * ones with no rules on this platform.
         *
         * Dropping empty levels would make the screen quietly shorter on the
         * device with the least cover, which is precisely backwards: the phone
         * that cannot check its own network is the one whose owner most needs to
         * see an empty Network row.
         */
        fun from(report: ScanReport, incomplete: Boolean = false): ThreatSummary {
            val findingsByCategory = report.result.findings.groupBy { it.finding.category }
            val reportsByCategory = report.rules.groupBy { it.category }

            val levels = Category.entries.map { category ->
                val rules = reportsByCategory[category].orEmpty()
                LevelSummary(
                    category = category,
                    found = rules.count { it.outcome == RuleReport.Outcome.FAILED },
                    clear = rules.count { it.outcome == RuleReport.Outcome.PASSED },
                    unobservable = rules.count { it.skippedAsUnobservable },
                    wrongPlatform = rules.count { it.skippedAsWrongPlatform },
                    findings = findingsByCategory[category].orEmpty().sortedWith(FINDING_ORDER)
                )
            }
            return ThreatSummary(levels, incomplete)
        }
    }
}
