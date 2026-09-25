package com.blanktick.core

import com.blanktick.core.model.Category
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Platform
import com.blanktick.core.model.ScanResult
import com.blanktick.core.rules.AccountSecurityRules
import com.blanktick.core.rules.AiSecurityRules
import com.blanktick.core.rules.AppHygieneRules
import com.blanktick.core.rules.BaselineRules
import com.blanktick.core.rules.DataExposureRules
import com.blanktick.core.rules.HardeningRules
import com.blanktick.core.rules.MalwareRules
import com.blanktick.core.rules.DesktopRules
import com.blanktick.core.rules.DeviceIntegrityRules
import com.blanktick.core.rules.NetworkRules
import com.blanktick.core.rules.OsCurrencyRules
import com.blanktick.core.rules.Rule
import com.blanktick.core.rules.RuleOutcome
import com.blanktick.core.scoring.ScoringEngine
import com.blanktick.core.scoring.ScoringPolicy

/**
 * A rule that ran, and what it concluded. Drives the "checks" screen.
 *
 * @param eligibleOnPlatform whether the rule *applies* to this platform at all.
 *   This is what separates the two very different reasons a check can be
 *   [Outcome.NOT_APPLICABLE], and the UI must not conflate them: a rule written
 *   for a phone will never run on a desktop no matter what the user does
 *   (`false`), whereas a rule that applies here and returned nothing means this
 *   machine would not answer the question, which may change on the next scan or
 *   once the user grants something (`true`). Reporting 28 checks as one
 *   undifferentiated "could not run" is the honest floor; this is the honest
 *   answer.
 */
data class RuleReport(
    val ruleId: String,
    val description: String,
    val outcome: Outcome,
    val eligibleOnPlatform: Boolean = true,
    /**
     * The rule's own category, copied onto the report.
     *
     * Carried here rather than looked up by id in the UI because a summary that
     * groups by category must account for *every* rule, including the ones that
     * did not run — and a lookup table built from the rules that produced
     * findings would silently drop exactly those. Copying it makes the grouping
     * total by construction.
     */
    val category: Category = Category.DEVICE_INTEGRITY
) {
    enum class Outcome { PASSED, FAILED, NOT_APPLICABLE }

    /** Not run because the rule is not written for this kind of device. */
    val skippedAsWrongPlatform: Boolean
        get() = outcome == Outcome.NOT_APPLICABLE && !eligibleOnPlatform

    /** Not run because this device did not supply the inputs. */
    val skippedAsUnobservable: Boolean
        get() = outcome == Outcome.NOT_APPLICABLE && eligibleOnPlatform
}

/** Everything a scan produced: the score, plus a per-rule audit trail. */
data class ScanReport(
    val result: ScanResult,
    val rules: List<RuleReport>
) {
    val notApplicable: List<RuleReport>
        get() = rules.filter { it.outcome == RuleReport.Outcome.NOT_APPLICABLE }

    /** Skipped because the rule is not written for this kind of device. Permanent. */
    val skippedWrongPlatform: List<RuleReport>
        get() = rules.filter { it.skippedAsWrongPlatform }

    /** Skipped because this device did not answer. May change between scans. */
    val skippedUnobservable: List<RuleReport>
        get() = rules.filter { it.skippedAsUnobservable }
}

/**
 * The entry point. Give it a [DeviceSnapshot], get a [ScanReport].
 *
 * Pure and synchronous: no threads, no I/O, no clock. All the platform-specific
 * work happens in the collectors that build the snapshot, which is what makes
 * the same rule set testable identically on both platforms and reproducible from
 * a JSON fixture.
 */
class BlanktickScanner(
    private val rules: List<Rule> = DefaultRules.ALL,
    policy: ScoringPolicy = ScoringPolicy.DEFAULT
) {
    private val engine = ScoringEngine(policy)

    init {
        val duplicates = rules.groupBy { it.id }.filterValues { it.size > 1 }.keys
        require(duplicates.isEmpty()) { "duplicate rule ids: $duplicates" }
    }

    fun scan(snapshot: DeviceSnapshot): ScanReport {
        val findings = mutableListOf<Finding>()
        val reports = mutableListOf<RuleReport>()
        var run = 0
        var skipped = 0

        for (rule in rules) {
            val eligible = snapshot.platform in rule.platforms
            when (val outcome = rule.evaluate(snapshot)) {
                is RuleOutcome.NotApplicable -> {
                    skipped++
                    reports += RuleReport(
                        rule.id, rule.description, RuleReport.Outcome.NOT_APPLICABLE, eligible, rule.category
                    )
                }

                is RuleOutcome.Pass -> {
                    run++
                    reports += RuleReport(
                        rule.id, rule.description, RuleReport.Outcome.PASSED, eligible, rule.category
                    )
                }

                is RuleOutcome.Fail -> {
                    run++
                    findings += outcome.findings
                    // A rule whose only findings are informational did not
                    // actually fail; the user has nothing to fix.
                    val actionable = outcome.findings.any { it.severity.isActionable }
                    reports += RuleReport(
                        rule.id,
                        rule.description,
                        if (actionable) RuleReport.Outcome.FAILED else RuleReport.Outcome.PASSED,
                        eligible,
                        rule.category
                    )
                }
            }
        }

        val result = engine.score(
            findings = findings,
            platform = snapshot.platform,
            checksRun = run,
            checksSkipped = skipped,
            scannedAt = snapshot.collectedAt,
            intelBundleDate = snapshot.intelBundleDate,
            intelStalenessDays = snapshot.intelStalenessDays
        )

        return ScanReport(result, reports)
    }

    /** Rules that this platform can actually run. Used to size the UI's checklist. */
    fun applicableRules(platform: Platform): List<Rule> =
        rules.filter { platform in it.platforms }
}

/**
 * The shipping rule set.
 *
 * Order is irrelevant to scoring — [ScoringEngine] sorts deterministically — but
 * it is preserved in the "checks run" list, so it is grouped the way a person
 * would read it.
 */
object DefaultRules {
    val ALL: List<Rule> =
        DeviceIntegrityRules.ALL +
            OsCurrencyRules.ALL +
            NetworkRules.ALL +
            AppHygieneRules.ALL +
            DataExposureRules.ALL +
            AccountSecurityRules.ALL +
            DesktopRules.ALL +
            HardeningRules.ALL +
            BaselineRules.ALL +
            MalwareRules.ALL +
            AiSecurityRules.ALL

    val COUNT: Int get() = ALL.size

    fun countFor(platform: Platform): Int = ALL.count { platform in it.platforms }
}
