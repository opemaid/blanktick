package com.mume.core

import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.Platform
import com.mume.core.model.ScanResult
import com.mume.core.rules.AccountSecurityRules
import com.mume.core.rules.AppHygieneRules
import com.mume.core.rules.DataExposureRules
import com.mume.core.rules.DesktopRules
import com.mume.core.rules.DeviceIntegrityRules
import com.mume.core.rules.NetworkRules
import com.mume.core.rules.OsCurrencyRules
import com.mume.core.rules.Rule
import com.mume.core.rules.RuleOutcome
import com.mume.core.scoring.ScoringEngine
import com.mume.core.scoring.ScoringPolicy

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
    val eligibleOnPlatform: Boolean = true
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
class MumeScanner(
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
                        rule.id, rule.description, RuleReport.Outcome.NOT_APPLICABLE, eligible
                    )
                }

                is RuleOutcome.Pass -> {
                    run++
                    reports += RuleReport(
                        rule.id, rule.description, RuleReport.Outcome.PASSED, eligible
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
                        eligible
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
            DesktopRules.ALL

    val COUNT: Int get() = ALL.size

    fun countFor(platform: Platform): Int = ALL.count { platform in it.platforms }
}
