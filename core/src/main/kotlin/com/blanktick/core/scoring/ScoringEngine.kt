package com.blanktick.core.scoring

import com.blanktick.core.model.Category
import com.blanktick.core.model.CategoryScore
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Platform
import com.blanktick.core.model.ScanResult
import com.blanktick.core.model.ScoredFinding
import kotlin.math.pow
import kotlin.math.roundToInt

/**
 * Turns a bag of [Finding]s into a score, deterministically.
 *
 * Pure: no I/O, no clock, no randomness, no platform types. Given the same
 * findings and the same [ScoringPolicy] it returns the same result on every
 * machine, in both languages. That property is what the golden fixtures test.
 *
 * ## The algorithm, in full
 *
 * ```
 * for each category:
 *     base_i      = severityWeight(severity_i) * weightMultiplier_i
 *     order       = base descending, then ruleId, then subjectId   (deterministic)
 *     decayed_i   = base_i * decay^rank_i
 *     categoryRaw = sum(decayed)
 *     categoryDed = min(categoryRaw, cap[category])
 *     scale       = categoryDed / categoryRaw          (1.0 when under the cap)
 *     effective_i = decayed_i * scale
 *
 * totalRaw = sum(effective over all categories)
 * score    = clamp(100 - round(totalRaw), 0, 100)
 * displayed deductions = largestRemainder(effective, 100 - score)
 * ```
 *
 * The final line is what makes the numbers on screen add up exactly; see
 * [Apportionment].
 */
class ScoringEngine(private val policy: ScoringPolicy = ScoringPolicy.DEFAULT) {

    /**
     * @param findings every finding produced by the rule pass, in any order.
     * @param checksRun rules that executed on this platform.
     * @param checksSkipped rules skipped as unobservable here (the D-01 contract).
     */
    fun score(
        findings: List<Finding>,
        platform: Platform,
        checksRun: Int,
        checksSkipped: Int,
        scannedAt: Long,
        intelBundleDate: String? = null,
        intelStalenessDays: Int? = null
    ): ScanResult {
        // Deduplicate defensively: two rules emitting the same key would double
        // charge the user for one problem.
        val unique = findings.distinctBy { it.key }

        val perCategory = unique.groupBy { it.category }
        val effective = HashMap<String, Double>(unique.size)

        for ((category, group) in perCategory) {
            val ordered = group.sortedWith(orderWithinCategory)
            val decayed = ordered.mapIndexed { rank, f ->
                baseWeight(f) * policy.decay.pow(rank)
            }
            val categoryRaw = decayed.sum()
            val cap = policy.capFor(category).toDouble()
            val categoryDeduction = minOf(categoryRaw, cap)
            val scale = if (categoryRaw > 0.0) categoryDeduction / categoryRaw else 0.0

            ordered.forEachIndexed { rank, f ->
                effective[f.key] = decayed[rank] * scale
            }
        }

        // Stable global ordering for output: worst first, then alphabetical.
        val ordered = unique.sortedWith(globalOrder)
        val weights = ordered.map { effective.getValue(it.key) }

        val totalRaw = weights.sum()
        val score = (100 - totalRaw.roundToInt()).coerceIn(0, 100)
        val target = 100 - score

        val displayed = Apportionment.largestRemainder(weights, target)

        val scored = ordered.mapIndexed { i, f ->
            ScoredFinding(finding = f, deduction = displayed[i], rawDeduction = weights[i])
        }

        val categories = Category.entries.mapNotNull { category ->
            val inCategory = scored.filter { it.finding.category == category }
            if (inCategory.isEmpty()) return@mapNotNull null
            val deduction = inCategory.sumOf { it.deduction }
            val cap = policy.capFor(category)
            CategoryScore(
                category = category,
                deduction = deduction,
                cappedAt = if (deduction >= cap) cap else null,
                findingCount = inCategory.count { it.finding.severity.isActionable }
            )
        }

        val actionable = scored.count { it.finding.severity.isActionable }

        return ScanResult(
            score = score,
            grade = policy.gradeFor(score),
            findings = scored,
            categories = categories,
            checksRun = checksRun,
            checksPassed = (checksRun - actionable).coerceAtLeast(0),
            checksSkipped = checksSkipped,
            platform = platform,
            intelBundleDate = intelBundleDate,
            intelStalenessDays = intelStalenessDays,
            scannedAt = scannedAt
        )
    }

    private fun baseWeight(f: Finding): Double =
        policy.weightFor(f.severity) * f.weightMultiplier

    private val orderWithinCategory = compareByDescending<Finding> { baseWeight(it) }
        .thenBy { it.ruleId }
        .thenBy { it.subjectId }

    private val globalOrder = compareByDescending<Finding> { it.severity.ordinal }
        .thenByDescending { baseWeight(it) }
        .thenBy { it.category.ordinal }
        .thenBy { it.ruleId }
        .thenBy { it.subjectId }
}
