package com.mume.core.scoring

import com.mume.core.model.Category
import com.mume.core.model.Grade
import com.mume.core.model.Severity

/**
 * The normative scoring parameters.
 *
 * This class is the single source of truth for how a device score is produced.
 * The Swift implementation in `ios/MumeCore/ScoringPolicy.swift` mirrors these
 * exact values, and the JSON fixtures in `shared/fixtures` assert that both implementations
 * agree to the integer.
 *
 * ## Design constraints this encodes
 *
 * 1. **Every point is attributable.** No hidden bonuses or global fudge factors;
 *    the score is exactly `100` minus the sum of per-finding deductions.
 * 2. **Pile-up resistance.** Twelve medium findings about installed apps must
 *    not be worse than a rooted device. Two mechanisms enforce this: an
 *    intra-category geometric [decay] and a hard [categoryCaps] ceiling.
 * 3. **Explainability over precision.** The decay factor is a round 0.6 rather
 *    than a tuned constant, because a user tapping a finding must be shown
 *    arithmetic they can follow.
 */
data class ScoringPolicy(
    /** Base deduction for a single finding at each severity, before decay. */
    val severityWeights: Map<Severity, Double> = mapOf(
        Severity.INFO to 0.0,
        Severity.LOW to 4.0,
        Severity.MEDIUM to 9.0,
        Severity.HIGH to 14.0,
        Severity.CRITICAL to 25.0
    ),

    /**
     * Maximum total deduction any one category may contribute.
     *
     * Sum of caps is 165, deliberately greater than 100: a device that is bad in
     * every dimension should be able to reach a score of 0, but a device bad in
     * only one dimension should not.
     */
    val categoryCaps: Map<Category, Int> = mapOf(
        Category.DEVICE_INTEGRITY to 40,
        Category.OS_CURRENCY to 25,
        Category.NETWORK to 25,
        Category.APP_HYGIENE to 35,
        Category.DATA_EXPOSURE to 20,
        Category.ACCOUNT_SECURITY to 20
    ),

    /**
     * Geometric decay applied to the 2nd, 3rd, ... findings within a category,
     * ordered by descending base weight.
     *
     * With `decay = 0.6`, three HIGH findings in one category cost
     * `14 + 8.4 + 5.04 = 27.44` rather than `42`. The first instance of a
     * problem carries nearly all the signal; the tenth adds little.
     */
    val decay: Double = 0.6,

    /** Lower bound (inclusive) of each grade band. */
    val gradeThresholds: List<Pair<Int, Grade>> = listOf(
        90 to Grade.STRONG,
        75 to Grade.GOOD,
        50 to Grade.FAIR,
        25 to Grade.WEAK,
        0 to Grade.AT_RISK
    )
) {
    init {
        require(decay > 0.0 && decay <= 1.0) { "decay must be in (0, 1], was $decay" }
        require(severityWeights.keys.containsAll(Severity.entries.toSet())) {
            "severityWeights must cover every Severity"
        }
        require(categoryCaps.keys.containsAll(Category.entries.toSet())) {
            "categoryCaps must cover every Category"
        }
        require(severityWeights[Severity.INFO] == 0.0) {
            "INFO findings must never deduct points"
        }
        require(gradeThresholds.isNotEmpty() && gradeThresholds.last().first == 0) {
            "gradeThresholds must include a band starting at 0"
        }
        require(gradeThresholds.zipWithNext().all { (a, b) -> a.first > b.first }) {
            "gradeThresholds must be sorted strictly descending"
        }
    }

    fun weightFor(severity: Severity): Double =
        severityWeights.getValue(severity)

    fun capFor(category: Category): Int =
        categoryCaps.getValue(category)

    fun gradeFor(score: Int): Grade =
        gradeThresholds.first { score >= it.first }.second

    companion object {
        /** The shipping policy. Changing it is a spec change; bump [VERSION]. */
        val DEFAULT = ScoringPolicy()

        /** Bumped whenever any value above changes, so fixtures stay pinned. */
        const val VERSION = "1.0.0"
    }
}
