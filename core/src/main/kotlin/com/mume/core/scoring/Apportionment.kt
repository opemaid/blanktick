package com.mume.core.scoring

import kotlin.math.floor

/**
 * Distributes an integer total across fractional weights so that the parts sum
 * **exactly** to the total.
 *
 * ## Why this exists
 *
 * The home screen lists findings with a "-14" next to each, and shows an
 * overall score. If those integers are produced by rounding each finding
 * independently, they will not add up: eight findings each rounding up by 0.4
 * silently invents three points of deduction the score does not reflect.
 *
 * A user who tries to check our arithmetic and finds it wrong has every reason
 * to distrust the rest of the app. So we use the **largest remainder method**
 * (Hamilton's method): floor everything, then hand the leftover units to the
 * entries with the largest fractional parts.
 *
 * Ties are broken by index, which keeps the result deterministic across
 * platforms — a hard requirement, since the golden fixtures compare Kotlin and
 * Swift output byte for byte.
 */
internal object Apportionment {

    /**
     * @param weights non-negative fractional parts to distribute across.
     * @param total the integer that the result must sum to. Must be >= 0.
     * @return a list the same length as [weights], summing exactly to [total].
     */
    fun largestRemainder(weights: List<Double>, total: Int): List<Int> {
        require(total >= 0) { "total must be non-negative, was $total" }
        require(weights.all { it >= 0.0 && it.isFinite() }) {
            "weights must be finite and non-negative"
        }
        if (weights.isEmpty()) {
            require(total == 0) { "cannot distribute $total across zero weights" }
            return emptyList()
        }

        val sum = weights.sum()
        if (sum <= 0.0) {
            // Nothing to weight by. Everything gets zero; only valid when the
            // caller also asked for a total of zero.
            require(total == 0) { "cannot distribute $total across all-zero weights" }
            return List(weights.size) { 0 }
        }

        val exact = weights.map { it / sum * total }
        val floors = exact.map { floor(it).toInt() }
        var remaining = total - floors.sum()

        // `remaining` is in [0, weights.size) by construction, but guard anyway:
        // floating point could in principle push it out by one.
        if (remaining <= 0) return floors

        val order = exact.indices.sortedWith(
            compareByDescending<Int> { exact[it] - floor(exact[it]) }.thenBy { it }
        )

        val result = floors.toMutableList()
        var i = 0
        while (remaining > 0 && i < order.size) {
            result[order[i]] += 1
            remaining -= 1
            i += 1
        }
        // If we ran out of entries before running out of units (only reachable
        // with pathological inputs), dump the rest on the largest weight so the
        // sum invariant still holds.
        if (remaining > 0) result[order.first()] += remaining

        return result
    }
}
