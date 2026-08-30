package com.mume.core.rules

import com.mume.core.model.Category
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.Platform

/**
 * Result of evaluating one rule.
 *
 * [NotApplicable] is the load-bearing case. It is returned when the platform
 * could not observe the rule's inputs at all, and is reported to the user as
 * "not checkable on this device" — never as a pass. See D-01.
 */
sealed interface RuleOutcome {
    data object NotApplicable : RuleOutcome
    data object Pass : RuleOutcome
    data class Fail(val findings: List<Finding>) : RuleOutcome {
        constructor(finding: Finding) : this(listOf(finding))

        init {
            require(findings.isNotEmpty()) { "Fail must carry at least one finding" }
        }
    }
}

/**
 * One check.
 *
 * Rules are pure functions of a [DeviceSnapshot] plus the bundled intel. They
 * must not touch the clock (use [DeviceSnapshot.collectedAt]), the filesystem,
 * or the network — the core module has no dependency that would let them.
 *
 * ## Rule ID convention
 *
 * `<AREA>-<TOPIC>-<NNN>`, e.g. `NET-CA-001`. IDs are permanent: they appear in
 * the golden fixtures, in the Swift mirror, and in the user-facing "why did my
 * score change" history. Retire an ID by removing the rule, never by reusing it.
 */
interface Rule {
    val id: String
    val category: Category

    /** Platforms this rule can meaningfully run on. */
    val platforms: Set<Platform>

    /** One-line human description, shown in the "checks run" list. */
    val description: String

    fun evaluate(snapshot: DeviceSnapshot): RuleOutcome
}

/**
 * Named platform sets.
 *
 * Written out rather than derived (no `Platform.entries.toSet()` for
 * [EVERYWHERE]) so that adding a fourth platform to the enum cannot silently
 * enrol every existing rule on it. Enrolling a rule on a new platform must be
 * a deliberate edit to that rule.
 */
object Platforms {
    val MOBILE: Set<Platform> = setOf(Platform.ANDROID, Platform.IOS)
    val ANDROID_ONLY: Set<Platform> = setOf(Platform.ANDROID)
    val DESKTOP_ONLY: Set<Platform> = setOf(Platform.DESKTOP)
    val ANDROID_AND_DESKTOP: Set<Platform> = setOf(Platform.ANDROID, Platform.DESKTOP)
    val EVERYWHERE: Set<Platform> = setOf(Platform.ANDROID, Platform.IOS, Platform.DESKTOP)
}

/**
 * Convenience base that handles the platform gate.
 *
 * The default is [Platforms.MOBILE] — the two platforms that existed when the
 * rule set was written. A rule that should also run on a desktop says so
 * explicitly; there is no way to acquire desktop coverage by accident.
 */
abstract class BaseRule(
    override val id: String,
    override val category: Category,
    override val description: String,
    override val platforms: Set<Platform> = Platforms.MOBILE
) : Rule {

    final override fun evaluate(snapshot: DeviceSnapshot): RuleOutcome {
        if (snapshot.platform !in platforms) return RuleOutcome.NotApplicable
        return check(snapshot)
    }

    protected abstract fun check(s: DeviceSnapshot): RuleOutcome

    /** Helper: short-circuit to [RuleOutcome.NotApplicable] on a null input. */
    protected inline fun <T> requireObserved(value: T?, body: (T) -> RuleOutcome): RuleOutcome =
        if (value == null) RuleOutcome.NotApplicable else body(value)
}
