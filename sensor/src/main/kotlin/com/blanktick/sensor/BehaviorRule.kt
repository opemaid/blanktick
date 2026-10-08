package com.blanktick.sensor

import com.blanktick.core.model.Category
import com.blanktick.core.model.Finding

/**
 * What the sensor would do about a detection, weakest to strongest.
 *
 * The rule decides intent; the provider layer carries it out. Modelling the
 * intent here — rather than reaching for a process handle inside a rule — keeps
 * the rules pure and testable, and keeps the one privileged, dangerous act
 * (killing a process) in one place that a user has consented to run elevated.
 */
enum class Response { OBSERVE, ALERT, SUSPEND, KILL }

/**
 * A firing: the human-readable [finding], what the sensor intends to do, and the
 * process it would do it to ([targetPid], null when the detection is not tied to
 * a single process — a DNS name has no owning process from the cache).
 */
data class Detection(val finding: Finding, val response: Response, val targetPid: Long? = null)

/**
 * One dynamic detection, evaluated against a live event and the recent past.
 *
 * Kept deliberately separate from the free tier's `core.rules.Rule`: that one is
 * a pure function of a *snapshot* and must stay that way for the scoring spec
 * and its golden fixtures. A [BehaviorRule] is a pure function of *an event plus
 * a bounded window* — a different shape, a different guarantee, its own `DYN-*`
 * id namespace, and no path by which it could change a free-tier score.
 *
 * ## Honesty carried in
 *
 * "Not observed" is not "clean." A rule that never fired means only that the
 * sensor did not see the behaviour while it was running — the dynamic analogue
 * of the snapshot engine's `NotApplicable`, and the sensor's coverage
 * ([com.blanktick.sensor.providers.ProviderStatus]) is reported alongside so
 * silence is never read as a pass.
 */
interface BehaviorRule {
    /** Stable id in the `DYN-<TOPIC>-NNN` namespace. */
    val id: String
    val category: Category

    /** Look at the latest event (already added to [w]) and decide. Empty means nothing to say. */
    fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection>
}
