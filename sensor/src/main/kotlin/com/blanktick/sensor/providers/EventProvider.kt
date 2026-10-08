package com.blanktick.sensor.providers

import com.blanktick.sensor.SensorEvent

/** The privilege a provider needs. The free tier never asks for more than [USER]. */
enum class Privilege { USER, ADMIN, PPL }

/**
 * Whether a provider is actually watching, so that silence can be told apart
 * from safety. If a provider is not [running], the behaviours it would have seen
 * are *unobserved*, never *clean* — reported to the operator as a gap, the
 * dynamic analogue of the snapshot engine's `NotApplicable`.
 */
data class ProviderStatus(
    val running: Boolean,
    /** Epoch millis this provider started, or null if it never did. */
    val since: Long?,
    val note: String = ""
)

/**
 * A source of normalised events.
 *
 * This is the seam between the pure engine and the operating system. The live
 * Windows taps — an ETW `Kernel-Process` session, the AMSI provider, WMI
 * watchers — implement this behind elevation and native interop, and are built
 * and verified on real hardware (they cannot be unit-tested off it). The engine
 * and every [com.blanktick.sensor.BehaviorRule] depend only on this interface,
 * so their correctness is settled here, in the abstract, before any of that.
 *
 * A provider MUST stay inside the no-network gate: it reads local ETW/AMSI/file
 * state and opens no socket. Reading the machine's own network *events* via ETW
 * is not "using the network" — nothing is sent.
 */
interface EventProvider {
    val name: String
    val privilege: Privilege

    /** Begin delivering events to [sink]. Returns when the subscription is live. */
    fun start(sink: (SensorEvent) -> Unit)

    /** Stop delivering and release the subscription. */
    fun stop()

    fun status(): ProviderStatus
}

/**
 * A provider that replays a fixed list of events, in order.
 *
 * Fully implemented and offline: it is what the tests and the design harness run
 * the engine against, and it is how a captured incident can be re-examined
 * later. The live OS providers produce the same [SensorEvent] shape, so a rule
 * cannot tell the difference.
 */
class ReplayProvider(private val events: List<SensorEvent>) : EventProvider {
    override val name: String = "replay"
    override val privilege: Privilege = Privilege.USER
    private var started: Long? = null

    override fun start(sink: (SensorEvent) -> Unit) {
        started = events.firstOrNull()?.at
        events.forEach(sink)
    }

    override fun stop() { /* nothing to release */ }

    override fun status(): ProviderStatus =
        ProviderStatus(running = false, since = started, note = "replay of ${events.size} recorded events")
}
