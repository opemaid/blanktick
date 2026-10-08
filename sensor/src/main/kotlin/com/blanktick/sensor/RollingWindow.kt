package com.blanktick.sensor

/**
 * A bounded, in-memory history of recent events.
 *
 * Correlation rules ask questions like "did this process delete shadow copies
 * in the last five seconds?" — which needs memory of the recent past, but not
 * an unbounded one. The window is capped two ways: by age (relative to the
 * newest event's own timestamp, never a wall clock) and by count. Whichever
 * bites first evicts the oldest events, so memory stays flat under a flood.
 *
 * Time is taken from the events themselves, so a rule reasoning over this window
 * behaves identically on a live stream and a replayed one.
 */
class RollingWindow(
    private val maxAgeMillis: Long = 30_000,
    private val maxEvents: Int = 4096
) {
    private val events = ArrayDeque<SensorEvent>()

    init {
        require(maxAgeMillis > 0) { "maxAgeMillis must be positive" }
        require(maxEvents > 0) { "maxEvents must be positive" }
    }

    /** Add an event and evict anything now out of bounds. Newest event drives eviction. */
    fun add(e: SensorEvent) {
        events.addLast(e)
        val newest = e.at
        while (events.isNotEmpty() && newest - events.first().at > maxAgeMillis) {
            events.removeFirst()
        }
        while (events.size > maxEvents) {
            events.removeFirst()
        }
    }

    /** Everything currently retained, oldest first. */
    fun snapshot(): List<SensorEvent> = events.toList()

    val size: Int get() = events.size

    /** Events whose timestamp falls within [ofMillis] before (and including) [endingAt]. */
    fun within(endingAt: Long, ofMillis: Long): List<SensorEvent> =
        events.filter { it.at in (endingAt - ofMillis)..endingAt }

    /** Retained events of one concrete type, oldest first. */
    inline fun <reified T : SensorEvent> ofType(): List<T> = snapshot().filterIsInstance<T>()

    /** The most recent process-start seen for [pid], if still in the window. */
    fun latestProcessStart(pid: Long): SensorEvent.ProcessStart? =
        events.lastOrNull { it is SensorEvent.ProcessStart && it.pid == pid } as? SensorEvent.ProcessStart
}
