package com.blanktick.sensor

import com.blanktick.sensor.rules.DefaultBehaviorRules

/**
 * Feeds each event to every rule and returns what fired, once.
 *
 * The engine owns the [RollingWindow] and adds the event to it *before* running
 * the rules, so a correlation rule can look back over a history that includes
 * the event it is reacting to.
 *
 * De-duplication: a live attack produces the same behaviour many times a second
 * (thousands of encrypted files, a beacon every minute). Firing on every one
 * would bury the operator. The engine suppresses a repeat of the same
 * `(ruleId, subjectId)` for [suppressMillis], keyed off event time so it behaves
 * the same on a replayed stream.
 */
class BehaviorEngine(
    private val rules: List<BehaviorRule> = DefaultBehaviorRules.ALL,
    windowMillis: Long = 30_000,
    windowMaxEvents: Int = 4096,
    private val suppressMillis: Long = 60_000
) {
    private val window = RollingWindow(windowMillis, windowMaxEvents)
    private val lastFired = HashMap<String, Long>()

    /**
     * Observe one event; return the detections that are new (not currently
     * suppressed). Synchronised because several providers feed one engine from
     * their own reader threads.
     */
    @Synchronized
    fun observe(e: SensorEvent): List<Detection> {
        window.add(e)
        val fresh = ArrayList<Detection>()
        for (rule in rules) {
            for (d in rule.onEvent(e, window)) {
                val key = d.finding.ruleId + "|" + d.finding.subjectId
                val prev = lastFired[key]
                if (prev != null && e.at - prev < suppressMillis) continue
                lastFired[key] = e.at
                fresh += d
            }
        }
        return fresh
    }

    /** Convenience for replay and tests: observe a whole stream, collect everything fresh. */
    fun observeAll(stream: Iterable<SensorEvent>): List<Detection> =
        stream.flatMap { observe(it) }
}
