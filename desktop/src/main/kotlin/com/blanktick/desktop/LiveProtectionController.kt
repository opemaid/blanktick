package com.blanktick.desktop

import com.blanktick.sensor.BehaviorEngine
import com.blanktick.sensor.Detection
import com.blanktick.sensor.EnforcementResult
import com.blanktick.sensor.Enforcer
import com.blanktick.sensor.SensorEvent
import com.blanktick.sensor.WindowsElevation
import com.blanktick.sensor.providers.DnsProvider
import com.blanktick.sensor.providers.EventProvider
import com.blanktick.sensor.providers.NetworkProvider
import com.blanktick.sensor.providers.WindowsProcessProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** How many of each kind of event the sensor has observed since it started. */
data class LiveCounts(val processes: Int = 0, val connections: Int = 0, val dns: Int = 0)

/** A detection plus what enforcement did about it, if enforcement was on. */
data class LiveDetection(val detection: Detection, val enforcement: EnforcementResult?)

/**
 * Bridges the Pro sensor ([com.blanktick.sensor]) to the desktop UI.
 *
 * It owns a [BehaviorEngine] and the three taps, starts them on their own
 * threads (the providers already spawn their own), and republishes detections
 * and counts as StateFlows the [com.blanktick.desktop.ui.LiveProtectionScreen]
 * observes.
 *
 * Honest about what it is: the sensor **detects and warns**. The [Detection]'s
 * [com.blanktick.sensor.Response] (suspend/kill) is the action it *would* take;
 * enforcement is not wired yet, and the screen says so rather than implying a
 * live process was stopped.
 */
class LiveProtectionController {

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    /** Null until known; the sensor reports it once started. */
    private val _elevated = MutableStateFlow<Boolean?>(null)
    val elevated: StateFlow<Boolean?> = _elevated.asStateFlow()

    private val _providerName = MutableStateFlow("")
    val providerName: StateFlow<String> = _providerName.asStateFlow()

    private val _counts = MutableStateFlow(LiveCounts())
    val counts: StateFlow<LiveCounts> = _counts.asStateFlow()

    private val _detections = MutableStateFlow<List<LiveDetection>>(emptyList())
    val detections: StateFlow<List<LiveDetection>> = _detections.asStateFlow()

    /**
     * Whether the sensor may stop a flagged process, not just warn. Off by
     * default and the user's explicit choice: acting on a heuristic is
     * destructive, so it is never the default.
     */
    private val _enforce = MutableStateFlow(false)
    val enforce: StateFlow<Boolean> = _enforce.asStateFlow()

    fun setEnforce(on: Boolean) { _enforce.value = on }

    @Volatile private var engine: BehaviorEngine? = null
    @Volatile private var providers: List<EventProvider> = emptyList()

    @Synchronized
    fun start() {
        if (_running.value) return
        _running.value = true

        // The elevation probe and each provider launch spawn a child process, so
        // do the startup off whatever thread called this (the UI thread).
        Thread({
            val admin = WindowsElevation.isAdmin()
            _elevated.value = admin

            val e = BehaviorEngine(windowMillis = 600_000, windowMaxEvents = 8192)
            val processTap = if (admin) WindowsProcessProvider.etw() else WindowsProcessProvider.poll()
            val taps = listOf(processTap, NetworkProvider(), DnsProvider())
            _providerName.value = processTap.name

            val sink: (SensorEvent) -> Unit = { ev ->
                when (ev) {
                    is SensorEvent.ProcessStart -> _counts.update { it.copy(processes = it.processes + 1) }
                    is SensorEvent.NetworkConnect -> _counts.update { it.copy(connections = it.connections + 1) }
                    is SensorEvent.DnsQuery -> _counts.update { it.copy(dns = it.dns + 1) }
                    else -> {}
                }
                val fresh = engine?.observe(ev).orEmpty()
                if (fresh.isNotEmpty()) {
                    val wrapped = fresh.asReversed().map { d ->
                        val outcome = if (_enforce.value) Enforcer.enforce(d) else null
                        LiveDetection(d, outcome)
                    }
                    // Newest first, bounded so a long watch cannot grow without limit.
                    _detections.update { (wrapped + it).take(200) }
                }
            }

            engine = e
            providers = taps
            taps.forEach { it.start(sink) }
        }, "blanktick-live-start").apply { isDaemon = true }.start()
    }

    @Synchronized
    fun stop() {
        // stop() on each provider calls Process.destroy(); the providers'
        // ScriptTapProvider uses destroyForcibly under the hood so the child
        // PowerShell taps cannot outlive the app.
        providers.forEach { it.stop() }
        providers = emptyList()
        engine = null
        _running.value = false
    }
}
