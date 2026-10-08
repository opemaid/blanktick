package com.blanktick.sensor.providers

import com.blanktick.sensor.SensorEvent
import java.io.File
import java.nio.file.Files

/**
 * Shared machinery for a provider whose events come from a bundled PowerShell
 * script that prints one tab-separated line per event.
 *
 * It runs the script, reads its output on a daemon thread, notes an
 * `#elevated=...` status line if the script emits one, and hands every other
 * line to the subclass's [parse]. It spawns a child process and reads its output
 * — no socket — so every provider built on it stays inside the no-network gate.
 */
abstract class ScriptTapProvider(
    private val scriptResource: String,
    final override val name: String,
    final override val privilege: Privilege,
    private val statusNote: String
) : EventProvider {

    @Volatile private var process: Process? = null
    @Volatile private var reader: Thread? = null
    @Volatile private var startedAt: Long? = null
    @Volatile private var scriptFile: File? = null

    /** Whether the tap reported itself running elevated, once it has said so. */
    @Volatile var reportedElevated: Boolean? = null
        private set

    /** Turn one output line into an event, or null if it is not one. */
    protected abstract fun parse(line: String): SensorEvent?

    final override fun start(sink: (SensorEvent) -> Unit) {
        if (process != null) return

        val script = javaClass.getResourceAsStream(scriptResource)
            ?.bufferedReader()?.readText()
            ?: error("bundled tap $scriptResource is missing")
        val tmp = Files.createTempFile("blanktick-sensor-", ".ps1").toFile()
        tmp.writeText(script)
        scriptFile = tmp

        val p = ProcessBuilder(
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp.absolutePath
        ).redirectErrorStream(false).start()
        process = p
        startedAt = System.currentTimeMillis()

        val t = Thread({
            p.inputStream.bufferedReader().forEachLine { line ->
                if (line.startsWith("#elevated=")) {
                    reportedElevated = line.substringAfter('=').trim() == "true"
                } else {
                    parse(line)?.let(sink)
                }
            }
        }, "blanktick-sensor-reader")
        t.isDaemon = true
        t.start()
        reader = t
    }

    final override fun stop() {
        // Forcible: a polling PowerShell loop ignores a gentle terminate, and an
        // orphaned tap must never outlive the app that started it.
        process?.destroyForcibly()
        process = null
        reader?.interrupt()
        reader = null
        scriptFile?.delete()
        scriptFile = null
    }

    final override fun status(): ProviderStatus =
        ProviderStatus(running = process?.isAlive == true, since = startedAt, note = statusNote)
}
