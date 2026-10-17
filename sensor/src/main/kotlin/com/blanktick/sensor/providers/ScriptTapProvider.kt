package com.blanktick.sensor.providers

import com.blanktick.sensor.SensorEvent
import com.blanktick.sensor.TrustedPowerShell
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
    @Volatile private var scriptDir: File? = null

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

        // Resolve PowerShell to its absolute System32 path, never the PATH:
        // this tap may run elevated, so a planted powershell.exe would run as
        // administrator. Refuse to start rather than fall back to the PATH.
        val psExe = TrustedPowerShell.path()
            ?: error("no trusted powershell.exe found; refusing to launch the $name tap via PATH")

        // Write the script into a fresh, randomly-named DIRECTORY rather than
        // straight into the shared temp namespace, mirroring Shell.powershell:
        // it removes the predictable path an unprivileged process would need to
        // swap the .ps1 contents out from under an elevated run (TOCTOU → LPE).
        val dir = Files.createTempDirectory("blanktick-sensor-").toFile().apply { deleteOnExit() }
        val tmp = File.createTempFile("tap-", ".ps1", dir).apply { deleteOnExit() }
        tmp.writeText(script)
        scriptDir = dir
        scriptFile = tmp

        // redirectErrorStream(true): the reader drains ONE stream. With stderr
        // separate and unread, a chatty tap script fills the stderr pipe buffer,
        // the child blocks forever on write, and live protection silently stops
        // emitting. Merging stderr into stdout drains it; a stderr line that is
        // not an event simply fails parse() and is ignored.
        val p = ProcessBuilder(
            psExe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp.absolutePath
        ).redirectErrorStream(true).start()
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
        // Remove the per-run directory too, not just the file inside it.
        scriptDir?.delete()
        scriptDir = null
    }

    final override fun status(): ProviderStatus =
        ProviderStatus(running = process?.isAlive == true, since = startedAt, note = statusNote)
}
