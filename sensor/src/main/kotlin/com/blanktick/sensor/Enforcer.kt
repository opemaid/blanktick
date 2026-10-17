package com.blanktick.sensor

/** What happened when the sensor tried to act on a detection. */
enum class EnforcementOutcome {
    /** The process was stopped. */
    STOPPED,
    /** The detection is advisory (an ALERT/OBSERVE); nothing to enforce. */
    ADVISORY,
    /** No single process to act on (e.g. a DNS-name detection). */
    NO_TARGET,
    /** Refused on purpose: a system process, or Blanktick itself. */
    PROTECTED,
    /** The process was already gone, or could not be stopped (rights?). */
    FAILED
}

data class EnforcementResult(val outcome: EnforcementOutcome, val detail: String)

/**
 * Carries out a detection's intended response.
 *
 * Native-free: it stops a process through the JVM's own [ProcessHandle], which
 * opens no socket, so the gate still holds. It is the one place that does
 * something irreversible, which is why it is small, guarded, and only ever
 * reached when the user has turned enforcement on.
 *
 * ## An honest limit
 *
 * Both [Response.KILL] and [Response.SUSPEND] are carried out here as a
 * **terminate**. A true suspend — freezing a process for forensics rather than
 * killing it — needs native calls Blanktick does not make yet. So under
 * enforcement a flagged process is stopped, not frozen, and the UI says
 * "stopped" rather than implying a suspend that did not happen.
 */
object Enforcer {

    /**
     * Windows images that are kernel-critical: terminating any of them bugchecks
     * the machine (BSOD). Lower-cased leaf names.
     *
     * Matched by name regardless of path, which is conservative by design: a
     * process masquerading as `csrss.exe` in a user folder is refused too (it is
     * still reported — it is just never worth risking a kernel panic to kill one
     * automatically). Deliberately NOT here: `cmd.exe`, `powershell.exe`,
     * `wscript.exe`, `svchost.exe` — those are safe to terminate and are exactly
     * the living-off-the-land targets the DYN rules detect.
     */
    private val criticalImages = setOf(
        "system", "registry", "memory compression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsaiso.exe", "fontdrvhost.exe"
    )

    /**
     * Refuse to terminate a kernel-critical image — judged from the process as it
     * is NOW, which also closes the PID-reuse window (a recycled pid is evaluated
     * as whatever currently holds it). A process whose image cannot be read is
     * refused too: terminating blind is the exact irreversible mistake this guard
     * exists to prevent. (pid <= 4 and Blanktick's own pid are refused earlier,
     * before a handle is even resolved.)
     */
    private fun isProtected(handle: ProcessHandle): Boolean {
        if (handle.pid() <= 4L || handle.pid() == ProcessHandle.current().pid()) return true
        val command = handle.info().command().orElse(null) ?: return true
        return java.io.File(command).name.lowercase() in criticalImages
    }

    fun enforce(d: Detection): EnforcementResult {
        if (d.response != Response.KILL && d.response != Response.SUSPEND) {
            return EnforcementResult(EnforcementOutcome.ADVISORY, "advisory (${d.response}); investigate")
        }
        val pid = d.targetPid
            ?: return EnforcementResult(EnforcementOutcome.NO_TARGET, "no single process to stop")
        // Cheap, handle-free refusals first, so System (pid <= 4) and Blanktick
        // itself read as PROTECTED rather than being mislabelled "already gone"
        // when no handle can be opened for them.
        if (pid <= 4L || pid == ProcessHandle.current().pid()) {
            return EnforcementResult(EnforcementOutcome.PROTECTED, "refused to stop protected process $pid")
        }
        val handle = ProcessHandle.of(pid).orElse(null)
            ?: return EnforcementResult(EnforcementOutcome.FAILED, "process $pid is already gone")
        // Then the image-based refusals, on the live handle, so the decision is
        // made about the process that actually holds the pid right now.
        if (isProtected(handle)) {
            return EnforcementResult(EnforcementOutcome.PROTECTED, "refused to stop protected process $pid")
        }
        val ok = handle.destroyForcibly()
        return if (ok) {
            EnforcementResult(EnforcementOutcome.STOPPED, "stopped process $pid")
        } else {
            EnforcementResult(EnforcementOutcome.FAILED, "could not stop $pid (insufficient rights?)")
        }
    }
}
