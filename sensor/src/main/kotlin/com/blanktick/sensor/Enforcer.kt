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

    /** Never touch these: 0 = System Idle, 4 = System, and Blanktick's own process. */
    private fun isProtected(pid: Long): Boolean =
        pid <= 4L || pid == ProcessHandle.current().pid()

    fun enforce(d: Detection): EnforcementResult {
        if (d.response != Response.KILL && d.response != Response.SUSPEND) {
            return EnforcementResult(EnforcementOutcome.ADVISORY, "advisory (${d.response}); investigate")
        }
        val pid = d.targetPid
            ?: return EnforcementResult(EnforcementOutcome.NO_TARGET, "no single process to stop")
        if (isProtected(pid)) {
            return EnforcementResult(EnforcementOutcome.PROTECTED, "refused to stop protected process $pid")
        }
        val handle = ProcessHandle.of(pid).orElse(null)
            ?: return EnforcementResult(EnforcementOutcome.FAILED, "process $pid is already gone")
        val ok = handle.destroyForcibly()
        return if (ok) {
            EnforcementResult(EnforcementOutcome.STOPPED, "stopped process $pid")
        } else {
            EnforcementResult(EnforcementOutcome.FAILED, "could not stop $pid (insufficient rights?)")
        }
    }
}
