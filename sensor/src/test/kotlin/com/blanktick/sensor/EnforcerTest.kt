package com.blanktick.sensor

import com.blanktick.core.model.Category
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class EnforcerTest {

    private fun detection(response: Response, targetPid: Long?): Detection = Detection(
        Finding(
            ruleId = "DYN-TEST-001", category = Category.DEVICE_INTEGRITY, severity = Severity.HIGH,
            title = "test", detail = "test", remediation = "test", subjectId = "test"
        ),
        response, targetPid
    )

    @Test
    fun `an advisory detection is not enforced`() {
        assertEquals(EnforcementOutcome.ADVISORY, Enforcer.enforce(detection(Response.ALERT, 1234L)).outcome)
    }

    @Test
    fun `a detection with no target process cannot be enforced`() {
        assertEquals(EnforcementOutcome.NO_TARGET, Enforcer.enforce(detection(Response.KILL, null)).outcome)
    }

    @Test
    fun `system processes and Blanktick itself are protected`() {
        assertEquals(EnforcementOutcome.PROTECTED, Enforcer.enforce(detection(Response.KILL, 4L)).outcome)
        val self = ProcessHandle.current().pid()
        assertEquals(EnforcementOutcome.PROTECTED, Enforcer.enforce(detection(Response.KILL, self)).outcome)
    }

    @Test
    fun `a flagged process is actually stopped`() {
        val cmd = if (System.getProperty("os.name").startsWith("Windows"))
            listOf("cmd", "/c", "timeout /t 30 /nobreak")
        else
            listOf("sh", "-c", "sleep 30")
        val victim = ProcessBuilder(cmd).start()
        try {
            val result = Enforcer.enforce(detection(Response.KILL, victim.pid()))
            assertEquals(EnforcementOutcome.STOPPED, result.outcome, result.detail)
            victim.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
            assertFalse(victim.isAlive, "the victim process should be gone")
        } finally {
            victim.destroyForcibly()
        }
    }
}
