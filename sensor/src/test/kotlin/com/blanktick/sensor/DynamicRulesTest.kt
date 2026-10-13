package com.blanktick.sensor

import com.blanktick.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Each dynamic rule, exercised through the engine against a synthetic stream —
 * the same shape the live ETW/AMSI providers will produce, so these hold whether
 * the events came from a replay or a machine.
 */
class DynamicRulesTest {

    private fun fired(vararg events: SensorEvent): List<String> =
        BehaviorEngine().observeAll(events.toList()).map { it.finding.ruleId }

    // ---------------------------------------------------------------- office

    @Test
    fun `office spawning a shell fires DYN-OFFICE-001 and intends to kill`() {
        val detections = BehaviorEngine().observeAll(
            listOf(
                SensorEvent.ProcessStart(
                    at = 1_000, pid = 200, image = "powershell.exe",
                    parentPid = 100, parentImage = "winword.exe",
                    commandLine = "powershell -enc ..."
                )
            )
        )
        assertEquals(listOf("DYN-OFFICE-001"), detections.map { it.finding.ruleId })
        assertEquals(Response.KILL, detections.single().response)
        assertEquals(Severity.HIGH, detections.single().finding.severity)
    }

    @Test
    fun `powershell from explorer is not flagged`() {
        val ids = fired(
            SensorEvent.ProcessStart(
                at = 1_000, pid = 200, image = "powershell.exe",
                parentPid = 100, parentImage = "explorer.exe"
            )
        )
        assertTrue(ids.isEmpty(), "a user opening PowerShell is normal; fired: $ids")
    }

    // ------------------------------------------------------------ credentials

    @Test
    fun `a non-system process opening lsass fires DYN-CRED-001`() {
        val ids = fired(
            SensorEvent.HandleOpen(
                at = 1_000, pid = 500, image = "rundll32.exe",
                targetImage = "lsass.exe", access = "PROCESS_VM_READ"
            )
        )
        assertEquals(listOf("DYN-CRED-001"), ids)
    }

    @Test
    fun `a system component reading lsass is not flagged`() {
        val ids = fired(
            SensorEvent.HandleOpen(
                at = 1_000, pid = 8, image = "wininit.exe",
                targetImage = "lsass.exe", access = "PROCESS_VM_READ"
            )
        )
        assertTrue(ids.isEmpty(), "fired on a legitimate reader: $ids")
    }

    @Test
    fun `svchost querying lsass without VM_READ is not flagged`() {
        // The real false positive a live elevated run produced: svchost opens
        // lsass with a query-only mask (PROCESS_QUERY_LIMITED_INFORMATION, 0x1000),
        // no PROCESS_VM_READ bit. It must not fire.
        val ids = fired(
            SensorEvent.HandleOpen(
                at = 1_000, pid = 1816, image = "svchost.exe",
                targetImage = "C:\\Windows\\System32\\lsass.exe", access = "0x1000"
            )
        )
        assertTrue(ids.isEmpty(), "fired on a query-only svchost->lsass open: $ids")
    }

    @Test
    fun `a mimikatz-style VM_READ mask on lsass fires DYN-CRED-001 and intends to suspend`() {
        val detections = BehaviorEngine().observeAll(
            listOf(
                SensorEvent.HandleOpen(
                    at = 1_000, pid = 6164, image = "mimikatz.exe",
                    targetImage = "C:\\Windows\\System32\\lsass.exe", access = "0x1410"
                )
            )
        )
        assertEquals(listOf("DYN-CRED-001"), detections.map { it.finding.ruleId })
        assertEquals(Response.SUSPEND, detections.single().response)
        assertEquals(Severity.CRITICAL, detections.single().finding.severity)
    }

    @Test
    fun `a Defender ASR lsass hit fires even without a numeric mask`() {
        val ids = fired(
            SensorEvent.HandleOpen(
                at = 1_000, pid = 4242, image = "evil.exe",
                targetImage = "C:\\Windows\\System32\\lsass.exe", access = "ASR"
            )
        )
        assertEquals(listOf("DYN-CRED-001"), ids)
    }

    @Test
    fun `an lsass open with an unknown access does not fire`() {
        val ids = fired(
            SensorEvent.HandleOpen(
                at = 1_000, pid = 500, image = "unknown.exe",
                targetImage = "C:\\Windows\\System32\\lsass.exe", access = ""
            )
        )
        assertTrue(ids.isEmpty(), "fired without evidence of a memory-read right: $ids")
    }

    // ------------------------------------------------------------- ransomware

    @Test
    fun `deleting shadow copies fires DYN-RANSOM-001`() {
        val ids = fired(
            SensorEvent.ShadowCopyDeletion(
                at = 1_000, pid = 700, image = "vssadmin.exe",
                commandLine = "vssadmin delete shadows /all /quiet"
            )
        )
        assertEquals(listOf("DYN-RANSOM-001"), ids)
    }

    @Test
    fun `a burst of high-entropy writes fires DYN-RANSOM-001`() {
        val stream = (0 until 12).map { i ->
            SensorEvent.FileModify(
                at = 1_000 + i.toLong(), pid = 700, image = "evil.exe",
                path = "C:\\Users\\me\\doc$i.docx", op = FileOp.WRITE, highEntropy = true
            )
        }
        val ids = BehaviorEngine().observeAll(stream).map { it.finding.ruleId }
        assertEquals(listOf("DYN-RANSOM-001"), ids, "should fire exactly once, on crossing the threshold")
    }

    @Test
    fun `a few high-entropy writes do not fire`() {
        val stream = (0 until 5).map { i ->
            SensorEvent.FileModify(
                at = 1_000 + i.toLong(), pid = 700, image = "7zip.exe",
                path = "C:\\tmp\\a$i.zip", op = FileOp.WRITE, highEntropy = true
            )
        }
        assertTrue(BehaviorEngine().observeAll(stream).isEmpty())
    }

    // ---------------------------------------------------------- the AI layer

    @Test
    fun `an MCP server spawning a shell fires DYN-AI-001`() {
        val ids = fired(
            SensorEvent.ProcessStart(at = 1_000, pid = 300, image = "node.exe", actor = Actor.MCP_SERVER),
            SensorEvent.ProcessStart(
                at = 1_500, pid = 400, image = "cmd.exe",
                parentPid = 300, parentImage = "node.exe", commandLine = "cmd /c whoami"
            )
        )
        assertEquals(listOf("DYN-AI-001"), ids)
    }

    @Test
    fun `an agent writing a file right after reading a web page fires DYN-AI-003`() {
        val ids = fired(
            SensorEvent.ContentIntake(
                at = 1_000, pid = 300, image = "node.exe",
                actor = Actor.AI_AGENT, source = "https://evil.example/post"
            ),
            SensorEvent.FileModify(
                at = 3_000, pid = 300, image = "node.exe", actor = Actor.AI_AGENT,
                path = "C:\\Users\\me\\.ssh\\authorized_keys", op = FileOp.WRITE
            )
        )
        assertEquals(listOf("DYN-AI-003"), ids)
    }

    @Test
    fun `an agent acting with no recent intake does not fire DYN-AI-003`() {
        val ids = fired(
            SensorEvent.FileModify(
                at = 3_000, pid = 300, image = "node.exe", actor = Actor.AI_AGENT,
                path = "C:\\Users\\me\\notes.txt", op = FileOp.WRITE
            )
        )
        assertTrue(ids.isEmpty(), "an agent writing a file on its own is normal; fired: $ids")
    }
}
