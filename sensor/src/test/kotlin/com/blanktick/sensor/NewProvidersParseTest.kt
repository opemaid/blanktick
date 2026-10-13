package com.blanktick.sensor

import com.blanktick.sensor.providers.ContentIntakeProvider
import com.blanktick.sensor.providers.FileActivityProvider
import com.blanktick.sensor.providers.HandleOpenProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Parser coverage for the three providers that feed the previously-unfed rules:
 * credential theft (lsass handle), ransomware (entropy writes + shadow delete),
 * and the AI content-intake proxy. The event-plus-window rules themselves are
 * already proven in DynamicRulesTest; these assert the line-to-event edge.
 */
class NewProvidersParseTest {

    private val handle = HandleOpenProvider()
    private val file = FileActivityProvider()
    private val intake = ContentIntakeProvider()

    @Test
    fun `handle-open line parses into an lsass access event`() {
        val e = handle.parseLine("1712000000000\t6164\tmimikatz.exe\tC:\\Windows\\System32\\lsass.exe\tPROCESS_VM_READ")
        requireNotNull(e)
        assertEquals(6164L, e.pid)
        assertEquals("mimikatz.exe", e.image)
        assertTrue(Images.isLsass(e.targetImage))
        assertEquals("PROCESS_VM_READ", e.access)
    }

    @Test
    fun `handle-open status and malformed lines are rejected`() {
        assertNull(handle.parseLine("#source=none"))
        assertNull(handle.parseLine("#elevated=true"))
        assertNull(handle.parseLine("1712000000000\t6164\tmimikatz.exe"))
        assertNull(handle.parseLine("notanumber\t6164\tx\tlsass.exe"))
    }

    @Test
    fun `file line parses into an encryption-shaped modify with unknown pid`() {
        val e = file.parseLine("FILE\t1712000000000\t-1\t\tC:\\Users\\me\\Documents\\a.locky\tENCRYPT_SUSPECTED\ttrue")
        requireNotNull(e)
        assertIs<SensorEvent.FileModify>(e)
        assertEquals(-1L, e.pid)
        assertEquals(FileOp.ENCRYPT_SUSPECTED, e.op)
        assertTrue(e.highEntropy)
    }

    @Test
    fun `vssdel line parses into a shadow-copy deletion keeping its pid`() {
        val e = file.parseLine("VSSDEL\t1712000000000\t7777\tvssadmin.exe\tvssadmin delete shadows /all /quiet")
        requireNotNull(e)
        assertIs<SensorEvent.ShadowCopyDeletion>(e)
        assertEquals(7777L, e.pid)
        assertEquals("vssadmin.exe", e.image)
    }

    @Test
    fun `file provider rejects status, unknown tags and bad ops`() {
        assertNull(file.parseLine("#source=fsw"))
        assertNull(file.parseLine("OTHER\t1\t2\tx"))
        assertNull(file.parseLine("FILE\t1712000000000\t-1\t\tpath\tNOT_AN_OP\ttrue"))
        assertNull(file.parseLine("FILE\t1712000000000"))
    }

    @Test
    fun `intake line parses into agent-tagged content intake`() {
        val e = intake.parseLine("1712000000000\t4242\tollama.exe\tnet:203.0.113.9:443")
        requireNotNull(e)
        assertEquals(4242L, e.pid)
        assertEquals("ollama.exe", e.image)
        assertEquals(Actor.AI_AGENT, e.actor)
        assertEquals("net:203.0.113.9:443", e.source)
    }

    @Test
    fun `intake status and malformed lines are rejected`() {
        assertNull(intake.parseLine("#elevated=false"))
        assertNull(intake.parseLine("1712000000000\t4242\tollama.exe"))
        assertNull(intake.parseLine("1712000000000\t4242\tollama.exe\t"))
    }
}
