package com.blanktick.sensor

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RollingWindowTest {

    private fun proc(at: Long, pid: Long, actor: Actor = Actor.UNKNOWN) =
        SensorEvent.ProcessStart(at = at, pid = pid, image = "p$pid.exe", actor = actor)

    @Test
    fun `evicts by age relative to the newest event`() {
        val w = RollingWindow(maxAgeMillis = 1_000, maxEvents = 100)
        w.add(proc(at = 0, pid = 1))
        w.add(proc(at = 500, pid = 2))
        w.add(proc(at = 2_000, pid = 3)) // now 0 and 500 are older than 1000ms

        assertEquals(1, w.size)
        assertEquals(3, (w.snapshot().single() as SensorEvent.ProcessStart).pid)
    }

    @Test
    fun `caps by count, dropping the oldest`() {
        val w = RollingWindow(maxAgeMillis = 1_000_000, maxEvents = 3)
        (1..5).forEach { w.add(proc(at = it.toLong(), pid = it.toLong())) }

        assertEquals(3, w.size)
        assertEquals(listOf(3L, 4L, 5L), w.snapshot().map { (it as SensorEvent.ProcessStart).pid })
    }

    @Test
    fun `within returns only events inside the trailing span`() {
        val w = RollingWindow(maxAgeMillis = 1_000_000, maxEvents = 100)
        listOf(1_000L, 3_000L, 7_000L, 8_000L).forEach { w.add(proc(at = it, pid = it)) }

        val recent = w.within(endingAt = 8_000, ofMillis = 2_000)
        assertEquals(listOf(7_000L, 8_000L), recent.map { it.at })
    }

    @Test
    fun `latestProcessStart returns the most recent for a pid, or null`() {
        val w = RollingWindow()
        w.add(proc(at = 1, pid = 42, actor = Actor.USER))
        w.add(proc(at = 2, pid = 42, actor = Actor.MCP_SERVER))

        assertEquals(Actor.MCP_SERVER, w.latestProcessStart(42)?.actor)
        assertNull(w.latestProcessStart(999))
    }

    @Test
    fun `ofType filters to one concrete event kind`() {
        val w = RollingWindow()
        w.add(proc(at = 1, pid = 1))
        w.add(SensorEvent.ShadowCopyDeletion(at = 2, pid = 2, image = "vssadmin.exe"))

        assertEquals(1, w.ofType<SensorEvent.ShadowCopyDeletion>().size)
        assertTrue(w.ofType<SensorEvent.HandleOpen>().isEmpty())
    }
}
