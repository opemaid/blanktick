package com.blanktick.sensor

import com.blanktick.sensor.providers.ReplayProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BehaviorEngineTest {

    private fun shadowDelete(at: Long, pid: Long = 700) =
        SensorEvent.ShadowCopyDeletion(at = at, pid = pid, image = "vssadmin.exe", commandLine = "delete shadows")

    @Test
    fun `the same detection is suppressed within the window, then allowed again`() {
        val engine = BehaviorEngine(suppressMillis = 60_000)
        val detections = engine.observeAll(
            listOf(
                shadowDelete(at = 1_000),   // fires
                shadowDelete(at = 2_000),   // suppressed (1s later, same pid)
                shadowDelete(at = 62_000)   // 61s later — allowed again
            )
        )
        assertEquals(2, detections.size, "one suppressed, two allowed")
        assertTrue(detections.all { it.finding.ruleId == "DYN-RANSOM-001" })
    }

    @Test
    fun `distinct subjects are not suppressed against each other`() {
        val engine = BehaviorEngine(suppressMillis = 60_000)
        val detections = engine.observeAll(
            listOf(shadowDelete(at = 1_000, pid = 700), shadowDelete(at = 1_100, pid = 900))
        )
        assertEquals(2, detections.size, "different processes are different subjects")
    }

    @Test
    fun `a replayed incident drives the engine identically to a live stream`() {
        val incident = listOf(
            SensorEvent.ProcessStart(
                at = 1_000, pid = 200, image = "powershell.exe",
                parentPid = 100, parentImage = "excel.exe", commandLine = "powershell -w hidden"
            )
        )
        val provider = ReplayProvider(incident)
        val engine = BehaviorEngine()
        val out = mutableListOf<Detection>()

        provider.start { e -> out += engine.observe(e) }

        assertEquals(listOf("DYN-OFFICE-001"), out.map { it.finding.ruleId })
        // "Not observed" is not "clean": a replay is not a running watch.
        assertFalse(provider.status().running)
        assertTrue(provider.status().note.contains("replay"))
    }
}
