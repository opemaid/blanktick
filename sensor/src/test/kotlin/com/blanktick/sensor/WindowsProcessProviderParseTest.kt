package com.blanktick.sensor

import com.blanktick.sensor.providers.WindowsProcessProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class WindowsProcessProviderParseTest {

    private val provider = WindowsProcessProvider()

    @Test
    fun `parses a well-formed line into a process-start`() {
        val e = provider.parseLine("1712000000000\t2500\t100\texcel.exe\tpowershell.exe\tpowershell -enc AAA")
        requireNotNull(e)
        assertEquals(1712000000000L, e.at)
        assertEquals(2500L, e.pid)
        assertEquals(100L, e.parentPid)
        assertEquals("excel.exe", e.parentImage)
        assertEquals("powershell.exe", e.image)
        assertEquals("powershell -enc AAA", e.commandLine)
    }

    @Test
    fun `an empty command line is allowed`() {
        val e = provider.parseLine("1\t2\t3\texplorer.exe\tnotepad.exe\t")
        requireNotNull(e)
        assertEquals("", e.commandLine)
    }

    @Test
    fun `a known model runner is tagged as an agent`() {
        val e = provider.parseLine("1\t9\t1\t\tollama.exe\tollama serve")
        requireNotNull(e)
        assertEquals(Actor.AI_AGENT, e.actor)
    }

    @Test
    fun `malformed lines are rejected, not guessed`() {
        assertNull(provider.parseLine("garbage"))
        assertNull(provider.parseLine("notanumber\t2\t3\ta\tb\tc"))
        assertNull(provider.parseLine(""))
    }
}
