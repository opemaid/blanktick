package com.blanktick.sensor

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NetworkDnsRulesTest {

    private fun fired(vararg events: SensorEvent): List<String> =
        BehaviorEngine().observeAll(events.toList()).map { it.finding.ruleId }

    private fun connect(at: Long, addr: String = "203.0.113.7", port: Int = 443) =
        SensorEvent.NetworkConnect(at = at, pid = 555, image = "rat.exe", remoteAddress = addr, remotePort = port)

    // --------------------------------------------------------------- beaconing

    @Test
    fun `evenly spaced callbacks to one host fire DYN-C2-001 once`() {
        val beacons = (0 until 5).map { connect(at = 1_000 + it * 2_000L) }
        val ids = BehaviorEngine().observeAll(beacons).map { it.finding.ruleId }
        assertEquals(listOf("DYN-C2-001"), ids, "should fire once on crossing the threshold, then suppress")
    }

    @Test
    fun `irregular connections do not fire`() {
        val jittery = listOf(0L, 1_000L, 5_000L, 5_200L, 5_300L).map { connect(at = it) }
        assertTrue(BehaviorEngine().observeAll(jittery).isEmpty(), "high jitter is not a beacon")
    }

    @Test
    fun `a couple of connections are not enough to call it a beacon`() {
        val few = listOf(0L, 2_000L, 4_000L).map { connect(at = it) }
        assertTrue(BehaviorEngine().observeAll(few).isEmpty())
    }

    // ------------------------------------------------------------ dns tunneling

    @Test
    fun `an over-long DNS label fires DYN-DNS-001`() {
        val ids = fired(
            SensorEvent.DnsQuery(
                at = 1_000, pid = -1, image = "",
                queryName = "aVeryLongBase32EncodedLabelThatCarriesData0123456789ABCDEF.evil.example"
            )
        )
        assertEquals(listOf("DYN-DNS-001"), ids)
    }

    @Test
    fun `an ordinary domain is not flagged`() {
        assertTrue(
            fired(SensorEvent.DnsQuery(at = 1_000, pid = -1, image = "", queryName = "www.google.com")).isEmpty()
        )
    }
}
