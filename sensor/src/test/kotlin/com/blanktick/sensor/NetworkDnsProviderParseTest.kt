package com.blanktick.sensor

import com.blanktick.sensor.providers.DnsProvider
import com.blanktick.sensor.providers.NetworkProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class NetworkDnsProviderParseTest {

    private val net = NetworkProvider()
    private val dns = DnsProvider()

    @Test
    fun `network line parses into a connection`() {
        val e = net.parseLine("1712000000000\t4321\tchrome.exe\t203.0.113.9\t443\tTCP")
        requireNotNull(e)
        assertEquals(4321L, e.pid)
        assertEquals("chrome.exe", e.image)
        assertEquals("203.0.113.9", e.remoteAddress)
        assertEquals(443, e.remotePort)
        assertEquals("TCP", e.protocol)
    }

    @Test
    fun `network line with a non-numeric port is rejected`() {
        assertNull(net.parseLine("1712000000000\t4321\tchrome.exe\t203.0.113.9\tnotaport\tTCP"))
        assertNull(net.parseLine("garbage"))
    }

    @Test
    fun `dns line parses into a query with no attributed process`() {
        val e = dns.parseLine("1712000000000\tlong.name.example.com")
        requireNotNull(e)
        assertEquals(-1L, e.pid)
        assertEquals("long.name.example.com", e.queryName)
    }

    @Test
    fun `dns line without a name is rejected`() {
        assertNull(dns.parseLine("1712000000000"))
        assertNull(dns.parseLine("1712000000000\t"))
    }
}
