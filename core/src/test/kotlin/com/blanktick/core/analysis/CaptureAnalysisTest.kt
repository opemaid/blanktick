package com.blanktick.core.analysis

import com.blanktick.core.filters.SortedHashSet64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CaptureAnalysisTest {

    // A small Wireshark "Export Packet Dissections -> As CSV" sample. The last
    // row has a comma inside a quoted Info field, which the splitter must respect.
    private val csv = """
        "No.","Time","Source","Destination","Protocol","Length","Info"
        "1","0.000","192.168.1.5","8.8.8.8","DNS","74","Standard query 0x1a2b A evil.example"
        "2","0.010","192.168.1.5","93.184.216.34","HTTP","320","GET / HTTP/1.1"
        "3","0.020","192.168.1.5","192.168.1.1","TCP","60","443 > 55000 [ACK]"
        "4","0.030","192.168.1.5","8.8.8.8","TCP","60","54321 > 443 [SYN, ECN]"
    """.trimIndent()

    @Test
    fun `parses the wireshark csv columns`() {
        val packets = CaptureAnalysis.parse(csv)
        assertEquals(4, packets.size)
        assertEquals("8.8.8.8", packets[0].destination)
        assertEquals("DNS", packets[0].protocol)
        // The quoted comma in row 4's Info must not have split the row.
        assertTrue(packets[3].info.contains("SYN, ECN"), "quoted comma split the CSV row")
    }

    @Test
    fun `a header without the needed columns yields nothing rather than guessing`() {
        assertTrue(CaptureAnalysis.parse("\"a\",\"b\"\n\"1\",\"2\"").isEmpty())
    }

    @Test
    fun `pulls out queried domains and external destinations`() {
        val r = CaptureAnalysis.analyze(CaptureAnalysis.parse(csv))
        assertEquals(listOf("evil.example"), r.domains)
        // 192.168.1.1 is local and excluded; the two public IPs remain.
        assertEquals(listOf("8.8.8.8", "93.184.216.34"), r.externalDestinations)
    }

    @Test
    fun `flags cleartext protocols`() {
        val r = CaptureAnalysis.analyze(CaptureAnalysis.parse(csv))
        assertTrue(r.findings.any { it.id == "CAP-PLAINTEXT" }, "HTTP should raise a cleartext finding")
    }

    @Test
    fun `cross-references queried names against the offline blocklist`() {
        val blocklist = SortedHashSet64.build(listOf("evil.example"))
        val r = CaptureAnalysis.analyze(CaptureAnalysis.parse(csv), blocklist)
        val hit = r.findings.singleOrNull { it.id == "CAP-DNS-BLOCK" }
        assertTrue(hit != null, "a blocklisted domain in the capture was not flagged")
        assertTrue(hit.detail.contains("evil.example"))
        assertEquals("HIGH", hit.severity)
    }

    @Test
    fun `no blocklist means no blocklist finding, not a crash`() {
        val r = CaptureAnalysis.analyze(CaptureAnalysis.parse(csv), blocklist = null)
        assertFalse(r.findings.any { it.id == "CAP-DNS-BLOCK" })
    }

    @Test
    fun `classifies addresses as external or local`() {
        assertTrue(CaptureAnalysis.isExternal("8.8.8.8"))
        assertTrue(CaptureAnalysis.isExternal("93.184.216.34"))
        assertFalse(CaptureAnalysis.isExternal("192.168.1.1"))
        assertFalse(CaptureAnalysis.isExternal("10.0.0.5"))
        assertFalse(CaptureAnalysis.isExternal("172.16.4.4"))
        assertFalse(CaptureAnalysis.isExternal("127.0.0.1"))
        assertFalse(CaptureAnalysis.isExternal("224.0.0.251"))
        assertFalse(CaptureAnalysis.isExternal("::1"))
    }
}
