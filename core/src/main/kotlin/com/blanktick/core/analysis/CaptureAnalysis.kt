package com.blanktick.core.analysis

import com.blanktick.core.filters.DomainNormalizer
import com.blanktick.core.filters.SortedHashSet64

/**
 * Reads a network capture the **user** exported from Wireshark or tshark, and
 * reports on it.
 *
 * Blanktick never captures a packet and never opens a socket. Capturing is the
 * user's own act, with their own tool, at their own elevation — this class only
 * ingests the file that act produced. That is the same shape as the rest of the
 * product: it reads Defender's verdict rather than being a scanner, it reads the
 * kernel's connection table rather than probing, and here it reads a capture
 * rather than sniffing. **Reading a file is not networking**, so the desktop
 * bytecode gate is unaffected and the zero-network claim is intact.
 *
 * ## Input
 *
 * A CSV as produced by Wireshark's *File → Export Packet Dissections → As CSV*
 * (whose columns include `Source`, `Destination`, `Protocol`, `Info`), or any
 * CSV carrying those four names in a header row. Equivalent tshark:
 *
 * ```
 * tshark -r capture.pcapng -T fields -E header=y -E separator=,
 *        -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info
 * ```
 * (rename the columns to Source/Destination/Protocol/Info, or export from the GUI).
 *
 * Only connection **metadata** is read — addresses, protocol, and the DNS query
 * name out of the Info column. No payload bytes are parsed. This class writes
 * nothing; persistence, if any, is the caller's decision and carries the same
 * sensitivity rules as the scan history.
 *
 * ## What a capture can and cannot say
 *
 * A capture is a slice of time. A clean one means *nothing bad was seen while
 * you were watching* — never *nothing bad happens*. The report says so, because
 * "the capture was clean" is exactly where a reader rounds to "safe".
 */
object CaptureAnalysis {

    /** Cleartext application protocols: their appearance is itself the finding. */
    private val PLAINTEXT = setOf("HTTP", "FTP", "FTP-DATA", "TELNET", "TFTP", "SMTP", "POP", "IMAP", "LDAP", "SNMP")

    /** Pulls a queried hostname out of a Wireshark DNS Info string. */
    private val DNS_NAME = Regex(
        """\b(?:A|AAAA|CNAME|PTR|MX|TXT|SRV|NS|HTTPS)\s+([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)+)"""
    )

    data class Packet(val source: String, val destination: String, val protocol: String, val info: String)

    data class Finding(val id: String, val severity: String, val title: String, val detail: String)

    data class Report(
        val packets: Int,
        val externalDestinations: List<String>,
        val domains: List<String>,
        val protocolCounts: Map<String, Int>,
        val findings: List<Finding>
    )

    fun parse(csv: String): List<Packet> {
        val lines = csv.lineSequence().filter { it.isNotBlank() }.toList()
        if (lines.isEmpty()) return emptyList()
        val header = splitCsv(lines.first()).map { it.trim().lowercase() }
        fun col(name: String) = header.indexOf(name)
        val si = col("source"); val di = col("destination"); val pi = col("protocol"); val ii = col("info")
        // If the header does not name the columns we need, this is not a capture
        // export we understand; return nothing rather than guess column order.
        if (si < 0 || di < 0 || pi < 0) return emptyList()
        return lines.drop(1).mapNotNull { line ->
            val f = splitCsv(line)
            val max = maxOf(si, di, pi, ii)
            if (f.size <= max) return@mapNotNull null
            Packet(
                source = f[si].trim(),
                destination = f[di].trim(),
                protocol = f[pi].trim(),
                info = if (ii >= 0 && ii < f.size) f[ii] else ""
            )
        }
    }

    fun analyze(packets: List<Packet>, blocklist: SortedHashSet64? = null): Report {
        val protocolCounts = packets.groupingBy { it.protocol.uppercase() }.eachCount()

        val domains = packets
            .filter { it.protocol.uppercase().contains("DNS") }
            .mapNotNull { DNS_NAME.find(it.info)?.groupValues?.get(1)?.lowercase() }
            .distinct()
            .sorted()

        val externalDestinations = packets
            .map { it.destination }
            .filter(::isExternal)
            .distinct()
            .sorted()

        val findings = mutableListOf<Finding>()

        // The differentiated check: cross-reference the queried names against the
        // OFFLINE bundled blocklist. No lookup leaves the machine.
        blocklist?.let { list ->
            val hits = domains.mapNotNull { d ->
                list.matchDomain(DomainNormalizer.normalize(d))?.let { matched -> d to matched }
            }
            if (hits.isNotEmpty()) {
                findings += Finding(
                    "CAP-DNS-BLOCK", "HIGH",
                    "This capture queried ${hits.size} name(s) on the bundled blocklist",
                    hits.joinToString("; ") { (d, m) -> if (d == m) d else "$d (listed as $m)" } +
                        ". A DNS query is an intent to connect; it does not prove the connection " +
                        "succeeded, but nothing on this machine should be resolving these."
                )
            }
        }

        val plaintext = protocolCounts.filterKeys { it in PLAINTEXT }
        if (plaintext.isNotEmpty()) {
            findings += Finding(
                "CAP-PLAINTEXT", "MEDIUM",
                "Cleartext protocol traffic is present",
                plaintext.entries.joinToString(", ") { "${it.key} (${it.value} packet(s))" } +
                    ". These carry their contents unencrypted; anyone on the path can read them."
            )
        }

        return Report(packets.size, externalDestinations, domains, protocolCounts, findings)
    }

    fun render(report: Report): String = buildString {
        appendLine("BLANKTICK CAPTURE REVIEW")
        appendLine("=".repeat(60))
        appendLine("This reads a capture you exported from Wireshark. Blanktick captured")
        appendLine("nothing and opened no socket. A capture is a slice of time: a clean")
        appendLine("one means nothing bad was seen while you watched, not that nothing bad")
        appendLine("happens.")
        appendLine()
        if (report.packets == 0) {
            appendLine("No rows understood. Expected a CSV with Source, Destination, Protocol")
            appendLine("and Info columns (Wireshark: File -> Export Packet Dissections -> As CSV).")
            return@buildString
        }
        appendLine("packets read:          ${report.packets}")
        appendLine("distinct domains seen: ${report.domains.size}")
        appendLine("external destinations: ${report.externalDestinations.size}")
        appendLine("protocols:             " + report.protocolCounts.entries.sortedByDescending { it.value }
            .joinToString(", ") { "${it.key}:${it.value}" })
        appendLine()
        if (report.findings.isEmpty()) {
            appendLine("No findings in what was captured. See the caveat above about what that means.")
        } else {
            report.findings.forEach { f ->
                appendLine("[${f.severity}] ${f.id}  ${f.title}")
                appendLine("   ${f.detail}")
            }
        }
    }

    // ------------------------------------------------------------- internals

    /** True if [address] is a routable destination, not local/loopback/multicast. */
    fun isExternal(address: String): Boolean {
        if (address.isBlank()) return false
        if (":" in address) return isExternalIpv6(address)
        val p = address.split(".").mapNotNull { it.toIntOrNull() }
        if (p.size != 4 || p.any { it !in 0..255 }) return false
        val a = p[0]; val b = p[1]
        return when {
            a == 0 || a == 127 || a == 255 -> false          // this-network, loopback, broadcast
            a == 10 -> false                                  // RFC1918
            a == 172 && b in 16..31 -> false                  // RFC1918
            a == 192 && b == 168 -> false                     // RFC1918
            a == 169 && b == 254 -> false                     // link-local
            a in 224..239 -> false                            // multicast
            a >= 240 -> false                                 // reserved
            else -> true
        }
    }

    private fun isExternalIpv6(a: String): Boolean {
        val l = a.lowercase()
        return l != "::1" && !l.startsWith("fe80") && !l.startsWith("ff") && !l.startsWith("::")
    }

    /** A minimal CSV field splitter: handles quoted fields and doubled quotes. */
    private fun splitCsv(line: String): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var inQuote = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '"' && inQuote && i + 1 < line.length && line[i + 1] == '"' -> { sb.append('"'); i++ }
                c == '"' -> inQuote = !inQuote
                c == ',' && !inQuote -> { out.add(sb.toString()); sb.setLength(0) }
                else -> sb.append(c)
            }
            i++
        }
        out.add(sb.toString())
        return out
    }
}
