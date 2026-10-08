package com.blanktick.sensor.providers

import com.blanktick.sensor.SensorEvent

/**
 * DNS names this machine resolved, read from the resolver cache without elevation.
 *
 * Runs a bundled script that polls `Get-DnsClientCache` and reports each newly
 * cached name. The cache is machine-wide and not attributed to a process, so
 * these events carry pid = -1; the name's shape is what the tunneling rule reads.
 *
 * This is the poll fallback; the ETW `DNS-Client` provider (admin) sees every
 * live query as it happens, with the process that made it.
 */
class DnsProvider : ScriptTapProvider(
    "/dns-provider.ps1",
    "windows-dns (Get-DnsClientCache poll)",
    Privilege.USER,
    "user-level DNS cache poll; ETW DNS-Client (admin) sees live per-query names with their process"
) {
    override fun parse(line: String): SensorEvent? = parseLine(line)

    /** Parse `at<TAB>queryName`. */
    internal fun parseLine(line: String): SensorEvent.DnsQuery? {
        val f = line.split('\t')
        if (f.size < 2) return null
        val at = f[0].toLongOrNull() ?: return null
        val name = f[1]
        if (name.isBlank()) return null
        return SensorEvent.DnsQuery(at = at, pid = -1L, image = "", queryName = name)
    }
}
