package com.blanktick.sensor.providers

import com.blanktick.sensor.SensorEvent

/**
 * Outbound TCP connections, read from Windows without elevation.
 *
 * Runs a bundled script that polls `Get-NetTCPConnection` and reports each new
 * established remote connection: the process, the destination, the port. That is
 * enough for the beaconing pattern rule to work. Loopback and unspecified
 * addresses are dropped at the source.
 *
 * This is the poll fallback; the ETW `Kernel-Network` provider (admin) sees each
 * connection the instant it opens and cannot miss a short-lived one.
 */
class NetworkProvider : ScriptTapProvider(
    "/network-provider.ps1",
    "windows-network (Get-NetTCPConnection poll)",
    Privilege.USER,
    "user-level established-TCP poll; ETW Kernel-Network (admin) is the higher-fidelity upgrade"
) {
    override fun parse(line: String): SensorEvent? = parseLine(line)

    /** Parse `at<TAB>pid<TAB>image<TAB>remoteAddr<TAB>remotePort<TAB>proto`. */
    internal fun parseLine(line: String): SensorEvent.NetworkConnect? {
        val f = line.split('\t')
        if (f.size < 5) return null
        val at = f[0].toLongOrNull() ?: return null
        val pid = f[1].toLongOrNull() ?: -1L
        val image = f[2]
        val remoteAddress = f[3]
        val remotePort = f[4].toIntOrNull() ?: return null
        val protocol = if (f.size >= 6 && f[5].isNotBlank()) f[5] else "TCP"
        return SensorEvent.NetworkConnect(
            at = at, pid = pid, image = image,
            remoteAddress = remoteAddress, remotePort = remotePort, protocol = protocol
        )
    }
}
