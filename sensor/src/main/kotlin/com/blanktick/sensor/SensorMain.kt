package com.blanktick.sensor

import com.blanktick.sensor.providers.DnsProvider
import com.blanktick.sensor.providers.EventProvider
import com.blanktick.sensor.providers.NetworkProvider
import com.blanktick.sensor.providers.Privilege
import com.blanktick.sensor.providers.WindowsProcessProvider
import java.util.concurrent.CountDownLatch

/**
 * A minimal live runner: wire the Windows taps into the engine and print what
 * they see.
 *
 * It runs the process tap (ETW when elevated, poll otherwise) plus the network
 * and DNS taps, all feeding one engine. Detections fire only on genuinely
 * malicious shapes, so on an ordinary session it streams observations and stays
 * quiet, which is correct.
 *
 * Flags (JVM system properties):
 *   -Dblanktick.sensor.seconds=N   run for N seconds, then stop
 *   -Dblanktick.sensor.demo=true   inject clearly-labelled synthetic attack
 *                                  events (incl. a beacon and a tunneling DNS
 *                                  name) so detections can be seen firing,
 *                                  without any real malware
 */

/** A window wide enough that a slow beacon's several check-ins fall inside it. */
private val engine = BehaviorEngine(windowMillis = 600_000, windowMaxEvents = 8192)

fun main() {
    val seconds = System.getProperty("blanktick.sensor.seconds")?.toLongOrNull()
    val demo = System.getProperty("blanktick.sensor.demo")?.toBoolean() == true

    val admin = WindowsElevation.isAdmin()
    val processTap = if (admin) WindowsProcessProvider.etw() else WindowsProcessProvider.poll()
    val providers: List<EventProvider> = listOf(processTap, NetworkProvider(), DnsProvider())

    println("Blanktick sensor")
    println("  running elevated : $admin")
    providers.forEach { println("  provider         : ${it.name}  [needs ${it.privilege}]") }
    if (!admin && processTap.privilege == Privilege.USER) {
        println("  note             : not elevated — process tap is the poll fallback. Run as admin for ETW.")
    }
    println(if (seconds != null) "Watching for ${seconds}s. Detections print as ALERT lines."
            else "Watching until stopped. Detections print as ALERT lines.")

    val done = CountDownLatch(1)
    Runtime.getRuntime().addShutdownHook(Thread { providers.forEach { it.stop() } })

    val sink: (SensorEvent) -> Unit = { e ->
        when (e) {
            is SensorEvent.ProcessStart ->
                println("  observed  proc  pid=${e.pid}  ${Images.basename(e.image)}  <-  ${Images.basename(e.parentImage)}")
            is SensorEvent.NetworkConnect ->
                println("  observed  net   pid=${e.pid}  ${Images.basename(e.image)}  ->  ${e.remoteAddress}:${e.remotePort}")
            is SensorEvent.DnsQuery ->
                println("  observed  dns   ${e.queryName}")
            else -> {}
        }
        engine.observe(e).forEach { d ->
            println("  ALERT  ${d.finding.ruleId}  [${d.response}]  ${d.finding.title}")
        }
    }

    providers.forEach { it.start(sink) }
    if (demo) injectDemo()

    if (seconds != null) {
        Thread.sleep(seconds * 1000)
        providers.forEach { it.stop() }
        done.countDown()
    } else {
        done.await()
    }
    println("Sensor stopped.")
}

/**
 * Feed clearly-labelled synthetic events so detections can be watched firing end
 * to end. These touch nothing: no process starts, no connection opens, no file
 * is written. They are ordinary [SensorEvent]s handed to the same engine the
 * live taps feed, and every line they produce is prefixed [DEMO].
 */
private fun injectDemo() {
    val now = System.currentTimeMillis()
    println("[DEMO] injecting synthetic attack events — no real malware, nothing on the machine is touched")

    val synthetic = mutableListOf<SensorEvent>(
        // Malicious document: Word spawns PowerShell -> DYN-OFFICE-001
        SensorEvent.ProcessStart(
            at = now, pid = 999_001, image = "powershell.exe",
            parentPid = 999_000, parentImage = "winword.exe", commandLine = "powershell -enc <synthetic>"
        ),
        // MCP server process...
        SensorEvent.ProcessStart(at = now + 1, pid = 999_010, image = "node.exe", actor = Actor.MCP_SERVER),
        // ...spawns a shell -> DYN-AI-001
        SensorEvent.ProcessStart(
            at = now + 2, pid = 999_011, image = "cmd.exe",
            parentPid = 999_010, parentImage = "node.exe", commandLine = "cmd /c whoami"
        ),
        // A DNS name shaped like exfiltration -> DYN-DNS-001
        SensorEvent.DnsQuery(
            at = now + 3, pid = -1, image = "",
            queryName = "d2VkbmVzZGF5c2VjcmV0ZXhmaWx0cmF0aW9uZGF0YWJsb2I.evil.example"
        )
    )
    // Five evenly-spaced callbacks to one host -> DYN-C2-001
    for (i in 0 until 5) {
        synthetic += SensorEvent.NetworkConnect(
            at = now + 10_000 + i * 2_000L, pid = 999_020, image = "rat.exe",
            remoteAddress = "203.0.113.7", remotePort = 443
        )
    }

    synthetic.forEach { e ->
        engine.observe(e).forEach { d ->
            println("[DEMO] ALERT  ${d.finding.ruleId}  [${d.response}]  ${d.finding.title}")
        }
    }
}
