package com.blanktick.sensor

import com.blanktick.sensor.providers.ContentIntakeProvider
import com.blanktick.sensor.providers.DnsProvider
import com.blanktick.sensor.providers.EventProvider
import com.blanktick.sensor.providers.FileActivityProvider
import com.blanktick.sensor.providers.HandleOpenProvider
import com.blanktick.sensor.providers.NetworkProvider
import com.blanktick.sensor.providers.Privilege
import com.blanktick.sensor.providers.ScriptTapProvider
import com.blanktick.sensor.providers.WindowsProcessProvider
import java.util.concurrent.CountDownLatch

/**
 * A minimal live runner: wire the Windows taps into the engine and print what
 * they see.
 *
 * It runs the process tap (ETW when elevated, poll otherwise), the network and
 * DNS taps, and the three credential/ransomware/AI-intake taps, all feeding one
 * engine. Detections fire only on genuinely malicious shapes, so on an ordinary
 * session it streams observations and stays quiet, which is correct.
 *
 * Flags (JVM system properties):
 *   -Dblanktick.sensor.seconds=N   run for N seconds, then stop
 *   -Dblanktick.sensor.demo=true   inject clearly-labelled synthetic attack
 *                                  events covering all seven rules so detections
 *                                  can be seen firing, without any real malware
 */

/** A window wide enough that a slow beacon's several check-ins fall inside it. */
private val engine = BehaviorEngine(windowMillis = 600_000, windowMaxEvents = 8192)

fun main() {
    val seconds = System.getProperty("blanktick.sensor.seconds")?.toLongOrNull()
    val demo = System.getProperty("blanktick.sensor.demo")?.toBoolean() == true
    // Enforcement is the one irreversible act; it is off unless explicitly asked for.
    val enforce = System.getProperty("blanktick.sensor.enforce")?.toBoolean() == true

    val admin = WindowsElevation.isAdmin()
    // Prefer Sysmon ProcessCreate (inline parentage, no race) → Win32_ProcessStartTrace
    // → user-level poll, in descending fidelity.
    val processTap = when {
        admin && WindowsProcessProvider.sysmonProcessLogAvailable() -> WindowsProcessProvider.sysmon()
        admin -> WindowsProcessProvider.etw()
        else -> WindowsProcessProvider.poll()
    }
    val providers: List<EventProvider> = listOf(
        processTap, NetworkProvider(), DnsProvider(),
        HandleOpenProvider(), FileActivityProvider(), ContentIntakeProvider()
    )

    println("Blanktick sensor")
    println("  running elevated : $admin")
    providers.forEach { println("  provider         : ${it.name}  [needs ${it.privilege}]") }
    if (!admin && processTap.privilege == Privilege.USER) {
        println("  note             : not elevated — process tap is the poll fallback. Run as admin for ETW.")
    }
    println("  enforcement      : " + (if (enforce) "ON — flagged processes will be STOPPED" else "off (detect-only)"))
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
            is SensorEvent.HandleOpen ->
                println("  observed  hopen pid=${e.pid}  ${Images.basename(e.image)}  ->  ${Images.basename(e.targetImage)}")
            is SensorEvent.FileModify ->
                println("  observed  file  pid=${e.pid}  ${e.op}  ${e.path}")
            is SensorEvent.ShadowCopyDeletion ->
                println("  observed  vssdel pid=${e.pid}  ${Images.basename(e.image)}")
            is SensorEvent.ContentIntake ->
                println("  observed  intake pid=${e.pid}  ${Images.basename(e.image)}  <-  ${e.source}")
            else -> {}
        }
        engine.observe(e).forEach { d ->
            println("  ALERT  ${d.finding.ruleId}  [${d.response}]  ${d.finding.title}")
            if (enforce) {
                val r = Enforcer.enforce(d)
                println("  ENFORCE  ${d.finding.ruleId}  ${r.outcome}  ${r.detail}")
            }
        }
    }

    providers.forEach { it.start(sink) }
    if (demo) injectDemo()

    // Give the script taps a moment to report their chosen source, then print an
    // honest coverage line: a tap with no live source is a gap, not a pass.
    Thread.sleep(2_500)
    println("Coverage (what is actually being observed):")
    providers.forEach { p ->
        if (p is ScriptTapProvider) {
            val elev = p.reportedElevated?.let { if (it) "elevated" else "NOT elevated" } ?: "—"
            val src = p.reportedSource?.let { "  source=$it" } ?: ""
            println("  ${p.name}  [$elev]$src")
        }
    }

    if (seconds != null) {
        Thread.sleep((seconds * 1000 - 2_500).coerceAtLeast(0))
        providers.forEach { it.stop() }
        done.countDown()
    } else {
        done.await()
    }
    println("Sensor stopped.")
}

/**
 * Feed clearly-labelled synthetic events so detections can be watched firing end
 * to end, across all seven rules. These touch nothing: no process starts, no
 * connection opens, no handle is opened, no file is written. They are ordinary
 * [SensorEvent]s handed to the same engine the live taps feed, and every line
 * they produce is prefixed [DEMO].
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
        ),
        // A non-system process reading lsass memory (mask includes PROCESS_VM_READ)
        // -> DYN-CRED-001
        SensorEvent.HandleOpen(
            at = now + 4, pid = 999_050, image = "mimikatz.exe",
            targetImage = "C:\\Windows\\System32\\lsass.exe", access = "0x1410"
        ),
        // Deleting volume shadow copies -> DYN-RANSOM-001
        SensorEvent.ShadowCopyDeletion(
            at = now + 5, pid = 999_060, image = "vssadmin.exe",
            commandLine = "vssadmin delete shadows /all /quiet"
        ),
        // An agent reads outside content... -> left half of DYN-AI-003
        SensorEvent.ContentIntake(
            at = now + 6, pid = 999_070, image = "node.exe", actor = Actor.AI_AGENT,
            source = "https://evil.example/injected-page"
        ),
        // ...then acts within seconds -> DYN-AI-003
        SensorEvent.FileModify(
            at = now + 1_500, pid = 999_070, image = "node.exe", actor = Actor.AI_AGENT,
            path = "C:\\Users\\me\\Documents\\exfil.txt", op = FileOp.WRITE
        )
    )
    // A burst of high-entropy writes from one process -> DYN-RANSOM-001
    for (i in 0 until 13) {
        synthetic += SensorEvent.FileModify(
            at = now + 2_000 + i * 100L, pid = 999_080, image = "locky.exe",
            path = "C:\\Users\\me\\Documents\\file$i.locky", op = FileOp.ENCRYPT_SUSPECTED, highEntropy = true
        )
    }
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
