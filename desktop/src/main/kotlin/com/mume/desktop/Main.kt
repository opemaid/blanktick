package com.mume.desktop

import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import androidx.compose.ui.window.WindowPosition
import com.mume.desktop.collect.DesktopCollector
import com.mume.desktop.collect.DesktopIntel
import com.mume.desktop.ui.MumeApp
import com.mume.desktop.ui.MumeTheme
import java.time.LocalDate

/**
 * Entry point.
 *
 * The first statement installs the runtime network blocks, before Compose,
 * Skiko or any other library has had a chance to initialise. Order matters:
 * both JVM mechanisms [NoNetwork] uses are one-shot factories, and whoever sets
 * them first wins. If Skiko were allowed to register a URL stream handler
 * factory first, ours would throw and the block would be silently absent —
 * which is why [NoNetwork.gaps] records the failure and the About screen prints
 * it rather than showing a tick that was not earned.
 */
fun main(args: Array<String>) {
    NoNetwork.install()

    when {
        "--probe" in args -> printProbe()
        "--script" in args -> printScript()
        "--tools" in args -> printTools()
        "--scan" in args -> printScan()
        else -> ui()
    }
}

private fun ui() = application {
    val scope = rememberCoroutineScope()
    val state = remember { AppState(scope) }

    Window(
        onCloseRequest = ::exitApplication,
        title = "Mume",
        state = rememberWindowState(
            size = defaultWindowSize(),
            position = WindowPosition(Alignment.Center)
        )
    ) {
        // defaultWindowSize() only floors the INITIAL size; rememberWindowState
        // has no minimum. Verified by dragging the real window to 420x400: the
        // 240dp rail took 57% of the width and "Run the first scan" left the
        // screen entirely. ComposeWindow is a JFrame, and AWT logical units are
        // Compose dp on a DPI-aware JVM (see defaultWindowSize below).
        window.minimumSize = java.awt.Dimension(880, 620)

        // Theme and text size come from Settings, because Compose Desktop reads
        // neither the OS theme preference nor its text-size slider.
        val settings by state.settings.collectAsState()
        val dark = when (settings.theme) {
            Settings.ThemeChoice.SYSTEM -> androidx.compose.foundation.isSystemInDarkTheme()
            Settings.ThemeChoice.LIGHT -> false
            Settings.ThemeChoice.DARK -> true
        }
        MumeTheme(darkTheme = dark) {
            androidx.compose.runtime.CompositionLocalProvider(
                androidx.compose.ui.platform.LocalDensity provides
                    androidx.compose.ui.unit.Density(
                        androidx.compose.ui.platform.LocalDensity.current.density,
                        settings.textScale
                    )
            ) {
                MumeApp(state)
            }
        }
    }
}

/**
 * A window that fits the screen it opens on.
 *
 * The preferred size is what the layout was designed for, clamped to the
 * desktop's **work area** — the screen minus the taskbar. A fixed 1100x820
 * opens partly underneath the taskbar on a 1080p display at 125% scaling, which
 * is an entirely ordinary setup, and the thing that gets cut off is the primary
 * button.
 *
 * ## Do not "fix" this by dividing by the DPI scale
 *
 * The first version did exactly that and made the window 26% shorter than
 * intended. `GraphicsEnvironment.maximumWindowBounds` is already reported in
 * **logical** units on a DPI-aware JVM: on this 1920x1080 display at 125% it
 * returns 1536x816, not 1920x1080. Compose desktop's `dp` is the same unit —
 * a 1100 dp window measures 1375 physical pixels at 1.25 scale, and
 * 1100 x 1.25 = 1375. So logical AWT units and Compose dp are interchangeable
 * here, and dividing by `scaleY` applies the scale factor a second time.
 *
 * Measured on the development machine: bounds 1536x816, scaleY 1.25. Correct
 * result is 776 dp of usable height; the double-scaled version produced 613.
 *
 * Falls back to the preferred size if the environment is headless or reports
 * nothing sensible — a slightly-too-large window beats no window.
 */
private fun defaultWindowSize(): DpSize {
    val preferred = DpSize(1100.dp, 820.dp)
    val minimum = DpSize(760.dp, 560.dp)

    /** Breathing room so the window is not flush against every screen edge. */
    val margin = 40

    return runCatching {
        val bounds = java.awt.GraphicsEnvironment
            .getLocalGraphicsEnvironment()
            .maximumWindowBounds

        require(bounds.width > 0 && bounds.height > 0)

        DpSize(
            width = minOf(preferred.width, (bounds.width - margin).dp)
                .coerceAtLeast(minimum.width),
            height = minOf(preferred.height, (bounds.height - margin).dp)
                .coerceAtLeast(minimum.height)
        )
    }.getOrDefault(preferred)
}

/**
 * Prints the snapshot Mume built, field by field, and exits.
 *
 * This exists so the answer to "what did it actually read off my machine?" is a
 * command rather than a promise. Everything the UI shows is derived from this
 * output and nothing else, so a value that looks wrong on screen can be traced
 * to the exact field that produced it — or to the `null` that means Mume never
 * managed to read it.
 *
 * It also makes the not-checkable list debuggable: a field printed as `null`
 * here is a query that returned nothing, which is either an honest limit of the
 * platform or a bug in the collector, and this is how the two are told apart.
 */
private fun printProbe() {
    val collector = DesktopCollector.forCurrentOs()
    if (collector == null) {
        println("Mume does not know this operating system: ${System.getProperty("os.name")}")
        return
    }

    val intel = DesktopIntel.load().snapshot(LocalDate.now().toString())
    val snapshot = collector.collect(intel)
    val d = snapshot.desktop

    println("Mume probe - ${collector.os.displayName}")
    println("=".repeat(64))
    println("os.build                       ${d?.osBuild}")
    println()
    println("firewallEnabled                ${d?.firewallEnabled}")
    println("firewallProfilesOff            ${d?.firewallProfilesOff}")
    println("antivirusProduct               ${d?.antivirusProduct}")
    println("antivirusRealtimeEnabled       ${d?.antivirusRealtimeEnabled}")
    println("antivirusSignatureAgeDays      ${d?.antivirusSignatureAgeDays}")
    println("appReputationEnabled           ${d?.appReputationEnabled}")
    println("secureBootEnabled              ${d?.secureBootEnabled}")
    println("systemIntegrityProtection      ${d?.systemIntegrityProtectionEnabled}")
    println("automaticUpdatesEnabled        ${d?.automaticUpdatesEnabled}")
    println("pendingSecurityUpdates         ${d?.pendingSecurityUpdates}")
    println("daysSinceLastUpdate            ${d?.daysSinceLastUpdate}")
    println("sessionIsAdministrator         ${d?.sessionIsAdministrator}")
    println("administratorAccounts          ${d?.administratorAccounts}")
    println("passwordlessAccounts           ${d?.passwordlessAccounts}")
    println("guestAccountEnabled            ${d?.guestAccountEnabled}")
    println("lockOnWakeEnabled              ${d?.lockOnWakeEnabled}")
    println("remoteAccessServices           ${d?.remoteAccessServices}")
    println("listeningPorts                 ${d?.listeningPorts?.size ?: "null"} entries")
    println("autoRunEntries                 ${d?.autoRunEntries?.size ?: "null"} entries")
    println("installedPrograms              ${d?.installedPrograms?.size ?: "null"} entries")
    println("autoRunBlockedForRemovable     ${d?.autoRunBlockedForRemovable}")
    println("removableDrives                ${d?.removableDrives?.size ?: "null"} attached")
    d?.removableDrives?.forEach { println("    ${it.letter} ${it.label} encrypted=${it.encrypted}") }
    println("rememberedUsbDevices           ${d?.rememberedUsbDevices?.size ?: "null"}")
    d?.rememberedUsbDevices?.forEach { println("    $it") }
    d?.installedPrograms?.filter { it.userWritableLocation }?.let {
        println("   ...of which user-writable:  ${it.size}  (no publisher: ${it.count { p -> p.publisher.isNullOrBlank() }})")
    }
    d?.autoRunEntries?.forEach {
        println("    ${it.name}  signed=${it.signedByKnownVendor}  @ ${it.location}")
    }
    println()
    println("diskEncrypted                  ${snapshot.diskEncrypted}")
    println("screenLock                     ${snapshot.screenLock}")
    println("screenLockTimeoutSeconds       ${snapshot.screenLockTimeoutSeconds}")
    println("userInstalledCaCerts           ${snapshot.userInstalledCaCerts?.size ?: "null"} entries")
    snapshot.userInstalledCaCerts?.forEach { println("    ${it.subject}") }
    println("dnsServers                     ${snapshot.dnsServers}")
    println("proxy                          ${snapshot.proxy}")
    println()
    println("A field printed as `null` was never read. Mume reports those as")
    println("\"not checkable\" and never as a passing check.")
}

/**
 * Prints the exact commands Mume runs, and exits.
 *
 * Paste the output into a terminal and compare. A security app that asks to be
 * trusted about privacy should be the easiest thing in the world to check.
 */
/**
 * Where every system tool Mume runs actually resolves, and whether that
 * location could have been written by an unprivileged process.
 *
 * ## Why this is a shipped command and not a test
 *
 * The binary-resolution guard is the difference between reading the operating
 * system and reading whatever an attacker put on `PATH`, and it depends on
 * facts that vary by machine: where a distribution puts `ss`, whether
 * `/usr/local/bin` belongs to root or to the logged-in user, whether Homebrew
 * has been near it. Those are not things a unit test on a build machine can
 * answer for someone else's computer.
 *
 * A test proves the guard works where it ran. This proves it works *here*, in
 * one command, for anyone who has the machine — which is the only honest way to
 * back the claim on a platform the author cannot test.
 */
private fun printTools() {
    val os = DesktopCollector.detectOs()
    println("Mume tool resolution - " + (os?.name?.lowercase() ?: "unknown OS"))
    println("=".repeat(72))
    println()
    println("A tool that does not resolve is not run at all: the checks that need it")
    println("report as NOT CHECKABLE rather than guessing. That is the safe failure,")
    println("but if something below is missing that you know is installed, the")
    println("trusted-directory list in Shell.kt is wrong for this machine.")
    println()

    val tools = when (os) {
        com.mume.core.model.DesktopOs.WINDOWS -> listOf("powershell.exe")
        com.mume.core.model.DesktopOs.MACOS -> listOf(
            "sw_vers", "spctl", "csrutil", "fdesetup", "systemsetup", "scutil",
            "defaults", "dscl", "id", "lsof"
        )
        com.mume.core.model.DesktopOs.LINUX -> listOf(
            "id", "lsof", "lsblk", "ss", "systemctl", "resolvectl",
            "gsettings", "nft", "ufw", "mokutil"
        )
        null -> emptyList()
    }

    var unresolved = 0
    for (t in tools) {
        val where = com.mume.desktop.collect.Shell.resolve(t)
        if (where == null) unresolved++
        println("  %-14s %s".format(t, where ?: "NOT RESOLVED - checks needing it report not checkable"))
    }

    println()
    println("$unresolved of ${tools.size} did not resolve.")
    println()
    println("Every path above must sit in a directory only an administrator can")
    println("write. On macOS and Linux that is verified against the filesystem at")
    println("run time - owner root, not group- or world-writable, all the way up -")
    println("rather than assumed from the path. Confirm with:  ls -ld <dir>")
}

/**
 * Runs a full scan and prints the scored result as text.
 *
 * The same report the dashboard renders, in a form that can be diffed between
 * builds. That is what it is for: a rule added without measuring is how a
 * security tool ends up crying wolf on a healthy machine, and the cheapest way
 * to check is to run every rule against a machine known to be fine and count
 * what fires.
 */
private fun printScan() {
    val collector = DesktopCollector.forCurrentOs()
    if (collector == null) {
        println("Mume does not know this operating system: ${System.getProperty("os.name")}")
        return
    }

    val loaded = DesktopIntel.load()
    val intel = loaded.snapshot(LocalDate.now().toString())
    val snapshot = collector.collect(intel)
    val report = com.mume.core.MumeScanner().scan(snapshot)
    val result = report.result

    println("Mume scan - ${collector.os.displayName}")
    println("=".repeat(72))
    // Which corpora are actually bundled. A check that reports "not performed"
    // because a table is missing looks identical to one the machine could not
    // answer, and telling those apart is the difference between a bug and a
    // build choice.
    println("intel bundle     built ${loaded.manifest?.builtOn ?: "(absent)"}" +
        (if (loaded.manifest?.synthetic == true) "  SYNTHETIC" else "") +
        "  malware hashes: " + (loaded.manifest?.malwareCount ?: 0) +
        "  lookup: " + (if (intel.isKnownMalware != null) "available" else "NOT LOADED"))

    // How much of the machine the hash check actually reached. "Not performed"
    // because nothing could be hashed and "not performed" because no corpus is
    // bundled are different answers, and both are different from "nothing
    // found".
    snapshot.desktop?.let { d ->
        val auto = d.autoRunEntries.orEmpty()
        val procs = d.runningProcesses.orEmpty()
        println("hash check       " +
            auto.count { it.sha256 != null } + "/" + auto.size + " startup entries, " +
            procs.count { it.sha256 != null } + "/" + procs.size + " processes hashed; " +
            (auto.count { it.matchesKnownMalware != null } +
                procs.count { it.matchesKnownMalware != null }) + " compared against the corpus")
    }
    println("score            ${result.score}/100   grade ${result.grade}")
    println("checks run       ${result.checksRun}")
    println("not checkable    ${result.checksSkipped}  " +
        "(${report.skippedWrongPlatform.size} wrong platform, " +
        "${report.skippedUnobservable.size} this machine would not say)")
    println("findings         ${result.actionableFindings.size}")
    println()

    result.actionableFindings
        .sortedBy { it.finding.severity.ordinal }
        .forEach { s ->
            val f = s.finding
            println("[%-8s] -%-3d %-14s %s".format(f.severity, s.deduction, f.ruleId, f.title))
        }

    println()
    println("--- checks that could not be performed ---")
    report.skippedUnobservable.forEach { println("  ${it.ruleId}  ${it.description}") }
}

private fun printScript() {
    when (DesktopCollector.detectOs()) {
        com.mume.core.model.DesktopOs.WINDOWS ->
            println(com.mume.desktop.collect.WindowsProbe.SCRIPT)
        else ->
            println(
                "The macOS and Linux collectors call individual command-line tools rather " +
                    "than one script; read MacCollector.kt / LinuxCollector.kt."
            )
    }
}
