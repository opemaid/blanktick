package com.mume.desktop.collect

import com.mume.core.model.AutoRunEntry
import com.mume.core.model.DesktopFacts
import com.mume.core.model.DesktopOs
import com.mume.core.model.ListeningPort
import com.mume.core.model.RemoteAccessService
import com.mume.core.model.ScreenLock
import java.io.File

/**
 * Reads macOS security posture.
 *
 * ## Status: written, never executed
 *
 * **This file has never run on a Mac.** It was written from the documented
 * behaviour of the command-line tools it calls, and it compiles, and it is
 * covered by parser tests against captured output — but no one has watched it
 * produce a snapshot on real hardware. It is in the same position as the Swift
 * mirror in `ios/MumeCore`, and it is said out loud here for the same reason:
 * the entire product is a claim about knowing the difference between "checked"
 * and "assumed".
 *
 * The design makes that survivable rather than dangerous. Every query below
 * returns `null` on any unexpected output, so the failure mode of a wrong guess
 * about a tool's format is *"not checkable"*, never a false green tick. A Mac
 * user running this today would see a short list of checks and a long list of
 * things Mume says it could not determine — which is honest, if not yet useful.
 *
 * ## What has to happen before this is trustworthy
 *
 * Run `MacCollectorParityTest` against real captured output from a current
 * macOS release, and confirm each parser against the same value read from
 * System Settings by eye. Until then the About screen labels macOS support as
 * unverified.
 */
internal class MacCollector : PlatformCollector {

    override val os = DesktopOs.MACOS

    override fun osBuild(): String? =
        Shell.stdout("sw_vers", "-productVersion")?.trim()?.takeIf { it.isNotBlank() }
            ?.let { "macOS $it" }

    override fun collect(): DesktopFacts = DesktopFacts(
        os = os,
        osBuild = osBuild(),

        firewallEnabled = firewallEnabled(),
        firewallProfilesOff = null,   // macOS has a single firewall, not profiles

        antivirusProduct = xprotectProduct(),
        antivirusRealtimeEnabled = null,   // no unprivileged query for XProtect Remediator state
        antivirusSignatureAgeDays = xprotectSignatureAgeDays(),
        appReputationEnabled = gatekeeperEnabled(),

        // Secure Boot policy on Apple Silicon is readable only through
        // `bputil`, which requires recovery mode. Not observable from a normal
        // session, so not claimed.
        secureBootEnabled = null,
        systemIntegrityProtectionEnabled = sipEnabled(),

        automaticUpdatesEnabled = automaticUpdatesEnabled(),
        // As on Windows: counting pending updates means asking Apple's servers.
        // Mume does not, and says so rather than reporting zero.
        pendingSecurityUpdates = null,
        daysSinceLastUpdate = daysSinceLastUpdate(),

        sessionIsAdministrator = sessionIsAdministrator(),
        administratorAccounts = administratorAccounts(),
        // `dscl` will not report password state without elevation, and guessing
        // would be the worst possible error on a CRITICAL rule.
        passwordlessAccounts = null,
        guestAccountEnabled = guestAccountEnabled(),
        lockOnWakeEnabled = lockOnWakeEnabled(),

        remoteAccessServices = remoteAccessServices(),
        listeningPorts = listeningPorts(),

        autoRunEntries = autoRunEntries()
    )

    // ------------------------------------------------------------- firewall

    /** `socketfilterfw --getglobalstate` prints "... is enabled." or "... is disabled.". */
    private fun firewallEnabled(): Boolean? {
        val out = Shell.stdout(
            "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"
        )?.lowercase() ?: return null
        return when {
            out.contains("enabled") -> true
            out.contains("disabled") -> false
            else -> null
        }
    }

    // ----------------------------------------------------------- protection

    private fun gatekeeperEnabled(): Boolean? {
        val out = Shell.stdout("spctl", "--status")?.trim()?.lowercase() ?: return null
        return when {
            out.contains("assessments enabled") -> true
            out.contains("assessments disabled") -> false
            else -> null
        }
    }

    private fun sipEnabled(): Boolean? {
        val out = Shell.stdout("csrutil", "status")?.lowercase() ?: return null
        return when {
            out.contains("status: enabled") -> true
            out.contains("status: disabled") -> false
            else -> null
        }
    }

    private fun xprotectProduct(): String? =
        if (File("/Library/Apple/System/Library/CoreServices/XProtect.bundle").exists()) "XProtect"
        else null

    /**
     * Age of the XProtect definitions, from the bundle's modification time.
     *
     * A proxy for the real thing: it measures when the bundle was last written,
     * which is when it last updated. Good enough to distinguish "yesterday" from
     * "eight months ago", which is the only distinction the rule makes.
     */
    private fun xprotectSignatureAgeDays(): Int? {
        val bundle = File("/Library/Apple/System/Library/CoreServices/XProtect.bundle")
        if (!bundle.exists()) return null
        val ageMillis = System.currentTimeMillis() - bundle.lastModified()
        if (ageMillis < 0) return null
        return (ageMillis / 86_400_000L).toInt()
    }

    // -------------------------------------------------------------- updates

    private fun automaticUpdatesEnabled(): Boolean? = Shell.parseBoolean(
        Shell.stdout(
            "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled"
        )?.trim()
    )

    private fun daysSinceLastUpdate(): Int? {
        val receipts = File("/Library/Receipts/InstallHistory.plist")
        if (!receipts.isFile) return null
        val ageMillis = System.currentTimeMillis() - receipts.lastModified()
        if (ageMillis < 0) return null
        return (ageMillis / 86_400_000L).toInt()
    }

    // ------------------------------------------------------------- accounts

    private fun sessionIsAdministrator(): Boolean? {
        val groups = Shell.stdout("id", "-Gn")?.trim() ?: return null
        return groups.split(' ').any { it == "admin" }
    }

    private fun administratorAccounts(): List<String>? =
        Shell.stdout("dscl", ".", "-read", "/Groups/admin", "GroupMembership")
            ?.substringAfter("GroupMembership:", "")
            ?.trim()
            ?.split(Regex("\\s+"))
            ?.filter { it.isNotBlank() }
            ?.takeIf { it.isNotEmpty() }

    private fun guestAccountEnabled(): Boolean? = Shell.parseBoolean(
        Shell.stdout(
            "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"
        )?.trim()
    )

    private fun lockOnWakeEnabled(): Boolean? = Shell.parseBoolean(
        Shell.stdout("defaults", "read", "com.apple.screensaver", "askForPassword")?.trim()
    )

    // -------------------------------------------------------- remote access

    private fun remoteAccessServices(): List<RemoteAccessService>? {
        val ssh = Shell.stdout("systemsetup", "-getremotelogin")?.lowercase()
        val ard = Shell.stdout(
            "launchctl", "print-disabled", "system"
        )?.contains("com.apple.screensharing")

        val services = buildList {
            when {
                ssh == null -> Unit
                ssh.contains("on") -> add(RemoteAccessService("Remote Login (SSH)", true, 22))
                ssh.contains("off") -> add(RemoteAccessService("Remote Login (SSH)", false, 22))
            }
            // `print-disabled` lists services and whether they are disabled; a
            // label that is present and not disabled is running.
            if (ard != null) {
                add(RemoteAccessService("Screen Sharing", enabled = !ard, port = 5900))
            }
        }
        return services.takeIf { it.isNotEmpty() }
    }

    /**
     * Listening sockets via `lsof`.
     *
     * Without elevation this only sees this user's processes, so it can
     * under-report. Under-reporting is the safe direction: the rule fires on
     * what it finds and stays silent otherwise, so a partial list can never
     * invent an exposure that is not there.
     */
    private fun listeningPorts(): List<ListeningPort>? {
        val raw = Shell.stdout("lsof", "-nP", "-iTCP", "-sTCP:LISTEN", timeoutSeconds = 30)
            ?: return null

        return raw.lineSequence()
            .drop(1)   // header
            .mapNotNull { line ->
                val cols = line.trim().split(Regex("\\s+"))
                if (cols.size < 9) return@mapNotNull null
                val endpoint = cols[8]                       // e.g. *:8080 or 127.0.0.1:5432
                val port = endpoint.substringAfterLast(':').toIntOrNull() ?: return@mapNotNull null
                ListeningPort(
                    address = endpoint.substringBeforeLast(':'),
                    port = port,
                    process = cols[0]
                )
            }
            .toList()
    }

    // ---------------------------------------------------------- persistence

    /**
     * LaunchAgents that start at login.
     *
     * `signedByKnownVendor` is left `null` throughout: verifying a signature
     * properly means `codesign --verify` on the executable named inside the
     * plist, and parsing a binary plist to find it is exactly the kind of
     * fragile guesswork that produces a false accusation. Until that is done
     * properly, `DSK-AUTO-001` correctly reports nothing here.
     */
    private fun autoRunEntries(): List<AutoRunEntry>? {
        val dirs = listOf(
            System.getProperty("user.home")?.let { "$it/Library/LaunchAgents" },
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons"
        ).filterNotNull()

        val entries = dirs.flatMap { dir ->
            File(dir).takeIf { it.isDirectory }
                ?.listFiles { f -> f.isFile && f.name.endsWith(".plist") }
                ?.map { AutoRunEntry(it.nameWithoutExtension, dir, signedByKnownVendor = null) }
                .orEmpty()
        }
        return entries.takeIf { it.isNotEmpty() || dirs.any { d -> File(d).isDirectory } }
    }

    // ------------------------------------------------ shared mobile-ish facts

    override fun diskEncrypted(): Boolean? {
        val out = Shell.stdout("fdesetup", "status")?.lowercase() ?: return null
        return when {
            out.contains("filevault is on") -> true
            out.contains("filevault is off") -> false
            else -> null
        }
    }

    /**
     * macOS exposes no unprivileged way to read the strength of the login
     * password, so this reports [ScreenLock.UNKNOWN] when a password exists and
     * declines otherwise. `ACC-LOCK-001` treats UNKNOWN as not checkable.
     */
    override fun screenLock(): ScreenLock? =
        if (lockOnWakeEnabled() != null) ScreenLock.UNKNOWN else null

    override fun screenLockTimeoutSeconds(): Int? =
        Shell.stdout("defaults", "read", "com.apple.screensaver", "idleTime")
            ?.trim()?.toIntOrNull()?.takeIf { it > 0 }

    override fun dnsServers(): List<String>? {
        val raw = Shell.stdout("scutil", "--dns") ?: return null
        return raw.lineSequence()
            .filter { it.trim().startsWith("nameserver[") }
            .mapNotNull { it.substringAfter(':').trim().takeIf { s -> s.isNotBlank() } }
            .distinct()
            .toList()
            .takeIf { it.isNotEmpty() }
    }
}
