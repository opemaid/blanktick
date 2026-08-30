package com.mume.desktop.collect

import com.mume.core.model.AutoRunEntry
import com.mume.core.model.CaCertificate
import com.mume.core.model.DesktopFacts
import com.mume.core.model.DesktopOs
import com.mume.core.model.InstalledProgram
import com.mume.core.model.ListeningPort
import com.mume.core.model.RemoteAccessService
import com.mume.core.model.ScreenLock

/**
 * Reads Windows 10/11 security posture.
 *
 * ## One script, not twenty-five
 *
 * Everything below comes from a single PowerShell run (see [WindowsProbe]) that
 * emits `key=value` lines. The first version made one call per question and
 * took minutes; this takes seconds. It also means the entire set of commands
 * Mume runs on your machine is one readable block of text you can paste into a
 * terminal and compare against what the app showed you.
 *
 * ## Everything here is unprivileged
 *
 * Mume does not ask for elevation and must work as a standard user. That shaped
 * several of the queries: Secure Boot is read from the registry rather than via
 * `Confirm-SecureBootUEFI` (which needs rights we do not have), and BitLocker
 * status comes from the shell property rather than `Get-BitLockerVolume` (same
 * reason). Where no unprivileged route exists, the value is `null` and the rule
 * reports *not checkable* — which is better than an app that demands
 * administrator rights in order to tell you not to run as administrator.
 *
 * ## Why PowerShell rather than JNA
 *
 * A native binding would be faster and would not spawn a process. It would also
 * mean shipping an opaque binary inside a security app whose whole pitch is
 * auditability. Text you can read and re-run beats milliseconds.
 */
internal class WindowsCollector : PlatformCollector {

    override val os = DesktopOs.WINDOWS

    /**
     * Answers, collected once and reused.
     *
     * [PlatformCollector] exposes several accessors that the caller invokes
     * separately; without this they would each re-run the probe.
     */
    private val probe: Map<String, List<String>> by lazy {
        Shell.powershellKeyValues(WindowsProbe.SCRIPT)
    }

    private fun one(key: String): String? = probe[key]?.firstOrNull()
    private fun all(key: String): List<String>? = probe[key]
    private fun bool(key: String): Boolean? = Shell.parseBoolean(one(key))
    private fun int(key: String): Int? = one(key)?.toIntOrNull()

    override fun osBuild(): String? = one("os.build")

    override fun collect(): DesktopFacts {
        val profiles = all("fw.profile").orEmpty()
            .mapNotNull { row ->
                val parts = row.split('\t')
                if (parts.size != 2) return@mapNotNull null
                val enabled = Shell.parseBoolean(parts[1]) ?: return@mapNotNull null
                parts[0] to enabled
            }

        return DesktopFacts(
            os = os,
            osBuild = osBuild(),

            // Absent profile list means the query failed, not that there is no
            // firewall. Both fields stay null and DSK-FW-001 says so.
            firewallEnabled = if (profiles.isEmpty()) null else profiles.all { it.second },
            firewallProfilesOff = if (profiles.isEmpty()) null
            else profiles.filterNot { it.second }.map { it.first },

            antivirusProduct = antivirusProduct(),
            antivirusRealtimeEnabled = antivirusRealtime(),
            antivirusSignatureAgeDays = int("av.signatureAgeDays"),
            appReputationEnabled = smartScreenEnabled(),

            secureBootEnabled = secureBootEnabled(),
            systemIntegrityProtectionEnabled = null,   // a macOS concept

            automaticUpdatesEnabled = automaticUpdatesEnabled(),
            // Deliberately null, and this is the one place the offline promise
            // costs a real check. Enumerating pending Windows updates means
            // calling the Windows Update Agent, which contacts Microsoft. That
            // is a network operation, so Mume does not do it, and reports the
            // check as not performed rather than as "nothing pending".
            pendingSecurityUpdates = null,
            daysSinceLastUpdate = int("update.daysSinceLast"),

            sessionIsAdministrator = bool("acct.sessionIsAdmin"),
            administratorAccounts = all("acct.admin"),
            passwordlessAccounts = passwordlessAccounts(),
            guestAccountEnabled = bool("acct.guestEnabled"),
            lockOnWakeEnabled = lockOnWakeEnabled(),

            remoteAccessServices = remoteAccessServices(),
            listeningPorts = listeningPorts(),

            autoRunEntries = autoRunEntries(),
            installedPrograms = installedPrograms()
        )
    }

    // ------------------------------------------------------------- defender

    private fun antivirusProduct(): String? =
        one("av.registered") ?: one("av.defenderPresent")?.let { "Microsoft Defender" }

    /**
     * Real-time protection state.
     *
     * When a third-party suite is installed, Defender stands down and
     * `Get-MpComputerStatus` reports real-time protection as off. Presenting
     * that as "you have no protection" would be wrong and alarming, so an
     * active non-Microsoft product yields `null` here — Security Center does not
     * expose the third party's own state, and we do not invent one.
     */
    private fun antivirusRealtime(): Boolean? {
        val registered = one("av.registered")
        val thirdParty = registered != null &&
            !registered.startsWith("Windows Defender") &&
            !registered.startsWith("Microsoft Defender")
        return if (thirdParty) null else bool("av.realtimeEnabled")
    }

    /**
     * SmartScreen for downloaded programs.
     *
     * Policy wins where present; the Explorer value is the per-user setting.
     * Absent from both is the shipping default (on) *and* what a failed read
     * looks like — indistinguishable, so this declines to answer rather than
     * assert the default. On a stock Windows 11 machine, where neither value has
     * ever been written, `DSK-REP-001` therefore reports not-checkable. That is
     * the correct answer to "did you verify SmartScreen is on?", which is no.
     */
    private fun smartScreenEnabled(): Boolean? {
        one("smartscreen.policy")?.let { return it != "0" }
        return when (one("smartscreen.explorer")?.lowercase()) {
            "off" -> false
            "warn", "requireadmin", "prompt", "block" -> true
            else -> null
        }
    }

    /** `UEFISecureBootEnabled`: 1 on, 0 off. Readable without elevation. */
    private fun secureBootEnabled(): Boolean? = when (one("secureboot.enabled")) {
        "1" -> true
        "0" -> false
        else -> null
    }

    // -------------------------------------------------------------- updates

    /**
     * Whether Windows Update installs on its own.
     *
     * Two independent ways people switch it off: the `NoAutoUpdate` policy, and
     * disabling the service outright. The second is invisible in the first, so
     * both are checked.
     */
    private fun automaticUpdatesEnabled(): Boolean? {
        if (one("update.serviceStartType")?.equals("Disabled", ignoreCase = true) == true) return false
        val policy = one("update.noAutoUpdate")
        if (policy != null) return policy != "1"
        // No policy set and the service is not disabled: updates are automatic.
        // Only claimed when the service state was actually readable.
        return one("update.serviceStartType")?.let { true }
    }

    // ------------------------------------------------------------- accounts

    /**
     * Enabled local accounts that can sign in with no password.
     *
     * An empty result here is a real answer, not a missing one — but only if the
     * enumeration itself worked. `acct.userCount` is emitted so the two can be
     * told apart: no count means `Get-LocalUser` failed (a domain-joined machine
     * may refuse it), and this returns `null` rather than "none found".
     */
    private fun passwordlessAccounts(): List<String>? {
        if (one("acct.userCount") == null) return null
        return all("acct.passwordless").orEmpty()
    }

    /**
     * Whether waking the screen asks for a password.
     *
     * Only answerable via the screensaver settings. Windows 11's "require
     * sign-in on wake" lives in a power setting that `powercfg` hides by default
     * and does not expose to an unprivileged query, so on a machine with no
     * screensaver configured this returns `null` and `DSK-LOCK-001` reports not
     * checkable. Guessing "yes, it locks" from a machine that never said so
     * would be the single most reassuring lie in the app.
     */
    private fun lockOnWakeEnabled(): Boolean? {
        val active = one("lock.screenSaverActive")
        if (active == null || active == "0") return null
        val secure = one("lock.screenSaverIsSecure") ?: return null
        return secure == "1"
    }

    // -------------------------------------------------------- remote access

    private fun remoteAccessServices(): List<RemoteAccessService>? {
        val rdpDenied = one("rdp.denyConnections") ?: return null
        val nla = one("rdp.userAuthentication")?.let { it == "1" }
        val sshStatus = one("ssh.status")

        return buildList {
            add(
                RemoteAccessService(
                    name = "Remote Desktop",
                    enabled = rdpDenied == "0",
                    port = 3389,
                    hardened = nla
                )
            )
            if (sshStatus != null) {
                add(
                    RemoteAccessService(
                        name = "OpenSSH Server",
                        enabled = sshStatus.equals("Running", ignoreCase = true),
                        port = 22
                    )
                )
            }
        }
    }

    /**
     * Sockets in LISTEN state.
     *
     * Reads the same kernel table `netstat` prints. Nothing is connected to, and
     * the desktop build has no code path that could — `assertNoNetworkBytecode`
     * fails the build if one ever appears.
     */
    private fun listeningPorts(): List<ListeningPort>? = all("port")?.mapNotNull { row ->
        val parts = row.split('\t')
        if (parts.size < 2) return@mapNotNull null
        val port = parts[1].toIntOrNull() ?: return@mapNotNull null
        ListeningPort(
            address = parts[0],
            port = port,
            process = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
        )
    }

    // ---------------------------------------------------------- persistence

    /**
     * Programs that start at sign-in: the two Run keys and the two Startup
     * folders, which is where consumer malware actually lives.
     *
     * Deliberately *not* a full Autoruns sweep — services and scheduled tasks
     * need elevation to enumerate reliably, and a partial sweep presented as
     * complete is the kind of half-truth this app exists to avoid. The finding
     * says "starts automatically", never "this is everything that does".
     */
    private fun autoRunEntries(): List<AutoRunEntry>? = all("autorun")?.mapNotNull { row ->
        val parts = row.split('\t')
        if (parts.size < 2 || parts[0].isBlank()) return@mapNotNull null
        AutoRunEntry(
            name = parts[0],
            location = parts[1],
            command = parts.getOrNull(2)?.takeIf { it.isNotBlank() }?.take(200),
            // "Valid" / "NotSigned" / anything else. Only a positive "NotSigned"
            // becomes false; an unverifiable path stays null, and DSK-AUTO-001
            // ignores nulls rather than accusing a legitimate tool.
            signedByKnownVendor = when (parts.getOrNull(3)) {
                "Valid" -> true
                "NotSigned", "HashMismatch" -> false
                else -> null
            }
        )
    }

    // ------------------------------------------------------ installed software

    /**
     * What the uninstall registry reports.
     *
     * Returns `null` only when the enumeration itself failed, so "nothing
     * installed" and "could not look" stay distinguishable — an empty list from
     * a working query is a real answer.
     */
    private fun installedPrograms(): List<InstalledProgram>? {
        if (one("program.enumerated") == null) return null
        return all("program").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val name = f.getOrNull(0)?.trim().orEmpty()
            if (name.isEmpty()) return@mapNotNull null
            InstalledProgram(
                name = name,
                version = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() },
                publisher = f.getOrNull(2)?.trim()?.takeIf { it.isNotBlank() },
                installLocation = f.getOrNull(3)?.trim()?.takeIf { it.isNotBlank() },
                userWritableLocation = f.getOrNull(4)?.trim().equals("True", ignoreCase = true)
            )
        }
    }

    // ------------------------------------------------ shared mobile-ish facts

    /**
     * BitLocker on the system volume, via the shell property.
     *
     * `Get-BitLockerVolume` needs elevation on most builds;
     * `System.Volume.BitLockerProtection` does not. Values: 1 on, 2 off, 3
     * encrypting, 6 on-but-suspended. Suspended counts as *not* protecting,
     * because that is exactly what it means — the key is sitting in the clear.
     */
    override fun diskEncrypted(): Boolean? = when (one("bitlocker.protection")) {
        "1", "5" -> true
        "2", "6" -> false
        else -> null
    }

    /**
     * Sign-in credential strength.
     *
     * Windows will not tell an unprivileged app whether the current user signs
     * in with a PIN, a password or a picture, so the only genuinely observable
     * fact is whether a credential is required at all. Everything else is
     * [ScreenLock.UNKNOWN], which `ACC-LOCK-001` treats as not checkable rather
     * than grading a strength nobody measured.
     */
    override fun screenLock(): ScreenLock? = when (bool("acct.currentPasswordRequired")) {
        false -> ScreenLock.NONE
        true -> ScreenLock.UNKNOWN
        null -> null      // domain or Microsoft account: not a local user
    }

    override fun screenLockTimeoutSeconds(): Int? = int("lock.screenSaverTimeout")

    /**
     * Certificates added to this user's root store and not present machine-wide.
     *
     * See [WindowsProbe] for why the difference is taken rather than the raw
     * user store: Windows mirrors the machine roots into every user, so the
     * naive query returns ~50 legitimate certificates and would have produced
     * fifty critical findings on a healthy machine.
     *
     * Returns an empty list — a real "none found" — when the store was read and
     * held nothing extra, and `null` when it could not be read at all.
     */
    override fun userInstalledCaCerts(): List<CaCertificate>? {
        if (one("cert.storeRead") == null) return null
        return all("cert").orEmpty().mapNotNull { row ->
            val parts = row.split('	')
            if (parts.size < 3) return@mapNotNull null
            CaCertificate(
                subject = parts[0].substringAfter("CN=").substringBefore(',').trim()
                    .ifBlank { parts[0].trim() },
                issuer = parts[1].substringAfter("CN=").substringBefore(',').trim()
                    .ifBlank { parts[1].trim() },
                // Windows exposes the SHA-1 thumbprint here, not SHA-256.
                // Carried as-is rather than relabelled as something it is not.
                sha256 = parts[2].trim().uppercase(),
                notAfterEpochMillis = null,
                mdmInstalled = false
            )
        }
    }

    override fun dnsServers(): List<String>? = all("dns")?.distinct()

    override fun proxyHostPort(): Pair<String, Int>? {
        if (one("proxy.enable") != "1") return null
        val server = one("proxy.server") ?: return null
        // May be "host:port" or "http=host:port;https=host:port".
        val first = server.split(';').firstOrNull()?.substringAfter('=') ?: return null
        val host = first.substringBeforeLast(':').trim().takeIf { it.isNotBlank() } ?: return null
        val port = first.substringAfterLast(':').trim().toIntOrNull() ?: return null
        return host to port
    }
}
