package com.blanktick.desktop.collect

import com.blanktick.core.analysis.DisplaySafe
import com.blanktick.core.model.AiFacts
import com.blanktick.core.model.AntivirusPosture
import com.blanktick.core.model.AutoRunEntry
import com.blanktick.core.model.CaCertificate
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DesktopOs
import com.blanktick.core.model.HardeningFacts
import com.blanktick.core.model.InstalledProgram
import com.blanktick.core.model.CredentialBearingFile
import com.blanktick.core.model.ListeningPort
import com.blanktick.core.model.McpServer
import com.blanktick.core.model.ProcessImage
import com.blanktick.core.model.RemoteAccessService
import com.blanktick.core.model.RemovableDrive
import com.blanktick.core.model.ScreenLock

/**
 * Reads Windows 10/11 security posture.
 *
 * ## One script, not twenty-five
 *
 * Everything below comes from a single PowerShell run (see [WindowsProbe]) that
 * emits `key=value` lines. The first version made one call per question and
 * took minutes; this takes seconds. It also means the entire set of commands
 * Blanktick runs on your machine is one readable block of text you can paste into a
 * terminal and compare against what the app showed you.
 *
 * ## Everything here is unprivileged
 *
 * Blanktick does not ask for elevation and must work as a standard user. That shaped
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

    /**
     * Set for the duration of one [collect] call so the hash lookups below can
     * reach the bundled table without every private helper taking a parameter.
     */
    private var knownMalware: ((String) -> Boolean?)? = null

    /**
     * Resolves one file hash against the bundled corpus.
     *
     * `null` when there is no corpus, when the file could not be hashed, or
     * when the table says nothing — three different reasons that all mean the
     * same thing to a rule: this was not checked. Only a positive match is ever
     * `true`, because the one output this feature must never produce by
     * accident is an accusation.
     */
    /**
     * Verdicts from the scanner already installed, keyed by file path.
     *
     * Built once per collect: the probe emits one row per file it asked about,
     * and both the autorun and process parsers look their own paths up here.
     */
    private val antivirusVerdicts: Map<String, String> by lazy {
        all("avscan").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val path = f.getOrNull(0)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val verdict = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            path.lowercase() to verdict
        }.toMap()
    }

    private fun verdictFor(path: String?): String? =
        path?.trim()?.lowercase()?.let { antivirusVerdicts[it] }

    private fun matchesKnownMalware(sha256: String?): Boolean? {
        val hash = sha256?.trim()?.lowercase()?.takeIf { it.length == 64 } ?: return null
        return knownMalware?.invoke(hash)
    }

    private fun one(key: String): String? = probe[key]?.firstOrNull()
    private fun all(key: String): List<String>? = probe[key]
    private fun bool(key: String): Boolean? = Shell.parseBoolean(one(key))
    private fun int(key: String): Int? = one(key)?.toIntOrNull()

    override fun osBuild(): String? = one("os.build")

    override fun collect(intel: DesktopIntelSnapshot): DesktopFacts {
        knownMalware = intel.isKnownMalware
        // The sentinel, not the row count, decides whether this is an answer.
        // Two profiles enumerated and both enabled is not "the firewall is on"
        // -- Windows has three, and the one that failed to read is exactly the
        // one worth knowing about.
        val profiles = if (one("fw.enumerated") == null) emptyList() else all("fw.profile").orEmpty()
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
            // is a network operation, so Blanktick does not do it, and reports the
            // check as not performed rather than as "nothing pending".
            // No longer permanently null. The Windows Update Agent keeps a local
            // catalogue of what it already knows applies here, and searching it
            // with Online = false opens no connection -- so the answer changes
            // from "we will not ask" to what the machine already knows.
            pendingSecurityUpdates = if (one("update.pendingRead") == null) null
            else int("update.pendingCount"),
            daysSinceLastUpdate = int("update.daysSinceLast"),

            sessionIsAdministrator = bool("acct.sessionIsAdmin"),
            // Get-LocalGroupMember throws mid-enumeration on Azure AD members.
            // Without the sentinel a truncated list reads as the whole group.
            administratorAccounts = if (one("acct.adminEnumerated") == null) null else all("acct.admin").orEmpty(),
            passwordlessAccounts = passwordlessAccounts(),
            guestAccountEnabled = bool("acct.guestEnabled"),
            lockOnWakeEnabled = lockOnWakeEnabled(),

            remoteAccessServices = remoteAccessServices(),
            listeningPorts = listeningPorts(),
            reachableFromNetwork = reachableFromNetwork(),
            listeningPortsUnattributed = int("reachable.unattributed"),
            machineAddedRootCerts = machineAddedRootCerts(),

            autoRunEntries = autoRunEntries(),
            autoRunSourcesUnread = if (all("autorun.read").isNullOrEmpty()) null
            else all("autorun.failed").orEmpty(),
            // Registry names are attacker-choosable text headed for the screen.
            autoRunKeysUnread = if (all("autorun.read").isNullOrEmpty()) null
            else all("autorun.denied").orEmpty().map { DisplaySafe.label(it) }.distinct(),
            installedPrograms = installedPrograms(),

            autoRunBlockedForRemovable = bool("usb.autorunBlocked"),
            removableDrives = removableDrives(),
            rememberedUsbDevices = all("usbdevice")?.map { DisplaySafe.label(it) }?.distinct()?.sorted(),

            runningProcesses = runningProcesses(),
            processesWithUnreadablePath = int("process.pathUnreadable"),
            // Emitted against a file every Windows machine has. Without it,
            // "nothing matched the malware list" and "hashing silently returned
            // nothing" are the same output.
            fileHashingWorks = one("hash.selfTest")?.let { it.length == 64 },
            ai = aiFacts(),
            hardening = hardening(),
            antivirusPosture = antivirusPosture(),

            // Emitted as the probe's last line. Absent means it did not get
            // there, and every fact above is however far it happened to reach.
            collectionCompleted = probe.isNotEmpty() && one("probe.complete") != null,
            collectionTruncated = Shell.lastRunTruncated,
            probeLanguageMode = one("ps.languageMode")
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
    private fun listeningPorts(): List<ListeningPort>? {
        // An empty port table is a real and good answer; a failed read is not.
        if (one("port.enumerated") == null) return null
        return all("port").orEmpty().mapNotNull { row ->
        val parts = row.split('\t')
        if (parts.size < 2) return@mapNotNull null
        val port = parts[1].toIntOrNull() ?: return@mapNotNull null
        ListeningPort(
            address = parts[0],
            port = port,
            process = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
        )
        }
    }

    /**
     * Listening sockets an inbound firewall rule actually permits.
     *
     * Joined on the PROGRAM rather than the port, which is how Windows firewall
     * rules are written: 254 inbound allow rules on the development machine,
     * only 72 naming a specific program, and almost all of them with
     * `LocalPort=Any`. Joining on port concludes everything is allowed.
     */
    private fun reachableFromNetwork(): List<ListeningPort>? {
        if (one("reachable.enumerated") == null) return null
        return all("reachable").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val port = f.getOrNull(0)?.trim()?.toIntOrNull() ?: return@mapNotNull null
            ListeningPort(
                address = "0.0.0.0",
                port = port,
                process = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() }
                    ?.substringAfterLast('\\')?.let { DisplaySafe.label(it) }
            )
        }
    }

    /** Machine-wide roots Windows did not deliver and policy did not deploy. */
    private fun machineAddedRootCerts(): List<CaCertificate>? {
        if (one("machinecert.enumerated") == null) return null
        return all("machinecert").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val subject = f.getOrNull(0)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            CaCertificate(
                subject = DisplaySafe.label(subject),
                issuer = DisplaySafe.label(f.getOrNull(1)?.trim().orEmpty()),
                sha256 = f.getOrNull(2)?.trim().orEmpty()
            )
        }
    }

    // ---------------------------------------------------------- persistence

    /**
     * Programs that start themselves, from every mechanism that can be read
     * without elevation.
     *
     * ## What changed, and why the old comment here was the bug
     *
     * This used to read four locations -- two Run keys, two Startup folders --
     * under a comment stating that services and scheduled tasks "need elevation
     * to enumerate reliably" and that a partial sweep presented as complete was
     * the kind of half-truth this app exists to avoid.
     *
     * The second half of that was right and the first half was false. Measured
     * in a plain non-elevated session: `Get-ScheduledTask` returned all 210
     * tasks and `Win32_Service` all 306. So the app was performing exactly the
     * partial sweep its own comment warned against, and the justification for
     * doing so did not survive being tested.
     *
     * Concretely, on the development machine: 9 entries shown, 39 more sitting
     * in places never looked at -- 20 third-party scheduled tasks, 15
     * auto-start services outside system32, 2 RunOnce values, and Winlogon's
     * `Shell` and `Userinit`. Scheduled tasks are where commodity malware
     * actually persists now, for the same reason burglars stopped trying the
     * front door.
     *
     * Still not everything: WMI event subscriptions and COM hijacks are not
     * read, and the finding says "starts automatically", never "this is
     * everything that does".
     */
    private fun autoRunEntries(): List<AutoRunEntry>? {
        // At least one source has to have worked. Rows from the sources that
        // did are kept even when another failed; which ones failed is reported
        // separately in autoRunSourcesUnread rather than folded into silence.
        if (all("autorun.read").isNullOrEmpty()) return null
        return all("autorun").orEmpty().mapNotNull { row ->
            val parts = row.split('	')
            if (parts.size < 2 || parts[0].isBlank()) return@mapNotNull null
            AutoRunEntry(
                // Attacker-chosen text on its way to a screen. A right-to-left
                // override here reverses how the rest of the row reads.
                name = DisplaySafe.label(parts[0]),
                location = parts[1],
                command = parts.getOrNull(2)?.takeIf { it.isNotBlank() }?.take(200),
                // "Valid" / "NotSigned" / anything else. Only a positive "NotSigned"
                // becomes false; an unverifiable path stays null, and DSK-AUTO-001
                // ignores nulls rather than accusing a legitimate tool.
                signedByKnownVendor = when {
                    // A binary inside an MSIX/Store package carries no
                    // Authenticode signature of its own -- the PACKAGE is
                    // signed, and Windows verifies it at install time. Reading
                    // "NotSigned" off one of these and calling it unsigned
                    // would accuse every Store app on the machine, starting
                    // with Intel's own graphics service on this one. We cannot
                    // verify the package signature from here, so the honest
                    // answer is that this route cannot tell -- null, not false.
                    parts.getOrNull(2)?.contains(WINDOWS_APPS, ignoreCase = true) == true -> null
                    else -> when (parts.getOrNull(3)) {
                        "Valid" -> true
                        "NotSigned", "HashMismatch" -> false
                        else -> null
                    }
                },
                kind = parts.getOrNull(4)?.takeIf { it.isNotBlank() },
                usesSystemBinary = parts.getOrNull(5)?.let { it.equals("True", ignoreCase = true) },
                downloadedFromInternet = parts.getOrNull(6)?.let { it.equals("True", ignoreCase = true) },
                sha256 = parts.getOrNull(7)?.trim()?.takeIf { it.length == 64 },
                matchesKnownMalware = matchesKnownMalware(parts.getOrNull(7)),
                // Keyed on the RESOLVED executable (field 8), not the command
                // line: the command may carry arguments and quoting, and the
                // scanner was handed the resolved path.
                antivirusVerdict = verdictFor(parts.getOrNull(8))
            )
        }
    }

    /**
     * Programs running right now that are worth a second look.
     *
     * Only masquerading processes and those running from user-writable folders
     * are collected. An inventory of the several hundred processes a Windows
     * machine runs is not information, and the two questions worth asking
     * without a malware corpus — is it pretending to be a system binary, and
     * did it come from a folder anyone can write to — are answerable from that
     * subset alone.
     */
    private fun runningProcesses(): List<ProcessImage>? {
        if (one("process.enumerated") == null) return null
        return all("process").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val name = f.getOrNull(0)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val path = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            ProcessImage(
                name = DisplaySafe.label(name),
                path = path,
                signatureStatus = f.getOrNull(2)?.trim()?.takeIf { it.isNotBlank() },
                masqueradingAs = f.getOrNull(3)?.trim()?.takeIf { it.isNotBlank() },
                downloadedFromInternet = f.getOrNull(4)?.trim()?.equals("True", ignoreCase = true),
                sha256 = f.getOrNull(5)?.trim()?.takeIf { it.length == 64 },
                matchesKnownMalware = matchesKnownMalware(f.getOrNull(5)),
                antivirusVerdict = verdictFor(f.getOrNull(1))
            )
        }
    }

    /**
     * Tools granted to a language model, and Windows' own AI features.
     *
     * `null` until the config files have been looked at, so "no MCP servers
     * configured" stays distinguishable from "the files were never read".
     */
    private fun aiFacts(): AiFacts? {
        if (one("ai.configsRead") == null) return null
        return AiFacts(
            mcpServers = all("ai.mcpServer").orEmpty().mapNotNull { row ->
                val f = row.split('	')
                val name = f.getOrNull(0)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                McpServer(
                    name = DisplaySafe.label(name),
                    launcher = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() }
                        ?.let { DisplaySafe.label(it) },
                    configFile = f.getOrNull(2)?.trim().orEmpty()
                )
            },
            configsWithCredentials = all("ai.configSecrets").orEmpty().mapNotNull { row ->
                val f = row.split('	')
                val path = f.getOrNull(0)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                CredentialBearingFile(path, f.getOrNull(1)?.trim()?.toIntOrNull() ?: 1)
            },
            recallDisabled = bool("ai.recallDisabled"),
            recallStorePresent = bool("ai.recallStorePresent"),
            recallArtifactCount = int("ai.recallArtifacts")
        )
    }

    // ------------------------------------------------------------- hardening

    /**
     * Settings that decide how far an attacker gets after arriving.
     *
     * ## Absence means different things in different rows, and that is the work
     *
     * Three of these are absent from the registry on a perfectly healthy
     * machine, and absence does **not** carry the same meaning in each:
     *
     * - `WDigest` absent means **off**. Microsoft changed the default in 2014,
     *   so the key is only written when someone re-enables plaintext credential
     *   caching. Absence is a pass.
     * - `SMB1` absent means **off**, same reasoning.
     * - `LLMNR` absent means **on**. Disabling it requires writing the policy,
     *   so the missing key is the insecure state, not the safe one.
     *
     * Treating all three the same way would either accuse every machine alive
     * or quietly reassure about the one that is actually exposed. This is the
     * same asymmetry the AutoRun policy has, and it is why each of these is
     * resolved here rather than by a generic "absent means secure" helper.
     */
    private fun hardening(): HardeningFacts? {
        if (one("hard.settingsRead") == null) return null
        return HardeningFacts(
            uacEnabled = one("hard.enableLua")?.let { it == "1" },
            // 0 = elevate silently, with no prompt at all.
            uacPromptsForElevation = one("hard.consentPrompt")?.let { it != "0" },
            // 0, 1 and 2 are all "protected"; only an absent value is unknown.
            lsaProtected = one("hard.runAsPPL")?.let { it != "0" },
            plaintextCredentialsInMemory = one("hard.wdigest")?.let { it == "1" } ?: false,
            smb1Enabled = one("hard.smb1")?.let { it == "1" } ?: false,
            // Absent = enabled. The inverse of the two above.
            llmnrEnabled = one("hard.llmnr")?.let { it != "0" } ?: true,
            powerShellV2Available = Shell.parseBoolean(one("hard.psV2Present")),
            autoLogonEnabled = one("hard.autoAdminLogon")?.let { it == "1" } ?: false,
            autoLogonPasswordStored = Shell.parseBoolean(one("hard.autoLogonPasswordStored")),
            remoteManagementRunning = one("hard.winrmStatus")?.equals("Running", true),
            remoteRegistryRunning = one("hard.remoteRegistry")?.equals("Running", true)
        )
    }

    /**
     * What the antivirus is doing, which is a different question from what is
     * on the disk.
     *
     * Blanktick has no scanner and no network, so it cannot offer a second opinion
     * about files. It can read whether the scanner already present has been
     * quietly switched off in part, and whether it found something it never
     * finished dealing with — both entirely local, and neither surfaced by any
     * consumer tool this project has looked at.
     */
    private fun antivirusPosture(): AntivirusPosture? {
        val defender = one("av.defenderPresent") ?: return null
        if (defender.isBlank()) return null
        return AntivirusPosture(
            tamperProtectionEnabled = bool("av.tamperProtected"),
            behaviourMonitoringEnabled = bool("av.behaviorMonitor"),
            downloadScanningEnabled = bool("av.ioavProtection"),
            networkInspectionEnabled = bool("av.networkInspection"),
            antiSpywareEnabled = bool("av.antispyware"),
            knownThreatCount = int("av.threatsKnown"),
            // Only an answer if the threat list was actually readable; an empty
            // list from a failed query would read as "nothing active".
            activeThreatNames = if (one("av.threatsRead") == null) null
            else all("av.threatActive").orEmpty(),
            // Almost always null on Windows: the exclusion list needs
            // administrator rights, and Blanktick does not ask for them. Reported as
            // a blind spot rather than as "no exclusions are configured".
            exclusionPaths = if (bool("av.exclusionsReadable") == true) all("av.exclusion").orEmpty()
            else null
        )
    }

    // -------------------------------------------------------- removable media

    /**
     * Drives attached right now.
     *
     * `null` only when the enumeration failed, so "nothing plugged in" (an empty
     * list) stays distinguishable from "could not look". `DSK-USB-002` treats
     * both as not-checkable, but for different reasons, and the probe screen
     * shows which.
     */
    private fun removableDrives(): List<RemovableDrive>? {
        if (one("drive.enumerated") == null) return null
        return all("drive").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val letter = f.getOrNull(0)?.trim()?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            RemovableDrive(
                letter = letter + ":",
                label = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() }?.let { DisplaySafe.label(it) },
                fileSystem = f.getOrNull(2)?.trim()?.takeIf { it.isNotBlank() },
                sizeBytes = f.getOrNull(3)?.trim()?.toLongOrNull(),
                // Same shell property as the system drive: 1 and 5 are protected,
                // 2 and 6 are not, anything else is unknown and stays null rather
                // than being rounded towards a verdict.
                encrypted = when (f.getOrNull(4)?.trim()) {
                    "1", "5" -> true
                    "2", "6" -> false
                    else -> null
                }
            )
        }
    }

    // ------------------------------------------------------ installed software

    /**
     * What the uninstall registry AND the Store/UWP package list report — the
     * probe emits both as `program` rows, so together they match Settings > Apps.
     *
     * Returns `null` only when the registry enumeration itself failed, so "nothing
     * installed" and "could not look" stay distinguishable — an empty list from
     * a working query is a real answer. (The Store pass is additive and does not
     * gate the sentinel; if only it fails, the registry list still stands.)
     */
    private fun installedPrograms(): List<InstalledProgram>? {
        if (one("program.enumerated") == null) return null
        return all("program").orEmpty().mapNotNull { row ->
            val f = row.split('	')
            val name = f.getOrNull(0)?.trim().orEmpty()
            if (name.isEmpty()) return@mapNotNull null
            InstalledProgram(
                name = DisplaySafe.label(name),
                version = f.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() },
                publisher = f.getOrNull(2)?.trim()?.takeIf { it.isNotBlank() }?.let { DisplaySafe.label(it) },
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

    private companion object {
        /** Store/MSIX install root. Binaries here are signed at package level. */
        const val WINDOWS_APPS = "\\Program Files\\WindowsApps\\"
    }

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
