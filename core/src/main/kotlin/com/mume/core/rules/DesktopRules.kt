package com.mume.core.rules

import com.mume.core.model.Category
import com.mume.core.model.DesktopFacts
import com.mume.core.model.DesktopOs
import com.mume.core.model.DeviceSnapshot
import com.mume.core.intel.EolCatalog
import com.mume.core.model.Finding
import com.mume.core.model.Severity

/**
 * Checks that only exist on a desktop.
 *
 * ## Why these are separate rules, not desktop branches inside the mobile ones
 *
 * A phone and a laptop fail in different places. The phone's threat is a
 * malicious app inside a sandbox; the laptop's is an account with administrator
 * rights, a program that starts itself at login, and a service quietly
 * listening on every interface. Forcing those into `DEV-ROOT-001` would produce
 * a rule whose description is true on neither platform.
 *
 * ## The honesty rule still binds, harder
 *
 * A desktop will happily answer a question wrongly. `netsh` prints a firewall
 * profile that is "ON" while a third-party firewall has taken over; a Linux box
 * may have `ufw` inactive and `nftables` doing the work. Wherever the collector
 * cannot distinguish "off" from "I do not understand this configuration", it
 * must pass `null` and the rule below reports *not checkable*. Every one of
 * these rules therefore begins by unwrapping a nullable, and none of them
 * treats a missing answer as good news.
 */
object DesktopRules {

    /** Shorthand: unwrap the desktop block, or report not-checkable. */
    private inline fun facts(s: DeviceSnapshot, body: (DesktopFacts) -> RuleOutcome): RuleOutcome =
        s.desktop?.let(body) ?: RuleOutcome.NotApplicable

    // ------------------------------------------------------------ perimeter

    /**
     * The host firewall.
     *
     * On a laptop this is the highest-value setting in this file: it is what
     * stands between a service bound to `0.0.0.0` and everyone else on the cafe
     * Wi-Fi. Scored HIGH rather than CRITICAL because a machine behind a home
     * router is not immediately exposed - but the same machine leaves the house.
     */
    val FirewallOff = object : BaseRule(
        id = "DSK-FW-001",
        category = Category.NETWORK,
        description = "Firewall is protecting this machine",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val enabled = d.firewallEnabled ?: return@facts RuleOutcome.NotApplicable
            val off = d.firewallProfilesOff.orEmpty()
            if (enabled && off.isEmpty()) return@facts RuleOutcome.Pass

            // "Some profiles off" is the more common and more dangerous case:
            // people turn off the Public profile to fix a printer and never turn
            // it back on, which disarms the firewall precisely when the machine
            // leaves a trusted network.
            val partial = enabled && off.isNotEmpty()
            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (partial) Severity.MEDIUM else Severity.HIGH,
                    title = if (partial) "Firewall is off for: " + off.joinToString(", ")
                    else "The firewall is switched off",
                    detail = if (partial)
                        "The firewall is running, but not for " + off.joinToString(" or ") +
                            ". That is usually the profile in use on public Wi-Fi, so it is off " +
                            "exactly when it matters most."
                    else
                        "Any service running on this machine is reachable by every other device " +
                            "on the same network. On a home network that is your household; on " +
                            "cafe or hotel Wi-Fi it is everyone in the building.",
                    remediation = when (d.os) {
                        DesktopOs.WINDOWS ->
                            "Windows Security, then Firewall & network protection: turn it on for " +
                                "every profile, especially Public."
                        DesktopOs.MACOS ->
                            "System Settings, then Network, then Firewall: turn it on."
                        DesktopOs.LINUX ->
                            "Enable your firewall, for example `sudo ufw enable` or " +
                                "`sudo systemctl enable --now firewalld`."
                    },
                    evidence = mapOf("profilesOff" to off.joinToString(","))
                )
            )
        }
    }

    /**
     * Inbound remote control: RDP, SSH, VNC, Remote Management.
     *
     * Almost nobody who has this on at home turned it on deliberately, and it is
     * the front door credential-stuffing actually walks through.
     */
    val RemoteAccessEnabled = object : BaseRule(
        id = "DSK-RMT-001",
        category = Category.NETWORK,
        description = "No remote-control service is accepting connections",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val services = d.remoteAccessServices ?: return@facts RuleOutcome.NotApplicable
            val on = services.filter { it.enabled }
            if (on.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                on.map { svc ->
                    // A hardened service (RDP with Network Level Authentication,
                    // SSH with keys only) is a considered choice, not an
                    // accident. It is still reported, but not scored as though
                    // the door were standing open.
                    val hardened = svc.hardened == true
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = if (hardened) Severity.LOW else Severity.HIGH,
                        title = svc.name + " is accepting incoming connections",
                        detail = if (hardened)
                            svc.name + " is enabled but requires authentication before a session " +
                                "starts, which blocks the automated attempts. Worth confirming you " +
                                "still need it."
                        else
                            svc.name + " lets someone connect to this machine over the network and " +
                                "control it. Services like this are scanned for continuously and " +
                                "attacked with lists of leaked passwords.",
                        remediation = if (hardened)
                            "If you no longer use " + svc.name + ", turn it off."
                        else
                            "Turn " + svc.name + " off unless you actively use it. If you need it, " +
                                "require multi-factor or key-based sign-in and do not expose it to " +
                                "the internet.",
                        subjectId = svc.name,
                        evidence = buildMap {
                            svc.port?.let { put("port", it.toString()) }
                            svc.hardened?.let { put("hardened", it.toString()) }
                        }
                    )
                }
            )
        }
    }

    /**
     * Sockets bound to every interface rather than loopback.
     *
     * Reported as one aggregate finding: the decision the user faces is "do I
     * need any of these", and ten separate cards would push everything else off
     * the screen while adding no information.
     */
    val PubliclyBoundServices = object : BaseRule(
        id = "DSK-PORT-001",
        category = Category.NETWORK,
        description = "No unexpected service is listening to the whole network",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        /**
         * Ports the OS itself binds publicly as a matter of course.
         *
         * Excluded not because they are harmless, but because flagging file
         * sharing and mDNS on every machine would train the user to ignore this
         * rule, and a check people learn to dismiss protects nobody.
         */
        private val EXPECTED = setOf(137, 138, 139, 445, 1900, 3702, 5353, 5355)

        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ports = d.listeningPorts ?: return@facts RuleOutcome.NotApplicable

            // ## Listening is not reachable, and the firewall already knows
            //
            // This rule used to report every publicly-bound socket. On the
            // development machine that was "17 services are reachable from the
            // whole network" for 9 points -- and it was not true. Windows blocks
            // inbound by default; of 25 sockets bound to all interfaces, exactly
            // 2 belonged to a program the firewall actually permits, and both
            // were the developer's own HTTP servers.
            //
            // So when the firewall's answer is available, it is used, and the
            // finding describes what is genuinely reachable. Without it the old
            // behaviour stands, because "bound to every interface" remains the
            // honest worst case when nothing better can be established.
            val reachable = d.reachableFromNetwork
            val exposed = (reachable ?: ports.filter { it.isPubliclyBound })
                .filter { it.port !in EXPECTED }
                .distinctBy { it.port }
                .sortedBy { it.port }
            if (exposed.isEmpty()) return@facts RuleOutcome.Pass

            val listed = exposed.joinToString(", ") { p ->
                if (p.process != null) p.port.toString() + " (" + p.process + ")" else p.port.toString()
            }
            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (exposed.size >= 4) Severity.MEDIUM else Severity.LOW,
                    title = exposed.size.toString() +
                        (if (reachable != null) " service(s) are reachable from the network"
                        else " service(s) are listening to the whole network"),
                    detail = "These are listening on every network interface rather than only on " +
                        "this machine: " + listed + ". That is fine at home behind a router, and " +
                        "not fine on shared Wi-Fi.",
                    remediation = "Close anything you do not recognise, and make sure the firewall " +
                        "is on for public networks.",
                    evidence = mapOf("ports" to exposed.joinToString(",") { it.port.toString() })
                )
            )
        }
    }

    // ------------------------------------------------------ malware defence

    val RealtimeProtectionOff = object : BaseRule(
        id = "DSK-AV-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Real-time malware protection is running",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.antivirusRealtimeEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "Real-time malware protection is switched off",
                    detail = "Files are not being checked as they are opened or downloaded. This is " +
                        "often switched off temporarily to install something, and then never " +
                        "switched back on.",
                    remediation = when (d.os) {
                        DesktopOs.WINDOWS ->
                            "Windows Security, then Virus & threat protection: turn Real-time " +
                                "protection back on."
                        DesktopOs.MACOS ->
                            "Re-enable your security software, and confirm Gatekeeper is on."
                        DesktopOs.LINUX ->
                            "Re-enable on-access scanning in your security software."
                    },
                    evidence = buildMap { d.antivirusProduct?.let { put("product", it) } }
                )
            )
        }
    }

    /**
     * Definition age.
     *
     * Scaled by how stale: a week behind is a nag, three months behind means the
     * scanner has been inert through an entire threat cycle.
     */
    val StaleSignatures = object : BaseRule(
        id = "DSK-AV-002",
        category = Category.DEVICE_INTEGRITY,
        description = "Malware definitions are current",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        private val ACCEPTABLE_DAYS = 7

        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val age = d.antivirusSignatureAgeDays ?: return@facts RuleOutcome.NotApplicable
            if (age <= ACCEPTABLE_DAYS) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (age >= 30) Severity.MEDIUM else Severity.LOW,
                    title = "Malware definitions are " + age + " days old",
                    detail = "The scanner is running, but it is looking for last month's threats. " +
                        "Definitions normally update daily; " + age + " days usually means updates " +
                        "are failing rather than merely late.",
                    remediation = "Check for updates by hand. If that fails, the failure is itself " +
                        "worth investigating: malware disables updates.",
                    weightMultiplier = if (age >= 90) 1.5 else 1.0,
                    evidence = mapOf("ageDays" to age.toString())
                )
            )
        }
    }

    /** SmartScreen / Gatekeeper: the check that runs before you launch a download. */
    val AppReputationOff = object : BaseRule(
        id = "DSK-REP-001",
        category = Category.APP_HYGIENE,
        description = "Downloaded programs are checked before they run",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.appReputationEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            val name = when (d.os) {
                DesktopOs.WINDOWS -> "SmartScreen"
                DesktopOs.MACOS -> "Gatekeeper"
                DesktopOs.LINUX -> "Package signature checking"
            }
            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = name + " is switched off",
                    detail = "Programs you download will start without any warning, even ones the " +
                        "system has never seen before and cannot attribute to anyone. This is the " +
                        "warning that stops most accidental installs.",
                    remediation = when (d.os) {
                        DesktopOs.WINDOWS ->
                            "Windows Security, then App & browser control: turn on " +
                                "Reputation-based protection."
                        DesktopOs.MACOS ->
                            "System Settings, then Privacy & Security: allow apps from the App " +
                                "Store and identified developers."
                        DesktopOs.LINUX ->
                            "Re-enable signature verification for your package manager, and stop " +
                                "installing packages with checks bypassed."
                    }
                )
            )
        }
    }

    // ------------------------------------------------------- boot integrity

    val SecureBootOff = object : BaseRule(
        id = "DSK-BOOT-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Secure Boot is enabled",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.secureBootEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "Secure Boot is off",
                    detail = "The machine does not verify the software that loads before the " +
                        "operating system does. Malware that installs itself there survives " +
                        "reinstalling the operating system entirely.",
                    remediation = "Turn Secure Boot on in the firmware (UEFI) settings. On a " +
                        "dual-boot machine this can stop the other system booting, so check what " +
                        "else is installed first.",
                    evidence = mapOf("os" to d.os.displayName)
                )
            )
        }
    }

    /** SIP is macOS-only; elsewhere the field is null and this is not checkable. */
    val SystemIntegrityProtectionOff = object : BaseRule(
        id = "DSK-SIP-001",
        category = Category.DEVICE_INTEGRITY,
        description = "System Integrity Protection is enabled",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.systemIntegrityProtectionEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "System Integrity Protection is disabled",
                    detail = "SIP stops even an administrator from modifying the operating system " +
                        "itself. Turning it off requires booting into recovery, so it is never " +
                        "accidental, but people forget to turn it back on afterwards.",
                    remediation = "Reboot into Recovery, open Terminal, run `csrutil enable`, then " +
                        "restart."
                )
            )
        }
    }

    // -------------------------------------------------------------- updates

    val AutomaticUpdatesOff = object : BaseRule(
        id = "DSK-UPD-001",
        category = Category.OS_CURRENCY,
        description = "Security updates install automatically",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.automaticUpdatesEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "Updates are not installing on their own",
                    detail = "Fixes for actively exploited flaws only protect you once installed. " +
                        "Updating by hand works right up until the month you are busy.",
                    remediation = "Turn automatic updates back on, and set an active-hours window " +
                        "if surprise restarts are the reason they were switched off."
                )
            )
        }
    }

    val PendingSecurityUpdates = object : BaseRule(
        id = "DSK-UPD-002",
        category = Category.OS_CURRENCY,
        description = "No security updates are waiting to install",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val pending = d.pendingSecurityUpdates ?: return@facts RuleOutcome.NotApplicable
            if (pending == 0) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (pending >= 5) Severity.HIGH else Severity.MEDIUM,
                    title = pending.toString() + " security update(s) are waiting",
                    detail = "These have been offered or downloaded and not applied. What each one " +
                        "fixes is public information, which is exactly what makes an unpatched " +
                        "machine worth attacking.",
                    remediation = "Install them and restart. If a restart keeps being postponed, " +
                        "schedule one now.",
                    evidence = mapOf("pending" to pending.toString())
                )
            )
        }
    }

    val UpdateStalled = object : BaseRule(
        id = "DSK-UPD-003",
        category = Category.OS_CURRENCY,
        description = "Updates have been applied recently",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        private val ACCEPTABLE_DAYS = 60

        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val days = d.daysSinceLastUpdate ?: return@facts RuleOutcome.NotApplicable
            if (days <= ACCEPTABLE_DAYS) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (days >= 180) Severity.HIGH else Severity.MEDIUM,
                    title = "Nothing has been updated for " + days + " days",
                    detail = "Even with automatic updates switched on, nothing has actually " +
                        "installed in " + days + " days. That usually means the update service is " +
                        "broken, out of disk space, or has been disabled by something else.",
                    remediation = "Run an update check by hand and read the error it gives. A " +
                        "silently failing updater deserves more attention than a late one.",
                    weightMultiplier = if (days >= 365) 1.5 else 1.0,
                    evidence = mapOf("daysSinceLastUpdate" to days.toString())
                )
            )
        }
    }

    // ------------------------------------------------------------- accounts

    val PasswordlessAccount = object : BaseRule(
        id = "DSK-ACC-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Every account needs a password to sign in",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val accounts = d.passwordlessAccounts ?: return@facts RuleOutcome.NotApplicable
            if (accounts.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.CRITICAL,
                    title = accounts.size.toString() + " account(s) sign in with no password",
                    detail = "Anyone with the machine in front of them can sign in as " +
                        accounts.joinToString(", ") + " without knowing anything at all. An " +
                        "account with no password also cannot protect anything encrypted with it.",
                    remediation = "Set a password on each of these accounts, or delete the ones " +
                        "nobody uses.",
                    evidence = mapOf("accounts" to accounts.joinToString(","))
                )
            )
        }
    }

    val DailyDriverIsAdmin = object : BaseRule(
        id = "DSK-ADM-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Everyday account does not hold administrator rights",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val isAdmin = d.sessionIsAdministrator ?: return@facts RuleOutcome.NotApplicable
            if (!isAdmin) return@facts RuleOutcome.Pass

            // Deliberately MEDIUM, not HIGH. On a personal machine this is the
            // overwhelmingly common setup, and a rule that tells nearly every
            // home user their computer is badly broken is a rule they stop
            // reading. It is real, it is worth saying once, it is not an
            // emergency.
            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "You are signed in as an administrator",
                    detail = "Anything you run inherits the power to change the whole system. Most " +
                        "malware that gets a foothold only becomes serious at this point; on a " +
                        "standard account it usually cannot.",
                    remediation = "Create a second account for day-to-day use and keep the " +
                        "administrator one for installing things. It is a mild inconvenience and " +
                        "it removes a whole class of damage.",
                    evidence = buildMap {
                        d.administratorAccounts?.let { put("administrators", it.size.toString()) }
                    }
                )
            )
        }
    }

    val GuestAccountEnabled = object : BaseRule(
        id = "DSK-ACC-002",
        category = Category.ACCOUNT_SECURITY,
        description = "The guest account is disabled",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.guestAccountEnabled ?: return@facts RuleOutcome.NotApplicable
            if (!on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "The guest account is enabled",
                    detail = "Guest gives anyone a way onto the machine without a password. It is " +
                        "off by default, so something turned it on.",
                    remediation = "Disable the guest account unless you are deliberately sharing " +
                        "this machine with strangers."
                )
            )
        }
    }

    val LockOnWakeOff = object : BaseRule(
        id = "DSK-LOCK-001",
        category = Category.ACCOUNT_SECURITY,
        description = "A password is required when the screen wakes",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.lockOnWakeEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "The screen unlocks without a password",
                    detail = "A sign-in password only protects the machine while it is asking for " +
                        "one. Waking this machine from sleep goes straight back to your desktop.",
                    remediation = "Turn on the option to require a password when the screen wakes, " +
                        "and set the delay to a minute or less."
                )
            )
        }
    }

    // ---------------------------------------------------------- persistence

    /**
     * Programs that start themselves.
     *
     * This is where desktop malware lives, and it is also where every printer
     * utility ever written lives. So the rule reports only entries the platform
     * positively identified as *not* signed by a recognised vendor. An entry
     * whose signature simply could not be checked (`null`) is excluded, because
     * on Linux that is nearly all of them, and a rule that fires on everything
     * says nothing.
     */
    val UnsignedAutoRuns = object : BaseRule(
        id = "DSK-AUTO-001",
        category = Category.APP_HYGIENE,
        description = "Programs that start automatically are recognised",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        /** Cap on cards emitted. The decay curve makes the sixth worth ~0.08 points. */
        private val MAX_REPORTED = 5

        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val entries = d.autoRunEntries ?: return@facts RuleOutcome.NotApplicable
            val unsigned = entries.filter { it.signedByKnownVendor == false }
            if (unsigned.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                unsigned.take(MAX_REPORTED).map { entry ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "\"" + entry.name + "\" starts automatically and is not signed",
                        detail = "It is configured at " + entry.location + " and runs every time " +
                            "you sign in, without a verifiable publisher. Legitimate small tools " +
                            "are often unsigned too, but this is where things that want to persist " +
                            "put themselves.",
                        remediation = "If you do not recognise it, stop it starting automatically, " +
                            "and look up the file it runs before deleting anything.",
                        subjectId = entry.name,
                        evidence = buildMap {
                            put("location", entry.location)
                            entry.command?.let { put("command", it) }
                        }
                    )
                }
            )
        }
    }

    // ---------------------------------------------------- installed software

    /**
     * Software the vendor stopped patching.
     *
     * Matched against [EolCatalog], which contains only products whose end of
     * life has already happened and is final — so this list can go out of date
     * by becoming incomplete, never by becoming wrong. Mume cannot know what
     * "current" is without a network, so it does not claim to: "your browser is
     * out of date" is not a check this product offers.
     */
    val EndOfLifeSoftware = object : BaseRule(
        id = "DSK-SW-001",
        category = Category.APP_HYGIENE,
        description = "No software is past its security support",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val programs = d.installedPrograms ?: return@facts RuleOutcome.NotApplicable
            val dead = programs.mapNotNull { p ->
                EolCatalog.match(p.name, p.version)?.let { p to it }
            }
            if (dead.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                dead.take(5).map { (program, entry) ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.HIGH,
                        title = program.name + " no longer gets security fixes",
                        detail = entry.product + " has been unsupported since " +
                            entry.endedYear + ". " + entry.why,
                        remediation = "Uninstall it if you can. If something still needs it, " +
                            "find out what and replace that instead.",
                        subjectId = program.name,
                        evidence = buildMap {
                            put("product", entry.product)
                            put("endedYear", entry.endedYear.toString())
                            program.version?.let { put("version", it) }
                        }
                    )
                }
            )
        }
    }

    /**
     * Software installed where it did not need permission to install.
     *
     * **Neither half is a finding alone**, and that is the point. Plenty of
     * legitimate software lives in a user-writable folder — on the development
     * machine, 11 programs do: every WinGet package, VS Code, PowerToys, Ollama.
     * All eleven declare a publisher. Drive-by installers routinely do not,
     * because filling that field in is a step nobody bothers with when the goal
     * is to arrive unnoticed.
     *
     * Measured before shipping: on that machine this rule produces **zero**
     * findings, while a naive "installed under AppData" rule would have produced
     * seven. A check that fires on a healthy machine is a check people learn to
     * dismiss.
     */
    val UnattributedUserInstall = object : BaseRule(
        id = "DSK-SW-002",
        category = Category.APP_HYGIENE,
        description = "Installed software says who made it",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val programs = d.installedPrograms ?: return@facts RuleOutcome.NotApplicable
            val suspect = programs.filter {
                it.userWritableLocation && it.publisher.isNullOrBlank()
            }
            if (suspect.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                suspect.take(5).map { program ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "\"" + program.name + "\" names no publisher",
                        detail = "It is installed at " + (program.installLocation ?: "a user folder") +
                            ", which needs no administrator permission, and it does not say who " +
                            "made it. Ordinary software fills that in; software that would rather " +
                            "not be noticed often does not.",
                        remediation = "If you did not install it deliberately, uninstall it and " +
                            "look the name up first.",
                        subjectId = program.name,
                        evidence = buildMap {
                            program.installLocation?.let { put("location", it) }
                            program.version?.let { put("version", it) }
                        }
                    )
                }
            )
        }
    }

    // ------------------------------------------------------- removable media

    /**
     * AutoRun re-enabled for removable media.
     *
     * ## Why this fires so rarely, on purpose
     *
     * `autorun.inf` executing itself off a USB stick was how Conficker and a
     * decade of worms spread, and it is the check every "USB security" article
     * still tells you to make. On Windows 10 and 11 it is **already off**:
     * Microsoft disabled autorun for removable drives in 2011 and the policy key
     * is absent on a stock machine precisely because the hardened behaviour is
     * the default.
     *
     * So an absent policy is a **pass**, not a finding and not "not checkable".
     * This rule fires only when someone or something has explicitly written a
     * permissive value back — which is a deliberate act, and worth knowing about.
     *
     * Measured on the development machine before shipping: policy absent in both
     * HKLM and HKCU, so this passes. A rule written the obvious way — "AutoPlay
     * is enabled, warn" — would fire on essentially every Windows machine alive,
     * and a check that always fires is one people learn to dismiss.
     */
    val AutoRunOnRemovable = object : BaseRule(
        id = "DSK-USB-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Programs cannot auto-run from a USB stick",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val blocked = d.autoRunBlockedForRemovable ?: return@facts RuleOutcome.NotApplicable
            if (blocked) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "Programs can start themselves from a plugged-in drive",
                    detail = "The AutoRun policy on this computer has been changed from the " +
                        "Windows default to allow removable drives to run a program the moment " +
                        "they are connected. Windows turned that off in 2011 because it was how " +
                        "USB worms spread, so something here turned it back on.",
                    remediation = "Set AutoPlay back to the default: Settings, then Bluetooth & " +
                        "devices, then AutoPlay, and choose to take no action for removable drives.",
                    evidence = mapOf("autoRunBlockedForRemovable" to "false")
                )
            )
        }
    }

    /**
     * A removable drive that is attached and not encrypted.
     *
     * Checked only while something is actually plugged in — there is no way to
     * know retrospectively whether a stick that was here last week was
     * encrypted, and pretending otherwise would be inventing a finding. No drive
     * attached therefore reports not-checkable rather than passing: "nothing is
     * wrong" and "there was nothing to look at" are different answers.
     */
    val UnencryptedRemovableDrive = object : BaseRule(
        id = "DSK-USB-002",
        category = Category.ACCOUNT_SECURITY,
        description = "Attached removable drives are encrypted",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val drives = d.removableDrives ?: return@facts RuleOutcome.NotApplicable
            if (drives.isEmpty()) return@facts RuleOutcome.NotApplicable

            // A drive whose state could not be read is excluded, not accused.
            val unencrypted = drives.filter { it.encrypted == false }
            if (unencrypted.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                unencrypted.take(4).map { drive ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "Drive " + drive.letter + " is not encrypted",
                        detail = (drive.label?.let { "\"" + it + "\" (" + drive.letter + ")" }
                            ?: ("The drive at " + drive.letter)) +
                            " is readable by any computer it is plugged into. A memory stick is " +
                            "the easiest thing you own to lose, and whoever finds it does not " +
                            "need your password to read it.",
                        remediation = "Right-click the drive and choose Turn on BitLocker, then " +
                            "keep the recovery key somewhere other than the drive itself.",
                        subjectId = drive.letter,
                        evidence = buildMap {
                            drive.label?.let { put("label", it) }
                            drive.fileSystem?.let { put("fileSystem", it) }
                        }
                    )
                }
            )
        }
    }

    val ALL: List<Rule> = listOf(
        // Perimeter
        FirewallOff, RemoteAccessEnabled, PubliclyBoundServices,
        // Malware defence
        RealtimeProtectionOff, StaleSignatures, AppReputationOff,
        // Boot integrity
        SecureBootOff, SystemIntegrityProtectionOff,
        // Updates
        AutomaticUpdatesOff, PendingSecurityUpdates, UpdateStalled,
        // Accounts
        PasswordlessAccount, DailyDriverIsAdmin, GuestAccountEnabled, LockOnWakeOff,
        // Persistence
        UnsignedAutoRuns,
        // Installed software
        EndOfLifeSoftware, UnattributedUserInstall,
        // Removable media
        AutoRunOnRemovable, UnencryptedRemovableDrive
    )
}
