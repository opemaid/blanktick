package com.mume.core.rules

import com.mume.core.model.Category
import com.mume.core.model.DesktopFacts
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.Severity

/**
 * Machine hardening, and an audit of the antivirus that is already installed.
 *
 * ## Why these are here and not in DesktopRules
 *
 * `DesktopRules` answers "is protection switched on" — firewall, updates,
 * Secure Boot, screen lock. The rules below answer two different questions:
 * **how much does an attacker get after they arrive**, and **is the security
 * software actually doing the job its own dashboard claims**.
 *
 * ## What these are not
 *
 * Mume is not an antivirus and cannot become one. It has no network, so no
 * reputation lookup; it has no file scanner and never opens a file to inspect
 * its contents. Nothing in this file detects malware.
 *
 * What it does instead is the honest version of the same job. A behaviour
 * monitor quietly switched off, tamper protection disabled, a threat the
 * product found and never resolved, an exclusion folder added during a
 * compromise — those are local facts about the scanner, they need no network,
 * and no consumer tool this project has looked at surfaces them. An AV that has
 * been partly disabled looks identical to a working one from the outside, which
 * is exactly why it is worth checking.
 *
 * ## Every rule below returns zero findings on a healthy machine
 *
 * Measured on the development machine before any of them were written, which is
 * the standing requirement in this codebase. A rule that fires on a stock
 * install is not a security check, it is a reason to stop reading the report.
 */
object HardeningRules {

    private inline fun facts(s: DeviceSnapshot, body: (DesktopFacts) -> RuleOutcome): RuleOutcome =
        s.desktop?.let(body) ?: RuleOutcome.NotApplicable

    // ------------------------------------------------------------------ UAC

    val UacDisabled = object : BaseRule(
        id = "DSK-UAC-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Administrator actions require confirmation",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val enabled = h.uacEnabled ?: return@facts RuleOutcome.NotApplicable
            val prompts = h.uacPromptsForElevation

            if (enabled && prompts != false) return@facts RuleOutcome.Pass

            val silent = enabled && prompts == false
            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (silent) Severity.MEDIUM else Severity.HIGH,
                    title = if (silent) "Programs can gain full control without asking"
                    else "User Account Control is switched off",
                    detail = if (silent)
                        "Elevation is set to happen silently. A program that wants full control " +
                            "of this computer gets it without the prompt that would otherwise be " +
                            "the one moment you could notice and refuse."
                    else
                        "Every program you run has full control of this computer. There is no " +
                            "prompt, and no difference between opening a document and installing " +
                            "something permanent.",
                    remediation = "Open Settings and search for \"Change User Account Control " +
                        "settings\", then move the slider to at least the default position. It " +
                        "takes a restart.",
                    evidence = mapOf(
                        "enableLUA" to enabled.toString(),
                        "promptsForElevation" to prompts.toString()
                    )
                )
            )
        }
    }

    // ---------------------------------------------------------- credentials

    /**
     * The two settings that decide whether a foothold becomes your password.
     *
     * Kept as one rule because they are one problem — an attacker who is
     * already running code as you reads credentials straight out of memory —
     * and reporting them separately would double the noise for a single fix.
     */
    val CredentialsExposedInMemory = object : BaseRule(
        id = "DSK-CRED-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Sign-in credentials are not left readable in memory",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val wdigest = h.plaintextCredentialsInMemory
            val lsa = h.lsaProtected
            if (wdigest == null && lsa == null) return@facts RuleOutcome.NotApplicable

            val findings = buildList {
                if (wdigest == true) {
                    add(
                        Finding(
                            ruleId = id,
                            category = category,
                            severity = Severity.HIGH,
                            title = "Your password is being kept in memory in readable form",
                            detail = "A setting called WDigest has been switched back on. It " +
                                "keeps your actual password — not a scrambled version of it — in " +
                                "the computer's memory while you are signed in. Windows stopped " +
                                "doing this by default in 2014, so something turned it back on.",
                            remediation = "Unless a specific old application needs it, this should " +
                                "be off. It is the value UseLogonCredential under WDigest in the " +
                                "registry; ask whoever manages this machine before changing it.",
                            subjectId = "wdigest",
                            evidence = mapOf("UseLogonCredential" to "1")
                        )
                    )
                }
                // Only reported when the machine is otherwise modern: on older
                // hardware LSA protection is genuinely unavailable, and a
                // finding nobody can act on is not worth a point.
                if (lsa == false && wdigest != true) {
                    add(
                        Finding(
                            ruleId = id,
                            category = category,
                            severity = Severity.LOW,
                            title = "Extra protection for stored sign-in details is off",
                            detail = "Windows can run the part of the system that holds your " +
                                "sign-in details in a protected mode that other programs cannot " +
                                "read from. It is not switched on here. This is a hardening " +
                                "improvement rather than an active problem.",
                            remediation = "This one is genuinely technical and can stop some " +
                                "older drivers loading. If this is a personal machine and you " +
                                "are not sure, it is reasonable to leave it.",
                            subjectId = "lsa",
                            evidence = mapOf("RunAsPPL" to "0")
                        )
                    )
                }
            }
            if (findings.isEmpty()) RuleOutcome.Pass else RuleOutcome.Fail(findings)
        }
    }

    val AutoLogonPasswordStored = object : BaseRule(
        id = "DSK-CRED-002",
        category = Category.ACCOUNT_SECURITY,
        description = "No sign-in password is stored in the registry",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val stored = h.autoLogonPasswordStored ?: return@facts RuleOutcome.NotApplicable
            if (!stored) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "A sign-in password is stored on this computer in plain text",
                    detail = "Automatic sign-in has been set up, and the password was saved in " +
                        "the registry unencrypted. Any program running as any user on this " +
                        "machine can read it, and people reuse passwords.",
                    remediation = "Turn automatic sign-in off, then change that password — " +
                        "assume it is already known. Run netplwiz and tick \"Users must enter a " +
                        "user name and password\".",
                    // The value is deliberately absent from the evidence. Mume
                    // never reads the password itself; an app that printed a
                    // stored credential into its own report would have made the
                    // problem worse in the course of describing it.
                    evidence = mapOf("location" to "Winlogon\\DefaultPassword")
                )
            )
        }
    }

    // ------------------------------------------------------- network legacy

    val LegacyNetworkProtocols = object : BaseRule(
        id = "DSK-NET-003",
        category = Category.NETWORK,
        description = "Obsolete network protocols are switched off",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            if (h.smb1Enabled == null && h.llmnrEnabled == null) {
                return@facts RuleOutcome.NotApplicable
            }

            val findings = buildList {
                if (h.smb1Enabled == true) {
                    add(
                        Finding(
                            ruleId = id,
                            category = category,
                            severity = Severity.HIGH,
                            title = "SMBv1, the file-sharing protocol used by WannaCry, is on",
                            detail = "This is the thirty-year-old version of Windows file " +
                                "sharing. It is the transport the 2017 ransomware outbreaks " +
                                "spread over, Microsoft removed it from new installations, and " +
                                "almost nothing still needs it.",
                            remediation = "Search for \"Turn Windows features on or off\" and " +
                                "untick \"SMB 1.0/CIFS File Sharing Support\". If a very old " +
                                "network printer or NAS stops working, that device was the reason " +
                                "it was on.",
                            subjectId = "smb1"
                        )
                    )
                }
                if (h.llmnrEnabled == true) {
                    add(
                        Finding(
                            ruleId = id,
                            category = category,
                            // LOW on purpose, and the severity was set by
                            // measurement. This is the one rule in the file that
                            // fires on a stock machine -- LLMNR ships enabled,
                            // so every Windows install would report it. The
                            // exposure is real (it is what Responder-style
                            // credential capture on shared Wi-Fi depends on), so
                            // suppressing it would be hiding something true; but
                            // charging MEDIUM for a setting Microsoft chose costs
                            // 9 points on a healthy computer and turns the score
                            // into a number nobody trusts. Advice, not an
                            // accusation.
                            severity = Severity.LOW,
                            title = "This computer shouts network lookups to whoever is listening",
                            detail = "When a name cannot be resolved normally, Windows broadcasts " +
                                "\"does anyone know this?\" to the whole local network and trusts " +
                                "the first reply. On shared Wi-Fi — a hotel, an office, a café — " +
                                "anyone can answer and collect the sign-in attempt that follows. " +
                                "It is on by default, so this is not a sign anyone changed " +
                                "anything.",
                            remediation = "Worth turning off if you use public or shared networks. " +
                                "It is the Multicast Name Resolution policy, and turning it off " +
                                "rarely breaks anything on a home network.",
                            subjectId = "llmnr"
                        )
                    )
                }
            }
            if (findings.isEmpty()) RuleOutcome.Pass else RuleOutcome.Fail(findings)
        }
    }

    val RemoteServicesRunning = object : BaseRule(
        id = "DSK-RMT-002",
        category = Category.NETWORK,
        description = "No remote-administration service is running",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val winrm = h.remoteManagementRunning
            val remoteReg = h.remoteRegistryRunning
            if (winrm == null && remoteReg == null) return@facts RuleOutcome.NotApplicable

            val running = buildList {
                if (winrm == true) add("Windows Remote Management" to "run commands on this computer")
                if (remoteReg == true) add("Remote Registry" to "read and change its settings")
            }
            if (running.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                running.map { (name, what) ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "$name is running",
                        detail = "This service lets another computer on the network $what. It is " +
                            "meant for managed office machines and is off by default on a " +
                            "personal one.",
                        remediation = "If this is your own computer and you did not set this up, " +
                            "stop the service and set it to Manual in Services.",
                        subjectId = name
                    )
                }
            )
        }
    }

    val PowerShellV2Available = object : BaseRule(
        id = "DSK-PS-001",
        category = Category.APP_HYGIENE,
        description = "The unlogged PowerShell version has been removed",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val present = h.powerShellV2Available ?: return@facts RuleOutcome.NotApplicable
            if (!present) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "An old version of PowerShell is still installed",
                    detail = "Version 2 is still available on this machine. It predates the " +
                        "logging and restrictions in the current version, so anything that wants " +
                        "to run unobserved can simply ask for it by name.",
                    remediation = "Search for \"Turn Windows features on or off\" and untick " +
                        "\"Windows PowerShell 2.0\". Modern software does not use it.",
                    evidence = mapOf("engine" to "PowerShell 1/PowerShellEngine present")
                )
            )
        }
    }

    // ---------------------------------------------- auditing the antivirus

    val AntivirusPartlyDisabled = object : BaseRule(
        id = "DSK-AV-003",
        category = Category.DEVICE_INTEGRITY,
        description = "The antivirus has all of its protections switched on",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val av = d.antivirusPosture ?: return@facts RuleOutcome.NotApplicable

            val off = buildList {
                if (av.behaviourMonitoringEnabled == false) {
                    add("behaviour monitoring" to "spotting a program acting like malware even " +
                        "when the file itself is unknown")
                }
                if (av.downloadScanningEnabled == false) {
                    add("download and attachment scanning" to "checking files as they arrive " +
                        "rather than after you open them")
                }
                if (av.antiSpywareEnabled == false) {
                    add("spyware protection" to "detecting software that watches what you do")
                }
                if (av.networkInspectionEnabled == false) {
                    add("network inspection" to "blocking attacks aimed at the machine over the " +
                        "network")
                }
            }
            if (off.isEmpty() && av.behaviourMonitoringEnabled == null) {
                return@facts RuleOutcome.NotApplicable
            }
            if (off.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                off.map { (feature, what) ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.HIGH,
                        title = "Your antivirus has $feature switched off",
                        detail = "The antivirus is installed and reports itself as running, but " +
                            "this part of it is not. It is responsible for $what. Software that " +
                            "wants to survive on a machine often turns off one piece rather than " +
                            "the whole product, because the whole product going dark is noticed.",
                        remediation = "Open Windows Security > Virus & threat protection > Manage " +
                            "settings and turn it back on. If it will not stay on, or switches " +
                            "itself off again, treat that as serious.",
                        subjectId = feature
                    )
                }
            )
        }
    }

    val TamperProtectionOff = object : BaseRule(
        id = "DSK-AV-004",
        category = Category.DEVICE_INTEGRITY,
        description = "The antivirus cannot be switched off by other software",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val av = d.antivirusPosture ?: return@facts RuleOutcome.NotApplicable
            val on = av.tamperProtectionEnabled ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "Other programs are allowed to switch your antivirus off",
                    detail = "Tamper Protection stops software — including software you did not " +
                        "choose to install — from changing your antivirus settings. With it off, " +
                        "the first thing a piece of malware does is disable the thing that would " +
                        "have caught it.",
                    remediation = "Windows Security > Virus & threat protection > Manage settings " +
                        "> Tamper Protection, and turn it on."
                )
            )
        }
    }

    /**
     * A threat the antivirus found and has not finished dealing with.
     *
     * ## The measurement that shaped this
     *
     * The obvious version — "report anything in the detection history" — was
     * tried against the real history first: 73 detections on the development
     * machine, none of them a current problem. 42 were behaviour alerts against
     * the developer's own JVM, 28 were files in a security-research repository.
     * A rule on that number would have produced 73 alarming findings on a
     * healthy machine.
     *
     * `IsActive` is the field that means "this is still here", and finding that
     * out required measuring rather than reading: `ActionSuccess` reports true
     * even for detections whose own status code says the action failed, so the
     * intuitive check could never have fired at all.
     */
    val UnresolvedThreat = object : BaseRule(
        id = "DSK-AV-005",
        category = Category.DEVICE_INTEGRITY,
        description = "The antivirus has no unresolved detections",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        /** Cap on cards emitted, matching DSK-AUTO-001. */
        private val MAX_REPORTED = 5

        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val av = d.antivirusPosture ?: return@facts RuleOutcome.NotApplicable
            val active = av.activeThreatNames ?: return@facts RuleOutcome.NotApplicable
            if (active.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                active.distinct().take(MAX_REPORTED).map { name ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.CRITICAL,
                        title = "Your antivirus found something and has not dealt with it",
                        detail = "The antivirus still lists \"" + name + "\" as present on this " +
                            "computer. This is not history: it is a detection the product has " +
                            "not resolved, which usually means removal failed or was refused.",
                        remediation = "Open Windows Security > Virus & threat protection > " +
                            "Protection history, find this item and complete the action. If it " +
                            "will not clear, that is worth taking to someone.",
                        subjectId = name,
                        evidence = mapOf("threat" to name)
                    )
                }
            )
        }
    }

    val ALL: List<Rule> = listOf(
        UacDisabled,
        CredentialsExposedInMemory,
        AutoLogonPasswordStored,
        LegacyNetworkProtocols,
        RemoteServicesRunning,
        PowerShellV2Available,
        AntivirusPartlyDisabled,
        TamperProtectionOff,
        UnresolvedThreat
    )
}
