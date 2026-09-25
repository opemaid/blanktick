package com.blanktick.core.rules

import com.blanktick.core.model.Category
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Severity

/**
 * The Windows baseline that open-source auditors check and Blanktick did not.
 *
 * ## Where these came from
 *
 * On 2026-09-25 Blanktick's probe was compared, setting by setting, against
 * apotrope (~55 checks, from its source), HardeningKitty (418 machine settings)
 * and Harden-Windows-Security's categories. Everything below was absent from
 * the probe. Items that need business management to change (Attack Surface
 * Reduction rules, audit policy) were left out on purpose: a home user cannot
 * act on them, and a finding nobody can act on is not worth a point.
 *
 * ## Measured before written, as every rule here is
 *
 * Each was read non-elevated on a Windows 11 Home 26200 machine first. Three
 * are **off on a stock install** — Smart App Control, controlled folder access,
 * PowerShell script-block logging — so they report at INFO: shown on the
 * Policy page, costing nothing. Charging points for a setting Microsoft ships
 * off would fail every healthy computer, which is the one thing this codebase
 * refuses (see HardeningRules). Everything else returns zero findings on a
 * healthy machine.
 */
object BaselineRules {

    private inline fun facts(s: DeviceSnapshot, body: (DesktopFacts) -> RuleOutcome): RuleOutcome =
        s.desktop?.let(body) ?: RuleOutcome.NotApplicable

    // ------------------------------------------------ virtualisation security

    val MemoryIntegrityOff = object : BaseRule(
        id = "DSK-VBS-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Memory integrity protects the Windows core",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val running = h.memoryIntegrityRunning ?: return@facts RuleOutcome.NotApplicable
            if (running) return@facts RuleOutcome.Pass
            // Hardware that cannot run it is not a fault anyone can fix.
            if (h.memoryIntegrityAvailable == false) return@facts RuleOutcome.NotApplicable
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.MEDIUM,
                    title = "Memory integrity is switched off",
                    detail = "This computer can run memory integrity, which stops a malicious " +
                        "driver from planting code in the core of Windows, but it is off. New " +
                        "Windows 11 installations turn it on by default; it is usually switched " +
                        "off because an old driver was incompatible with it.",
                    remediation = "Open Windows Security → Device security → Core isolation details " +
                        "and turn on Memory integrity. If Windows names an incompatible driver, " +
                        "updating or removing that driver is the fix. It needs a restart.",
                    evidence = mapOf("memoryIntegrityRunning" to "false")
                )
            )
        }
    }

    val CredentialGuardOff = object : BaseRule(
        id = "DSK-VBS-002",
        category = Category.ACCOUNT_SECURITY,
        description = "Credential Guard isolates sign-in secrets",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            // Home editions do not have it; nothing to act on.
            if (h.credentialGuardSupportedEdition != true) return@facts RuleOutcome.NotApplicable
            val running = h.credentialGuardRunning ?: return@facts RuleOutcome.NotApplicable
            if (running) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.LOW,
                    title = "Credential Guard is not running",
                    detail = "This edition of Windows can keep sign-in secrets in an isolated " +
                        "area that even malware with full control of the system cannot read. It " +
                        "is not running here. Without it, a program that gains administrator " +
                        "rights can copy the secrets and reuse them on other machines.",
                    remediation = "It is turned on through Group Policy (Device Guard → Turn On " +
                        "Virtualization Based Security → Credential Guard) or by whoever manages " +
                        "this computer. It needs a restart.",
                    evidence = mapOf("credentialGuardRunning" to "false")
                )
            )
        }
    }

    val NoTpm = object : BaseRule(
        id = "DSK-TPM-001",
        category = Category.DEVICE_INTEGRITY,
        description = "A working security chip (TPM) is present",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val working = d.hardening?.tpmWorking ?: return@facts RuleOutcome.NotApplicable
            if (working) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.LOW,
                    title = "No working security chip (TPM) was found",
                    detail = "The TPM is what lets disk encryption, Windows Hello and secure " +
                        "startup keep their keys out of reach of software. Windows 11 requires " +
                        "one. It is either missing, switched off in the firmware, or reporting " +
                        "an error.",
                    remediation = "Most computers made since 2016 have one that can be switched on " +
                        "in the firmware settings (often called TPM, PTT or fTPM). If it shows an " +
                        "error in Device Manager under Security devices, a firmware update " +
                        "usually fixes it.",
                    evidence = mapOf("tpmWorking" to "false")
                )
            )
        }
    }

    // ------------------------------------------------------- app protection

    /** INFO: off on every upgraded machine, and only a reinstall can turn it on. */
    val SmartAppControlOff = object : BaseRule(
        id = "DSK-SAC-001",
        category = Category.APP_HYGIENE,
        description = "Smart App Control blocks untrusted apps",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val state = d.hardening?.smartAppControlState ?: return@facts RuleOutcome.NotApplicable
            if (state == 1 || state == 2) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.INFO,
                    title = "Smart App Control is off",
                    detail = "Smart App Control blocks programs that are neither signed nor " +
                        "known to be safe. It is off here, as it is on most computers that were " +
                        "upgraded rather than freshly installed. This costs no points: once off, " +
                        "Windows only lets it be turned back on by reinstalling.",
                    remediation = "Nothing to do now. If you ever reset or reinstall Windows, " +
                        "leave it in evaluation mode and it will decide whether it suits you.",
                    evidence = mapOf("state" to state.toString())
                )
            )
        }
    }

    /** INFO: off by default, and it can break programs that save to protected folders. */
    val ControlledFolderAccessOff = object : BaseRule(
        id = "DSK-CFA-001",
        category = Category.DATA_EXPOSURE,
        description = "Ransomware protection guards your folders",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.antivirusPosture?.controlledFolderAccess ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.INFO,
                    title = "Ransomware protection for your folders is off",
                    detail = "Controlled folder access stops unknown programs from changing files " +
                        "in Documents, Pictures and similar folders — the files ransomware " +
                        "encrypts. It is off by default because it also blocks some legitimate " +
                        "programs until you allow them. No points: off is Microsoft's choice.",
                    remediation = "Worth turning on if you keep irreplaceable files here without " +
                        "a backup: Windows Security → Virus & threat protection → Manage " +
                        "ransomware protection. Allow a program when Windows says it was blocked.",
                    evidence = mapOf("controlledFolderAccess" to "false")
                )
            )
        }
    }

    val UnwantedAppsAllowed = object : BaseRule(
        id = "DSK-AV-006",
        category = Category.APP_HYGIENE,
        description = "Potentially unwanted apps are blocked",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.antivirusPosture?.unwantedAppBlocking ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.LOW,
                    title = "Adware and bundled junk are not being blocked",
                    detail = "Windows can block \"potentially unwanted\" software — toolbars, " +
                        "coin miners and installers that sneak extra programs in. Windows 11 " +
                        "turns this on by default; here it is off.",
                    remediation = "Windows Security → App & browser control → Reputation-based " +
                        "protection settings → turn on Potentially unwanted app blocking.",
                    evidence = mapOf("unwantedAppBlocking" to "false")
                )
            )
        }
    }

    val ExploitMitigationsOff = object : BaseRule(
        id = "DSK-EXP-001",
        category = Category.DEVICE_INTEGRITY,
        description = "System-wide exploit protections are not switched off",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val off = d.hardening?.exploitMitigationsOff ?: return@facts RuleOutcome.NotApplicable
            if (off.isEmpty()) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.MEDIUM,
                    title = "Exploit protection has been switched off: ${off.joinToString(", ")}",
                    detail = "These protections make it much harder for a malicious document or " +
                        "web page to turn a bug into control of the computer. Windows has them on " +
                        "by default, so someone or something switched them off for every program.",
                    remediation = "Windows Security → App & browser control → Exploit protection " +
                        "settings → System settings, and set each one back to \"Use default (On)\".",
                    evidence = mapOf("off" to off.joinToString(","))
                )
            )
        }
    }

    // ---------------------------------------------------------------- network

    val FileSharingUnprotected = object : BaseRule(
        id = "DSK-SMB-001",
        category = Category.NETWORK,
        description = "File sharing is signed and refuses anonymous shares",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            if (h.smbClientRequiresSigning == null && h.smbServerRequiresSigning == null &&
                h.smbInsecureGuestLogons == null
            ) return@facts RuleOutcome.NotApplicable

            val findings = buildList {
                if (h.smbInsecureGuestLogons == true) {
                    add(
                        Finding(
                            ruleId = id, category = category, severity = Severity.LOW,
                            title = "This computer will open network shares that ask for no password",
                            detail = "Windows is set to connect to file shares as an anonymous " +
                                "guest. Anyone on the same network can set up such a share, and " +
                                "because nothing is signed, they can also sit in the middle of a " +
                                "connection and swap the files you open. Windows 11 Pro and " +
                                "Enterprise turn this off by default; Home still ships with it on, " +
                                "so on Home this is not a sign anything was changed.",
                            remediation = "Unless an old NAS or media box needs it, turn it off: in " +
                                "an administrator PowerShell, Set-SmbClientConfiguration " +
                                "-EnableInsecureGuestLogons \$false. If a device stops working, " +
                                "give it a username and password instead.",
                            subjectId = "insecureGuest"
                        )
                    )
                }
                val unsigned = listOfNotNull(
                    "outgoing".takeIf { h.smbClientRequiresSigning == false },
                    "incoming".takeIf { h.smbServerRequiresSigning == false }
                )
                if (unsigned.isNotEmpty()) {
                    add(
                        Finding(
                            ruleId = id, category = category, severity = Severity.LOW,
                            title = "File-sharing traffic is not required to be signed (${unsigned.joinToString(" and ")})",
                            detail = "Signing proves a file-sharing message was not altered on the " +
                                "way. Without it, someone on the same network can relay or tamper " +
                                "with connections. Windows 11 24H2 requires it by default.",
                            remediation = "In an administrator PowerShell: Set-SmbClientConfiguration " +
                                "-RequireSecuritySignature \$true and Set-SmbServerConfiguration " +
                                "-RequireSecuritySignature \$true.",
                            subjectId = "signing"
                        )
                    )
                }
            }
            if (findings.isEmpty()) RuleOutcome.Pass else RuleOutcome.Fail(findings)
        }
    }

    val SharedPrinterSpooler = object : BaseRule(
        id = "DSK-SPOOL-001",
        category = Category.NETWORK,
        description = "The printer service is not shared to the network",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val h = d.hardening ?: return@facts RuleOutcome.NotApplicable
            val running = h.printSpoolerRunning ?: return@facts RuleOutcome.NotApplicable
            if (!running) return@facts RuleOutcome.Pass
            val shared = h.sharedPrinterCount ?: return@facts RuleOutcome.NotApplicable
            if (shared == 0) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.LOW,
                    title = "A printer is shared to the network ($shared)",
                    detail = "Sharing a printer makes the Windows printer service answer other " +
                        "computers. That service is where the 2021 PrintNightmare flaws were, " +
                        "which let a network visitor run code as the system. Patched, but it is " +
                        "the kind of door worth keeping shut when it is not needed.",
                    remediation = "If nobody else prints through this computer, stop sharing: " +
                        "Settings → Printers & scanners → the printer → Printer properties → " +
                        "Sharing, and untick \"Share this printer\".",
                    evidence = mapOf("sharedPrinters" to shared.toString())
                )
            )
        }
    }

    // --------------------------------------------------------------- accounts

    val NoAccountLockout = object : BaseRule(
        id = "DSK-PWD-003",
        category = Category.ACCOUNT_SECURITY,
        description = "Repeated password guessing locks the account",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val threshold = d.hardening?.lockoutThreshold ?: return@facts RuleOutcome.NotApplicable
            if (threshold in 1..10) return@facts RuleOutcome.Pass
            val never = threshold == 0
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category,
                    severity = if (never) Severity.MEDIUM else Severity.LOW,
                    title = if (never) "Passwords can be guessed without limit"
                    else "Accounts only lock after $threshold wrong passwords",
                    detail = if (never)
                        "Nothing stops someone trying password after password on a local account " +
                            "— at the keyboard, or over the network if sharing or remote access is " +
                            "on. Windows 11 locks an account after 10 wrong attempts by default; " +
                            "that has been switched off here."
                    else
                        "The limit is higher than Windows' default of 10, which gives someone " +
                            "guessing passwords more attempts than they need.",
                    remediation = "In an administrator Command Prompt: net accounts " +
                        "/lockoutthreshold:10. It only affects local accounts; a Microsoft " +
                        "account is protected by Microsoft's own limits.",
                    evidence = mapOf("lockoutThreshold" to threshold.toString())
                )
            )
        }
    }

    val BuiltinAdministratorEnabled = object : BaseRule(
        id = "DSK-ADM-002",
        category = Category.ACCOUNT_SECURITY,
        description = "The built-in Administrator account is disabled",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val enabled = d.hardening?.builtinAdministratorEnabled ?: return@facts RuleOutcome.NotApplicable
            if (!enabled) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.MEDIUM,
                    title = "The built-in Administrator account is switched on",
                    detail = "Every Windows computer has this account, with the same name, and it " +
                        "is exempt from account lockout — so it can be guessed at indefinitely. " +
                        "It also skips the User Account Control prompt. Windows ships it disabled.",
                    remediation = "Use your own account for administration and disable this one: " +
                        "in an administrator Command Prompt, net user Administrator /active:no.",
                    evidence = mapOf("builtinAdministratorEnabled" to "true")
                )
            )
        }
    }

    // ----------------------------------------------------------- services, logs

    val UnquotedServicePaths = object : BaseRule(
        id = "DSK-SVC-001",
        category = Category.DEVICE_INTEGRITY,
        description = "No service can be hijacked through an unquoted path",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val names = d.hardening?.unquotedServicePaths ?: return@facts RuleOutcome.NotApplicable
            if (names.isEmpty()) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                names.map { name ->
                    Finding(
                        ruleId = id, category = category, severity = Severity.MEDIUM,
                        title = "Service \"$name\" can be hijacked through its path",
                        detail = "Its program path contains a space and is not in quotes. When " +
                            "Windows starts it, it tries each shorter version of the path first — " +
                            "so a program placed at the right spot runs with the service's full " +
                            "system rights. It is a mistake by the software's installer.",
                        remediation = "Update or reinstall the program that owns \"$name\"; current " +
                            "versions usually fix the path. Otherwise the service's ImagePath in " +
                            "the registry can be wrapped in quotes by an administrator.",
                        subjectId = name
                    )
                }
            )
        }
    }

    /** INFO: off on every stock machine; it matters after an incident, not before. */
    val PowerShellLoggingOff = object : BaseRule(
        id = "DSK-PS-002",
        category = Category.APP_HYGIENE,
        description = "PowerShell activity is recorded",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val on = d.hardening?.powerShellScriptBlockLogging ?: return@facts RuleOutcome.NotApplicable
            if (on) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.INFO,
                    title = "PowerShell commands are not being recorded",
                    detail = "Most modern attacks on Windows run through PowerShell. Script-block " +
                        "logging keeps a record of what was run, which is what an investigator " +
                        "looks for afterwards. It is off by default. No points: it records an " +
                        "attack rather than preventing one.",
                    remediation = "Group Policy → Administrative Templates → Windows Components → " +
                        "Windows PowerShell → Turn on PowerShell Script Block Logging.",
                    evidence = mapOf("scriptBlockLogging" to "false")
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        MemoryIntegrityOff,
        CredentialGuardOff,
        NoTpm,
        SmartAppControlOff,
        ControlledFolderAccessOff,
        UnwantedAppsAllowed,
        ExploitMitigationsOff,
        FileSharingUnprotected,
        SharedPrinterSpooler,
        NoAccountLockout,
        BuiltinAdministratorEnabled,
        UnquotedServicePaths,
        PowerShellLoggingOff
    )
}
