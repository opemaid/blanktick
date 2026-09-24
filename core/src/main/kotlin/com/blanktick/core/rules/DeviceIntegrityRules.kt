package com.blanktick.core.rules

import com.blanktick.core.model.Category
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Platform
import com.blanktick.core.model.Severity

/**
 * Rules covering whether the device's own security model is intact.
 *
 * This is the highest-weighted category (cap 40) because every other check in
 * the app is downstream of it: on a rooted device, an attacker can defeat the
 * app-sandbox guarantees that make the other findings meaningful.
 */
object DeviceIntegrityRules {

    /**
     * Root / jailbreak.
     *
     * Deliberately scored CRITICAL but *not* framed as "you did something wrong".
     * A meaningful number of Blanktick's likely users root their devices on purpose.
     * The remediation text acknowledges that and explains the consequence rather
     * than nagging — a security app that cries wolf at power users gets deleted.
     */
    val Rooted = object : BaseRule(
        id = "DEV-ROOT-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Device is not rooted or jailbroken"
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.rootedOrJailbroken) { rooted ->
            if (!rooted) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.CRITICAL,
                    title = if (s.platform == Platform.ANDROID) "Device is rooted" else "Device is jailbroken",
                    detail = "The operating system's app sandbox is no longer enforced. Any app with " +
                        "elevated access can read another app's private data, including saved " +
                        "passwords and messages.",
                    remediation = "If you did not do this deliberately, back up your data and factory " +
                        "reset the device. If you rooted it on purpose, treat every app on it as able " +
                        "to read everything else."
                )
            )
        }
    }

    /**
     * Active instrumentation (Frida, Substrate, Xposed).
     *
     * Distinct from root: a hooking framework running *right now* means code is
     * actively being injected into other processes.
     */
    val Hooking = object : BaseRule(
        id = "DEV-HOOK-001",
        category = Category.DEVICE_INTEGRITY,
        description = "No code-injection framework is running"
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.hookingArtifacts) { artifacts ->
            if (artifacts.isEmpty()) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.CRITICAL,
                    title = "Code-injection framework detected",
                    detail = "Instrumentation tooling is running on this device and can rewrite the " +
                        "behaviour of other apps while they run: ${artifacts.joinToString(", ")}.",
                    remediation = "Close or uninstall the instrumentation tooling. If you did not " +
                        "install it, factory reset the device.",
                    evidence = mapOf("artifacts" to artifacts.joinToString(","))
                )
            )
        }
    }

    /** Unlocked bootloader — persistent, survives a reset, enables offline tampering. */
    val Bootloader = object : BaseRule(
        id = "DEV-BOOT-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Bootloader is locked",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.bootloaderUnlocked) { unlocked ->
            if (!unlocked) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "Bootloader is unlocked",
                    detail = "Verified Boot is disabled, so the system partition can be modified " +
                        "offline. Someone with brief physical access could install software that " +
                        "survives a factory reset.",
                    remediation = "Relock the bootloader from fastboot. Note this erases the device."
                )
            )
        }
    }

    /**
     * ADB reachable over the network.
     *
     * Rated CRITICAL rather than HIGH: an open ADB TCP port is full remote shell
     * access to anyone on the same Wi-Fi, with no authentication once a host has
     * been authorised. This is the single worst misconfiguration a stock Android
     * device can be in, and it is one toggle away.
     */
    val AdbOverNetwork = object : BaseRule(
        id = "DEV-ADB-002",
        category = Category.DEVICE_INTEGRITY,
        description = "Debugging is not exposed over the network",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val port = s.adbOverNetworkPort
            if (s.adbEnabled == null && port == null) return RuleOutcome.NotApplicable
            if (port == null) return RuleOutcome.Pass
            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.CRITICAL,
                    title = "Wireless debugging is listening on port $port",
                    detail = "Anyone on this network can attempt to connect a debugger to your " +
                        "device. Once a computer has been authorised, it keeps shell access.",
                    remediation = "Turn off Wireless debugging in Developer options, and revoke " +
                        "previously authorised computers.",
                    evidence = mapOf("port" to port.toString())
                )
            )
        }
    }

    /** USB debugging on: lower severity than network ADB, still worth flagging. */
    val AdbEnabled = object : BaseRule(
        id = "DEV-ADB-001",
        category = Category.DEVICE_INTEGRITY,
        description = "USB debugging is off",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.adbEnabled) { enabled ->
            // Network ADB already fires a CRITICAL for this device; don't double-charge.
            if (!enabled || s.adbOverNetworkPort != null) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "USB debugging is enabled",
                    detail = "A computer you plug into can be authorised to run commands on this " +
                        "device. Public charging points and borrowed cables are the usual risk.",
                    remediation = "Turn off USB debugging in Developer options when you are not using it."
                )
            )
        }
    }

    /**
     * Developer options enabled. LOW on its own — it is a prerequisite for
     * several riskier settings rather than a vulnerability in itself.
     */
    val DeveloperOptions = object : BaseRule(
        id = "DEV-DEVOPT-001",
        category = Category.DEVICE_INTEGRITY,
        description = "Developer options are off",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.developerOptionsEnabled) { on ->
            if (!on) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "Developer options are enabled",
                    detail = "Not dangerous by itself, but it unlocks settings that are — including " +
                        "USB and wireless debugging, and permission overrides.",
                    remediation = "Turn off Developer options if you are not actively developing."
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        Rooted, Hooking, Bootloader, AdbOverNetwork, AdbEnabled, DeveloperOptions
    )
}
