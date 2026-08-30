package com.mume.core.rules

import com.mume.core.model.Category
import com.mume.core.model.DesktopOs
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.Platform
import com.mume.core.model.ScreenLock
import com.mume.core.model.Severity

/**
 * Personal-data exposure. Both rules here run identically on iOS and Android —
 * this is the category where the two builds are at parity.
 */
object DataExposureRules {

    /**
     * Photos carrying precise GPS coordinates.
     *
     * Runs entirely on-device: the platform layer reads EXIF from the user's own
     * library and reports counts only. No image, no coordinate and no filename
     * ever enters the core module, so a snapshot can be logged safely.
     */
    val PhotoLocation = object : BaseRule(
        id = "DATA-EXIF-001",
        category = Category.DATA_EXPOSURE,
        description = "Photos do not carry your exact location",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val scanned = s.photosScanned ?: return RuleOutcome.NotApplicable
            val tagged = s.photosWithPreciseLocation ?: return RuleOutcome.NotApplicable
            if (scanned == 0) return RuleOutcome.NotApplicable
            if (tagged == 0) return RuleOutcome.Pass

            val share = tagged.toDouble() / scanned
            val severity = when {
                share >= 0.5 -> Severity.MEDIUM
                else -> Severity.LOW
            }

            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = severity,
                    title = "$tagged of your last $scanned photos contain your exact location",
                    detail = "Each of these records the GPS coordinates where it was taken, to within " +
                        "a few metres. Most messaging apps strip this, but email attachments, cloud " +
                        "links and many social platforms do not — which can publish your home address.",
                    remediation = "Mume can remove the location from copies of these photos without " +
                        "touching the originals. You can also turn off location for the camera app.",
                    evidence = mapOf(
                        "scanned" to scanned.toString(),
                        "tagged" to tagged.toString()
                    )
                )
            )
        }
    }

    /** Message content visible on a locked screen. */
    val LockscreenPreviews = object : BaseRule(
        id = "DATA-LOCK-001",
        category = Category.DATA_EXPOSURE,
        description = "Notification content is hidden on the lock screen"
    ) {
        override fun check(s: DeviceSnapshot) =
            requireObserved(s.lockscreenShowsNotificationContent) { shows ->
                if (!shows) RuleOutcome.Pass else RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "Messages are readable without unlocking",
                        detail = "Anyone who picks up your device can read message previews and, more " +
                            "importantly, the one-time codes sent for password resets — without " +
                            "knowing your PIN.",
                        remediation = "Set notifications to hide sensitive content on the lock screen."
                    )
                )
            }
    }

    val ALL: List<Rule> = listOf(PhotoLocation, LockscreenPreviews)
}

/**
 * Access control and credential hygiene.
 *
 * The password rules consume [DeviceSnapshot.passwordAudit], which carries only
 * counts. The comparison itself happens in the platform layer against the
 * bundled Bloom filter, and nothing — not the password, not a hash, not even a
 * hash prefix — leaves the device or enters this module.
 */
object AccountSecurityRules {

    val ScreenLockStrength = object : BaseRule(
        id = "ACC-LOCK-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Device is protected by a strong screen lock",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.screenLock) { lock ->
            val desktop = s.platform == Platform.DESKTOP
            when (lock) {
                ScreenLock.NONE, ScreenLock.SWIPE -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.CRITICAL,
                        title = if (desktop) "This account signs in without a password"
                        else "This device has no screen lock",
                        detail = if (desktop)
                            "Anyone who opens the lid, or who walks past while you are away, is " +
                                "already signed in as you — with your saved browser passwords, your " +
                                "mail and your files. On most machines an account with no password " +
                                "also cannot protect its own encryption key."
                        else
                            "Anyone who picks it up has your email, your messages and every app " +
                                "you stay signed in to. On most devices, no screen lock also means the " +
                                "storage is not meaningfully encrypted.",
                        remediation = if (desktop)
                            "Set a sign-in password on this account, then turn on \"require a " +
                                "password when the screen wakes\"."
                        else
                            "Set a PIN of at least six digits, then add a fingerprint or " +
                                "face unlock for convenience."
                    )
                )

                ScreenLock.PATTERN -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "Screen lock is a pattern",
                        detail = "Patterns leave a smudge trail on the glass and are unusually easy " +
                            "to read over someone's shoulder. In practice most people choose one of " +
                            "a small number of shapes.",
                        remediation = "Switch to a six-digit PIN or a passcode."
                    )
                )

                ScreenLock.PIN_SHORT -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.LOW,
                        title = "Screen lock is a four-digit PIN",
                        detail = "Four digits is ten thousand combinations, and roughly a quarter of " +
                            "people pick one of the twenty most common.",
                        remediation = "Move to at least six digits."
                    )
                )

                ScreenLock.PIN_LONG, ScreenLock.PASSWORD -> RuleOutcome.Pass
                ScreenLock.UNKNOWN -> RuleOutcome.NotApplicable
            }
        }
    }

    val DiskEncryption = object : BaseRule(
        id = "ACC-CRYPT-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Device storage is encrypted",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.diskEncrypted) { encrypted ->
            if (encrypted) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "Storage is not encrypted",
                    detail = "If this device is lost or stolen, its contents can be read directly " +
                        "from the storage chip without ever unlocking the screen.",
                    // The product name differs per OS and getting it wrong sends
                    // the user hunting for a menu that does not exist.
                    remediation = when (s.desktop?.os) {
                        DesktopOs.WINDOWS ->
                            "Turn on BitLocker (Settings → Privacy & security → Device encryption). " +
                                "Save the recovery key somewhere other than this machine."
                        DesktopOs.MACOS ->
                            "Turn on FileVault (System Settings → Privacy & Security → FileVault) " +
                                "and keep the recovery key somewhere safe."
                        DesktopOs.LINUX ->
                            "Full-disk encryption is set at install time on most distributions. " +
                                "Moving to it usually means a reinstall, so back up first."
                        null ->
                            "Set a screen lock, which enables encryption on most devices, then " +
                                "check Settings → Security for an encryption option."
                    }
                )
            )
        }
    }

    /**
     * Breached passwords, checked against the bundled corpus.
     *
     * Severity scales with count but the *first* one carries most of the weight,
     * matching the decay behaviour of the scoring engine — the message is "you
     * reuse breached passwords", not "you have exactly seven problems".
     */
    val BreachedPasswords = object : BaseRule(
        id = "ACC-PWD-001",
        category = Category.ACCOUNT_SECURITY,
        description = "Saved passwords do not appear in known breaches",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.passwordAudit) { audit ->
            if (audit.credentialsChecked == 0) return@requireObserved RuleOutcome.NotApplicable
            if (audit.breachedCount == 0) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = if (audit.breachedCount >= 3) Severity.HIGH else Severity.MEDIUM,
                    title = "${audit.breachedCount} of your saved passwords appear in known breaches",
                    detail = "These exact passwords are in public lists that attackers try first. " +
                        "Checking happened entirely on this device against a list built into the " +
                        "app — none of your passwords were sent anywhere.",
                    remediation = "Change these passwords now, starting with email and banking. Use " +
                        "a different password for every site.",
                    evidence = mapOf(
                        "breached" to audit.breachedCount.toString(),
                        "checked" to audit.credentialsChecked.toString()
                    )
                )
            )
        }
    }

    val ReusedPasswords = object : BaseRule(
        id = "ACC-PWD-002",
        category = Category.ACCOUNT_SECURITY,
        description = "Saved passwords are not reused across sites",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.passwordAudit) { audit ->
            if (audit.credentialsChecked == 0) return@requireObserved RuleOutcome.NotApplicable
            if (audit.reusedCount == 0) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "${audit.reusedCount} passwords are used on more than one site",
                    detail = "When any one of those sites is breached, every account sharing the " +
                        "password is opened with it. This is how most account takeovers actually " +
                        "happen — not by cracking anything.",
                    remediation = "Give each account its own password, beginning with the accounts " +
                        "that can reset the others: your email.",
                    evidence = mapOf("reused" to audit.reusedCount.toString())
                )
            )
        }
    }

    /** A long auto-lock delay is a screen lock that is often not applied. */
    val LockTimeout = object : BaseRule(
        id = "ACC-LOCK-002",
        category = Category.ACCOUNT_SECURITY,
        description = "Device locks itself promptly",
        platforms = Platforms.EVERYWHERE
    ) {
        private val MAX_ACCEPTABLE_SECONDS = 300

        override fun check(s: DeviceSnapshot) = requireObserved(s.screenLockTimeoutSeconds) { secs ->
            if (secs <= MAX_ACCEPTABLE_SECONDS) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "Device stays unlocked for ${secs / 60} minutes",
                    detail = "A screen lock only protects you once it engages. Left on a desk or a " +
                        "table, this device is open for ${secs / 60} minutes after you last touched it.",
                    remediation = "Reduce the automatic lock delay to one or two minutes.",
                    evidence = mapOf("timeoutSeconds" to secs.toString())
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        ScreenLockStrength, DiskEncryption, BreachedPasswords, ReusedPasswords, LockTimeout
    )
}
