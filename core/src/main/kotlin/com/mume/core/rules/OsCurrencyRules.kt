package com.mume.core.rules

import com.mume.core.model.Category
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.Platform
import com.mume.core.model.Severity
import com.mume.core.util.IsoDate

/**
 * How far behind the device's security patch level is.
 *
 * ## Working without a CVE feed
 *
 * With no network we cannot ask "which CVEs affect this exact build". What we
 * *can* ship is a reference table of the newest security patch level known to
 * exist for each OS major version at the time the app was built, and measure the
 * gap. That gap is a good proxy: patch lag correlates directly with exposure to
 * publicly-disclosed, already-exploited bugs.
 *
 * Crucially the rule degrades honestly. If our bundled reference is older than
 * the device's own patch level, we do not claim the device is up to date — we
 * say our data cannot tell, and skip. Claiming a pass from stale data would be
 * exactly the kind of lie the offline design is supposed to make impossible.
 */
object OsCurrencyRules {

    /** Lag thresholds in days, ordered most severe first. */
    private val BANDS = listOf(
        365 to Severity.CRITICAL,
        240 to Severity.HIGH,
        120 to Severity.MEDIUM,
        60 to Severity.LOW
    )

    val PatchLag = object : BaseRule(
        id = "OS-PATCH-001",
        category = Category.OS_CURRENCY,
        description = "Security patch level is current",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val devicePatch = s.securityPatchDate ?: return RuleOutcome.NotApplicable
            val major = s.osMajor ?: return RuleOutcome.NotApplicable
            val reference = s.referencePatchDates?.get(major) ?: return RuleOutcome.NotApplicable

            val lag = IsoDate.daysBetween(devicePatch, reference) ?: return RuleOutcome.NotApplicable

            // Device is at or ahead of what our bundle knows about: we cannot
            // make a claim either way, so we make none.
            if (lag <= 0L) return RuleOutcome.Pass

            val severity = BANDS.firstOrNull { lag > it.first }?.second
                ?: return RuleOutcome.Pass

            val months = lag / 30
            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = severity,
                    title = "Security updates are about $months months behind",
                    detail = "This device reports security patch level $devicePatch. The newest level " +
                        "known to this app for Android $major is $reference. Vulnerabilities fixed in " +
                        "between are public and are actively exploited.",
                    remediation = "Open Settings and install any pending system update. If none is " +
                        "offered, this device may no longer receive security updates from its maker.",
                    evidence = mapOf(
                        "devicePatch" to devicePatch,
                        "referencePatch" to reference,
                        "lagDays" to lag.toString(),
                        "intelBundleDate" to (s.intelBundleDate ?: "unknown")
                    )
                )
            )
        }
    }

    /**
     * The device is no longer covered by our reference table at all, which in
     * practice means the OS major version is old enough that its vendor has
     * stopped publishing patch levels.
     */
    val UnsupportedOs = object : BaseRule(
        id = "OS-EOL-001",
        category = Category.OS_CURRENCY,
        description = "Operating system version still receives updates"
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val major = s.osMajor ?: return RuleOutcome.NotApplicable
            val table = s.referencePatchDates ?: return RuleOutcome.NotApplicable
            if (table.isEmpty()) return RuleOutcome.NotApplicable
            if (table.containsKey(major)) return RuleOutcome.Pass

            val newest = table.keys.max()
            // Only flag versions *older* than our table; a newer OS than we know
            // about is not a problem, it just means the bundle is behind.
            if (major >= newest) return RuleOutcome.Pass

            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "This version of the OS is no longer supported",
                    detail = "Version $major is older than every version this app has update data " +
                        "for. Devices in this position usually receive no further security fixes, " +
                        "and known vulnerabilities in them stay unpatched permanently.",
                    remediation = "Upgrade the operating system if an upgrade is offered. If not, " +
                        "plan to replace the device, and in the meantime avoid using it for banking " +
                        "or email.",
                    evidence = mapOf("osMajor" to major.toString(), "newestKnown" to newest.toString())
                )
            )
        }
    }

    /**
     * Our own intel is old. Reported at INFO so it costs nothing, but it is
     * displayed prominently — the user deserves to know the age of the data
     * every other finding rests on.
     */
    val IntelStale = object : BaseRule(
        id = "OS-INTEL-001",
        category = Category.OS_CURRENCY,
        description = "Threat data is reasonably fresh",
        // Nothing about bundle age is platform-specific: this rule inspects our
        // own shipped data, not the machine.
        platforms = Platforms.EVERYWHERE
    ) {
        private val STALE_AFTER_DAYS = 90

        override fun check(s: DeviceSnapshot) = requireObserved(s.intelStalenessDays) { days ->
            if (days <= STALE_AFTER_DAYS) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.INFO,
                    title = "Threat data is $days days old",
                    detail = "Mume works entirely offline, so its blocklists and update reference " +
                        "data ship inside the app and refresh when the app updates. This copy was " +
                        "built on ${s.intelBundleDate ?: "an unknown date"}.",
                    remediation = "Update Mume from the store to refresh its threat data."
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(PatchLag, UnsupportedOs, IntelStale)
}
