package com.mume.core.rules

import com.mume.core.intel.ClusterRulePack
import com.mume.core.model.Category
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.InstalledApp
import com.mume.core.model.Platform
import com.mume.core.model.Severity

/**
 * The Android-only app auditor.
 *
 * Every rule here returns [RuleOutcome.NotApplicable] on iOS, because iOS has no
 * API that enumerates other apps' permissions or signatures. The iOS build shows
 * these as "not checkable on iPhone" rather than as passing checks — decision
 * D-01, enforced by the null contract on [DeviceSnapshot.installedApps].
 */
object AppHygieneRules {

    private val ANDROID_ONLY = setOf(Platform.ANDROID)

    /** Official installers. Anything else is treated as an unknown source. */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",
        "com.google.android.feedback",
        "com.amazon.venezia",
        "com.sec.android.app.samsungapps",
        "com.huawei.appmarket",
        "com.xiaomi.market",
        "com.heytap.market",
        "com.oppo.market",
        "com.vivo.appstore",
        "org.fdroid.fdroid"
    )

    /**
     * Repackaged / impersonating app.
     *
     * The most valuable check in the entire product, and it works entirely from
     * bundled data: if a package name we have a known-good signing key for is
     * present with a *different* key, the app on this device is not the app it
     * claims to be.
     */
    val ClonedApp = object : BaseRule(
        id = "APP-CLONE-001",
        category = Category.APP_HYGIENE,
        description = "No app is impersonating a known one",
        platforms = ANDROID_ONLY
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val apps = s.installedApps ?: return RuleOutcome.NotApplicable
            val registry = s.knownSigners ?: return RuleOutcome.NotApplicable

            val impostors = apps.mapNotNull { app ->
                val allowed = registry[app.packageName] ?: return@mapNotNull null
                val actual = app.signerSha256 ?: return@mapNotNull null
                if (actual.uppercase() in allowed.map { it.uppercase() }) null else app to actual
            }

            if (impostors.isEmpty()) return RuleOutcome.Pass

            return RuleOutcome.Fail(
                impostors.map { (app, actual) ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.CRITICAL,
                        subjectId = app.packageName,
                        title = "\"${app.label}\" is not the real app",
                        detail = "This app uses the identity ${app.packageName}, but it was signed " +
                            "with a different key than the genuine app. It is a modified copy. " +
                            "Modified copies of popular apps are the most common way banking " +
                            "credentials are stolen on Android.",
                        remediation = "Uninstall it now. Then install the genuine app from an " +
                            "official store, and change any password you typed into the fake one.",
                        evidence = mapOf(
                            "package" to app.packageName,
                            "signerSha256" to actual,
                            "installer" to (app.installerPackage ?: "unknown")
                        )
                    )
                }
            )
        }
    }

    /** Dangerous permission/capability combinations — see [ClusterRulePack]. */
    val DangerousCluster = object : BaseRule(
        id = "APP-CLUSTER-001",
        category = Category.APP_HYGIENE,
        description = "No app holds a dangerous combination of permissions",
        platforms = ANDROID_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.installedApps) { apps ->
            val hits = apps.mapNotNull { app ->
                ClusterRulePack.mostSevereMatch(app)?.let { app to it }
            }
            if (hits.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                hits.map { (app, cluster) ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = cluster.severity,
                        subjectId = app.packageName,
                        title = "\"${app.label}\" — ${cluster.name.lowercase()}",
                        detail = cluster.explanation,
                        remediation = "If you do not know why \"${app.label}\" needs this, uninstall " +
                            "it. If you need the app, revoke what you can in Settings → Apps → " +
                            "${app.label} → Permissions.",
                        evidence = mapOf(
                            "package" to app.packageName,
                            "cluster" to cluster.id,
                            "installer" to (app.installerPackage ?: "unknown")
                        )
                    )
                }
            )
        }
    }

    /**
     * Sideloaded apps.
     *
     * Scored MEDIUM, not HIGH: sideloading is legitimate and common, and this is
     * a security app whose own audience sideloads things. The finding is framed
     * as "these bypassed store review" rather than "these are malware".
     */
    val UnknownSource = object : BaseRule(
        id = "APP-SOURCE-001",
        category = Category.APP_HYGIENE,
        description = "All apps came from a recognised store",
        platforms = ANDROID_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.installedApps) { apps ->
            val sideloaded = apps.filterNot { it.isSystemApp }
                .filter { it.installerPackage == null || it.installerPackage !in TRUSTED_INSTALLERS }

            if (sideloaded.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "${sideloaded.size} app(s) did not come from a store",
                    detail = "These apps were installed outside an app store, so nothing reviewed " +
                        "them before they reached your device: " +
                        sideloaded.take(5).joinToString(", ") { it.label } +
                        if (sideloaded.size > 5) " and ${sideloaded.size - 5} more." else ".",
                    remediation = "Check each one is something you deliberately installed from a " +
                        "source you trust. Uninstall anything you do not recognise.",
                    evidence = mapOf(
                        "packages" to sideloaded.joinToString(",") { it.packageName },
                        "count" to sideloaded.size.toString()
                    )
                )
            )
        }
    }

    /**
     * Apps shipping a debuggable build, or permitting clear-text HTTP.
     *
     * Both are developer settings that should never reach a released app; both
     * mean the app's own traffic or memory is trivially readable.
     */
    val InsecureBuild = object : BaseRule(
        id = "APP-BUILD-001",
        category = Category.APP_HYGIENE,
        description = "No app ships an insecure build configuration",
        platforms = ANDROID_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.installedApps) { apps ->
            val offenders = apps.filterNot { it.isSystemApp }.mapNotNull { app ->
                val problems = buildList {
                    if (app.isDebuggable == true) add("is debuggable")
                    if (app.usesCleartextTraffic == true) add("allows unencrypted connections")
                }
                if (problems.isEmpty()) null else app to problems
            }

            if (offenders.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                offenders.map { (app, problems) ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = if (app.isDebuggable == true) Severity.HIGH else Severity.MEDIUM,
                        subjectId = app.packageName,
                        title = "\"${app.label}\" ${problems.joinToString(" and ")}",
                        detail = if (app.isDebuggable == true) {
                            "A debuggable app lets any other process on the device read its memory " +
                                "and inspect its data, including anything you have signed in to."
                        } else {
                            "This app is allowed to send data over unencrypted connections, which " +
                                "anyone on the same network can read or alter."
                        },
                        remediation = "Uninstall it, or contact the developer. A released app should " +
                            "never ship in this state.",
                        evidence = mapOf(
                            "package" to app.packageName,
                            "problems" to problems.joinToString(";")
                        )
                    )
                }
            )
        }
    }

    /**
     * Apps that target an old SDK level.
     *
     * Targeting an old API level opts an app out of newer platform protections —
     * scoped storage, background limits, stricter permission prompts. Play
     * enforces a minimum for *updates*, but long-abandoned apps stay installed.
     */
    val StaleTargetSdk = object : BaseRule(
        id = "APP-SDK-001",
        category = Category.APP_HYGIENE,
        description = "No app opts out of modern platform protections",
        platforms = ANDROID_ONLY
    ) {
        /** Android 10. Below this, scoped storage does not apply. */
        private val MIN_ACCEPTABLE_TARGET = 29

        override fun check(s: DeviceSnapshot) = requireObserved(s.installedApps) { apps ->
            val stale = apps.filterNot { it.isSystemApp }
                .filter { (it.targetSdk ?: Int.MAX_VALUE) < MIN_ACCEPTABLE_TARGET }

            if (stale.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "${stale.size} app(s) opt out of modern protections",
                    detail = "These apps were built for an older Android and are exempt from newer " +
                        "safeguards such as restricted file access: " +
                        stale.take(5).joinToString(", ") { it.label } +
                        if (stale.size > 5) " and ${stale.size - 5} more." else ".",
                    remediation = "Update them if updates exist. Replace any that have been abandoned.",
                    evidence = mapOf("packages" to stale.joinToString(",") { it.packageName })
                )
            )
        }
    }

    /**
     * Dormant apps holding sensitive permissions.
     *
     * Not a vulnerability, but the cheapest real risk reduction available: an app
     * you have not opened in six months that can still use your microphone is
     * pure downside.
     */
    val DormantPrivileged = object : BaseRule(
        id = "APP-DORMANT-001",
        category = Category.APP_HYGIENE,
        description = "Unused apps do not retain sensitive permissions",
        platforms = ANDROID_ONLY
    ) {
        private val DORMANT_DAYS = 180L
        private val MILLIS_PER_DAY = 86_400_000L

        private val SENSITIVE = setOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CONTACTS"
        )

        override fun check(s: DeviceSnapshot) = requireObserved(s.installedApps) { apps ->
            val cutoff = s.collectedAt - DORMANT_DAYS * MILLIS_PER_DAY
            val dormant = apps.filterNot { it.isSystemApp }.filter { app ->
                val lastUsed = app.lastUsedEpochMillis ?: return@filter false
                lastUsed < cutoff && app.grantedPermissions.any { it in SENSITIVE }
            }

            if (dormant.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "${dormant.size} unused app(s) still hold sensitive permissions",
                    detail = "You have not opened these in six months, but they can still use your " +
                        "camera, microphone, location or contacts: " +
                        dormant.take(5).joinToString(", ") { it.label } +
                        if (dormant.size > 5) " and ${dormant.size - 5} more." else ".",
                    remediation = "Uninstall what you no longer use. For the rest, revoke the " +
                        "permissions until you next need them.",
                    evidence = mapOf("packages" to dormant.joinToString(",") { it.packageName })
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        ClonedApp, DangerousCluster, UnknownSource, InsecureBuild, StaleTargetSdk, DormantPrivileged
    )

    /** Exposed for the UI's per-app drill-down screen. */
    fun riskScoreForApp(app: InstalledApp): Severity? =
        ClusterRulePack.mostSevereMatch(app)?.severity
}
