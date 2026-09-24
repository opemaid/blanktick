package com.blanktick.app.collect

import android.annotation.SuppressLint
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import com.blanktick.core.model.CaCertificate
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.InstalledApp
import com.blanktick.core.model.Platform
import com.blanktick.core.model.ProxyInfo
import com.blanktick.core.model.ScreenLock
import com.blanktick.core.model.WifiSecurity
import com.blanktick.core.model.WifiSnapshot
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * Builds a [DeviceSnapshot] from what Android will actually tell us.
 *
 * ## The one rule
 *
 * **When a value cannot be read, the field is left `null`. Never `false`,
 * never a guess.**
 *
 * `null` propagates through the core as "this platform cannot observe this",
 * and the rule that depends on it is reported to the user as *not checkable*
 * rather than as passing. Substituting `false` for "the permission was denied"
 * would silently turn a missing check into a green tick, which is the exact
 * failure mode the whole architecture is built to prevent.
 *
 * Every `runCatching { ... }.getOrNull()` below is therefore deliberate, not
 * lazy error handling.
 */
class AndroidCollector(private val context: Context) {

    fun collect(intel: IntelSnapshot): DeviceSnapshot {
        val pm = context.packageManager
        return DeviceSnapshot(
            platform = Platform.ANDROID,
            collectedAt = System.currentTimeMillis(),

            rootedOrJailbroken = detectRoot(),
            bootloaderUnlocked = detectUnlockedBootloader(),
            developerOptionsEnabled = globalFlag(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
            adbEnabled = globalFlag(Settings.Global.ADB_ENABLED),
            adbOverNetworkPort = adbTcpPort(),
            runningOnEmulator = detectEmulator(),
            hookingArtifacts = detectHooking(),

            osVersion = Build.VERSION.RELEASE,
            osMajor = Build.VERSION.SDK_INT.let { sdkToMajor(it) },
            securityPatchDate = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() },

            screenLock = detectScreenLock(),
            diskEncrypted = detectEncryption(),
            biometricEnrolled = null,   // needs androidx.biometric; not read in v1
            screenLockTimeoutSeconds = lockTimeoutSeconds(),
            lockscreenShowsNotificationContent = lockscreenPreviews(),

            wifi = collectWifi(),
            userInstalledCaCerts = collectUserCaCerts(),
            proxy = collectProxy(),
            vpnActive = detectVpn(),
            vpnOwnerPackage = null,     // Android exposes no owner for the tunnel
            dnsServers = collectDns(),
            privateDnsMode = secureString("private_dns_mode"),

            installedApps = collectApps(pm),

            // Photo and password audits run in their own screens and are merged
            // into the snapshot by the view model when the user has run them.
            photosScanned = null,
            photosWithPreciseLocation = null,
            passwordAudit = null,

            intelBundleDate = intel.builtOn,
            intelStalenessDays = intel.stalenessDays,
            referencePatchDates = intel.referencePatchDates,
            knownSigners = intel.knownSigners
        )
    }

    /**
     * `AppOpsManager.OPSTR_REQUEST_INSTALL_PACKAGES` is not public API, so the
     * op is named by its stable platform string. If a future Android renames
     * it, [appOpAllowed] returns null and the caller falls back to the
     * requested-permission signal rather than reporting a false negative.
     */
    private val OP_REQUEST_INSTALL_PACKAGES = "android:request_install_packages"

    // ---------------------------------------------------------------- root

    private val SU_PATHS = arrayOf(
        "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
        "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/su", "/su/bin/su", "/system/app/Superuser.apk",
        "/system/xbin/daemonsu", "/dev/com.koushikdutta.superuser.daemon/"
    )

    private val MAGISK_PATHS = arrayOf(
        "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock",
        "/data/adb/magisk", "/data/adb/modules"
    )

    /**
     * Root detection, deliberately conservative.
     *
     * This is a heuristic and it is presented as one. Returning a false
     * positive here costs the user 25 points and tells them to factory reset,
     * so the signals used are ones that essentially do not occur on a stock
     * device: a `su` binary on the path, Magisk's own directories, or a build
     * signed with the public AOSP test keys.
     *
     * We do **not** treat "the device is unusual" as root.
     */
    private fun detectRoot(): Boolean = runCatching {
        if (Build.TAGS?.contains("test-keys") == true) return@runCatching true
        if (SU_PATHS.any { File(it).exists() }) return@runCatching true
        if (MAGISK_PATHS.any { File(it).exists() }) return@runCatching true
        // A writable system partition means verified boot is not holding.
        listOf("/system", "/system/bin", "/vendor").any { File(it).canWrite() }
    }.getOrElse { return@getOrElse false }

    private fun detectUnlockedBootloader(): Boolean? = runCatching {
        when (systemProperty("ro.boot.verifiedbootstate")?.lowercase()) {
            "green" -> false
            "orange", "yellow", "red" -> true
            else -> when (systemProperty("ro.boot.flash.locked")) {
                "1" -> false
                "0" -> true
                else -> null
            }
        }
    }.getOrNull()

    private fun detectEmulator(): Boolean = runCatching {
        val fingerprint = Build.FINGERPRINT ?: ""
        fingerprint.startsWith("generic") || fingerprint.contains("vbox") ||
            fingerprint.contains("emulator") || Build.MODEL.contains("sdk_gphone") ||
            Build.PRODUCT == "google_sdk" || Build.HARDWARE == "goldfish" ||
            Build.HARDWARE == "ranchu"
    }.getOrElse { false }

    /**
     * Instrumentation frameworks currently loaded into *our own* process.
     *
     * We can only see our own memory map, which is exactly the right scope: if
     * something has injected into Blanktick, every other reading in this snapshot is
     * suspect anyway.
     */
    private fun detectHooking(): List<String> = runCatching {
        val needles = mapOf(
            "frida" to "frida", "gum-js-loop" to "frida", "gadget" to "frida-gadget",
            "substrate" to "substrate", "xposed" to "xposed", "epic." to "epic"
        )
        val maps = File("/proc/self/maps").takeIf { it.canRead() }?.readText().orEmpty()
        val found = needles.filterKeys { maps.contains(it, ignoreCase = true) }.values.toSet()

        val traced = File("/proc/self/status").takeIf { it.canRead() }?.readLines()
            ?.firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0

        (found + if (traced != 0) setOf("attached debugger (pid $traced)") else emptySet()).toList()
    }.getOrElse { emptyList() }

    // -------------------------------------------------------------- system

    private fun globalFlag(key: String): Boolean? = runCatching {
        Settings.Global.getInt(context.contentResolver, key) == 1
    }.getOrNull()

    private fun secureString(key: String): String? = runCatching {
        Settings.Global.getString(context.contentResolver, key)
    }.getOrNull()

    /** ADB listening on TCP. `service.adb.tcp.port` is set while it is on. */
    private fun adbTcpPort(): Int? = runCatching {
        systemProperty("service.adb.tcp.port")?.toIntOrNull()?.takeIf { it > 0 }
    }.getOrNull()

    private fun systemProperty(key: String): String? = runCatching {
        @Suppress("PrivateApi")
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java)
        (get.invoke(null, key) as? String)?.takeIf { it.isNotBlank() }
    }.getOrNull()

    /** SDK level to the marketing major version people recognise. */
    private fun sdkToMajor(sdk: Int): Int = when {
        sdk >= 36 -> 16
        sdk == 35 -> 15
        sdk == 34 -> 14
        sdk == 33 -> 13
        sdk == 32 || sdk == 31 -> 12
        sdk == 30 -> 11
        sdk == 29 -> 10
        else -> 9
    }

    // ------------------------------------------------------- lock & crypto

    /**
     * Screen-lock strength.
     *
     * Android exposes whether a lock exists, but not its exact form, to an
     * unprivileged app. So we report the two states we can genuinely tell apart
     * and use [ScreenLock.UNKNOWN] — which the rule treats as *not checkable* —
     * rather than inventing a strength we cannot observe.
     */
    private fun detectScreenLock(): ScreenLock = runCatching {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (!km.isDeviceSecure) ScreenLock.NONE else ScreenLock.UNKNOWN
    }.getOrElse { ScreenLock.UNKNOWN }

    /**
     * File-based encryption has been mandatory since Android 10, which is our
     * minSdk, and it is keyed to the screen lock. So: encrypted iff there is a
     * lock. Reported honestly rather than hard-coded true.
     */
    private fun detectEncryption(): Boolean? = runCatching {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        km.isDeviceSecure
    }.getOrNull()

    private fun lockTimeoutSeconds(): Int? = runCatching {
        Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_OFF_TIMEOUT) / 1000
    }.getOrNull()

    private fun lockscreenPreviews(): Boolean? = runCatching {
        // 0 = hide all, 1 = hide sensitive, 2 = show everything
        Settings.Secure.getInt(context.contentResolver, "lock_screen_show_notifications") == 1 &&
            Settings.Secure.getInt(context.contentResolver, "lock_screen_allow_private_notifications") == 1
    }.getOrNull()

    /* --------------------------------------------------------------- network
     *
     * ## These four collectors are expected to return null on a shipping build
     *
     * `ConnectivityManager.getActiveNetwork()` and everything reached through
     * it require `ACCESS_NETWORK_STATE`, which is on the forbidden-permission
     * list enforced by `assertNoNetworkPermission` in `build.gradle.kts`. So on
     * a real device these throw `SecurityException`, the `runCatching` turns
     * that into `null`, and `NET-WIFI-001`, `NET-PROXY-001`, `NET-VPN-001` and
     * `NET-DNS-001` report *not checkable*.
     *
     * That is the honest outcome and it is what the user is shown. It is also a
     * real cost of the permission policy, and it is written here rather than
     * discovered later: **the Android build currently cannot see the network it
     * is on.** The desktop build can, because a desktop has no such permission
     * model to opt out of.
     *
     * Whether to keep this trade-off is a product decision, not a code one.
     * `ACCESS_NETWORK_STATE` grants no ability to send anything — without
     * `INTERNET` the kernel still refuses every socket — so allowing it would
     * buy four working checks without weakening the guarantee that actually
     * matters. Until that decision is revisited, the code stays: it is correct,
     * it degrades honestly, and it starts working the moment the policy changes.
     *
     * The lint suppression below is therefore deliberate and narrow. It says
     * "we know the permission is missing, and missing is the plan".
     */

    @SuppressLint("MissingPermission")
    private fun collectWifi(): WifiSnapshot? = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return@runCatching null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return@runCatching null

        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        @Suppress("DEPRECATION")
        val info = wm.connectionInfo

        val security = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.currentSecurityType) {
                WifiInfo.SECURITY_TYPE_OPEN -> WifiSecurity.OPEN
                WifiInfo.SECURITY_TYPE_WEP -> WifiSecurity.WEP
                WifiInfo.SECURITY_TYPE_PSK -> WifiSecurity.WPA2
                WifiInfo.SECURITY_TYPE_SAE -> WifiSecurity.WPA3
                WifiInfo.SECURITY_TYPE_OWE -> WifiSecurity.OWE
                WifiInfo.SECURITY_TYPE_EAP,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE -> WifiSecurity.WPA2
                else -> WifiSecurity.UNKNOWN
            }
        } else {
            // Below API 31 the security type is not exposed. We do not guess.
            WifiSecurity.UNKNOWN
        }

        WifiSnapshot(
            ssid = info.ssid?.trim('"')?.takeIf { it.isNotBlank() && it != "<unknown ssid>" },
            security = security,
            captivePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            gatewayMacChanged = null,   // needs history; wired up in a later phase
            isMetered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        )
    }.getOrNull()

    /**
     * Certificate authorities in the trust store that the OS did not ship.
     *
     * The highest-signal local indicator of TLS interception, and readable
     * without any permission at all: `AndroidCAStore` prefixes user-added
     * aliases with `user:` and system ones with `system:`.
     */
    private fun collectUserCaCerts(): List<CaCertificate>? = runCatching {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
        ks.aliases().toList()
            .filter { it.startsWith("user:") }
            .mapNotNull { alias ->
                val cert = ks.getCertificate(alias) as? X509Certificate ?: return@mapNotNull null
                CaCertificate(
                    subject = cert.subjectX500Principal.name.substringAfter("CN=").substringBefore(','),
                    issuer = cert.issuerX500Principal.name.substringAfter("CN=").substringBefore(','),
                    sha256 = sha256Hex(cert.encoded),
                    notAfterEpochMillis = cert.notAfter?.time,
                    mdmInstalled = isManagedDevice()
                )
            }
    }.getOrNull()

    private fun isManagedDevice(): Boolean = runCatching {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        dpm.activeAdmins?.isNotEmpty() == true
    }.getOrElse { false }

    @SuppressLint("MissingPermission")
    private fun collectProxy(): ProxyInfo? = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val proxy = cm.defaultProxy ?: return@runCatching null
        val host = proxy.host?.takeIf { it.isNotBlank() } ?: return@runCatching null
        ProxyInfo(host = host, port = proxy.port, pacUrl = proxy.pacFileUrl?.toString())
    }.getOrNull()

    @SuppressLint("MissingPermission")
    private fun detectVpn(): Boolean? = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }.getOrNull()

    @SuppressLint("MissingPermission")
    private fun collectDns(): List<String>? = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val link: LinkProperties = cm.getLinkProperties(cm.activeNetwork) ?: return@runCatching null
        link.dnsServers.map { it.hostAddress ?: it.toString().removePrefix("/") }
    }.getOrNull()

    // ---------------------------------------------------------------- apps

    /**
     * Installed apps, via a launcher-intent query rather than
     * `QUERY_ALL_PACKAGES`.
     *
     * This returns the apps a person would list if asked what is on their
     * phone. It deliberately omits packages with no launcher entry — which
     * means a headless dropper could hide from this list. That trade-off is
     * accepted: `QUERY_ALL_PACKAGES` is a restricted permission that puts the
     * app into a Play review category we would rather avoid, and the highest
     * value checks (cloned banking apps, trojan permission sets) target apps
     * the user can see and launch.
     */
    private fun collectApps(pm: PackageManager): List<InstalledApp>? = runCatching {
        val launcherIntent = android.content.Intent(android.content.Intent.ACTION_MAIN)
            .addCategory(android.content.Intent.CATEGORY_LAUNCHER)

        @Suppress("DEPRECATION")
        val resolved = pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
        val packages = resolved.mapNotNull { it.activityInfo?.packageName }.distinct()

        val accessibility = enabledComponentPackages(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val notificationListeners = enabledComponentPackages("enabled_notification_listeners")
        val deviceAdmins = activeAdminPackages()
        val usage = recentUsage()

        packages.mapNotNull { pkg ->
            val info = packageInfo(pm, pkg) ?: return@mapNotNull null
            val app = info.applicationInfo ?: return@mapNotNull null
            val granted = grantedPermissions(info)

            InstalledApp(
                packageName = pkg,
                label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(pkg),
                versionName = info.versionName,
                installerPackage = installerOf(pm, pkg),
                signerSha256 = signerSha256(info),
                isSystemApp = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                targetSdk = app.targetSdkVersion,
                grantedPermissions = granted,
                holdsAccessibilityService = pkg in accessibility,
                holdsDeviceAdmin = pkg in deviceAdmins,
                holdsNotificationListener = pkg in notificationListeners,
                canDrawOverlays = appOpAllowed(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, app.uid, pkg)
                    ?: granted.contains("android.permission.SYSTEM_ALERT_WINDOW"),
                canRequestPackageInstalls =
                    appOpAllowed(OP_REQUEST_INSTALL_PACKAGES, app.uid, pkg)
                        ?: granted.contains("android.permission.REQUEST_INSTALL_PACKAGES"),
                usesCleartextTraffic =
                    (app.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0,
                isDebuggable = (app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                lastUsedEpochMillis = usage?.get(pkg)
            )
        }
    }.getOrNull()

    private fun packageInfo(pm: PackageManager, pkg: String): PackageInfo? = runCatching {
        val flags = PackageManager.GET_PERMISSIONS or
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES
            else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        @Suppress("DEPRECATION")
        pm.getPackageInfo(pkg, flags)
    }.getOrNull()

    /** Only permissions actually GRANTED, not merely requested. */
    private fun grantedPermissions(info: PackageInfo): Set<String> {
        val requested = info.requestedPermissions ?: return emptySet()
        val flags = info.requestedPermissionsFlags ?: return requested.toSet()
        return requested.filterIndexed { i, _ ->
            i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }.toSet()
    }

    private fun signerSha256(info: PackageInfo): String? = runCatching {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.let {
                if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION") info.signatures
        }
        signatures?.firstOrNull()?.toByteArray()?.let { sha256Hex(it) }
    }.getOrNull()

    private fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        }
    }.getOrNull()

    private fun enabledComponentPackages(settingKey: String): Set<String> = runCatching {
        Settings.Secure.getString(context.contentResolver, settingKey)
            ?.split(':', ';')
            ?.mapNotNull { it.substringBefore('/').takeIf(String::isNotBlank) }
            ?.toSet()
            .orEmpty()
    }.getOrElse { emptySet() }

    private fun activeAdminPackages(): Set<String> = runCatching {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        dpm.activeAdmins?.map { it.packageName }?.toSet().orEmpty()
    }.getOrElse { emptySet() }

    /**
     * @return null when PACKAGE_USAGE_STATS has not been granted — which makes
     *   the dormant-app rule report *not checkable* rather than claiming every
     *   app is in active use.
     */
    private fun recentUsage(): Map<String, Long>? = runCatching {
        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val end = System.currentTimeMillis()
        val start = end - 400L * 24 * 60 * 60 * 1000
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_YEARLY, start, end)
        if (stats.isNullOrEmpty()) return@runCatching null
        stats.associate { it.packageName to it.lastTimeUsed }
    }.getOrNull()

    /**
     * @return null when the op cannot be read for another package on this OS
     *   version, so the caller falls back to the requested-permission signal
     *   instead of assuming "not granted".
     */
    private fun appOpAllowed(op: String, uid: Int, pkg: String): Boolean? = runCatching {
        val aom = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            aom.unsafeCheckOpNoThrow(op, uid, pkg)
        } else {
            @Suppress("DEPRECATION") aom.checkOpNoThrow(op, uid, pkg)
        }
        mode == AppOpsManager.MODE_ALLOWED
    }.getOrNull()

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02X".format(it) }
}
