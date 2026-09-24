package com.blanktick.core.intel

import com.blanktick.core.model.InstalledApp
import com.blanktick.core.model.Severity

/** Android permission strings referenced by the cluster rules. */
object Perms {
    const val READ_SMS = "android.permission.READ_SMS"
    const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    const val SEND_SMS = "android.permission.SEND_SMS"
    const val READ_CONTACTS = "android.permission.READ_CONTACTS"
    const val RECORD_AUDIO = "android.permission.RECORD_AUDIO"
    const val CAMERA = "android.permission.CAMERA"
    const val FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
    const val BACKGROUND_LOCATION = "android.permission.ACCESS_BACKGROUND_LOCATION"
    const val READ_CALL_LOG = "android.permission.READ_CALL_LOG"
    const val READ_PHONE_STATE = "android.permission.READ_PHONE_STATE"
    const val SYSTEM_ALERT_WINDOW = "android.permission.SYSTEM_ALERT_WINDOW"
    const val REQUEST_INSTALL_PACKAGES = "android.permission.REQUEST_INSTALL_PACKAGES"
    const val QUERY_ALL_PACKAGES = "android.permission.QUERY_ALL_PACKAGES"
    const val READ_EXTERNAL_STORAGE = "android.permission.READ_EXTERNAL_STORAGE"
}

/** Capabilities that are granted through Settings rather than a runtime prompt. */
enum class AppCapability {
    ACCESSIBILITY_SERVICE,
    DEVICE_ADMIN,
    NOTIFICATION_LISTENER,
    DRAW_OVERLAY,
    INSTALL_PACKAGES;

    fun heldBy(app: InstalledApp): Boolean = when (this) {
        ACCESSIBILITY_SERVICE -> app.holdsAccessibilityService
        DEVICE_ADMIN -> app.holdsDeviceAdmin
        NOTIFICATION_LISTENER -> app.holdsNotificationListener
        DRAW_OVERLAY -> app.canDrawOverlays
        INSTALL_PACKAGES -> app.canRequestPackageInstalls
    }
}

/**
 * A combination of permissions and capabilities that is far more dangerous
 * together than apart.
 *
 * ## Why clusters rather than per-permission scoring
 *
 * Almost every individual Android permission has a legitimate use. `READ_SMS`
 * is what your messaging app does. An accessibility service is what a screen
 * reader is. Flagging them individually produces a wall of noise that trains
 * users to dismiss the app.
 *
 * *Combinations* are far more specific. An app that can read your texts, draw
 * over other apps, and drive the UI through the accessibility API has the exact
 * capability set of a banking trojan: overlay a fake login screen, capture what
 * you type, and read the one-time code out of your SMS. Almost nothing
 * legitimate needs all three.
 *
 * This is the whole reason the Android build is worth more than the iOS build,
 * and it needs no server at all.
 */
data class PermissionCluster(
    val id: String,
    val name: String,
    /** Written for the user, not for an analyst. */
    val explanation: String,
    val severity: Severity,
    val permissions: Set<String> = emptySet(),
    val capabilities: Set<AppCapability> = emptySet(),
    /** Packages with a legitimate reason to hold this exact combination. */
    val exemptPackages: Set<String> = emptySet()
) {
    init {
        require(permissions.isNotEmpty() || capabilities.isNotEmpty()) {
            "cluster $id matches nothing"
        }
    }

    fun matches(app: InstalledApp): Boolean {
        if (app.isSystemApp) return false
        if (app.packageName in exemptPackages) return false
        if (!app.grantedPermissions.containsAll(permissions)) return false
        return capabilities.all { it.heldBy(app) }
    }
}

/**
 * The bundled cluster rule pack.
 *
 * Ships inside the app; updated with app releases. Every entry here was chosen
 * because the combination is both (a) strongly associated with a real malware
 * family shape and (b) rare among legitimate apps.
 */
object ClusterRulePack {

    /** Apps that legitimately need deep accessibility + overlay access. */
    private val ACCESSIBILITY_LEGITIMATE = setOf(
        "com.google.android.marvin.talkback",
        "com.samsung.accessibility",
        "com.android.talkback",
        "org.nvda.android",
        "com.google.android.apps.accessibility.voiceaccess",
        "com.google.android.apps.accessibility.reveal",
        "net.tatans.tback",
        "com.lastpass.lpandroid",
        "com.agilebits.onepassword",
        "com.bitwarden.authenticator",
        "com.x8bit.bitwarden",
        "com.dashlane",
        "com.keepersecurity.parent"
    )

    val BANKING_TROJAN = PermissionCluster(
        id = "CLUSTER-BANKER",
        name = "Banking-trojan capability set",
        explanation = "This app can read your text messages, draw on top of other apps, and control " +
            "the screen. Together that is exactly what is needed to show a fake login screen over " +
            "your banking app, record what you type, and read the confirmation code out of your SMS.",
        severity = Severity.CRITICAL,
        permissions = setOf(Perms.RECEIVE_SMS),
        capabilities = setOf(AppCapability.DRAW_OVERLAY, AppCapability.ACCESSIBILITY_SERVICE),
        exemptPackages = ACCESSIBILITY_LEGITIMATE
    )

    val OVERLAY_PLUS_ACCESSIBILITY = PermissionCluster(
        id = "CLUSTER-OVERLAY-A11Y",
        name = "Screen control and overlay",
        explanation = "This app can both draw over whatever you are looking at and act on your " +
            "behalf through the accessibility system. That combination can capture anything you " +
            "type and tap buttons without you.",
        severity = Severity.HIGH,
        capabilities = setOf(AppCapability.DRAW_OVERLAY, AppCapability.ACCESSIBILITY_SERVICE),
        exemptPackages = ACCESSIBILITY_LEGITIMATE
    )

    val SMS_INTERCEPTOR = PermissionCluster(
        id = "CLUSTER-SMS",
        name = "Full SMS access",
        explanation = "This app can read, receive and send text messages. Anything protected by an " +
            "SMS code — bank transfers, account recovery — is reachable by it.",
        severity = Severity.HIGH,
        permissions = setOf(Perms.READ_SMS, Perms.RECEIVE_SMS, Perms.SEND_SMS),
        exemptPackages = setOf(
            "com.google.android.apps.messaging",
            "com.samsung.android.messaging",
            "com.android.mms",
            "org.thoughtcrime.securesms",
            "com.whatsapp",
            "org.telegram.messenger",
            "com.textra"
        )
    )

    val STALKERWARE = PermissionCluster(
        id = "CLUSTER-STALKER",
        name = "Surveillance capability set",
        explanation = "This app can record audio, use the camera, read your contacts and track your " +
            "location in the background. That is the full toolkit used by stalkerware.",
        severity = Severity.CRITICAL,
        permissions = setOf(
            Perms.RECORD_AUDIO, Perms.CAMERA, Perms.READ_CONTACTS, Perms.BACKGROUND_LOCATION
        )
    )

    val CALL_AND_CONTACTS_HARVEST = PermissionCluster(
        id = "CLUSTER-HARVEST",
        name = "Contact and call-history harvesting",
        explanation = "This app can read your contacts and your full call history. Both are commonly " +
            "sold on, and are used to make scam calls look convincing to the people you know.",
        severity = Severity.MEDIUM,
        permissions = setOf(Perms.READ_CONTACTS, Perms.READ_CALL_LOG),
        exemptPackages = setOf(
            "com.google.android.dialer", "com.samsung.android.dialer",
            "com.android.dialer", "com.android.contacts"
        )
    )

    val NOTIFICATION_HARVEST = PermissionCluster(
        id = "CLUSTER-NOTIF",
        name = "Reads every notification",
        explanation = "This app receives the content of every notification your device shows, " +
            "including one-time codes, message previews and email subjects.",
        severity = Severity.MEDIUM,
        capabilities = setOf(AppCapability.NOTIFICATION_LISTENER),
        exemptPackages = setOf(
            "com.google.android.wearable.app",
            "com.samsung.android.app.watchmanager",
            "com.google.android.projection.gearhead",
            "com.pushbullet.android"
        )
    )

    val SIDELOAD_INSTALLER = PermissionCluster(
        id = "CLUSTER-INSTALLER",
        name = "Can install other apps",
        explanation = "This app is allowed to install further apps onto your device. Droppers use " +
            "this to fetch their real payload after passing a store review.",
        severity = Severity.HIGH,
        capabilities = setOf(AppCapability.INSTALL_PACKAGES),
        exemptPackages = setOf(
            "com.android.vending", "com.google.android.packageinstaller",
            "com.android.packageinstaller", "com.amazon.venezia",
            "org.fdroid.fdroid", "com.aurora.store"
        )
    )

    val RANSOMWARE_ADMIN = PermissionCluster(
        id = "CLUSTER-ADMIN",
        name = "Device administrator held by a sideloaded app",
        explanation = "This app can lock the screen, change your PIN and wipe the device. Ransomware " +
            "takes device-administrator rights so it cannot easily be removed.",
        severity = Severity.HIGH,
        capabilities = setOf(AppCapability.DEVICE_ADMIN)
    )

    val ALL: List<PermissionCluster> = listOf(
        BANKING_TROJAN,
        STALKERWARE,
        OVERLAY_PLUS_ACCESSIBILITY,
        SMS_INTERCEPTOR,
        SIDELOAD_INSTALLER,
        RANSOMWARE_ADMIN,
        CALL_AND_CONTACTS_HARVEST,
        NOTIFICATION_HARVEST
    )

    /**
     * Evaluates in priority order and returns only the **most severe** matching
     * cluster for a given app.
     *
     * Reporting all eight matches for one bad app would triple-charge the score
     * and bury the user. The banking-trojan cluster subsumes the overlay one; we
     * say the worst true thing and stop.
     */
    fun mostSevereMatch(app: InstalledApp): PermissionCluster? =
        ALL.firstOrNull { it.matches(app) }
}
