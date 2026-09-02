package com.mume.desktop.collect

import com.mume.core.model.CaCertificate
import com.mume.core.model.DesktopFacts
import com.mume.core.model.DesktopOs
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Platform
import com.mume.core.model.ProxyInfo
import com.mume.core.model.ScreenLock

/**
 * What one operating system's collector must be able to answer.
 *
 * ## Every method may return `null`, and that is the point
 *
 * The contract is identical to `AndroidCollector`: **`null` means "this machine
 * would not tell me", never "no" and never a default.** The base implementations
 * below all return `null`, so a new OS collector starts out honestly reporting
 * that it knows nothing and gains coverage only as real queries are written.
 * There is no way to accidentally inherit a green tick.
 */
internal interface PlatformCollector {
    val os: DesktopOs

    /** Human-readable OS build string, for display only. */
    fun osBuild(): String? = null

    /**
     * The desktop-specific block.
     *
     * @param intel the bundled threat data, so a collector can resolve a file
     *   hash against the known-malware table while it still has the file in
     *   hand. The alternative -- carrying every hash up to a rule -- would mean
     *   putting a million-entry table on the snapshot.
     */
    fun collect(intel: DesktopIntelSnapshot): DesktopFacts

    // ---- Facts shared with the mobile snapshot -----------------------------

    fun diskEncrypted(): Boolean? = null
    fun screenLock(): ScreenLock? = null
    fun screenLockTimeoutSeconds(): Int? = null
    fun userInstalledCaCerts(): List<CaCertificate>? = null
    fun dnsServers(): List<String>? = null
    fun proxyHostPort(): Pair<String, Int>? = null
}

/**
 * Builds a [DeviceSnapshot] for whichever desktop this is running on.
 *
 * ## OS detection, and what happens on an unrecognised one
 *
 * If `os.name` is something this build has never heard of, [forCurrentOs]
 * returns `null` and the app says so plainly instead of guessing at Linux and
 * running commands that do not exist. An app that reports a confident security
 * verdict for an operating system it does not understand is worse than one that
 * declines.
 */
class DesktopCollector internal constructor(
    private val platform: PlatformCollector,
    private val now: () -> Long = System::currentTimeMillis
) {

    val os: DesktopOs get() = platform.os

    fun collect(intel: DesktopIntelSnapshot): DeviceSnapshot {
        val proxy = platform.proxyHostPort()

        return DeviceSnapshot(
            platform = Platform.DESKTOP,
            collectedAt = now(),

            // Mobile-only integrity signals. A desktop is not "rooted" in any
            // sense that maps onto this field, and inventing a value would make
            // DEV-ROOT-001 fire or pass on a machine it was never written for.
            rootedOrJailbroken = null,
            bootloaderUnlocked = null,
            developerOptionsEnabled = null,
            adbEnabled = null,
            hookingArtifacts = null,

            osVersion = platform.osBuild(),
            osMajor = null,             // the Android major-version table does not apply
            securityPatchDate = null,   // Android concept; desktops use DSK-UPD-*

            screenLock = platform.screenLock(),
            diskEncrypted = platform.diskEncrypted(),
            screenLockTimeoutSeconds = platform.screenLockTimeoutSeconds(),
            lockscreenShowsNotificationContent = null,

            // Wi-Fi security type is not readable without either elevation or a
            // platform-specific native binding on any of the three desktops, so
            // NET-WIFI-001 reports not-checkable here rather than guessing.
            wifi = null,
            userInstalledCaCerts = platform.userInstalledCaCerts(),
            proxy = proxy?.let { ProxyInfo(host = it.first, port = it.second) },
            vpnActive = null,
            dnsServers = platform.dnsServers(),
            privateDnsMode = null,

            installedApps = null,       // the Android app auditor has no desktop analogue

            // Filled in by the photo and password screens when the user runs
            // them, exactly as on Android.
            photosScanned = null,
            photosWithPreciseLocation = null,
            passwordAudit = null,

            desktop = platform.collect(intel),

            intelBundleDate = intel.builtOn,
            intelStalenessDays = intel.stalenessDays,
            referencePatchDates = null,
            knownSigners = null
        )
    }

    companion object {
        /** @return `null` when the OS is not one this build knows how to inspect. */
        fun forCurrentOs(): DesktopCollector? = detectOs()?.let { os ->
            DesktopCollector(
                when (os) {
                    DesktopOs.WINDOWS -> WindowsCollector()
                    DesktopOs.MACOS -> MacCollector()
                    DesktopOs.LINUX -> LinuxCollector()
                }
            )
        }

        fun detectOs(): DesktopOs? {
            val name = System.getProperty("os.name")?.lowercase() ?: return null
            return when {
                name.contains("win") -> DesktopOs.WINDOWS
                name.contains("mac") || name.contains("darwin") -> DesktopOs.MACOS
                name.contains("nux") || name.contains("nix") -> DesktopOs.LINUX
                else -> null
            }
        }
    }
}

/**
 * Bundle metadata, mirroring `IntelSnapshot` on Android, plus the one lookup a
 * collector needs while it still has a file in hand.
 *
 * @param isKnownMalware SHA-256 (lowercase hex) to a verdict. `null` from the
 *   function means no corpus is bundled, which must be reported as *not
 *   checked* and never as "nothing found". A `null` function is the same
 *   answer for platforms that never load one.
 *
 *   It lives here rather than on the snapshot the rules see because the
 *   alternative is putting a million-entry hash table on `DeviceSnapshot`.
 */
data class DesktopIntelSnapshot(
    val builtOn: String?,
    val stalenessDays: Int?,
    val isKnownMalware: ((String) -> Boolean?)? = null
)
