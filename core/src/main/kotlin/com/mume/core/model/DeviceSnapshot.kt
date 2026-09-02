package com.mume.core.model

/**
 * Everything the platform layer was able to observe about the device.
 *
 * ## The null contract
 *
 * **Every observable field is nullable, and `null` means "this platform cannot
 * observe this" — not "false", not "absent", not "zero".**
 *
 * This single convention is how decision D-01 is enforced in code. A rule whose
 * inputs are `null` returns [com.mume.core.rules.RuleOutcome.NotApplicable]
 * and is counted in [ScanResult.checksSkipped]. It never emits a passing check,
 * so the iOS build cannot display a green tick for something iOS is incapable
 * of inspecting.
 *
 * Collectors on both platforms MUST leave a field `null` rather than guessing.
 * Passing `false` for "no user CA certs installed" on iOS — where the trust
 * store is not enumerable — would be a lie the scoring engine cannot detect.
 */
data class DeviceSnapshot(
    val platform: Platform,
    val collectedAt: Long,

    // ---- Device integrity -------------------------------------------------
    /** Rooted (Android) or jailbroken (iOS). */
    val rootedOrJailbroken: Boolean? = null,
    val bootloaderUnlocked: Boolean? = null,
    val developerOptionsEnabled: Boolean? = null,
    val adbEnabled: Boolean? = null,
    /** Non-null when ADB is listening on TCP, which exposes the device on the LAN. */
    val adbOverNetworkPort: Int? = null,
    val runningOnEmulator: Boolean? = null,
    /** Names of detected instrumentation artefacts, e.g. `frida-agent`, `substrate`. */
    val hookingArtifacts: List<String>? = null,
    /** Result of a purely local integrity self-check. Null where unavailable. */
    val integrityVerdictOk: Boolean? = null,

    // ---- OS currency ------------------------------------------------------
    val osVersion: String? = null,
    val osMajor: Int? = null,
    /** ISO `yyyy-MM-dd`, from `Build.VERSION.SECURITY_PATCH` on Android. */
    val securityPatchDate: String? = null,

    // ---- Lock & crypto ----------------------------------------------------
    val screenLock: ScreenLock? = null,
    val diskEncrypted: Boolean? = null,
    val biometricEnrolled: Boolean? = null,
    val screenLockTimeoutSeconds: Int? = null,
    val lockscreenShowsNotificationContent: Boolean? = null,

    // ---- Network ----------------------------------------------------------
    val wifi: WifiSnapshot? = null,
    /**
     * CA certificates installed by the user (or by an MDM) rather than shipped
     * with the OS. A populated list is the classic signature of an active
     * TLS-interception proxy such as Burp or mitmproxy.
     */
    val userInstalledCaCerts: List<CaCertificate>? = null,
    val proxy: ProxyInfo? = null,
    val vpnActive: Boolean? = null,
    val vpnOwnerPackage: String? = null,
    val dnsServers: List<String>? = null,
    /** Android `private_dns_mode`: `off`, `opportunistic`, `hostname`. */
    val privateDnsMode: String? = null,

    // ---- Installed apps ---------------------------------------------------
    /** Null on iOS: no API enumerates other apps. Never an empty list on iOS. */
    val installedApps: List<InstalledApp>? = null,

    // ---- Personal data ----------------------------------------------------
    val photosScanned: Int? = null,
    val photosWithPreciseLocation: Int? = null,
    /** Results of checking the user's own saved passwords against the local corpus. */
    val passwordAudit: PasswordAudit? = null,

    // ---- Desktop ----------------------------------------------------------
    /**
     * Facts only a desktop can supply. `null` on Android and iOS.
     *
     * Grouped rather than flattened because these fields are jointly absent:
     * on a phone the whole block is unobservable, and a single `null` says so
     * once instead of twenty times.
     */
    val desktop: DesktopFacts? = null,

    // ---- Intel bundle metadata -------------------------------------------
    val intelBundleDate: String? = null,
    val intelStalenessDays: Int? = null,
    /** Reference "latest known patch level" per OS major, from the bundle. */
    val referencePatchDates: Map<Int, String>? = null,
    /**
     * Bundled registry of `packageName -> allowed signing-certificate SHA-256`.
     *
     * Powers clone detection: an app claiming to be `com.whatsapp` but signed by
     * a key not in this set is an impersonation, full stop. This is one of the
     * highest-signal malware indicators on Android and it needs no server —
     * cloud scanners frequently miss it because they key on file hashes, which
     * a repacker changes trivially.
     */
    val knownSigners: Map<String, Set<String>>? = null
)

/** State of the currently joined Wi-Fi network. */
data class WifiSnapshot(
    val ssid: String?,
    val security: WifiSecurity,
    val captivePortal: Boolean? = null,
    /** True when the gateway MAC has changed for a previously seen SSID. */
    val gatewayMacChanged: Boolean? = null,
    val isMetered: Boolean? = null
)

enum class WifiSecurity {
    /** No encryption whatsoever. */
    OPEN,
    /** Deprecated and trivially broken. */
    WEP,
    WPA,
    WPA2,
    WPA3,
    /** Open network with Opportunistic Wireless Encryption. */
    OWE,
    UNKNOWN
}

/**
 * A CA certificate present in the device trust store but not shipped by the OS.
 *
 * @param mdmInstalled true when the platform can attribute it to a managed
 *   configuration, which is legitimate on a work device and scored lower.
 */
data class CaCertificate(
    val subject: String,
    val issuer: String,
    val sha256: String,
    val notAfterEpochMillis: Long? = null,
    val mdmInstalled: Boolean = false
)

data class ProxyInfo(
    val host: String,
    val port: Int,
    val pacUrl: String? = null
)

/**
 * One installed application, as seen by the platform.
 *
 * On Android this comes from `PackageManager` restricted to launcher-visible
 * packages via a `<queries>` intent filter — deliberately *not* using
 * `QUERY_ALL_PACKAGES`, which is a restricted permission and a Play review
 * category we would rather not enter (kickoff decision, Agenda Item 6).
 */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionName: String? = null,
    /**
     * Package that installed this app. `null` means sideloaded or installed by
     * an unknown source, which is a meaningful signal in itself.
     */
    val installerPackage: String? = null,
    /** SHA-256 of the signing certificate, uppercase hex, no separators. */
    val signerSha256: String? = null,
    val isSystemApp: Boolean = false,
    val targetSdk: Int? = null,
    val grantedPermissions: Set<String> = emptySet(),
    val holdsAccessibilityService: Boolean = false,
    val holdsDeviceAdmin: Boolean = false,
    val holdsNotificationListener: Boolean = false,
    val canDrawOverlays: Boolean = false,
    val canRequestPackageInstalls: Boolean = false,
    val usesCleartextTraffic: Boolean? = null,
    val isDebuggable: Boolean? = null,
    val lastUsedEpochMillis: Long? = null
)

/**
 * Outcome of checking the user's saved credentials against the bundled corpus.
 *
 * Note what is *not* here: no passwords, no hashes, no identifiers. The audit
 * runs entirely in the platform layer and reports counts only, so a crash log
 * or a debug dump of a snapshot can never contain a credential.
 */
data class PasswordAudit(
    val credentialsChecked: Int,
    val breachedCount: Int,
    val reusedCount: Int,
    val weakCount: Int
)

/**
 * What a desktop operating system will tell an unprivileged, offline
 * application about its own security posture.
 *
 * ## Still the null contract
 *
 * Every field is nullable and `null` still means **"this machine could not be
 * asked"** — not "off", not "absent". A Linux box with no `ufw` and no
 * `firewalld` reports `firewallEnabled = null`, because "I could not find a
 * firewall manager I understand" is a different statement from "this machine
 * has no firewall", and only the first one is true.
 *
 * ## What is deliberately not here
 *
 * No file hashes, no document contents, no browsing history, no process
 * command lines. The desktop build reads posture, not activity: everything in
 * this class is a setting the user themselves can see in a settings panel, and
 * a support person reading a dumped snapshot learns nothing about what the
 * person actually *did* on the machine.
 */
data class DesktopFacts(
    val os: DesktopOs,
    /** e.g. `Windows 11 Pro 24H2`, `macOS 15.2`, `Ubuntu 24.04`. Display only. */
    val osBuild: String? = null,

    // ---- Perimeter --------------------------------------------------------
    /** Host firewall on for the profile currently in use. */
    val firewallEnabled: Boolean? = null,
    /** Profiles found to be off, e.g. `Public`. Empty list means all on. */
    val firewallProfilesOff: List<String>? = null,

    // ---- Malware defence --------------------------------------------------
    val antivirusProduct: String? = null,
    val antivirusRealtimeEnabled: Boolean? = null,
    /** Age of the malware definitions, in days. */
    val antivirusSignatureAgeDays: Int? = null,
    /**
     * SmartScreen (Windows), Gatekeeper (macOS). Linux has no equivalent and
     * reports `null` rather than a synthesised `false`.
     */
    val appReputationEnabled: Boolean? = null,

    // ---- Boot integrity ---------------------------------------------------
    val secureBootEnabled: Boolean? = null,
    /** macOS System Integrity Protection. `null` off macOS. */
    val systemIntegrityProtectionEnabled: Boolean? = null,

    // ---- Updates ----------------------------------------------------------
    val automaticUpdatesEnabled: Boolean? = null,
    /** Count of updates the OS itself classifies as security updates. */
    val pendingSecurityUpdates: Int? = null,
    /** Days since the machine last successfully applied any update. */
    val daysSinceLastUpdate: Int? = null,

    // ---- Accounts ---------------------------------------------------------
    /** True when the session running Mume holds administrator/root rights. */
    val sessionIsAdministrator: Boolean? = null,
    /** Local accounts holding administrator rights, by display name. */
    val administratorAccounts: List<String>? = null,
    /** Local accounts that can sign in with no password at all. */
    val passwordlessAccounts: List<String>? = null,
    val guestAccountEnabled: Boolean? = null,
    /** A password is required when the screen wakes or the saver exits. */
    val lockOnWakeEnabled: Boolean? = null,

    // ---- Remote access ----------------------------------------------------
    /** Inbound remote-control services that are enabled. */
    val remoteAccessServices: List<RemoteAccessService>? = null,
    /**
     * Sockets in LISTEN state, enumerated from the OS. Reading this table is
     * not a network operation — nothing is connected to, and the desktop build
     * has no code path that could.
     */
    val listeningPorts: List<ListeningPort>? = null,

    // ---- Persistence ------------------------------------------------------
    /** Programs configured to start automatically at login or boot. */
    val autoRunEntries: List<AutoRunEntry>? = null,

    // ---- Removable media --------------------------------------------------
    /**
     * Whether Windows is configured to refuse `autorun.inf` on removable media.
     *
     * `true` also covers "the policy is absent", because absent means the
     * shipping default, and since 2011 that default has been to ignore autorun
     * on removable drives. A rule that fired on every stock machine would be
     * noise, so only an explicitly weakened policy is a finding.
     */
    val autoRunBlockedForRemovable: Boolean? = null,

    /** Removable drives attached right now. Empty list means none plugged in. */
    val removableDrives: List<RemovableDrive>? = null,

    /**
     * Devices this computer remembers having been connected — USB sticks, phones.
     *
     * Not a vulnerability and never scored. It is shown because a machine
     * quietly keeping a list of every drive and handset you have ever plugged in
     * is the kind of thing people are surprised to learn, and this product's job
     * is to tell them what their computer knows.
     */
    val rememberedUsbDevices: List<String>? = null,

    /**
     * Persistence sources that could not be read, or were only partly read.
     *
     * ## Why a list and not a boolean
     *
     * "Programs that start themselves" is not one question, it is seven —
     * Run keys, Startup folders, Winlogon, Image File Execution Options,
     * scheduled tasks, services — and on a real machine they do not all
     * succeed. Several IFEO subkeys are ACL'd against a normal user, which is
     * ordinary rather than suspicious.
     *
     * An empty list means all sources were read. A non-empty list is what lets
     * the app say "six of seven, and this is the one it could not see" instead
     * of choosing between a reassuring lie and a useless silence. `null` means
     * the platform does not report per-source coverage.
     */
    val autoRunSourcesUnread: List<String>? = null,

    // ---- Hardening settings ------------------------------------------------
    /**
     * Individually small settings that jointly decide whether a foothold stays
     * a foothold.
     *
     * Grouped into one object for the same reason [DesktopFacts] itself is
     * grouped: on a platform that cannot report them the whole block is `null`
     * once, rather than a dozen separate nulls that each have to be explained.
     */
    val hardening: HardeningFacts? = null,

    /**
     * What the installed antivirus is actually doing, as opposed to what its
     * dashboard implies.
     *
     * Mume is not a malware scanner and cannot become one — no network means no
     * reputation lookup, and there is no file scanner. Auditing the scanner
     * that *is* installed is the honest version of the same job, and it is
     * entirely local: a switched-off behaviour monitor, tamper protection
     * disabled, or a threat the product found and never resolved.
     */
    val antivirusPosture: AntivirusPosture? = null,

    // ---- Integrity of the collection itself --------------------------------
    /**
     * Whether the collector ran all the way to the end.
     *
     * ## Why a scan needs to vouch for itself
     *
     * Every other field here answers "what is true of this machine". This one
     * answers "can the other answers be believed", and nothing else in the
     * model does.
     *
     * The desktop probe emits its facts in order and ends with a completion
     * marker. If it is killed partway — by a crash, a policy, or any process
     * running as this user that would rather the scan did not finish — the
     * output stops mid-stream and *looks exactly like a successful run of a
     * shorter script*. Each missing fact is correctly reported as not
     * checkable, which is the null contract working; but a report that is
     * three-quarters "not checkable" for an unstated reason still reads as
     * reassuring, and the user is never told the difference.
     *
     * `false` means the report is partial and the app must say so. `null` means
     * this platform has no completion signal to give.
     */
    val collectionCompleted: Boolean? = null,
    /**
     * Whether the collector's output hit its size ceiling and was cut short.
     *
     * A separate field from [collectionCompleted] because it is a separate
     * failure with the same symptom, and because it is the one an attacker can
     * aim: facts are emitted in order, so inflating an early answer deletes the
     * later ones. Also `true` on a machine that is merely very large, which is
     * why it is reported rather than treated as an attack.
     */
    val collectionTruncated: Boolean? = null,
    /**
     * The language mode the Windows probe ran under, when it could be read.
     *
     * Constrained Language Mode (WDAC, AppLocker, `__PSLockdownPolicy`) blocks
     * COM object creation, and the unprivileged BitLocker read depends on it.
     * Under lockdown that check returns nothing for a reason that has nothing
     * to do with encryption, and this is what lets the app say which.
     */
    val probeLanguageMode: String? = null,

    // ---- Installed software -----------------------------------------------
    /**
     * What is installed, as the OS's own uninstall registry reports it.
     *
     * The desktop counterpart of [InstalledApp], and deliberately a different
     * type: a Windows program has no package name, no signing certificate we
     * can cheaply verify, and no permission set. Reusing the Android shape
     * would have meant six fields that are permanently null and one rule set
     * that cannot run.
     */
    val installedPrograms: List<InstalledProgram>? = null
)

/**
 * One installed program.
 *
 * Every field here is self-declared by the installer — `publisher` in
 * particular is a string the software chose, not a verified signature. It is
 * still useful: legitimate software fills it in and drive-by installers
 * routinely do not, which is the asymmetry `DSK-SW-002` relies on.
 *
 * @param installLocation as recorded at install time. Often absent; absence is
 *   not evidence of anything.
 * @param userWritableLocation true when the program lives somewhere the user
 *   can write without elevation. That is how software avoids a UAC prompt —
 *   and also where WinGet, VS Code and Discord legitimately live, which is why
 *   this is never a finding on its own.
 */
/**
 * A removable drive currently attached.
 *
 * @param encrypted `null` when the encryption state could not be read, which is
 *   common on a drive formatted by another operating system. Never guessed:
 *   telling someone an encrypted drive is unprotected sends them to re-encrypt
 *   something that already is, and telling them an unencrypted one is fine is
 *   worse.
 */
data class RemovableDrive(
    val letter: String,
    val label: String? = null,
    val fileSystem: String? = null,
    val sizeBytes: Long? = null,
    val encrypted: Boolean? = null
)

data class InstalledProgram(
    val name: String,
    val version: String? = null,
    val publisher: String? = null,
    val installLocation: String? = null,
    val userWritableLocation: Boolean = false
)

/** An inbound remote-control service and whether it is currently enabled. */
data class RemoteAccessService(
    val name: String,
    val enabled: Boolean,
    val port: Int? = null,
    /**
     * True when the service additionally requires a second factor or a
     * pre-authenticated channel (e.g. Windows RDP Network Level
     * Authentication). `null` when it could not be determined.
     */
    val hardened: Boolean? = null
)

/**
 * A socket in LISTEN state.
 *
 * @param address the bound local address. `0.0.0.0` or `::` means the service
 *   is reachable from the whole network, which is the interesting case;
 *   `127.0.0.1` is local-only and is not a finding.
 */
data class ListeningPort(
    val address: String,
    val port: Int,
    val process: String? = null
) {
    /** Bound to every interface rather than loopback. */
    val isPubliclyBound: Boolean
        get() = address == "0.0.0.0" || address == "::" || address == "*" || address == "[::]"
}

/**
 * A program configured to run automatically.
 *
 * @param location where the entry lives — a registry Run key, a LaunchAgent
 *   plist, a systemd user unit. Shown verbatim so the user can go and look.
 * @param command the configured command line, truncated by the collector.
 * @param signedByKnownVendor null when the platform could not verify a
 *   signature, which is common on Linux and must not read as "unsigned".
 */
/**
 * Machine settings that decide how much an attacker gets *after* they arrive.
 *
 * Every field is nullable under the same contract as the rest of the model:
 * `null` means the setting could not be read, never that it is off. Several of
 * these are absent from the registry on a healthy machine *because the safe
 * behaviour is the default*, so each field below documents which reading
 * absence carries — getting that backwards would either accuse every machine
 * alive or reassure about a setting nobody checked.
 */
data class HardeningFacts(
    /** User Account Control master switch. Absent is not stock; it is always written. */
    val uacEnabled: Boolean? = null,
    /**
     * `ConsentPromptBehaviorAdmin`. 0 means elevation happens with no prompt at
     * all, which removes the one moment a person might notice it.
     */
    val uacPromptsForElevation: Boolean? = null,
    /** LSA run as a protected process, which stops most credential dumpers. */
    val lsaProtected: Boolean? = null,
    /**
     * WDigest caching plaintext credentials in memory.
     *
     * Absent means off — Microsoft changed the default in 2014 — so absence is
     * a pass here, and only an explicitly written `1` is a finding.
     */
    val plaintextCredentialsInMemory: Boolean? = null,
    /** SMBv1, deprecated and the transport EternalBlue used. Absent means off. */
    val smb1Enabled: Boolean? = null,
    /**
     * LLMNR, which broadcasts "does anyone know this name?" to the local
     * network and accepts the first answer. The basis of Responder-style
     * credential capture on any shared Wi-Fi.
     *
     * Absent means **enabled**: switching it off requires writing the policy.
     * The inverse of the WDigest case, which is why they are separate fields.
     */
    val llmnrEnabled: Boolean? = null,
    /** Windows PowerShell 2.0 engine, which can be invoked to bypass v5 logging. */
    val powerShellV2Available: Boolean? = null,
    /** Automatic sign-in configured. */
    val autoLogonEnabled: Boolean? = null,
    /**
     * Whether an auto-logon password sits in the registry in cleartext.
     *
     * The value itself is never collected. An app that read a stored password
     * into its own output would have made the problem worse in the course of
     * reporting it.
     */
    val autoLogonPasswordStored: Boolean? = null,
    /** Windows Remote Management, listening for remote command execution. */
    val remoteManagementRunning: Boolean? = null,
    /** Remote Registry service, which exposes the registry over the network. */
    val remoteRegistryRunning: Boolean? = null
)

/**
 * The state of the antivirus that is installed, rather than a second opinion
 * about the files on disk.
 *
 * @param exclusionPaths folders the scanner has been told to ignore. `null`
 *   when they could not be read, which on Windows is the ordinary case: the
 *   query returns "must be an administrator to view exclusions", and reporting
 *   that as an empty list would turn "I could not look" into "there are none".
 */
data class AntivirusPosture(
    val tamperProtectionEnabled: Boolean? = null,
    val behaviourMonitoringEnabled: Boolean? = null,
    /** Scanning of downloads and attachments as they arrive. */
    val downloadScanningEnabled: Boolean? = null,
    val networkInspectionEnabled: Boolean? = null,
    val antiSpywareEnabled: Boolean? = null,
    /** Threats the product knows about, resolved or not. Context, not a finding. */
    val knownThreatCount: Int? = null,
    /**
     * Threats the product still considers present.
     *
     * `IsActive` is the field that means this, and it had to be measured to
     * establish that: `ActionSuccess` reads true even for detections whose own
     * status says the action failed, so a check built on it could never fire.
     */
    val activeThreatNames: List<String>? = null,
    val exclusionPaths: List<String>? = null
)

data class AutoRunEntry(
    val name: String,
    val location: String,
    val command: String? = null,
    val signedByKnownVendor: Boolean? = null,
    /**
     * The mechanism, not the address: `Run`, `RunOnce`, `Scheduled task`,
     * `Service`, `Winlogon`, `IFEO debugger`, `Startup folder`.
     *
     * Worth a field of its own because the mechanisms are not equally
     * interesting. A Run-key entry is what every installer creates; an IFEO
     * debugger entry has essentially one legitimate use and a great many
     * illegitimate ones.
     */
    val kind: String? = null,
    /**
     * True when the thing that actually launches is one of Windows' own signed
     * binaries — `rundll32`, `mshta`, `regsvr32`, `powershell` and friends.
     *
     * This exists because [signedByKnownVendor] is otherwise actively
     * misleading here. An entry reading `rundll32.exe C:\Users\…\payload.dll`
     * has a perfectly valid Microsoft signature, so the signature check passes
     * it, and the code that runs is in a file nobody looked at. Reporting the
     * signature without reporting this would be technically true and useless.
     */
    val usesSystemBinary: Boolean? = null
)
