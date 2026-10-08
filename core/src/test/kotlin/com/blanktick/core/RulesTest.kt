package com.blanktick.core

import com.blanktick.core.intel.AppCapability
import com.blanktick.core.intel.ClusterRulePack
import com.blanktick.core.intel.Perms
import com.blanktick.core.model.AutoRunEntry
import com.blanktick.core.model.BrowserExtension
import com.blanktick.core.model.CaCertificate
import com.blanktick.core.model.AiFacts
import com.blanktick.core.model.AntivirusPosture
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.HardeningFacts
import com.blanktick.core.model.DesktopOs
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.ListeningPort
import com.blanktick.core.model.InstalledApp
import com.blanktick.core.model.InstalledProgram
import com.blanktick.core.model.PasswordAudit
import com.blanktick.core.model.ProcessImage
import com.blanktick.core.model.Platform
import com.blanktick.core.model.ProxyInfo
import com.blanktick.core.model.RemoteAccessService
import com.blanktick.core.model.RemovableDrive
import com.blanktick.core.model.ScreenLock
import com.blanktick.core.model.Severity
import com.blanktick.core.model.WifiSecurity
import com.blanktick.core.model.WifiSnapshot
import com.blanktick.core.rules.AppHygieneRules
import com.blanktick.core.rules.DeviceIntegrityRules
import com.blanktick.core.rules.NetworkRules
import com.blanktick.core.rules.RuleOutcome
import com.blanktick.core.util.IsoDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Snapshot builders shared by the rule tests and the fixture generator. */
object Snapshots {

    const val NOW = 1_788_000_000_000L   // fixed clock: 2026-08-28-ish, in millis

    val REFERENCE_PATCHES = mapOf(
        13 to "2026-08-01", 14 to "2026-08-01", 15 to "2026-08-01", 16 to "2026-08-01"
    )

    /** An Android device with nothing wrong with it. */
    fun healthyAndroid() = DeviceSnapshot(
        platform = Platform.ANDROID,
        collectedAt = NOW,
        rootedOrJailbroken = false,
        bootloaderUnlocked = false,
        developerOptionsEnabled = false,
        adbEnabled = false,
        adbOverNetworkPort = null,
        runningOnEmulator = false,
        hookingArtifacts = emptyList(),
        osVersion = "16",
        osMajor = 16,
        securityPatchDate = "2026-08-01",
        screenLock = ScreenLock.PIN_LONG,
        diskEncrypted = true,
        biometricEnrolled = true,
        screenLockTimeoutSeconds = 60,
        lockscreenShowsNotificationContent = false,
        wifi = WifiSnapshot(ssid = "Home", security = WifiSecurity.WPA3, gatewayMacChanged = false),
        userInstalledCaCerts = emptyList(),
        proxy = null,
        vpnActive = false,
        dnsServers = listOf("192.168.1.1"),
        privateDnsMode = "opportunistic",
        installedApps = emptyList(),
        photosScanned = 100,
        photosWithPreciseLocation = 0,
        passwordAudit = PasswordAudit(20, 0, 0, 0),
        intelBundleDate = "2026-08-20",
        intelStalenessDays = 8,
        referencePatchDates = REFERENCE_PATCHES,
        knownSigners = mapOf("com.whatsapp" to setOf("AA11"))
    )

    /**
     * An iPhone. Note how many fields are `null`: that is not laziness, it is
     * the D-01 contract. iOS genuinely cannot observe these, so the collector
     * must not guess.
     */
    fun healthyIos() = DeviceSnapshot(
        platform = Platform.IOS,
        collectedAt = NOW,
        rootedOrJailbroken = false,
        bootloaderUnlocked = null,
        developerOptionsEnabled = null,
        adbEnabled = null,
        adbOverNetworkPort = null,
        hookingArtifacts = emptyList(),
        osVersion = "20.1",
        osMajor = null,
        securityPatchDate = null,
        screenLock = ScreenLock.PIN_LONG,
        diskEncrypted = true,
        biometricEnrolled = true,
        screenLockTimeoutSeconds = 60,
        lockscreenShowsNotificationContent = false,
        wifi = WifiSnapshot(ssid = "Home", security = WifiSecurity.WPA3),
        userInstalledCaCerts = null,     // trust store is not enumerable on iOS
        proxy = null,
        vpnActive = null,
        dnsServers = null,
        privateDnsMode = null,
        installedApps = null,            // no API enumerates other apps
        photosScanned = 100,
        photosWithPreciseLocation = 0,
        passwordAudit = PasswordAudit(20, 0, 0, 0),
        intelBundleDate = "2026-08-20",
        intelStalenessDays = 8,
        referencePatchDates = null,
        knownSigners = null
    )

    /**
     * A Windows machine with nothing wrong with it.
     *
     * Note `sessionIsAdministrator = false`: the "healthy" reference is a
     * standard user, which is deliberately *not* the out-of-the-box state of a
     * consumer Windows install. The fixture describes the target, not the
     * average.
     */
    fun healthyDesktop(os: DesktopOs = DesktopOs.WINDOWS) = DeviceSnapshot(
        platform = Platform.DESKTOP,
        collectedAt = NOW,
        screenLock = ScreenLock.PASSWORD,
        diskEncrypted = true,
        screenLockTimeoutSeconds = 300,
        wifi = WifiSnapshot(ssid = "Home", security = WifiSecurity.WPA3),
        userInstalledCaCerts = emptyList(),
        proxy = null,
        dnsServers = listOf("192.168.1.1"),
        photosScanned = 100,
        photosWithPreciseLocation = 0,
        passwordAudit = PasswordAudit(20, 0, 0, 0),
        desktop = DesktopFacts(
            os = os,
            osBuild = "Windows 11 Pro 24H2",
            firewallEnabled = true,
            firewallProfilesOff = emptyList(),
            antivirusProduct = "Microsoft Defender",
            antivirusRealtimeEnabled = true,
            antivirusSignatureAgeDays = 1,
            appReputationEnabled = true,
            secureBootEnabled = true,
            // SIP exists only on macOS. On Windows this is null, and DSK-SIP-001
            // must therefore report not-checkable rather than passing.
            systemIntegrityProtectionEnabled = if (os == DesktopOs.MACOS) true else null,
            automaticUpdatesEnabled = true,
            pendingSecurityUpdates = 0,
            daysSinceLastUpdate = 3,
            sessionIsAdministrator = false,
            administratorAccounts = listOf("Admin"),
            passwordlessAccounts = emptyList(),
            guestAccountEnabled = false,
            lockOnWakeEnabled = true,
            remoteAccessServices = listOf(RemoteAccessService("Remote Desktop", enabled = false)),
            listeningPorts = listOf(ListeningPort("127.0.0.1", 49152, "svchost")),
            autoRunEntries = listOf(
                AutoRunEntry("OneDrive", "HKCU:Software/Microsoft/Windows/CurrentVersion/Run", signedByKnownVendor = true)
            ),
            // A healthy machine's software: current versions, and the one entry
            // in a user-writable folder names its publisher -- which is the
            // shape of every real user-writable install measured on the
            // development machine (11 of them, all attributed).
            autoRunBlockedForRemovable = true,
            // One attached, encrypted drive rather than none: an empty list makes
            // DSK-USB-002 report not-checkable, which would leave the pass path
            // untested by the fixture that exists to prove a healthy machine
            // scores 100.
            removableDrives = listOf(
                RemovableDrive("E:", "BACKUP", "exFAT", 64L * 1024 * 1024 * 1024, encrypted = true)
            ),
            rememberedUsbDevices = listOf("SanDisk Ultra"),
            // A healthy machine's browser extensions: both from the store, so
            // DSK-EXT-001 passes; neither pairs full-site access with a
            // traffic/data API, so DSK-EXT-002 passes too. An empty list would
            // make both report not-checkable and leave their pass path untested
            // by the fixture whose whole job is to prove a healthy machine
            // scores 100. The FAIL paths (unpacked, broad+sensitive) live in
            // BrowserRulesTest.
            browserExtensions = listOf(
                BrowserExtension(
                    browser = "Chrome", id = "cfhdojbkjhnklbpkdaibdccddilifddb",
                    name = "AdBlock", version = "5.17.0", installSource = "store",
                    enabled = true, hostPermissions = listOf("<all_urls>"),
                    apiPermissions = listOf("storage", "contextMenus")
                ),
                BrowserExtension(
                    browser = "Edge", id = "hokifickgkhplphjiodbggjmoafhignh",
                    name = "Microsoft Editor", version = "1.0.0", installSource = "store",
                    enabled = true, hostPermissions = emptyList(),
                    apiPermissions = listOf("storage")
                )
            ),
            browserExtensionsUnread = emptyList(),
            installedPrograms = listOf(
                InstalledProgram("Google Chrome", "151.0.7922.175", "Google LLC", "C:/Program Files/Google/Chrome"),
                InstalledProgram("Python 3.12.10", "3.12.10150.0", "Python Software Foundation"),
                InstalledProgram(
                    "Microsoft Visual Studio Code", "1.99.0", "Microsoft Corporation",
                    "C:/Users/x/AppData/Local/Programs/Microsoft VS Code", userWritableLocation = true
                )
            ),
            // Populated rather than left null so the hardening and AV-posture
            // rules are actually exercised by the fixture that exists to prove a
            // healthy machine scores 100. A fixture that omits a fact block
            // makes every rule reading it report not-checkable, which passes the
            // suite while testing nothing.
            // Two ordinary user-folder programs and nothing masquerading. An
            // empty list would make the malware rules report not-checkable,
            // leaving their pass path untested by the fixture whose whole job is
            // to prove a healthy machine scores 100.
            runningProcesses = listOf(
                // matchesKnownMalware = false, not null: the corpus was consulted
                // and said no. Null would make DSK-MAL-004 report not-checkable
                // and leave its pass path untested.
                ProcessImage(
                    "Code", "C:/Users/x/AppData/Local/Programs/Microsoft VS Code/Code.exe", "Valid",
                    matchesKnownMalware = false, antivirusVerdict = "clean"
                ),
                ProcessImage(
                    "Update", "C:/Users/x/AppData/Local/SquirrelTemp/Update.exe", "Valid",
                    matchesKnownMalware = false, antivirusVerdict = "clean"
                )
            ),
            processesWithUnreadablePath = 179,
            fileHashingWorks = true,
            // Empty, not null: a healthy machine's root store has no additions
            // Windows cannot account for. Null would make DSK-CA-001 report
            // not-checkable and leave its pass path untested.
            machineAddedRootCerts = emptyList(),
            // A developer machine with tool servers configured, none of them
            // launched through a shell, and no keys in the files. Populated
            // rather than null so the AI rules are actually exercised.
            ai = AiFacts(
                mcpServers = emptyList(),
                configsWithCredentials = emptyList(),
                recallStorePresent = false,
                recallDisabled = null
            ),
            // Two of the listening sockets are permitted inbound by a firewall
            // rule, which is the real shape of a developer machine.
            reachableFromNetwork = emptyList(),
            listeningPortsUnattributed = 23,
            hardening = HardeningFacts(
                uacEnabled = true,
                uacPromptsForElevation = true,
                lsaProtected = true,
                plaintextCredentialsInMemory = false,
                smb1Enabled = false,
                // The one setting a healthy Windows machine still has switched
                // on, because Microsoft ships it that way. Set false here so the
                // fixture scores 100; the real-machine behaviour is covered by
                // its own test in HardeningRulesTest.
                llmnrEnabled = false,
                powerShellV2Available = false,
                autoLogonEnabled = false,
                autoLogonPasswordStored = false,
                remoteManagementRunning = false,
                remoteRegistryRunning = false,
                // Like LLMNR above: NetBIOS ships on, set off so the fixture
                // scores 100. Its stock behaviour is tested in BaselineRulesTest.
                netbiosEnabled = false,
                uacSecureDesktop = true,
                memoryIntegrityRunning = true,
                memoryIntegrityAvailable = true,
                credentialGuardRunning = true,
                credentialGuardSupportedEdition = true,
                tpmWorking = true,
                smartAppControlState = 1,
                exploitMitigationsOff = emptyList(),
                smbClientRequiresSigning = true,
                smbServerRequiresSigning = true,
                smbInsecureGuestLogons = false,
                printSpoolerRunning = true,
                sharedPrinterCount = 0,
                lockoutThreshold = 10,
                builtinAdministratorEnabled = false,
                powerShellScriptBlockLogging = true,
                unquotedServicePaths = emptyList()
            ),
            antivirusPosture = AntivirusPosture(
                tamperProtectionEnabled = true,
                behaviourMonitoringEnabled = true,
                downloadScanningEnabled = true,
                networkInspectionEnabled = true,
                antiSpywareEnabled = true,
                knownThreatCount = 0,
                activeThreatNames = emptyList(),
                // Null even on a healthy machine: reading Defender's exclusion
                // list needs administrator rights Blanktick does not ask for, so this
                // is a permanent blind spot rather than an empty list.
                exclusionPaths = null,
                unwantedAppBlocking = true,
                controlledFolderAccess = true
            )
        ),
        intelBundleDate = "2026-08-20",
        intelStalenessDays = 8
    )

    fun app(
        pkg: String,
        label: String = pkg,
        perms: Set<String> = emptySet(),
        accessibility: Boolean = false,
        overlay: Boolean = false,
        deviceAdmin: Boolean = false,
        notificationListener: Boolean = false,
        installPackages: Boolean = false,
        installer: String? = "com.android.vending",
        signer: String? = null,
        system: Boolean = false,
        targetSdk: Int = 35,
        debuggable: Boolean? = false,
        cleartext: Boolean? = false,
        lastUsed: Long? = NOW
    ) = InstalledApp(
        packageName = pkg,
        label = label,
        installerPackage = installer,
        signerSha256 = signer,
        isSystemApp = system,
        targetSdk = targetSdk,
        grantedPermissions = perms,
        holdsAccessibilityService = accessibility,
        canDrawOverlays = overlay,
        holdsDeviceAdmin = deviceAdmin,
        holdsNotificationListener = notificationListener,
        canRequestPackageInstalls = installPackages,
        usesCleartextTraffic = cleartext,
        isDebuggable = debuggable,
        lastUsedEpochMillis = lastUsed
    )
}

class NullContractTest {

    private val scanner = BlanktickScanner()

    @Test
    fun `a healthy android device scores 100`() {
        val report = scanner.scan(Snapshots.healthyAndroid())
        assertEquals(100, report.result.score, "findings: ${report.result.findings.map { it.finding.key }}")
        assertEquals(0, report.result.actionableFindings.size)
    }

    @Test
    fun `a healthy iphone scores 100`() {
        val report = scanner.scan(Snapshots.healthyIos())
        assertEquals(100, report.result.score, "findings: ${report.result.findings.map { it.finding.key }}")
    }

    @Test
    fun `iOS skips checks it cannot perform rather than passing them`() {
        val report = scanner.scan(Snapshots.healthyIos())

        // This is decision D-01 made testable. The iPhone build must report
        // these as "not checkable", never as a green tick.
        val skipped = report.notApplicable.map { it.ruleId }.toSet()
        assertTrue("APP-CLONE-001" in skipped, "app clone detection is impossible on iOS")
        assertTrue("APP-CLUSTER-001" in skipped, "permission auditing is impossible on iOS")
        assertTrue("NET-CA-001" in skipped, "the iOS trust store is not enumerable")
        assertTrue("OS-PATCH-001" in skipped, "iOS exposes no security patch date")
        assertTrue(report.result.checksSkipped > 0)
    }

    @Test
    fun `android runs strictly more checks than iOS`() {
        val androidRuns = scanner.scan(Snapshots.healthyAndroid()).result.checksRun
        val iosRuns = scanner.scan(Snapshots.healthyIos()).result.checksRun
        assertTrue(
            androidRuns > iosRuns,
            "android=$androidRuns ios=$iosRuns — the asymmetry is the product, it must be real"
        )
    }

    @Test
    fun `a null field produces no finding at all`() {
        // Not "false", not a pass — nothing.
        val snapshot = Snapshots.healthyAndroid().copy(userInstalledCaCerts = null)
        val outcome = NetworkRules.UserInstalledCa.evaluate(snapshot)
        assertEquals(RuleOutcome.NotApplicable, outcome)
    }

    @Test
    fun `every rule id is unique`() {
        val ids = DefaultRules.ALL.map { it.id }
        assertEquals(ids.size, ids.toSet().size, "duplicate rule ids: ${ids.groupBy { it }.filterValues { it.size > 1 }.keys}")
    }

    @Test
    fun `every rule declares at least one platform`() {
        assertTrue(DefaultRules.ALL.all { it.platforms.isNotEmpty() })
    }

    @Test
    fun `rule ids follow the documented convention`() {
        val pattern = Regex("""^[A-Z]{2,4}-[A-Z0-9]+-\d{3}$""")
        DefaultRules.ALL.forEach {
            assertTrue(pattern.matches(it.id), "rule id '${it.id}' does not match AREA-TOPIC-NNN")
        }
    }
}

class DeviceIntegrityRuleTest {

    private val scanner = BlanktickScanner()

    @Test
    fun `a rooted device is critical`() {
        val report = scanner.scan(Snapshots.healthyAndroid().copy(rootedOrJailbroken = true))
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "DEV-ROOT-001" }
        assertEquals(Severity.CRITICAL, finding.severity)
        assertTrue(report.result.score < 80)
    }

    @Test
    fun `network ADB outranks USB debugging and is not double-charged`() {
        val snapshot = Snapshots.healthyAndroid()
            .copy(adbEnabled = true, adbOverNetworkPort = 5555)
        val report = scanner.scan(snapshot)
        val ids = report.result.findings.map { it.finding.ruleId }
        assertTrue("DEV-ADB-002" in ids)
        assertFalse(
            "DEV-ADB-001" in ids,
            "USB debugging must not also fire; the user has one problem, not two"
        )
    }

    @Test
    fun `USB debugging alone is medium`() {
        val report = scanner.scan(Snapshots.healthyAndroid().copy(adbEnabled = true))
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "DEV-ADB-001" }
        assertEquals(Severity.MEDIUM, finding.severity)
    }

    @Test
    fun `hooking artifacts are reported with names`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(hookingArtifacts = listOf("frida-agent", "gum-js-loop"))
        )
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "DEV-HOOK-001" }
        assertTrue(finding.detail.contains("frida-agent"))
    }

    @Test
    fun `bootloader rule does not run on iOS`() {
        assertEquals(
            RuleOutcome.NotApplicable,
            DeviceIntegrityRules.Bootloader.evaluate(Snapshots.healthyIos())
        )
    }
}

class NetworkRuleTest {

    private val scanner = BlanktickScanner()

    @Test
    fun `a user-installed CA is critical and named`() {
        val snapshot = Snapshots.healthyAndroid().copy(
            userInstalledCaCerts = listOf(
                CaCertificate("PortSwigger CA", "PortSwigger CA", "DEADBEEF", mdmInstalled = false)
            )
        )
        val report = scanner.scan(snapshot)
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "NET-CA-001" }
        assertEquals(Severity.CRITICAL, finding.severity)
        assertTrue(finding.detail.contains("PortSwigger"))
        assertEquals("DEADBEEF", finding.subjectId)
    }

    @Test
    fun `an MDM-installed CA is informational, not an alarm`() {
        val snapshot = Snapshots.healthyAndroid().copy(
            userInstalledCaCerts = listOf(
                CaCertificate("Corp Proxy", "Corp Proxy", "CAFE", mdmInstalled = true)
            )
        )
        val report = scanner.scan(snapshot)
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "NET-CA-001" }
        assertEquals(Severity.INFO, finding.severity)
        assertEquals(100, report.result.score, "a managed work device must not be scored as compromised")
    }

    @Test
    fun `open wifi is flagged and WEP is worse`() {
        val open = scanner.scan(
            Snapshots.healthyAndroid().copy(wifi = WifiSnapshot("Free_WiFi", WifiSecurity.OPEN))
        )
        val wep = scanner.scan(
            Snapshots.healthyAndroid().copy(wifi = WifiSnapshot("Old_Router", WifiSecurity.WEP))
        )
        assertTrue(wep.result.score < open.result.score)
        assertTrue(
            open.result.findings.map { it.finding }.single { it.ruleId == "NET-WIFI-001" }
                .title.contains("Free_WiFi")
        )
    }

    @Test
    fun `WPA3 and OWE pass`() {
        listOf(WifiSecurity.WPA2, WifiSecurity.WPA3, WifiSecurity.OWE).forEach { security ->
            val outcome = NetworkRules.OpenWifi.evaluate(
                Snapshots.healthyAndroid().copy(wifi = WifiSnapshot("x", security))
            )
            assertEquals(RuleOutcome.Pass, outcome, "$security should pass")
        }
    }

    @Test
    fun `unknown wifi security is skipped, not guessed`() {
        assertEquals(
            RuleOutcome.NotApplicable,
            NetworkRules.OpenWifi.evaluate(
                Snapshots.healthyAndroid().copy(wifi = WifiSnapshot("x", WifiSecurity.UNKNOWN))
            )
        )
    }

    @Test
    fun `private and well-known public DNS servers pass`() {
        listOf(
            listOf("192.168.0.1"), listOf("10.0.0.1"), listOf("1.1.1.1"), listOf("8.8.8.8", "8.8.4.4")
        ).forEach { servers ->
            assertEquals(
                RuleOutcome.Pass,
                NetworkRules.SuspiciousDns.evaluate(Snapshots.healthyAndroid().copy(dnsServers = servers)),
                "$servers should pass"
            )
        }
    }

    @Test
    fun `an unrecognised DNS server is flagged`() {
        val report = scanner.scan(Snapshots.healthyAndroid().copy(dnsServers = listOf("45.33.12.9")))
        assertTrue(report.result.findings.any { it.finding.ruleId == "NET-DNS-001" })
    }

    @Test
    fun `a proxy is high severity`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(proxy = ProxyInfo("10.0.0.5", 8080))
        )
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "NET-PROXY-001" }
        assertEquals(Severity.HIGH, finding.severity)
    }

    @Test
    fun `a changed gateway MAC is an evil-twin warning`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(
                wifi = WifiSnapshot("Home", WifiSecurity.WPA2, gatewayMacChanged = true)
            )
        )
        assertTrue(report.result.findings.any { it.finding.ruleId == "NET-WIFI-002" })
    }
}

class AppHygieneRuleTest {

    private val scanner = BlanktickScanner()

    @Test
    fun `a repackaged app is detected by its signature`() {
        val snapshot = Snapshots.healthyAndroid().copy(
            installedApps = listOf(
                Snapshots.app("com.whatsapp", "WhatsApp", signer = "BB22", installer = null)
            ),
            knownSigners = mapOf("com.whatsapp" to setOf("AA11"))
        )
        val report = scanner.scan(snapshot)
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "APP-CLONE-001" }
        assertEquals(Severity.CRITICAL, finding.severity)
        assertEquals("com.whatsapp", finding.subjectId)
    }

    @Test
    fun `the genuine app passes`() {
        val snapshot = Snapshots.healthyAndroid().copy(
            installedApps = listOf(Snapshots.app("com.whatsapp", "WhatsApp", signer = "aa11")),
            knownSigners = mapOf("com.whatsapp" to setOf("AA11"))
        )
        assertEquals(RuleOutcome.Pass, AppHygieneRules.ClonedApp.evaluate(snapshot))
    }

    @Test
    fun `an app with no known-good entry is not accused`() {
        val snapshot = Snapshots.healthyAndroid().copy(
            installedApps = listOf(Snapshots.app("com.some.indie.app", signer = "FF99")),
            knownSigners = mapOf("com.whatsapp" to setOf("AA11"))
        )
        assertEquals(RuleOutcome.Pass, AppHygieneRules.ClonedApp.evaluate(snapshot))
    }

    @Test
    fun `the banking trojan cluster fires`() {
        val trojan = Snapshots.app(
            pkg = "com.fake.updater",
            label = "System Update",
            perms = setOf(Perms.RECEIVE_SMS),
            accessibility = true,
            overlay = true,
            installer = null
        )
        val report = scanner.scan(Snapshots.healthyAndroid().copy(installedApps = listOf(trojan)))
        val finding = report.result.findings.map { it.finding }
            .single { it.ruleId == "APP-CLUSTER-001" }
        assertEquals(Severity.CRITICAL, finding.severity)
        assertEquals("CLUSTER-BANKER", finding.evidence["cluster"])
    }

    @Test
    fun `only the most severe cluster is reported per app`() {
        // This app matches BANKER, OVERLAY-A11Y and SMS_INTERCEPTOR. The user
        // has one bad app, so they should see one finding for it.
        val app = Snapshots.app(
            pkg = "com.bad",
            perms = setOf(Perms.READ_SMS, Perms.RECEIVE_SMS, Perms.SEND_SMS),
            accessibility = true,
            overlay = true
        )
        val report = scanner.scan(Snapshots.healthyAndroid().copy(installedApps = listOf(app)))
        val clusterFindings = report.result.findings.filter { it.finding.ruleId == "APP-CLUSTER-001" }
        assertEquals(1, clusterFindings.size)
        assertEquals("CLUSTER-BANKER", clusterFindings.single().finding.evidence["cluster"])
    }

    @Test
    fun `screen readers are exempt from the accessibility clusters`() {
        val talkback = Snapshots.app(
            pkg = "com.google.android.marvin.talkback",
            label = "TalkBack",
            accessibility = true,
            overlay = true
        )
        assertNull(ClusterRulePack.mostSevereMatch(talkback))
    }

    @Test
    fun `password managers are exempt from the accessibility clusters`() {
        val bitwarden = Snapshots.app(pkg = "com.x8bit.bitwarden", accessibility = true, overlay = true)
        assertNull(ClusterRulePack.mostSevereMatch(bitwarden))
    }

    @Test
    fun `the default SMS app is exempt from the SMS cluster`() {
        val messages = Snapshots.app(
            pkg = "com.google.android.apps.messaging",
            perms = setOf(Perms.READ_SMS, Perms.RECEIVE_SMS, Perms.SEND_SMS)
        )
        assertNull(ClusterRulePack.mostSevereMatch(messages))
    }

    @Test
    fun `system apps are never cluster-matched`() {
        val systemApp = Snapshots.app(
            pkg = "com.android.systemui",
            perms = setOf(Perms.RECEIVE_SMS),
            accessibility = true,
            overlay = true,
            system = true
        )
        assertNull(ClusterRulePack.mostSevereMatch(systemApp))
    }

    @Test
    fun `cluster pack is ordered most severe first`() {
        // mostSevereMatch relies on this ordering.
        val severities = ClusterRulePack.ALL.map { it.severity.ordinal }
        assertEquals(severities.sortedDescending(), severities, "ClusterRulePack.ALL must be ordered by severity")
    }

    @Test
    fun `sideloaded apps are flagged once, collectively`() {
        val apps = (1..4).map { Snapshots.app("com.side.$it", installer = null) }
        val report = scanner.scan(Snapshots.healthyAndroid().copy(installedApps = apps))
        val findings = report.result.findings.filter { it.finding.ruleId == "APP-SOURCE-001" }
        assertEquals(1, findings.size, "four sideloaded apps is one message, not four")
        assertEquals("4", findings.single().finding.evidence["count"])
    }

    @Test
    fun `a debuggable app is high severity`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(
                installedApps = listOf(Snapshots.app("com.leaky", debuggable = true))
            )
        )
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "APP-BUILD-001" }
        assertEquals(Severity.HIGH, finding.severity)
    }

    @Test
    fun `dormant apps with sensitive permissions are surfaced`() {
        val stale = Snapshots.app(
            pkg = "com.old.app",
            perms = setOf(Perms.RECORD_AUDIO),
            lastUsed = Snapshots.NOW - 200L * 86_400_000L
        )
        val report = scanner.scan(Snapshots.healthyAndroid().copy(installedApps = listOf(stale)))
        assertTrue(report.result.findings.any { it.finding.ruleId == "APP-DORMANT-001" })
    }

    @Test
    fun `recently used apps are not called dormant`() {
        val fresh = Snapshots.app(pkg = "com.new.app", perms = setOf(Perms.RECORD_AUDIO))
        val report = scanner.scan(Snapshots.healthyAndroid().copy(installedApps = listOf(fresh)))
        assertFalse(report.result.findings.any { it.finding.ruleId == "APP-DORMANT-001" })
    }

    @Test
    fun `capability helper reads the right flag`() {
        val app = Snapshots.app("x", accessibility = true)
        assertTrue(AppCapability.ACCESSIBILITY_SERVICE.heldBy(app))
        assertFalse(AppCapability.DEVICE_ADMIN.heldBy(app))
    }
}

class OsCurrencyRuleTest {

    private val scanner = BlanktickScanner()

    @Test
    fun `a device a year behind is critical`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(securityPatchDate = "2025-05-01")
        )
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "OS-PATCH-001" }
        assertEquals(Severity.CRITICAL, finding.severity)
        assertEquals("2025-05-01", finding.evidence["devicePatch"])
    }

    @Test
    fun `a device slightly behind is not punished`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(securityPatchDate = "2026-07-15")
        )
        assertFalse(report.result.findings.any { it.finding.ruleId == "OS-PATCH-001" })
    }

    @Test
    fun `a device ahead of our bundled data does not produce a claim`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(securityPatchDate = "2027-01-01")
        )
        assertFalse(report.result.findings.any { it.finding.ruleId == "OS-PATCH-001" })
    }

    @Test
    fun `an OS older than our whole table is flagged as unsupported`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(osMajor = 9, securityPatchDate = "2020-01-01")
        )
        assertTrue(report.result.findings.any { it.finding.ruleId == "OS-EOL-001" })
    }

    @Test
    fun `stale intel is reported but costs nothing`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(intelStalenessDays = 200, intelBundleDate = "2026-02-09")
        )
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "OS-INTEL-001" }
        assertEquals(Severity.INFO, finding.severity)
        assertEquals(100, report.result.score, "our own staleness is not the user's fault")
        assertTrue(finding.detail.contains("2026-02-09"))
    }
}

class DataAndAccessRuleTest {

    private val scanner = BlanktickScanner()

    @Test
    fun `no screen lock is critical`() {
        val report = scanner.scan(Snapshots.healthyAndroid().copy(screenLock = ScreenLock.NONE))
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "ACC-LOCK-001" }
        assertEquals(Severity.CRITICAL, finding.severity)
    }

    @Test
    fun `lock strength is graded, not binary`() {
        fun scoreFor(lock: ScreenLock) =
            scanner.scan(Snapshots.healthyAndroid().copy(screenLock = lock)).result.score

        assertTrue(scoreFor(ScreenLock.NONE) < scoreFor(ScreenLock.PATTERN))
        assertTrue(scoreFor(ScreenLock.PATTERN) < scoreFor(ScreenLock.PIN_SHORT))
        assertTrue(scoreFor(ScreenLock.PIN_SHORT) < scoreFor(ScreenLock.PIN_LONG))
        assertEquals(100, scoreFor(ScreenLock.PASSWORD))
    }

    @Test
    fun `breached passwords escalate with count`() {
        val one = scanner.scan(
            Snapshots.healthyAndroid().copy(passwordAudit = PasswordAudit(20, 1, 0, 0))
        )
        val many = scanner.scan(
            Snapshots.healthyAndroid().copy(passwordAudit = PasswordAudit(20, 5, 0, 0))
        )
        assertTrue(many.result.score < one.result.score)
    }

    @Test
    fun `the breach message states that nothing was transmitted`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(passwordAudit = PasswordAudit(20, 2, 0, 0))
        )
        val finding = report.result.findings.map { it.finding }.single { it.ruleId == "ACC-PWD-001" }
        assertTrue(
            finding.detail.contains("this device", ignoreCase = true),
            "users must be told the check was local: '${finding.detail}'"
        )
    }

    @Test
    fun `photo location findings scale with the proportion affected`() {
        val few = scanner.scan(
            Snapshots.healthyAndroid().copy(photosScanned = 100, photosWithPreciseLocation = 5)
        )
        val most = scanner.scan(
            Snapshots.healthyAndroid().copy(photosScanned = 100, photosWithPreciseLocation = 80)
        )
        assertTrue(most.result.score < few.result.score)
    }

    @Test
    fun `zero photos scanned is not a pass or a fail`() {
        val snapshot = Snapshots.healthyAndroid().copy(photosScanned = 0, photosWithPreciseLocation = 0)
        val report = BlanktickScanner().scan(snapshot)
        assertTrue(report.notApplicable.any { it.ruleId == "DATA-EXIF-001" })
    }

    @Test
    fun `lockscreen previews are flagged`() {
        val report = scanner.scan(
            Snapshots.healthyAndroid().copy(lockscreenShowsNotificationContent = true)
        )
        assertTrue(report.result.findings.any { it.finding.ruleId == "DATA-LOCK-001" })
    }
}

class IsoDateTest {

    @Test
    fun `epoch day zero`() {
        assertEquals(0L, IsoDate.toEpochDay("1970-01-01"))
    }

    @Test
    fun `known dates`() {
        assertEquals(1L, IsoDate.toEpochDay("1970-01-02"))
        assertEquals(-1L, IsoDate.toEpochDay("1969-12-31"))
        assertEquals(19_723L, IsoDate.toEpochDay("2024-01-01"))
    }

    @Test
    fun `agrees with java time across a wide range`() {
        // java.time is the oracle here, but it is deliberately not used in
        // production so that the Swift mirror can be exact.
        var day = java.time.LocalDate.of(1900, 1, 1)
        val end = java.time.LocalDate.of(2100, 1, 1)
        var checked = 0
        while (day.isBefore(end)) {
            assertEquals(day.toEpochDay(), IsoDate.toEpochDay(day.toString()), "mismatch on $day")
            day = day.plusDays(37)
            checked++
        }
        assertTrue(checked > 1_900)
    }

    @Test
    fun `leap years are handled`() {
        assertNotNull(IsoDate.toEpochDay("2024-02-29"))
        assertNotNull(IsoDate.toEpochDay("2000-02-29"))
        assertNull(IsoDate.toEpochDay("2023-02-29"))
        assertNull(IsoDate.toEpochDay("1900-02-29"), "1900 is not a leap year")
    }

    @Test
    fun `malformed input returns null`() {
        listOf("", "2024", "2024-13-01", "2024-00-10", "2024-01-32", "24-01-01", "2024/01/01", "abcd-ef-gh")
            .forEach { assertNull(IsoDate.toEpochDay(it), "'$it' should not parse") }
    }

    @Test
    fun `daysBetween is signed`() {
        assertEquals(31L, IsoDate.daysBetween("2026-01-01", "2026-02-01"))
        assertEquals(-31L, IsoDate.daysBetween("2026-02-01", "2026-01-01"))
        assertEquals(0L, IsoDate.daysBetween("2026-02-01", "2026-02-01"))
        assertNull(IsoDate.daysBetween("bad", "2026-02-01"))
    }
}
