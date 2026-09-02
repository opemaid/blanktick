package com.mume.core

import com.mume.core.model.DesktopOs
import com.mume.core.model.Platform
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the coverage numbers that appear in the README, on the marketing site
 * and in the app's own UI.
 *
 * These exist because the first draft of the README claimed "22 checks on
 * Android, 14 on iPhone" -- numbers nobody had measured. For a product whose
 * entire pitch is that it tells you exactly what it can and cannot see, quoting
 * an invented figure is the worst possible bug. So the numbers now come from
 * the code, and this test fails if a rule is added without updating them.
 */
class PlatformCoverageTest {

    private val scanner = MumeScanner()

    @Test
    fun `rule counts match what we publish`() {
        assertEquals(62, DefaultRules.COUNT, "total rule count changed — update README and web/")
        assertEquals(29, DefaultRules.countFor(Platform.ANDROID))
        assertEquals(15, DefaultRules.countFor(Platform.IOS), "rules iOS is even allowed to attempt")
        assertEquals(44, DefaultRules.countFor(Platform.DESKTOP))
    }

    /**
     * Adding the desktop platform must not have moved the mobile numbers.
     *
     * [com.mume.core.rules.BaseRule] defaults to the mobile pair, so a desktop
     * rule cannot leak onto a phone — but a careless `Platforms.EVERYWHERE` on
     * an Android-only rule would silently hand iOS a check it cannot perform.
     * This is the guard against that.
     */
    @Test
    fun `the desktop platform did not change mobile coverage`() {
        assertEquals(29, DefaultRules.countFor(Platform.ANDROID), "Android coverage moved")
        assertEquals(15, DefaultRules.countFor(Platform.IOS), "iOS coverage moved")
        assertTrue(
            com.mume.core.rules.DesktopRules.ALL.all { it.platforms == setOf(Platform.DESKTOP) },
            "every DSK- rule must be desktop-only"
        )
    }

    @Test
    fun `a healthy device runs the number of checks we advertise`() {
        val android = scanner.scan(Snapshots.healthyAndroid()).result
        val ios = scanner.scan(Snapshots.healthyIos()).result
        val desktop = scanner.scan(Snapshots.healthyDesktop()).result

        assertEquals(29, android.checksRun)
        assertEquals(33, android.checksSkipped, "the 33 desktop-only rules")
        assertEquals(62, android.checksRun + android.checksSkipped)

        // Three of the fifteen iOS-eligible rules still skip, because iOS
        // cannot supply their inputs even though the rule is not gated by
        // platform: the patch-level table, the DNS list and the Wi-Fi gateway
        // history are all null there.
        assertEquals(12, ios.checksRun)
        assertEquals(50, ios.checksSkipped)
        assertEquals(62, ios.checksRun + ios.checksSkipped)

        // 44 eligible, minus SIP which does not exist off macOS.
        assertEquals(43, desktop.checksRun)
        assertEquals(19, desktop.checksSkipped)
        assertEquals(62, desktop.checksRun + desktop.checksSkipped)
    }

    @Test
    fun `the iOS not-applicable list is exactly what we tell users`() {
        val skipped = scanner.scan(Snapshots.healthyIos()).notApplicable
            .map { it.ruleId }
            .filterNot { it.startsWith("DSK-") }   // desktop rules, listed separately
            .toSet()

        assertEquals(
            setOf(
                "DEV-BOOT-001", "DEV-ADB-002", "DEV-ADB-001", "DEV-DEVOPT-001",
                "OS-PATCH-001", "OS-EOL-001",
                "NET-CA-001", "NET-WIFI-002", "NET-DNS-001", "NET-DNS-002", "NET-VPN-001",
                "APP-CLONE-001", "APP-CLUSTER-001", "APP-SOURCE-001",
                "APP-BUILD-001", "APP-SDK-001", "APP-DORMANT-001"
            ),
            skipped,
            "the 'what Mume can't see on iPhone' screen must list exactly these"
        )
    }

    /**
     * The equivalent honesty list for a desktop.
     *
     * A laptop cannot be rooted, has no ADB and no installed-app inventory in
     * the Android sense, so those rules must appear here as *not checkable* and
     * never as passes.
     */
    @Test
    fun `the desktop not-applicable list is exactly what we tell users`() {
        val skipped = scanner.scan(Snapshots.healthyDesktop()).notApplicable.map { it.ruleId }.toSet()

        assertEquals(
            setOf(
                // Mobile device-integrity model: no equivalent on a desktop.
                "DEV-ROOT-001", "DEV-HOOK-001", "DEV-BOOT-001",
                "DEV-ADB-001", "DEV-ADB-002", "DEV-DEVOPT-001",
                // Android patch-level table; a desktop uses DSK-UPD-*.
                "OS-PATCH-001", "OS-EOL-001",
                // Android-specific network settings.
                "NET-WIFI-002", "NET-DNS-002", "NET-VPN-001",
                // The Android app auditor; a desktop uses DSK-AUTO-001/DSK-REP-001.
                "APP-CLONE-001", "APP-CLUSTER-001", "APP-SOURCE-001",
                "APP-BUILD-001", "APP-SDK-001", "APP-DORMANT-001",
                // Lock-screen notification previews are a phone concept.
                "DATA-LOCK-001",
                // SIP is macOS-only; this fixture is Windows.
                "DSK-SIP-001"
            ),
            skipped,
            "the 'what Mume can't see on this computer' screen must list exactly these"
        )
    }

    /** On a Mac, SIP becomes checkable and nothing else moves. */
    @Test
    fun `SIP is checkable on macOS and not elsewhere`() {
        val mac = scanner.scan(Snapshots.healthyDesktop(DesktopOs.MACOS))
        val windows = scanner.scan(Snapshots.healthyDesktop(DesktopOs.WINDOWS))

        assertTrue("DSK-SIP-001" !in mac.notApplicable.map { it.ruleId })
        assertTrue("DSK-SIP-001" in windows.notApplicable.map { it.ruleId })
        assertEquals(windows.result.checksRun + 1, mac.result.checksRun)
    }

    @Test
    fun `every app-hygiene rule is Android-only`() {
        // The app auditor is the whole reason the Android build is worth more.
        // If one of these ever becomes iOS-capable, the marketing copy is wrong.
        val appRules = com.mume.core.rules.AppHygieneRules.ALL
        assertTrue(appRules.all { Platform.IOS !in it.platforms })
        assertTrue(appRules.all { Platform.DESKTOP !in it.platforms })
        assertEquals(6, appRules.size)
    }

    /** A healthy machine of any kind scores 100 — the fixtures must stay clean. */
    @Test
    fun `healthy fixtures score 100 on every platform`() {
        assertEquals(100, scanner.scan(Snapshots.healthyAndroid()).result.score)
        assertEquals(100, scanner.scan(Snapshots.healthyIos()).result.score)
        assertEquals(100, scanner.scan(Snapshots.healthyDesktop()).result.score)
        assertEquals(100, scanner.scan(Snapshots.healthyDesktop(DesktopOs.MACOS)).result.score)
        assertEquals(100, scanner.scan(Snapshots.healthyDesktop(DesktopOs.LINUX)).result.score)
    }
}
