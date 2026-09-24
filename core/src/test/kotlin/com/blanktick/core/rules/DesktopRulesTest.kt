package com.blanktick.core.rules

import com.blanktick.core.BlanktickScanner
import com.blanktick.core.Snapshots
import com.blanktick.core.model.AutoRunEntry
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DesktopOs
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.ListeningPort
import com.blanktick.core.model.Platform
import com.blanktick.core.model.RemoteAccessService
import com.blanktick.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The desktop rule pack.
 *
 * Structured around one question per rule: *what does it do when it does not
 * know?* Every rule here has a null case asserted, because the null case is the
 * product promise and it is the one an implementation silently gets wrong.
 */
class DesktopRulesTest {

    private val scanner = BlanktickScanner()

    /** Mutate one desktop fact on the healthy fixture. */
    private fun with(block: DesktopFacts.() -> DesktopFacts): DeviceSnapshot {
        val base = Snapshots.healthyDesktop()
        return base.copy(desktop = base.desktop!!.block())
    }

    private fun outcome(rule: Rule, snapshot: DeviceSnapshot) = rule.evaluate(snapshot)

    // -------------------------------------------------------- the null case

    /**
     * The single most important test in this file.
     *
     * A [DesktopFacts] where nothing could be read must produce sixteen
     * not-applicable outcomes and zero passes. If this ever returns a Pass, the
     * app is telling someone their firewall is fine because it failed to look.
     */
    @Test
    fun `a machine that answered nothing passes nothing`() {
        val blind = Snapshots.healthyDesktop().copy(
            desktop = DesktopFacts(os = DesktopOs.WINDOWS)
        )
        val outcomes = DesktopRules.ALL.map { it.evaluate(blind) }

        assertTrue(
            outcomes.all { it is RuleOutcome.NotApplicable },
            "every desktop rule must report not-checkable when its input is null, got: " +
                DesktopRules.ALL.zip(outcomes)
                    .filter { it.second !is RuleOutcome.NotApplicable }
                    .joinToString { it.first.id }
        )
    }

    /** A phone snapshot has no desktop block at all, and must skip the whole pack. */
    @Test
    fun `desktop rules never run on a phone`() {
        val android = Snapshots.healthyAndroid()
        assertTrue(DesktopRules.ALL.all { it.evaluate(android) is RuleOutcome.NotApplicable })
        assertTrue(DesktopRules.ALL.none { Platform.ANDROID in it.platforms })
    }

    // ------------------------------------------------------------ perimeter

    @Test
    fun `a firewall that is entirely off is worse than one profile off`() {
        val allOff = outcome(DesktopRules.FirewallOff, with { copy(firewallEnabled = false) })
        val oneOff = outcome(
            DesktopRules.FirewallOff,
            with { copy(firewallEnabled = true, firewallProfilesOff = listOf("Public")) }
        )

        assertEquals(Severity.HIGH, assertIs<RuleOutcome.Fail>(allOff).findings.single().severity)
        val partial = assertIs<RuleOutcome.Fail>(oneOff).findings.single()
        assertEquals(Severity.MEDIUM, partial.severity)
        assertContains(partial.title, "Public")
    }

    @Test
    fun `the firewall remediation names the right control per OS`() {
        for (os in DesktopOs.entries) {
            val base = Snapshots.healthyDesktop(os)
            val snapshot = base.copy(desktop = base.desktop!!.copy(firewallEnabled = false))
            val finding = assertIs<RuleOutcome.Fail>(
                DesktopRules.FirewallOff.evaluate(snapshot)
            ).findings.single()

            val expected = when (os) {
                DesktopOs.WINDOWS -> "Windows Security"
                DesktopOs.MACOS -> "System Settings"
                DesktopOs.LINUX -> "ufw"
            }
            assertContains(finding.remediation, expected, message = "wrong instructions for $os")
        }
    }

    @Test
    fun `a hardened remote service is reported but not alarming`() {
        val open = outcome(DesktopRules.RemoteAccessEnabled, with {
            copy(remoteAccessServices = listOf(RemoteAccessService("Remote Desktop", true, 3389, hardened = false)))
        })
        val hardened = outcome(DesktopRules.RemoteAccessEnabled, with {
            copy(remoteAccessServices = listOf(RemoteAccessService("Remote Desktop", true, 3389, hardened = true)))
        })

        assertEquals(Severity.HIGH, assertIs<RuleOutcome.Fail>(open).findings.single().severity)
        assertEquals(Severity.LOW, assertIs<RuleOutcome.Fail>(hardened).findings.single().severity)
    }

    @Test
    fun `a disabled remote service is a pass, not a finding`() {
        val outcome = outcome(DesktopRules.RemoteAccessEnabled, with {
            copy(remoteAccessServices = listOf(RemoteAccessService("SSH", enabled = false)))
        })
        assertIs<RuleOutcome.Pass>(outcome)
    }

    @Test
    fun `loopback-only services are not exposure`() {
        val outcome = outcome(DesktopRules.PubliclyBoundServices, with {
            copy(
                listeningPorts = listOf(
                    ListeningPort("127.0.0.1", 8080, "node"),
                    ListeningPort("::1", 5432, "postgres")
                )
            )
        })
        assertIs<RuleOutcome.Pass>(outcome)
    }

    /**
     * SMB and mDNS bind publicly on a stock machine. Reporting them would make
     * this rule fire on every device it ever runs on, which is the same as not
     * having the rule.
     */
    @Test
    fun `ports the OS always binds publicly are not reported`() {
        val outcome = outcome(DesktopRules.PubliclyBoundServices, with {
            copy(
                listeningPorts = listOf(
                    ListeningPort("0.0.0.0", 445, "System"),
                    ListeningPort("0.0.0.0", 5353, "mDNSResponder")
                )
            )
        })
        assertIs<RuleOutcome.Pass>(outcome)
    }

    /**
     * The firewall's answer beats the socket table when it is available.
     *
     * "Bound to every interface" is not "reachable" — Windows blocks inbound by
     * default. On the development machine the old rule reported 17 services
     * reachable from the whole network, for 9 points; of 25 sockets bound to
     * all interfaces, exactly 2 belonged to a program the firewall permits.
     */
    @Test
    fun `ports the firewall blocks are not reported as reachable`() {
        val noneReachable = outcome(DesktopRules.PubliclyBoundServices, with {
            copy(
                reachableFromNetwork = emptyList(),
                listeningPorts = listOf(
                    ListeningPort("0.0.0.0", 8080, "node"),
                    ListeningPort("0.0.0.0", 5432, "postgres")
                )
            )
        })
        assertIs<RuleOutcome.Pass>(
            noneReachable,
            "sockets the firewall does not permit inbound must not be called reachable"
        )

        val oneReachable = outcome(DesktopRules.PubliclyBoundServices, with {
            copy(
                reachableFromNetwork = listOf(ListeningPort("0.0.0.0", 8080, "node")),
                listeningPorts = listOf(
                    ListeningPort("0.0.0.0", 8080, "node"),
                    ListeningPort("0.0.0.0", 5432, "postgres")
                )
            )
        })
        val f = assertIs<RuleOutcome.Fail>(oneReachable).findings.single()
        assertTrue("8080" in f.detail && "5432" !in f.detail, "only the permitted port belongs here")
    }

    @Test
    fun `an unexpected public port is one aggregate finding, not one per port`() {
        // reachableFromNetwork = null on purpose: this exercises the FALLBACK
        // path, where the firewall's answer was unavailable and "bound to every
        // interface" is the honest worst case. The precise path has its own
        // test below.
        val outcome = outcome(DesktopRules.PubliclyBoundServices, with {
            copy(
                reachableFromNetwork = null,
                listeningPorts = listOf(
                    ListeningPort("0.0.0.0", 8080, "node"),
                    ListeningPort("0.0.0.0", 5432, "postgres"),
                    ListeningPort("0.0.0.0", 6379, "redis"),
                    ListeningPort("0.0.0.0", 27017, "mongod"),
                    ListeningPort("0.0.0.0", 445, "System")   // expected, excluded
                )
            )
        })
        val findings = assertIs<RuleOutcome.Fail>(outcome).findings
        assertEquals(1, findings.size, "one card, not four")
        assertEquals(Severity.MEDIUM, findings.single().severity)
        assertEquals("5432,6379,8080,27017", findings.single().evidence["ports"])
    }

    // ------------------------------------------------------ malware defence

    @Test
    fun `stale signatures escalate with age and never below LOW`() {
        val week = outcome(DesktopRules.StaleSignatures, with { copy(antivirusSignatureAgeDays = 7) })
        val fortnight = outcome(DesktopRules.StaleSignatures, with { copy(antivirusSignatureAgeDays = 14) })
        val quarter = outcome(DesktopRules.StaleSignatures, with { copy(antivirusSignatureAgeDays = 120) })

        assertIs<RuleOutcome.Pass>(week)
        assertEquals(Severity.LOW, assertIs<RuleOutcome.Fail>(fortnight).findings.single().severity)

        val old = assertIs<RuleOutcome.Fail>(quarter).findings.single()
        assertEquals(Severity.MEDIUM, old.severity)
        assertEquals(1.5, old.weightMultiplier, "a scanner inert for a quarter weighs more")
    }

    @Test
    fun `app reputation names the control the user will actually see`() {
        for ((os, expected) in listOf(
            DesktopOs.WINDOWS to "SmartScreen",
            DesktopOs.MACOS to "Gatekeeper"
        )) {
            val base = Snapshots.healthyDesktop(os)
            val snapshot = base.copy(desktop = base.desktop!!.copy(appReputationEnabled = false))
            val finding = assertIs<RuleOutcome.Fail>(
                DesktopRules.AppReputationOff.evaluate(snapshot)
            ).findings.single()
            assertContains(finding.title, expected)
        }
    }

    // ------------------------------------------------------- boot integrity

    /** SIP is not a Windows concept; asking about it must not produce a verdict. */
    @Test
    fun `SIP is not checkable off macOS`() {
        assertIs<RuleOutcome.NotApplicable>(
            DesktopRules.SystemIntegrityProtectionOff.evaluate(Snapshots.healthyDesktop())
        )

        val mac = Snapshots.healthyDesktop(DesktopOs.MACOS)
        val disabled = mac.copy(desktop = mac.desktop!!.copy(systemIntegrityProtectionEnabled = false))
        assertEquals(
            Severity.HIGH,
            assertIs<RuleOutcome.Fail>(
                DesktopRules.SystemIntegrityProtectionOff.evaluate(disabled)
            ).findings.single().severity
        )
    }

    // -------------------------------------------------------------- updates

    @Test
    fun `pending updates escalate past four`() {
        val few = outcome(DesktopRules.PendingSecurityUpdates, with { copy(pendingSecurityUpdates = 2) })
        val many = outcome(DesktopRules.PendingSecurityUpdates, with { copy(pendingSecurityUpdates = 9) })

        assertEquals(Severity.MEDIUM, assertIs<RuleOutcome.Fail>(few).findings.single().severity)
        assertEquals(Severity.HIGH, assertIs<RuleOutcome.Fail>(many).findings.single().severity)
    }

    @Test
    fun `a machine updated within two months is current`() {
        assertIs<RuleOutcome.Pass>(
            outcome(DesktopRules.UpdateStalled, with { copy(daysSinceLastUpdate = 60) })
        )
        assertEquals(
            Severity.HIGH,
            assertIs<RuleOutcome.Fail>(
                outcome(DesktopRules.UpdateStalled, with { copy(daysSinceLastUpdate = 200) })
            ).findings.single().severity
        )
    }

    // ------------------------------------------------------------- accounts

    @Test
    fun `a passwordless account is critical and names the accounts`() {
        val finding = assertIs<RuleOutcome.Fail>(
            outcome(DesktopRules.PasswordlessAccount, with { copy(passwordlessAccounts = listOf("kids", "test")) })
        ).findings.single()

        assertEquals(Severity.CRITICAL, finding.severity)
        assertContains(finding.detail, "kids")
        assertContains(finding.detail, "test")
    }

    /**
     * Running as administrator is real but ubiquitous. If it were scored HIGH,
     * nearly every consumer machine would open on a red card for the thing the
     * user is least likely to change, and the genuinely urgent findings would
     * sit underneath it.
     */
    @Test
    fun `administrator session is medium, not high`() {
        val finding = assertIs<RuleOutcome.Fail>(
            outcome(DesktopRules.DailyDriverIsAdmin, with { copy(sessionIsAdministrator = true) })
        ).findings.single()
        assertEquals(Severity.MEDIUM, finding.severity)
    }

    @Test
    fun `a standard user account passes`() {
        assertIs<RuleOutcome.Pass>(
            outcome(DesktopRules.DailyDriverIsAdmin, with { copy(sessionIsAdministrator = false) })
        )
    }

    // ---------------------------------------------------------- persistence

    /**
     * An autorun whose signature could not be checked is *not* an unsigned
     * autorun. On Linux almost nothing is signed in a way we can verify, and
     * reporting all of it would bury the one entry that matters.
     */
    @Test
    fun `unverifiable autoruns are not accused of being unsigned`() {
        val unknown = outcome(DesktopRules.UnsignedAutoRuns, with {
            copy(
                autoRunEntries = listOf(
                    AutoRunEntry("syncthing", "~/.config/autostart", signedByKnownVendor = null),
                    AutoRunEntry("OneDrive", "Run key", signedByKnownVendor = true)
                )
            )
        })
        assertIs<RuleOutcome.Pass>(unknown)
    }

    @Test
    fun `a positively unsigned autorun is reported with where it lives`() {
        val finding = assertIs<RuleOutcome.Fail>(
            outcome(DesktopRules.UnsignedAutoRuns, with {
                copy(
                    autoRunEntries = listOf(
                        AutoRunEntry("svch0st", "HKCU Run", "C:/Users/x/AppData/svch0st.exe", false)
                    )
                )
            })
        ).findings.single()

        assertContains(finding.title, "svch0st")
        assertEquals("HKCU Run", finding.evidence["location"])
        assertEquals("C:/Users/x/AppData/svch0st.exe", finding.evidence["command"])
    }

    @Test
    fun `a long list of unsigned autoruns is capped`() {
        val findings = assertIs<RuleOutcome.Fail>(
            outcome(DesktopRules.UnsignedAutoRuns, with {
                copy(
                    autoRunEntries = (1..20).map {
                        AutoRunEntry("entry$it", "Run key", signedByKnownVendor = false)
                    }
                )
            })
        ).findings
        assertEquals(5, findings.size, "twenty cards would bury every other finding")
    }

    // ------------------------------------------------------------- scoring

    /**
     * A badly configured machine must be able to reach a low score without any
     * one category running away with it.
     */
    @Test
    fun `a neglected machine scores badly but the arithmetic still reconciles`() {
        val bad = with {
            copy(
                firewallEnabled = false,
                antivirusRealtimeEnabled = false,
                antivirusSignatureAgeDays = 200,
                appReputationEnabled = false,
                secureBootEnabled = false,
                automaticUpdatesEnabled = false,
                pendingSecurityUpdates = 12,
                daysSinceLastUpdate = 400,
                sessionIsAdministrator = true,
                passwordlessAccounts = listOf("guest"),
                guestAccountEnabled = true,
                lockOnWakeEnabled = false,
                remoteAccessServices = listOf(RemoteAccessService("Remote Desktop", true, 3389, false)),
                listeningPorts = (1..6).map { ListeningPort("0.0.0.0", 9000 + it, "svc$it") },
                autoRunEntries = listOf(AutoRunEntry("bad", "Run key", signedByKnownVendor = false))
            )
        }

        val result = scanner.scan(bad).result
        assertTrue(result.score < 25, "expected an at-risk score, got ${result.score}")
        assertTrue(result.deductionsReconcile, "the ledger must still add up")

        // No category may exceed its cap even with everything wrong at once.
        result.categories.forEach { category ->
            val cap = category.cappedAt
            if (cap != null) assertTrue(category.deduction <= cap)
        }
    }
}
