package com.blanktick.core.rules

import com.blanktick.core.Snapshots
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.HostsEntry
import com.blanktick.core.model.NearbyWifi
import com.blanktick.core.model.Severity
import com.blanktick.core.model.WifiSecurity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Each network-anomaly rule must FIRE on the attack, PASS on a clean network,
 * report NOT CHECKABLE when its input was not read, and DOES NOT APPLY when it
 * verified there is nothing to judge. Both polarities, every rule.
 */
class NetworkAnomalyRulesTest {

    private val healthy = Snapshots.healthyDesktop()
    private fun with(f: (com.blanktick.core.model.DesktopFacts) -> com.blanktick.core.model.DesktopFacts): DeviceSnapshot =
        healthy.copy(desktop = f(healthy.desktop!!))

    // ---- DSK-NET-010 router impersonation (ARP spoofing) ------------------
    @Test
    fun `router impersonation fires when another address claims the router MAC`() {
        val r = NetworkAnomalyRules.RouterImpersonation
        val f = assertIs<RuleOutcome.Fail>(r.evaluate(with { it.copy(routerMacSharedWith = listOf("192.168.1.66")) }))
        assertEquals(Severity.HIGH, f.findings.single().severity)
        assertIs<RuleOutcome.Pass>(r.evaluate(healthy))
        assertIs<RuleOutcome.NotApplicable>(r.evaluate(with { it.copy(routerMacSharedWith = null) }))
        assertIs<RuleOutcome.DoesNotApply>(r.evaluate(with { it.copy(networkConnected = false, routerMacSharedWith = null) }))
    }

    // ---- DSK-NET-011 hosts redirection -------------------------------------
    @Test
    fun `hosts redirect of a sensitive site is high, blocklist entries are ignored`() {
        val r = NetworkAnomalyRules.HostsRedirect
        val bad = with { it.copy(hostsEntries = listOf(HostsEntry("203.0.113.9", "login.microsoftonline.com"))) }
        assertEquals(Severity.HIGH, assertIs<RuleOutcome.Fail>(r.evaluate(bad)).findings.single().severity)

        // Ad-block style sinks are blocking, not redirecting.
        val blocklist = with {
            it.copy(hostsEntries = listOf(
                HostsEntry("0.0.0.0", "ads.example.com"), HostsEntry("127.0.0.1", "tracker.example"),
                HostsEntry("127.0.0.1", "localhost"), HostsEntry("::1", "localhost")
            ))
        }
        assertIs<RuleOutcome.Pass>(r.evaluate(blocklist))
        assertIs<RuleOutcome.Pass>(r.evaluate(healthy))

        // A developer's own mapping is listed, low.
        val dev = with { it.copy(hostsEntries = listOf(HostsEntry("192.168.1.20", "nas.home"))) }
        assertEquals(Severity.LOW, assertIs<RuleOutcome.Fail>(r.evaluate(dev)).findings.single().severity)

        assertIs<RuleOutcome.NotApplicable>(r.evaluate(with { it.copy(hostsEntries = null) }))
    }

    // ---- DSK-NET-012 evil twin ---------------------------------------------
    @Test
    fun `a weaker copy of the connected network fires, a mesh of equals does not`() {
        val r = NetworkAnomalyRules.EvilTwin
        val twin = with {
            it.copy(nearbyWifi = listOf(NearbyWifi("Home", WifiSecurity.WPA3), NearbyWifi("Home", WifiSecurity.OPEN)))
        }
        assertEquals(Severity.HIGH, assertIs<RuleOutcome.Fail>(r.evaluate(twin)).findings.single().severity)

        val mesh = with {
            it.copy(nearbyWifi = listOf(NearbyWifi("Home", WifiSecurity.WPA3), NearbyWifi("Home", WifiSecurity.WPA3),
                NearbyWifi("Neighbour", WifiSecurity.OPEN)))
        }
        assertIs<RuleOutcome.Pass>(r.evaluate(mesh))
        assertIs<RuleOutcome.NotApplicable>(r.evaluate(with { it.copy(nearbyWifi = null) }))
        assertIs<RuleOutcome.DoesNotApply>(r.evaluate(with { it.copy(onWifi = false) }.copy(wifi = null)))
    }

    // ---- DSK-NET-013 proxy auto-config -------------------------------------
    @Test
    fun `a proxy script is always reported, medium when fetched without encryption`() {
        val r = NetworkAnomalyRules.AutoProxyScript
        val http = with { it.copy(autoProxyConfigUrl = "http://wpad.evil.example/proxy.pac") }
        assertEquals(Severity.MEDIUM, assertIs<RuleOutcome.Fail>(r.evaluate(http)).findings.single().severity)
        val https = with { it.copy(autoProxyConfigUrl = "https://pac.corp.example/proxy.pac") }
        assertEquals(Severity.LOW, assertIs<RuleOutcome.Fail>(r.evaluate(https)).findings.single().severity)
        assertIs<RuleOutcome.Pass>(r.evaluate(healthy))
        assertIs<RuleOutcome.NotApplicable>(r.evaluate(with { it.copy(proxySettingsRead = null) }))
    }

    // ---- NET-WIFI-002 router changed (now on desktop) ----------------------
    @Test
    fun `router change fires on desktop, first sighting does not apply`() {
        val r = NetworkRules.EvilTwin   // the existing NET-WIFI-002 (router changed) rule
        val changed = healthy.copy(wifi = healthy.wifi!!.copy(gatewayMacChanged = true))
        assertEquals(Severity.HIGH, assertIs<RuleOutcome.Fail>(r.evaluate(changed)).findings.single().severity)
        assertIs<RuleOutcome.Pass>(r.evaluate(healthy))
        val first = healthy.copy(
            wifi = healthy.wifi!!.copy(gatewayMacChanged = null),
            desktop = healthy.desktop!!.copy(gatewayFirstSeen = true)
        )
        assertIs<RuleOutcome.DoesNotApply>(r.evaluate(first))
        val unread = healthy.copy(wifi = healthy.wifi!!.copy(gatewayMacChanged = null))
        assertIs<RuleOutcome.NotApplicable>(r.evaluate(unread))
    }
}
