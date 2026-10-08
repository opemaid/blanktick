package com.blanktick.core.rules

import com.blanktick.core.Snapshots
import com.blanktick.core.model.BrowserExtension
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DesktopOs
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Platform
import com.blanktick.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The browser-extension pack.
 *
 * Same discipline as the rest of the suite: every rule asserts its null case
 * (not-checkable is never a pass), its pass path, and each fail path it claims.
 */
class BrowserRulesTest {

    /** Replace the extension list on the healthy desktop fixture. */
    private fun withExts(vararg exts: BrowserExtension): DeviceSnapshot {
        val base = Snapshots.healthyDesktop()
        return base.copy(desktop = base.desktop!!.copy(browserExtensions = exts.toList()))
    }

    private fun ext(
        source: String?,
        hosts: List<String> = emptyList(),
        apis: List<String> = emptyList(),
        enabled: Boolean? = true,
        browser: String = "Chrome",
        id: String = "abcdefghijklmnopabcdefghijklmnop",
        name: String = "Test Extension"
    ) = BrowserExtension(
        browser = browser, id = id, name = name, version = "1.0",
        installSource = source, enabled = enabled,
        hostPermissions = hosts, apiPermissions = apis
    )

    // ------------------------------------------------------------ null case

    @Test
    fun `not-checkable when no extensions were read`() {
        val blind = Snapshots.healthyDesktop().copy(desktop = DesktopFacts(os = DesktopOs.WINDOWS))
        assertIs<RuleOutcome.NotApplicable>(BrowserRules.StoreProvenance.evaluate(blind))
        assertIs<RuleOutcome.NotApplicable>(BrowserRules.BroadAccess.evaluate(blind))
    }

    @Test
    fun `not applicable on mobile`() {
        val android = Snapshots.healthyAndroid()
        assertIs<RuleOutcome.NotApplicable>(BrowserRules.StoreProvenance.evaluate(android))
        assertIs<RuleOutcome.NotApplicable>(BrowserRules.BroadAccess.evaluate(android))
    }

    // ---------------------------------------------------- DSK-EXT-001 store

    @Test
    fun `store-only extensions pass provenance`() {
        val s = withExts(ext(source = "store"), ext(source = "component", name = "Built-in"))
        assertIs<RuleOutcome.Pass>(BrowserRules.StoreProvenance.evaluate(s))
    }

    @Test
    fun `an unknown source is not accused`() {
        // Cannot tell where it came from -> not a finding, honest.
        val s = withExts(ext(source = "unknown"), ext(source = null))
        assertIs<RuleOutcome.Pass>(BrowserRules.StoreProvenance.evaluate(s))
    }

    @Test
    fun `an unpacked extension is a high finding`() {
        val s = withExts(ext(source = "unpacked", name = "Loaded In Dev Mode"))
        val out = BrowserRules.StoreProvenance.evaluate(s)
        assertIs<RuleOutcome.Fail>(out)
        assertEquals(1, out.findings.size)
        assertEquals(Severity.HIGH, out.findings.single().severity)
        assertEquals("DSK-EXT-001", out.findings.single().ruleId)
    }

    @Test
    fun `a force-installed extension is a medium finding`() {
        val s = withExts(ext(source = "registry"), ext(source = "policy"))
        val out = BrowserRules.StoreProvenance.evaluate(s)
        assertIs<RuleOutcome.Fail>(out)
        assertEquals(2, out.findings.size)
        assertTrue(out.findings.all { it.severity == Severity.MEDIUM })
    }

    // ---------------------------------------------------- DSK-EXT-002 reach

    @Test
    fun `broad access with a sensitive api is surfaced as info`() {
        val s = withExts(ext(source = "store", hosts = listOf("<all_urls>"), apis = listOf("webRequest", "cookies")))
        val out = BrowserRules.BroadAccess.evaluate(s)
        assertIs<RuleOutcome.Fail>(out)
        assertEquals(Severity.INFO, out.findings.single().severity)
    }

    @Test
    fun `broad host access without a sensitive api passes`() {
        // e.g. a theme or a page-styler: sees every site, but cannot read traffic/data.
        val s = withExts(ext(source = "store", hosts = listOf("<all_urls>"), apis = listOf("storage", "contextMenus")))
        assertIs<RuleOutcome.Pass>(BrowserRules.BroadAccess.evaluate(s))
    }

    @Test
    fun `split http and https host patterns count as broad`() {
        val s = withExts(ext(source = "store", hosts = listOf("http://*/*", "https://*/*"), apis = listOf("cookies")))
        assertIs<RuleOutcome.Fail>(BrowserRules.BroadAccess.evaluate(s))
    }

    @Test
    fun `a disabled extension does not count toward reach`() {
        val s = withExts(ext(source = "store", hosts = listOf("<all_urls>"), apis = listOf("webRequest"), enabled = false))
        assertIs<RuleOutcome.Pass>(BrowserRules.BroadAccess.evaluate(s))
    }
}
