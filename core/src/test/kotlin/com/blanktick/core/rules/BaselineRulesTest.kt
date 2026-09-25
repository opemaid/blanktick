package com.blanktick.core.rules

import com.blanktick.core.Snapshots
import com.blanktick.core.model.AntivirusPosture
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.HardeningFacts
import com.blanktick.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The Windows baseline rules, both polarities each: what fires, what does not,
 * and what declines to judge.
 */
class BaselineRulesTest {

    private val healthy get() = Snapshots.healthyDesktop()
    private val h0 get() = healthy.desktop!!.hardening!!
    private val a0 get() = healthy.desktop!!.antivirusPosture!!

    private fun with(h: HardeningFacts = h0, a: AntivirusPosture = a0): DeviceSnapshot =
        healthy.copy(desktop = healthy.desktop!!.copy(hardening = h, antivirusPosture = a))

    private fun fail(rule: Rule, s: DeviceSnapshot) = assertIs<RuleOutcome.Fail>(rule.evaluate(s)).findings
    private fun pass(rule: Rule, s: DeviceSnapshot) = assertIs<RuleOutcome.Pass>(rule.evaluate(s))
    private fun na(rule: Rule, s: DeviceSnapshot) = assertIs<RuleOutcome.NotApplicable>(rule.evaluate(s))

    // ------------------------------------------------------------- baseline

    @Test
    fun `nothing fires and nothing declines on a healthy machine`() {
        for (r in BaselineRules.ALL) assertIs<RuleOutcome.Pass>(r.evaluate(healthy), r.id)
    }

    @Test
    fun `with no hardening facts every rule declines rather than passing`() {
        val bare = with(h = HardeningFacts(), a = AntivirusPosture())
        for (r in BaselineRules.ALL) assertIs<RuleOutcome.NotApplicable>(r.evaluate(bare), r.id)
    }

    /**
     * The development machine as measured on 2026-09-25 (Windows 11 Home 26200,
     * non-elevated). It is a healthy, stock machine, so the only point-costing
     * finding must be the one real deviation it has — insecure SMB guest logons
     * — and the three stock-off features must be INFO, costing nothing.
     */
    @Test
    fun `the measured stock Home machine gets exactly one actionable finding`() {
        val measured = with(
            h = h0.copy(
                netbiosEnabled = true, memoryIntegrityRunning = true, memoryIntegrityAvailable = true,
                credentialGuardRunning = false, credentialGuardSupportedEdition = false,
                tpmWorking = true, smartAppControlState = 0, exploitMitigationsOff = emptyList(),
                smbClientRequiresSigning = true, smbServerRequiresSigning = true,
                smbInsecureGuestLogons = true, printSpoolerRunning = true, sharedPrinterCount = 0,
                lockoutThreshold = 10, builtinAdministratorEnabled = false,
                powerShellScriptBlockLogging = false, unquotedServicePaths = emptyList()
            ),
            a = a0.copy(unwantedAppBlocking = true, controlledFolderAccess = false)
        )
        val findings = BaselineRules.ALL.mapNotNull { (it.evaluate(measured) as? RuleOutcome.Fail)?.findings }.flatten()
        val actionable = findings.filter { it.severity.isActionable }
        assertEquals(listOf("DSK-SMB-001"), actionable.map { it.ruleId })
        assertEquals(
            setOf("DSK-SAC-001", "DSK-CFA-001", "DSK-PS-002"),
            findings.filter { it.severity == Severity.INFO }.map { it.ruleId }.toSet()
        )
    }

    // ------------------------------------------------------ per-rule polarity

    @Test
    fun `memory integrity off fires only when the hardware can run it`() {
        assertEquals(Severity.MEDIUM, fail(BaselineRules.MemoryIntegrityOff, with(h0.copy(memoryIntegrityRunning = false))).single().severity)
        na(BaselineRules.MemoryIntegrityOff, with(h0.copy(memoryIntegrityRunning = false, memoryIntegrityAvailable = false)))
    }

    @Test
    fun `credential guard is not applicable on Home and fires on Pro when off`() {
        na(BaselineRules.CredentialGuardOff, with(h0.copy(credentialGuardRunning = false, credentialGuardSupportedEdition = false)))
        fail(BaselineRules.CredentialGuardOff, with(h0.copy(credentialGuardRunning = false)))
    }

    @Test
    fun `a missing or failed TPM fires`() {
        fail(BaselineRules.NoTpm, with(h0.copy(tpmWorking = false)))
        na(BaselineRules.NoTpm, with(h0.copy(tpmWorking = null)))
    }

    @Test
    fun `smart app control off is INFO and evaluation mode passes`() {
        assertEquals(Severity.INFO, fail(BaselineRules.SmartAppControlOff, with(h0.copy(smartAppControlState = 0))).single().severity)
        pass(BaselineRules.SmartAppControlOff, with(h0.copy(smartAppControlState = 2)))
    }

    @Test
    fun `controlled folder access off is INFO`() {
        assertEquals(Severity.INFO, fail(BaselineRules.ControlledFolderAccessOff, with(a = a0.copy(controlledFolderAccess = false))).single().severity)
    }

    @Test
    fun `unwanted app blocking off fires`() {
        fail(BaselineRules.UnwantedAppsAllowed, with(a = a0.copy(unwantedAppBlocking = false)))
    }

    @Test
    fun `an explicitly disabled mitigation fires and names it`() {
        val f = fail(BaselineRules.ExploitMitigationsOff, with(h0.copy(exploitMitigationsOff = listOf("DEP")))).single()
        assertTrue("DEP" in f.title)
    }

    @Test
    fun `SMB insecure guest and unsigned traffic are separate findings`() {
        val f = fail(
            BaselineRules.FileSharingUnprotected,
            with(h0.copy(smbInsecureGuestLogons = true, smbClientRequiresSigning = false))
        )
        assertEquals(setOf("insecureGuest", "signing"), f.map { it.subjectId }.toSet())
    }

    @Test
    fun `a running spooler is fine until a printer is shared`() {
        pass(BaselineRules.SharedPrinterSpooler, with(h0.copy(sharedPrinterCount = 0)))
        fail(BaselineRules.SharedPrinterSpooler, with(h0.copy(sharedPrinterCount = 1)))
        pass(BaselineRules.SharedPrinterSpooler, with(h0.copy(printSpoolerRunning = false, sharedPrinterCount = 1)))
    }

    @Test
    fun `no lockout is MEDIUM, a lax one LOW, the default passes, non-English declines`() {
        assertEquals(Severity.MEDIUM, fail(BaselineRules.NoAccountLockout, with(h0.copy(lockoutThreshold = 0))).single().severity)
        assertEquals(Severity.LOW, fail(BaselineRules.NoAccountLockout, with(h0.copy(lockoutThreshold = 50))).single().severity)
        pass(BaselineRules.NoAccountLockout, with(h0.copy(lockoutThreshold = 10)))
        na(BaselineRules.NoAccountLockout, with(h0.copy(lockoutThreshold = null)))
    }

    @Test
    fun `the built-in Administrator enabled fires`() {
        fail(BaselineRules.BuiltinAdministratorEnabled, with(h0.copy(builtinAdministratorEnabled = true)))
    }

    @Test
    fun `each unquoted service path is its own finding`() {
        val f = fail(BaselineRules.UnquotedServicePaths, with(h0.copy(unquotedServicePaths = listOf("A Svc", "B Svc"))))
        assertEquals(listOf("A Svc", "B Svc"), f.map { it.subjectId })
    }

    @Test
    fun `script block logging off is INFO`() {
        assertEquals(Severity.INFO, fail(BaselineRules.PowerShellLoggingOff, with(h0.copy(powerShellScriptBlockLogging = false))).single().severity)
    }

    // ------------------------------------------ the two extended existing rules

    @Test
    fun `NetBIOS alone keeps the name-broadcast finding alive after LLMNR is off`() {
        val f = fail(HardeningRules.LegacyNetworkProtocols, with(h0.copy(llmnrEnabled = false, netbiosEnabled = true))).single()
        assertEquals("netbios", f.subjectId)
        assertEquals(Severity.LOW, f.severity)
    }

    @Test
    fun `LLMNR and NetBIOS together are one finding keyed as llmnr for history`() {
        val f = fail(HardeningRules.LegacyNetworkProtocols, with(h0.copy(llmnrEnabled = true, netbiosEnabled = true)))
        assertEquals(listOf("llmnr"), f.map { it.subjectId })
    }

    @Test
    fun `a UAC prompt off the secure desktop is a LOW finding`() {
        val f = fail(HardeningRules.UacDisabled, with(h0.copy(uacSecureDesktop = false))).single()
        assertEquals(Severity.LOW, f.severity)
        assertEquals("secureDesktop", f.subjectId)
    }
}
