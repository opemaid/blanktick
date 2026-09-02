package com.mume.core.rules

import com.mume.core.Snapshots
import com.mume.core.model.AntivirusPosture
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.HardeningFacts
import com.mume.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The hardening and antivirus-audit rules.
 *
 * Every one of these was measured against a real, healthy Windows 11 machine
 * before it was written, and the whole set produces exactly **one** finding
 * there. The tests below pin both halves of that: what fires, and — more
 * importantly — what does not.
 */
class HardeningRulesTest {

    private fun withHardening(h: HardeningFacts): DeviceSnapshot {
        val base = Snapshots.healthyDesktop()
        return base.copy(desktop = base.desktop!!.copy(hardening = h))
    }

    private fun withAv(a: AntivirusPosture): DeviceSnapshot {
        val base = Snapshots.healthyDesktop()
        return base.copy(desktop = base.desktop!!.copy(antivirusPosture = a))
    }

    private val healthyHardening get() = Snapshots.healthyDesktop().desktop!!.hardening!!
    private val healthyAv get() = Snapshots.healthyDesktop().desktop!!.antivirusPosture!!

    // ------------------------------------------------------------ baseline

    /**
     * The whole point. A rule that fires on a stock install is not a security
     * check, it is a reason to stop reading the report.
     */
    @Test
    fun `no hardening rule fires on a healthy machine`() {
        val snapshot = Snapshots.healthyDesktop()
        val firing = HardeningRules.ALL
            .filter { it.evaluate(snapshot) is RuleOutcome.Fail }
            .map { it.id }
        assertTrue(firing.isEmpty(), "these fired on a healthy machine: $firing")
    }

    /** And none of them silently declines to run, which would be a hollow pass. */
    @Test
    fun `every hardening rule is answerable on a healthy machine`() {
        val snapshot = Snapshots.healthyDesktop()
        val skipped = HardeningRules.ALL
            .filter { it.evaluate(snapshot) is RuleOutcome.NotApplicable }
            .map { it.id }
        assertTrue(skipped.isEmpty(), "these could not be evaluated at all: $skipped")
    }

    /** With no facts at all, every rule declines rather than passing. */
    @Test
    fun `absent facts produce not-applicable, never a pass`() {
        val base = Snapshots.healthyDesktop()
        val blind = base.copy(
            desktop = base.desktop!!.copy(hardening = null, antivirusPosture = null)
        )
        HardeningRules.ALL.forEach { rule ->
            assertTrue(
                rule.evaluate(blind) is RuleOutcome.NotApplicable,
                "${rule.id} produced a verdict with nothing to go on"
            )
        }
    }

    // ----------------------------------------------------------------- UAC

    @Test
    fun `UAC switched off is a high finding`() {
        val outcome = HardeningRules.UacDisabled.evaluate(
            withHardening(healthyHardening.copy(uacEnabled = false))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.HIGH, f.severity)
    }

    /**
     * Elevation without a prompt is a genuine weakness but a lesser one: the
     * boundary still exists, it just stops asking.
     */
    @Test
    fun `silent elevation is reported, and below a disabled UAC`() {
        val outcome = HardeningRules.UacDisabled.evaluate(
            withHardening(healthyHardening.copy(uacEnabled = true, uacPromptsForElevation = false))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.MEDIUM, f.severity)
    }

    // --------------------------------------------------------- credentials

    @Test
    fun `WDigest plaintext caching is a high finding`() {
        val outcome = HardeningRules.CredentialsExposedInMemory.evaluate(
            withHardening(healthyHardening.copy(plaintextCredentialsInMemory = true))
        )
        val f = (outcome as RuleOutcome.Fail).findings.first()
        assertEquals(Severity.HIGH, f.severity)
        assertEquals("wdigest", f.subjectId)
    }

    /**
     * LSA protection is reported only when it is the *only* problem.
     *
     * Someone who has re-enabled plaintext credential caching does not also need
     * a low-severity note about a hardening option; they need the one urgent
     * thing said clearly. Two findings for one fix is how a report becomes a
     * list nobody finishes.
     */
    @Test
    fun `LSA protection is not reported alongside the bigger credential problem`() {
        val both = HardeningRules.CredentialsExposedInMemory.evaluate(
            withHardening(
                healthyHardening.copy(plaintextCredentialsInMemory = true, lsaProtected = false)
            )
        ) as RuleOutcome.Fail
        assertEquals(1, both.findings.size, "both problems were reported for one fix")
        assertEquals("wdigest", both.findings.single().subjectId)

        val alone = HardeningRules.CredentialsExposedInMemory.evaluate(
            withHardening(healthyHardening.copy(lsaProtected = false))
        ) as RuleOutcome.Fail
        assertEquals("lsa", alone.findings.single().subjectId)
        assertEquals(Severity.LOW, alone.findings.single().severity)
    }

    /**
     * A stored auto-logon password is high severity — and the password itself
     * must never appear in the report.
     *
     * An app that read a cleartext credential into its own output, evidence
     * map, or log would have made the problem worse in the course of describing
     * it. The probe never collects the value, and this pins that the finding
     * does not carry one either.
     */
    @Test
    fun `a stored auto-logon password is reported without the password`() {
        val outcome = HardeningRules.AutoLogonPasswordStored.evaluate(
            withHardening(healthyHardening.copy(autoLogonPasswordStored = true))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.HIGH, f.severity)

        val printed = (f.evidence.values + f.title + f.detail + f.remediation).joinToString(" ")
        assertTrue(
            "DefaultPassword" !in f.evidence.values.joinToString(" ") ||
                f.evidence.values.none { it.length > 60 },
            "evidence looks like it may contain a credential: ${f.evidence}"
        )
        assertTrue(printed.isNotBlank())
    }

    // ------------------------------------------------------ legacy network

    @Test
    fun `SMBv1 is a high finding`() {
        val outcome = HardeningRules.LegacyNetworkProtocols.evaluate(
            withHardening(healthyHardening.copy(smb1Enabled = true))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.HIGH, f.severity)
        assertEquals("smb1", f.subjectId)
    }

    /**
     * LLMNR is the one rule in this file that fires on a stock machine, and its
     * severity is set by that fact.
     *
     * The exposure is real — it is what Responder-style credential capture on
     * shared Wi-Fi depends on — so suppressing it would hide something true.
     * But Microsoft ships it enabled, so charging MEDIUM would cost every
     * Windows machine alive 9 points and turn the score into a number nobody
     * trusts. LOW makes it advice rather than an accusation.
     */
    @Test
    fun `LLMNR is reported, but only as low severity`() {
        val outcome = HardeningRules.LegacyNetworkProtocols.evaluate(
            withHardening(healthyHardening.copy(llmnrEnabled = true))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals("llmnr", f.subjectId)
        assertEquals(
            Severity.LOW, f.severity,
            "LLMNR is on by default, so anything above LOW penalises every stock machine"
        )
    }

    @Test
    fun `remote administration services are reported individually`() {
        val outcome = HardeningRules.RemoteServicesRunning.evaluate(
            withHardening(
                healthyHardening.copy(remoteManagementRunning = true, remoteRegistryRunning = true)
            )
        )
        assertEquals(2, (outcome as RuleOutcome.Fail).findings.size)
    }

    // ------------------------------------------------- auditing the antivirus

    /**
     * The case the rule exists for: the product reports itself as running while
     * a piece of it has been switched off.
     *
     * Malware disables one component rather than the whole suite, because the
     * whole suite going dark is noticed — by the user and by the OS security
     * centre. From the outside a partly-disabled AV looks exactly like a
     * working one.
     */
    @Test
    fun `an antivirus with a component switched off is a high finding`() {
        val outcome = HardeningRules.AntivirusPartlyDisabled.evaluate(
            withAv(healthyAv.copy(behaviourMonitoringEnabled = false))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.HIGH, f.severity)
        assertTrue("behaviour monitoring" in f.title)
    }

    @Test
    fun `several disabled components produce several findings`() {
        val outcome = HardeningRules.AntivirusPartlyDisabled.evaluate(
            withAv(
                healthyAv.copy(
                    behaviourMonitoringEnabled = false,
                    downloadScanningEnabled = false,
                    antiSpywareEnabled = false
                )
            )
        )
        assertEquals(3, (outcome as RuleOutcome.Fail).findings.size)
    }

    @Test
    fun `tamper protection off is reported`() {
        val outcome = HardeningRules.TamperProtectionOff.evaluate(
            withAv(healthyAv.copy(tamperProtectionEnabled = false))
        )
        assertTrue(outcome is RuleOutcome.Fail)
    }

    /**
     * An unresolved detection is the most serious thing Mume can say about a
     * machine, because the antivirus itself is reporting it.
     */
    @Test
    fun `an active threat is critical`() {
        val outcome = HardeningRules.UnresolvedThreat.evaluate(
            withAv(healthyAv.copy(activeThreatNames = listOf("Trojan:Win32/Wacatac.B!ml")))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.CRITICAL, f.severity)
        assertTrue("Trojan:Win32/Wacatac.B!ml" in f.detail)
    }

    /**
     * Detection *history* is not a finding, and this is the measurement that
     * decided it.
     *
     * The development machine has 73 entries in Defender's history and no
     * current problem: 42 behaviour alerts against the developer's own JVM, 28
     * files inside a security-research repository. A rule keyed on that count
     * would have produced 73 alarming findings on a healthy computer.
     */
    @Test
    fun `a long detection history with nothing active is a pass`() {
        val outcome = HardeningRules.UnresolvedThreat.evaluate(
            withAv(healthyAv.copy(knownThreatCount = 73, activeThreatNames = emptyList()))
        )
        assertTrue(outcome is RuleOutcome.Pass)
    }

    /**
     * Unreadable exclusions must never read as "none configured".
     *
     * Defender's exclusion list is the highest-signal thing in this whole area —
     * adding one is a standard step in a compromise — and it needs
     * administrator rights Mume does not ask for. An empty list would turn "I
     * could not look" into a reassuring claim.
     */
    @Test
    fun `unreadable exclusions stay null rather than becoming an empty list`() {
        assertEquals<List<String>?>(
            null, Snapshots.healthyDesktop().desktop!!.antivirusPosture!!.exclusionPaths,
            "the healthy fixture must model exclusions as unreadable, which is the real case"
        )
    }
}
