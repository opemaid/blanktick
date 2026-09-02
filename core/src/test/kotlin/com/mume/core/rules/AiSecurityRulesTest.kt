package com.mume.core.rules

import com.mume.core.Snapshots
import com.mume.core.model.AiFacts
import com.mume.core.model.CredentialBearingFile
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.ListeningPort
import com.mume.core.model.McpServer
import com.mume.core.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The AI surface.
 *
 * These exist because two things arrived on ordinary machines recently and
 * nothing audits either: a local model server, which is an unauthenticated API
 * by default, and a tool configuration, which is a JSON file naming programs a
 * language model may run — and which appears in none of the thirteen startup
 * locations this app otherwise checks.
 */
class AiSecurityRulesTest {

    private fun withAi(ai: AiFacts): DeviceSnapshot {
        val base = Snapshots.healthyDesktop()
        return base.copy(desktop = base.desktop!!.copy(ai = ai))
    }

    private fun withPorts(vararg p: ListeningPort): DeviceSnapshot {
        val base = Snapshots.healthyDesktop()
        return base.copy(desktop = base.desktop!!.copy(listeningPorts = p.toList()))
    }

    private val healthyAi get() = Snapshots.healthyDesktop().desktop!!.ai!!

    @Test
    fun `nothing fires on a healthy machine`() {
        val snapshot = Snapshots.healthyDesktop()
        val firing = AiSecurityRules.ALL
            .filter { it.evaluate(snapshot) is RuleOutcome.Fail }
            .map { it.id }
        assertTrue(firing.isEmpty(), "these fired on a healthy machine: $firing")
    }

    @Test
    fun `absent facts produce not-applicable, never a pass`() {
        val base = Snapshots.healthyDesktop()
        val blind = base.copy(desktop = base.desktop!!.copy(ai = null, listeningPorts = null))
        AiSecurityRules.ALL.forEach {
            assertTrue(
                it.evaluate(blind) is RuleOutcome.NotApplicable,
                "${it.id} produced a verdict with nothing to go on"
            )
        }
    }

    // ------------------------------------------------------- exposed server

    /**
     * These APIs have no password because they are meant to be loopback-only.
     * Bound to every interface on a shared network, the machine is running an
     * open inference endpoint for anyone who scans the subnet.
     */
    @Test
    fun `a model server bound to all interfaces is high severity`() {
        val outcome = AiSecurityRules.ExposedModelServer.evaluate(
            withPorts(ListeningPort("0.0.0.0", 11434, "ollama"))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.HIGH, f.severity)
        assertTrue("11434" in f.detail)
    }

    /** Loopback is the correct configuration and must never be reported. */
    @Test
    fun `a model server on loopback is not a finding`() {
        val outcome = AiSecurityRules.ExposedModelServer.evaluate(
            withPorts(ListeningPort("127.0.0.1", 11434, "ollama"))
        )
        assertTrue(outcome is RuleOutcome.Pass, "loopback is exactly how it should be bound")
    }

    /**
     * Matched on the process name, not the port.
     *
     * People move these servers to other ports, and a port table would flag
     * whatever else happened to be on 8080 — which on this developer's machine
     * is a perfectly ordinary web server.
     */
    @Test
    fun `an ordinary service on a port an AI tool might use is not flagged`() {
        val outcome = AiSecurityRules.ExposedModelServer.evaluate(
            withPorts(ListeningPort("0.0.0.0", 8080, "nginx"))
        )
        assertTrue(outcome is RuleOutcome.Pass, "the rule keys on the program, not the port")
    }

    // ------------------------------------------------------------ tool grants

    /**
     * A tool server started through a shell is unrestricted execution, and the
     * grant lives somewhere no autorun checker looks.
     */
    @Test
    fun `a tool launched through a shell is reported once, at low severity`() {
        val outcome = AiSecurityRules.ModelHasShellAccess.evaluate(
            withAi(
                healthyAi.copy(
                    mcpServers = listOf(
                        McpServer("mobile", "cmd", "~/.claude.json"),
                        McpServer("skill-bus", "node", "~/.claude.json"),
                        McpServer("mql5-rag", "python", "~/.claude.json")
                    )
                )
            )
        )
        val findings = (outcome as RuleOutcome.Fail).findings
        assertEquals(1, findings.size, "one card listing them, not one per tool")
        assertEquals(
            Severity.LOW, findings.single().severity,
            "the user configured these deliberately; this is context, not an accusation"
        )
        assertTrue("mobile" in findings.single().title)
    }

    /**
     * A purpose-built tool server is not a shell grant.
     *
     * `node` and `python` running a specific script are what most MCP servers
     * are, and flagging them would make the rule fire for everyone who has ever
     * configured one — which is the definition of noise in this codebase.
     */
    @Test
    fun `purpose-built tool servers are not reported`() {
        val outcome = AiSecurityRules.ModelHasShellAccess.evaluate(
            withAi(
                healthyAi.copy(
                    mcpServers = listOf(
                        McpServer("skill-bus", "node", "~/.claude.json"),
                        McpServer("mql5-rag", "python", "~/.claude.json")
                    )
                )
            )
        )
        assertTrue(outcome is RuleOutcome.Pass)
    }

    // ------------------------------------------------------------ credentials

    /**
     * The finding must carry the file and the count, and never the secret.
     *
     * An app that copied a credential into its own report, evidence map or log
     * would have made the problem worse in the course of describing it. The
     * probe only ever counts matches; this pins that the finding does too.
     */
    @Test
    fun `a key in an AI config is reported without the key`() {
        val outcome = AiSecurityRules.CredentialsInAiConfig.evaluate(
            withAi(
                healthyAi.copy(
                    configsWithCredentials = listOf(
                        CredentialBearingFile("C:/Users/x/AppData/Roaming/Claude/config.json", 2)
                    )
                )
            )
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.MEDIUM, f.severity)

        val everythingShown = (f.evidence.values + f.title + f.detail + f.remediation)
            .joinToString(" ")
        assertFalse("sk-" in everythingShown, "a credential prefix reached the report")
        assertTrue("2" in f.detail, "the count is the useful part")
    }

    // ---------------------------------------------------------------- Recall

    @Test
    fun `Recall keeping snapshots is reported`() {
        val outcome = AiSecurityRules.RecallStoringSnapshots.evaluate(
            withAi(healthyAi.copy(recallStorePresent = true, recallArtifactCount = 1_204))
        )
        val f = (outcome as RuleOutcome.Fail).findings.single()
        assertEquals(Severity.MEDIUM, f.severity)
        assertTrue("1204" in f.detail || "1,204" in f.detail || "1204" in f.evidence.values.joinToString())
    }

    /** Switched off by policy is a pass even if an old store is still on disk. */
    @Test
    fun `Recall disabled by policy is a pass`() {
        val outcome = AiSecurityRules.RecallStoringSnapshots.evaluate(
            withAi(healthyAi.copy(recallStorePresent = true, recallDisabled = true))
        )
        assertTrue(outcome is RuleOutcome.Pass)
    }

    /**
     * Most machines do not have the hardware for it, and "this feature does not
     * exist here" is not the same statement as "it is switched off".
     */
    @Test
    fun `a machine without Recall reports not-checkable rather than passing`() {
        val outcome = AiSecurityRules.RecallStoringSnapshots.evaluate(
            withAi(healthyAi.copy(recallStorePresent = null))
        )
        assertTrue(outcome is RuleOutcome.NotApplicable)
    }
}
