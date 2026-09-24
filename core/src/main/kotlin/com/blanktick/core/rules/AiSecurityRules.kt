package com.blanktick.core.rules

import com.blanktick.core.model.Category
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Severity

/**
 * The AI surface: what a language model has been allowed to do on this machine.
 *
 * ## Why a consumer security app should look at this
 *
 * Two things arrived on ordinary computers in the last couple of years, and
 * almost nothing audits either.
 *
 * A **local model server** is an HTTP API with no authentication by default. It
 * is meant to be reachable only from the machine itself, and when it is not,
 * anyone on the same network can use it — the compute, the models, and whatever
 * the running conversation contains.
 *
 * A **tool configuration** is a plain JSON file listing programs a model is
 * allowed to run. That is the more interesting one, because an entry in it
 * executes commands and yet appears in no Run key, no scheduled task and no
 * service list. Every autorun checker ever written looks straight past it,
 * including the thirteen-source sweep elsewhere in this app.
 *
 * ## What these rules do not do
 *
 * They do not judge whether the tools are appropriate. The user chose them, and
 * a security app that lectures someone about their own development environment
 * is one they will close. The point is that hardly anyone has read that file
 * since the day they pasted something into it, and the machine can simply say
 * what is in it.
 */
object AiSecurityRules {

    private inline fun facts(s: DeviceSnapshot, body: (DesktopFacts) -> RuleOutcome): RuleOutcome =
        s.desktop?.let(body) ?: RuleOutcome.NotApplicable

    /**
     * Process names of local model servers, matched case-insensitively against
     * the name of whatever owns a listening socket.
     *
     * Deliberately names rather than ports: people move ports, and a port table
     * would flag whatever else happened to be on 8080.
     */
    private val MODEL_SERVERS = setOf(
        "ollama", "ollama app", "lm studio", "lmstudio", "llama-server",
        "llamacpp", "koboldcpp", "text-generation-webui", "vllm", "localai",
        "jan", "gpt4all", "open-webui", "comfyui"
    )

    /** Shells and interpreters: a grant of these is unrestricted execution. */
    private val GENERAL_PURPOSE = setOf(
        "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "bash", "sh", "zsh", "wsl", "wsl.exe"
    )

    /**
     * A model server listening on every network interface.
     *
     * These APIs ship with no authentication because they are meant to be
     * loopback-only. Bound to all interfaces on a shared network — an office, a
     * hotel, a café — the machine is running an open, unauthenticated inference
     * endpoint for anyone who scans the subnet.
     */
    val ExposedModelServer = object : BaseRule(
        id = "DSK-AI-001",
        category = Category.NETWORK,
        description = "No local AI model server is exposed to the network",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ports = d.listeningPorts ?: return@facts RuleOutcome.NotApplicable
            val exposed = ports.filter { p ->
                p.isPubliclyBound && p.process?.lowercase()?.let { name ->
                    MODEL_SERVERS.any { name.startsWith(it) || name.contains(it) }
                } == true
            }.distinctBy { it.port }
            if (exposed.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                exposed.map { p ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.HIGH,
                        title = "\"" + (p.process ?: "An AI model server") +
                            "\" is answering from the whole network",
                        detail = "It is listening on port " + p.port + " on every network " +
                            "interface, not just this computer. Local AI servers have no " +
                            "password because they are designed to be reachable only from the " +
                            "machine they run on. On a shared network anyone can send it " +
                            "requests, use your hardware, and read whatever the models are " +
                            "handling.",
                        remediation = "Bind it to 127.0.0.1 instead of 0.0.0.0. For Ollama that " +
                            "means leaving OLLAMA_HOST unset, or setting it to 127.0.0.1; other " +
                            "servers have a --host or listen setting.",
                        subjectId = p.port.toString(),
                        evidence = mapOf("port" to p.port.toString(), "process" to (p.process ?: ""))
                    )
                }
            )
        }
    }

    /**
     * A model has been granted a general-purpose shell.
     *
     * Reported at `LOW`, and framed as "here is what you granted" rather than
     * "this is wrong", because it usually is not wrong — it is a developer's own
     * machine and their own choice. It is worth surfacing because the grant is
     * invisible everywhere else: it runs commands, and it lives in a JSON file
     * rather than in any of the thirteen places this app looks for things that
     * start themselves.
     */
    val ModelHasShellAccess = object : BaseRule(
        id = "DSK-AI-002",
        category = Category.APP_HYGIENE,
        description = "You know which tools an AI assistant can run here",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ai = d.ai ?: return@facts RuleOutcome.NotApplicable
            val servers = ai.mcpServers ?: return@facts RuleOutcome.NotApplicable
            val shells = servers.filter { sv ->
                sv.launcher?.lowercase()?.substringAfterLast('\\')?.let { it in GENERAL_PURPOSE } == true
            }
            if (shells.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = if (shells.size == 1)
                        "An AI assistant can run commands here through \"" + shells.first().name + "\""
                    else shells.size.toString() + " AI assistant tools can run commands here",
                    detail = "These are configured to start through a command shell, which means " +
                        "the assistant can run anything you can: " +
                        shells.joinToString(", ") { it.name } + ". That is normal if you set them " +
                        "up deliberately. It is worth knowing because the file granting it runs " +
                        "programs without appearing in any of the startup locations this app " +
                        "checks — nothing else on your computer is looking at it.",
                    remediation = "No action needed if you recognise them. If you do not, the " +
                        "configuration file is listed below and entries can be removed from it.",
                    subjectId = "mcp-shell",
                    evidence = mapOf(
                        "tools" to shells.joinToString("; ") { it.name },
                        "configuredIn" to shells.map { it.configFile }.distinct().joinToString("; ")
                    )
                )
            )
        }
    }

    /**
     * An API key sitting in plain text in an AI configuration file.
     *
     * The value is never read, only counted. An app that copied a credential
     * into its own report would have made the problem worse in the course of
     * describing it — the same rule the auto-logon password check follows.
     */
    val CredentialsInAiConfig = object : BaseRule(
        id = "DSK-AI-003",
        category = Category.DATA_EXPOSURE,
        description = "No API keys are sitting in plain text in AI settings",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ai = d.ai ?: return@facts RuleOutcome.NotApplicable
            val files = ai.configsWithCredentials ?: return@facts RuleOutcome.NotApplicable
            if (files.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                files.map { f ->
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "An API key is stored in plain text in an AI settings file",
                        detail = f.path + " contains " + f.matches + " value(s) shaped like an " +
                            "API key. Any program running as you can read that file. These keys " +
                            "are usually billable and often have no expiry.",
                        remediation = "Move them into environment variables or a credential " +
                            "store, and rotate any key that has been sitting in a file — assume " +
                            "it is already copied.",
                        subjectId = f.path,
                        // The path and the count. Never the value.
                        evidence = mapOf("file" to f.path, "matches" to f.matches.toString())
                    )
                }
            )
        }
    }

    /**
     * Windows Recall keeping a searchable history of everything on screen.
     *
     * Nothing leaves the machine, which is genuinely better than the
     * alternative — and it also means anything able to read your files can read
     * a searchable record of every screen you have looked at, including the ones
     * showing a password manager or a bank.
     *
     * Reports not-applicable on hardware without the feature, which is most
     * machines, rather than passing.
     */
    val RecallStoringSnapshots = object : BaseRule(
        id = "DSK-AI-004",
        category = Category.DATA_EXPOSURE,
        description = "Windows is not keeping a visual record of your screen",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ai = d.ai ?: return@facts RuleOutcome.NotApplicable
            val present = ai.recallStorePresent ?: return@facts RuleOutcome.NotApplicable
            if (!present) return@facts RuleOutcome.Pass
            if (ai.recallDisabled == true) return@facts RuleOutcome.Pass

            val count = ai.recallArtifactCount
            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "Windows is keeping a searchable record of your screen",
                    detail = "Recall periodically captures what is on screen and extracts the " +
                        "text from it into a database on this computer" +
                        (if (count != null) ", currently holding about $count files" else "") +
                        ". It never leaves the machine — but anything that can read your files " +
                        "can read a history of everything you have looked at, including the " +
                        "moments your password manager or bank was open.",
                    remediation = "If you do not use it: Settings > Privacy & security > Recall & " +
                        "snapshots, turn off saving snapshots and delete the ones already stored.",
                    evidence = buildMap {
                        put("store", "present")
                        count?.let { put("artifacts", it.toString()) }
                    }
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        ExposedModelServer,
        ModelHasShellAccess,
        CredentialsInAiConfig,
        RecallStoringSnapshots
    )
}
