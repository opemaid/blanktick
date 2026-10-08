package com.blanktick.core.rules

import com.blanktick.core.model.Category
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.McpServer
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
     * Package runners that fetch a tool's code from a public registry and run it,
     * usually at whatever the latest version is, each time the tool starts.
     *
     * Named rather than pattern-matched: these are the launchers that mean "the
     * code is downloaded, not a pinned local program." `pnpm dlx` / `yarn dlx`
     * are not here because the launcher is `pnpm` / `yarn` and the runner lives
     * in an argument this snapshot does not yet carry — captured as a known gap
     * in the dynamic-tier design rather than guessed at.
     */
    private val PACKAGE_RUNNERS = setOf(
        "npx", "npx.cmd", "npx.exe",
        "uvx", "uvx.exe",
        "bunx", "bunx.exe",
        "pipx", "pipx.exe"
    )

    /**
     * Tools that pull in content from outside the machine — the web, mailboxes,
     * chat, documents — i.e. text an attacker could author. Matched as substrings
     * of the tool's configured name, because that is what the snapshot carries.
     *
     * Heuristic by nature and deliberately conservative: the rule that uses this
     * only speaks up when an intake tool sits *alongside* an action tool, so a
     * mislabel on its own is silent.
     */
    private val CONTENT_INTAKE = setOf(
        "fetch", "http", "web", "browser", "puppeteer", "playwright", "crawl",
        "scrape", "search", "brave", "gmail", "mail", "email", "slack",
        "discord", "rss", "url", "news", "reddit", "notion", "confluence"
    )

    /**
     * Tools that can act on the machine with the user's access — write files,
     * run commands, reach a database. Combined at the call site with the
     * general-purpose shells above, which are the strongest form of this.
     */
    private val ACTION_CAPABLE = setOf(
        "filesystem", "file", "shell", "exec", "command", "terminal",
        "desktop-commander", "git", "docker", "ssh", "database", "sqlite",
        "postgres", "mysql", "kubernetes"
    )

    private fun McpServer.nameMatches(markers: Set<String>): Boolean =
        name.lowercase().let { n -> markers.any { n.contains(it) } }

    private fun McpServer.isShellLauncher(): Boolean =
        launcher?.lowercase()?.substringAfterLast('\\')?.substringAfterLast('/')
            ?.let { it in GENERAL_PURPOSE } == true

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

    /**
     * A tool the model can invoke is started through a package runner, so its
     * code is downloaded from a public registry and run as you each time.
     *
     * This is the quiet way a rogue tool gets in. A config entry like
     * `npx some-mcp-server` does not name a program on the machine — it fetches
     * one, usually at whatever the latest published version happens to be, and
     * runs it with the user's full access. A typo-squatted or later-compromised
     * package would run the same way, and none of the thirteen startup locations
     * this app checks would show it. Reported at MEDIUM, and framed as "here is
     * what this grants" rather than "this is wrong": it is normal in developer
     * setups, and the point is that the fetch-and-run is invisible everywhere
     * else, and the code can change between runs without the user touching
     * anything.
     */
    val ModelToolFetchesCodeToRun = object : BaseRule(
        id = "DSK-AI-005",
        category = Category.APP_HYGIENE,
        description = "You know which AI tools download and run code from the internet",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ai = d.ai ?: return@facts RuleOutcome.NotApplicable
            val servers = ai.mcpServers ?: return@facts RuleOutcome.NotApplicable
            val fetched = servers.filter { sv ->
                sv.launcher?.lowercase()?.substringAfterLast('\\')?.substringAfterLast('/')
                    ?.let { it in PACKAGE_RUNNERS } == true
            }
            if (fetched.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = if (fetched.size == 1)
                        "\"" + fetched.first().name + "\" starts an AI tool by downloading code from the internet"
                    else fetched.size.toString() + " AI tools start by downloading code from the internet",
                    detail = "These tools launch through a package runner (" +
                        fetched.mapNotNull { it.launcher }.map { it.substringAfterLast('\\').substringAfterLast('/') }
                            .distinct().joinToString(", ") + "), which fetches their code from a public " +
                        "registry and runs it as you — usually at the latest version, refreshed each time " +
                        "they start: " + fetched.joinToString(", ") { it.name } + ". That is convenient and " +
                        "common in developer setups. It is worth knowing because the code can change between " +
                        "runs without you doing anything, and a compromised or look-alike package would run " +
                        "with your full access. This is one of the main ways a malicious AI tool reaches a " +
                        "machine, and it appears in none of the startup locations this app otherwise checks.",
                    remediation = "If you rely on these, pin each to a specific version, or install the tool " +
                        "once to a fixed local path and point the config at that instead of a runner. If you " +
                        "do not recognise one, its configuration file is listed below and the entry can be removed.",
                    subjectId = "mcp-remote-fetch",
                    evidence = mapOf(
                        "tools" to fetched.joinToString("; ") { it.name },
                        "runners" to fetched.mapNotNull { it.launcher }.distinct().joinToString("; "),
                        "configuredIn" to fetched.map { it.configFile }.distinct().joinToString("; ")
                    )
                )
            )
        }
    }

    /**
     * The prompt-injection condition: one assistant can both read outside
     * content and act on the machine.
     *
     * Prompt injection is the AI-native attack. It works when a model reads text
     * an attacker controls — a web page, an email, a document — and that text
     * contains instructions the model then carries out. A single tool cannot do
     * much harm. The danger is the *combination*: a tool that pulls in outside
     * content sitting next to a tool that can write files or run commands as
     * you. Then a booby-trapped page the assistant reads can tell it to act, and
     * it has the means.
     *
     * Reported at MEDIUM, and framed as "here is the combination" rather than
     * "you are compromised": it is common on developer machines and is often
     * intended. It is worth surfacing because it is the specific pairing
     * attackers target, and nothing else on the machine points it out. Detection
     * only — stopping a live injection is the resident sensor's job, not a
     * snapshot's.
     */
    val PromptInjectionReach = object : BaseRule(
        id = "DSK-AI-006",
        category = Category.APP_HYGIENE,
        description = "No AI assistant here can be steered by outside content into acting as you",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val ai = d.ai ?: return@facts RuleOutcome.NotApplicable
            val servers = ai.mcpServers ?: return@facts RuleOutcome.NotApplicable

            val intake = servers.filter { it.nameMatches(CONTENT_INTAKE) }
            val action = servers.filter { it.nameMatches(ACTION_CAPABLE) || it.isShellLauncher() }
            if (intake.isEmpty() || action.isEmpty()) return@facts RuleOutcome.Pass

            RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "An AI assistant here can both read outside content and act on this computer",
                    detail = "One tool pulls in content from outside sources (" +
                        intake.joinToString(", ") { it.name } + ") and another can act on this " +
                        "machine with your access (" + action.joinToString(", ") { it.name } + "). " +
                        "On their own each is fine. Together they are the condition that makes prompt " +
                        "injection actionable: a web page, email or document the assistant reads can " +
                        "carry hidden instructions, and the assistant has a tool that can carry them " +
                        "out — write files, run commands — as you. This is common on developer " +
                        "machines and may be exactly what you set up. It is worth knowing because it " +
                        "is the specific combination an attacker aims for, and nothing else here " +
                        "points it out.",
                    remediation = "If you do not need them together, keep the content-reading tools " +
                        "in a separate assistant profile from the ones that can act, or remove " +
                        "whichever you do not use. If you keep both, treat everything the assistant " +
                        "reads as untrusted input to the tools it can run.",
                    subjectId = "mcp-injection-reach",
                    evidence = mapOf(
                        "intake" to intake.joinToString("; ") { it.name },
                        "action" to action.joinToString("; ") { it.name },
                        "configuredIn" to (intake + action).map { it.configFile }.distinct().joinToString("; ")
                    )
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        ExposedModelServer,
        ModelHasShellAccess,
        CredentialsInAiConfig,
        RecallStoringSnapshots,
        ModelToolFetchesCodeToRun,
        PromptInjectionReach
    )
}
