package com.blanktick.desktop.mcp

import com.blanktick.core.BlanktickScanner
import com.blanktick.core.json.Json
import com.blanktick.core.json.JsonValue
import com.blanktick.desktop.collect.DesktopCollector
import com.blanktick.desktop.collect.DesktopIntel
import com.blanktick.desktop.collect.WindowsProbe
import com.blanktick.desktop.history.ScanHistory
import java.time.LocalDate

/**
 * Exposes Blanktick to any language model, over stdio.
 *
 * ## Why this does not break the promise
 *
 * MCP has two transports. The HTTP one would make this app a network client and
 * is not implemented here at any level. **This is stdio**: the parent process
 * launches Blanktick, writes JSON-RPC on its standard input and reads replies from
 * its standard output. No socket is opened, nothing is bound, nothing is
 * connected to — the desktop build's bytecode gate still forbids a networking
 * API anywhere in Blanktick's own classes, and it still passes.
 *
 * ## Why it is read-only, and why that matters more than usual
 *
 * This app ships a rule, `DSK-AI-002`, that tells people an MCP entry lets a
 * model run commands on their machine and that it appears in none of the
 * startup locations anything else checks. Shipping an MCP server after writing
 * that would be indefensible unless this one is exactly what the app claims to
 * be: **it reports, and it changes nothing.**
 *
 * So every tool below is a question. There is no tool that fixes a finding,
 * changes a setting, deletes a file, or quarantines anything — not because it
 * would be hard, but because a model acting on a security report without a
 * person in the loop is a worse idea than any problem it would solve. The user
 * decides and acts; that has been true of this app since the first commit and
 * an automation surface is not a reason to stop.
 *
 * ## The one rule of a stdio server
 *
 * **Standard output is the protocol.** A stray `println` anywhere in the
 * process corrupts the stream and the client disconnects with a parse error
 * that names nothing useful. Everything diagnostic goes to stderr, and
 * [McpServerTest] asserts the scan path does not print.
 */
class McpServer(
    private val input: java.io.BufferedReader = System.`in`.bufferedReader(),
    private val output: java.io.Writer = System.out.writer()
) {

    /**
     * The version this speaks. A client asking for a different one is answered
     * with the version it asked for when we recognise it, because the wire
     * format has not changed across these revisions and refusing would strand
     * clients for no benefit.
     */
    private val supportedVersions = setOf("2024-11-05", "2025-03-26", "2025-06-18")
    private val preferredVersion = "2024-11-05"

    /** Cached so three tool calls in a row do not run three full scans. */
    private var cachedScan: com.blanktick.core.ScanReport? = null

    fun run() {
        while (true) {
            val line = input.readLine() ?: return
            if (line.isBlank()) continue

            val request = Json.parseOrNull(line)
            if (request == null) {
                respond(error(JsonValue.Null, -32700, "Parse error"))
                continue
            }
            val id = request["id"] ?: JsonValue.Null
            val method = request["method"]?.asString

            // A notification has no id and takes no reply. Answering one is a
            // protocol violation that some clients treat as fatal.
            val isNotification = request["id"] == null

            val reply = when (method) {
                "initialize" -> initialize(id, request)
                "tools/list" -> success(id, toolsList())
                "tools/call" -> toolsCall(id, request)
                "ping" -> success(id, Json.obj())
                null -> error(id, -32600, "Invalid request: no method")
                else -> if (isNotification) null else error(id, -32601, "Unknown method: $method")
            }
            if (reply != null && !isNotification) respond(reply)
        }
    }

    private fun respond(message: JsonValue) {
        output.write(Json.write(message))
        output.write("\n")
        output.flush()
    }

    // ------------------------------------------------------------- handshake

    private fun initialize(id: JsonValue, request: JsonValue): JsonValue {
        val asked = request["params"]?.get("protocolVersion")?.asString
        val version = if (asked != null && asked in supportedVersions) asked else preferredVersion
        return success(
            id,
            Json.obj(
                "protocolVersion" to Json.str(version),
                "capabilities" to Json.obj("tools" to Json.obj()),
                "serverInfo" to Json.obj(
                    "name" to Json.str("blanktick"),
                    "version" to Json.str("1.0.0")
                ),
                "instructions" to Json.str(
                    "Blanktick is a read-only security surface for surveying THIS computer: you " +
                        "query, you reason, you recommend — the user decides and acts. Nothing " +
                        "here changes a setting, removes a file, or fixes a finding, by design; " +
                        "if you conclude something should be changed, tell the user what and why, " +
                        "and let them do it.\n\n" +
                        "To survey the machine: call blanktick_coverage first to learn what can " +
                        "and cannot be checked here; blanktick_scan for a full posture read (about " +
                        "100s) or blanktick_history / blanktick_search / blanktick_changes to read " +
                        "what past scans already found without re-scanning; blanktick_facts for " +
                        "the raw readings; blanktick_probe_script to show exactly what it runs; and " +
                        "blanktick_netlog to review a Wireshark capture the user exported.\n\n" +
                        "Two rules you must carry into every summary. (1) A fact reported as not " +
                        "checkable means the machine would not answer — it is NOT a pass, and " +
                        "rounding 'I could not look' to 'this is fine' defeats the entire tool. " +
                        "(2) The score is deductions subtracted from 100, so it is only meaningful " +
                        "next to the coverage: a machine where little could be checked scores " +
                        "HIGH because little was found to deduct for. Say what was not checked."
                )
            )
        )
    }

    // ----------------------------------------------------------------- tools

    private fun toolsList(): JsonValue = Json.obj(
        "tools" to Json.arr(
            listOf(
                tool(
                    "blanktick_scan",
                    "Run a full security scan of this computer and return the score, every " +
                        "finding, and the list of checks that could not be performed. Takes " +
                        "about 100 seconds. Read-only.",
                    Json.obj(
                        "type" to Json.str("object"),
                        "properties" to Json.obj(
                            "refresh" to Json.obj(
                                "type" to Json.str("boolean"),
                                "description" to Json.str(
                                    "Re-run rather than returning the previous result of this session."
                                )
                            )
                        )
                    )
                ),
                tool(
                    "blanktick_facts",
                    "Return the raw facts read from this machine, including the nulls. A null " +
                        "means the machine would not answer, which is different from a negative " +
                        "answer. Read-only.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "blanktick_probe_script",
                    "Return the exact PowerShell Blanktick runs on this machine, so it can be read " +
                        "or re-run by hand and the output compared. Reads nothing.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "blanktick_coverage",
                    "Return what Blanktick can and cannot check on this platform and why, without " +
                        "running a scan.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "blanktick_history",
                    "List past scans from the local history (newest first): when each ran, its " +
                        "score and how many findings it had. This reads a stored record, not the " +
                        "live machine, and never runs a scan. Empty unless the user has turned " +
                        "history on. Read-only.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "blanktick_search",
                    "Search findings across stored scans without running one. All filters are " +
                        "optional and combine: severity (INFO/LOW/MEDIUM/HIGH/CRITICAL), rule " +
                        "(a rule id such as NET-DNS-001), category, and since (an ISO date, only " +
                        "scans on or after it). Returns matches with the date of the scan each " +
                        "came from. Reads stored history, not the live machine. Read-only.",
                    Json.obj(
                        "type" to Json.str("object"),
                        "properties" to Json.obj(
                            "severity" to Json.obj(
                                "type" to Json.str("string"),
                                "description" to Json.str("INFO, LOW, MEDIUM, HIGH or CRITICAL")
                            ),
                            "rule" to Json.obj(
                                "type" to Json.str("string"),
                                "description" to Json.str("A rule id, e.g. NET-DNS-001")
                            ),
                            "category" to Json.obj(
                                "type" to Json.str("string"),
                                "description" to Json.str("A finding category name")
                            ),
                            "since" to Json.obj(
                                "type" to Json.str("string"),
                                "description" to Json.str("ISO date (YYYY-MM-DD); only scans on or after it")
                            )
                        )
                    )
                ),
                tool(
                    "blanktick_changes",
                    "Compare the two most recent stored scans and report what is new and what is " +
                        "no longer found. A finding that is gone means it was not observed this " +
                        "time, which is not proof it was fixed. Reads stored history, runs no " +
                        "scan. Read-only.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "blanktick_netlog",
                    "Review a network capture the USER exported from Wireshark (File -> Export " +
                        "Packet Dissections -> As CSV). Reports the domains queried, external " +
                        "destinations, cleartext protocols, and any queried name on the offline " +
                        "blocklist. Blanktick captured nothing and opened no socket; it only reads " +
                        "the file at 'path'. A capture is a slice of time — a clean one means " +
                        "nothing bad was seen while watching, not that nothing bad happens. " +
                        "Read-only.",
                    Json.obj(
                        "type" to Json.str("object"),
                        "properties" to Json.obj(
                            "path" to Json.obj(
                                "type" to Json.str("string"),
                                "description" to Json.str("Path to the exported capture CSV to review")
                            )
                        ),
                        "required" to Json.arr(listOf(Json.str("path")))
                    )
                )
            )
        )
    )

    private fun tool(name: String, description: String, schema: JsonValue): JsonValue = Json.obj(
        "name" to Json.str(name),
        "description" to Json.str(description),
        "inputSchema" to schema
    )

    private fun toolsCall(id: JsonValue, request: JsonValue): JsonValue {
        val name = request["params"]?.get("name")?.asString
            ?: return error(id, -32602, "Missing tool name")
        val args = request["params"]?.get("arguments")

        return try {
            val text = when (name) {
                "blanktick_scan" -> scanText(refresh = args?.get("refresh")?.asBool == true)
                "blanktick_facts" -> factsText()
                "blanktick_probe_script" -> scriptText()
                "blanktick_coverage" -> coverageText()
                "blanktick_history" -> ScanHistory.renderHistory(ScanHistory.all())
                "blanktick_search" -> searchText(args)
                "blanktick_changes" -> {
                    val scans = ScanHistory.all()
                    ScanHistory.renderChanges(
                        previous = scans.getOrNull(scans.size - 2),
                        latest = scans.lastOrNull()
                    )
                }
                "blanktick_netlog" -> netlogText(args?.get("path")?.asString)
                else -> return error(id, -32602, "Unknown tool: $name")
            }
            success(id, content(text, isError = false))
        } catch (e: Exception) {
            // Reported as a tool error rather than a protocol error: the call
            // was well-formed, the machine just would not answer. That is the
            // same distinction the null contract makes everywhere else.
            success(
                id,
                content(
                    "Blanktick could not complete that: " + (e.message ?: e::class.simpleName) +
                        ". Nothing about this machine should be inferred from the failure.",
                    isError = true
                )
            )
        }
    }

    private fun content(text: String, isError: Boolean): JsonValue = Json.obj(
        "content" to Json.arr(
            listOf(Json.obj("type" to Json.str("text"), "text" to Json.str(text)))
        ),
        "isError" to Json.bool(isError)
    )

    private fun netlogText(path: String?): String {
        if (path.isNullOrBlank()) return "Provide 'path': the capture CSV the user exported from Wireshark."
        val file = java.io.File(path)
        if (!file.isFile) return "No such file: $path. It must be a CSV the user exported from Wireshark."
        // The blocklist is offline; cross-referencing it sends nothing. Parsing
        // returns a summary of connection metadata, never the file's raw contents.
        val blocklist = runCatching { DesktopIntel.load().domainBlocklist() }.getOrNull()
        val packets = com.blanktick.core.analysis.CaptureAnalysis.parse(file.readText())
        return com.blanktick.core.analysis.CaptureAnalysis.render(
            com.blanktick.core.analysis.CaptureAnalysis.analyze(packets, blocklist)
        )
    }

    private fun searchText(args: JsonValue?): String {
        // `since` is an ISO date; anything unparseable is ignored rather than
        // erroring, so a model's loose input narrows nothing instead of failing.
        val since = args?.get("since")?.asString
            ?.let { runCatching { LocalDate.parse(it) }.getOrNull() }
            ?.atStartOfDay(java.time.ZoneId.systemDefault())?.toInstant()?.toEpochMilli()
        return ScanHistory.renderSearch(
            ScanHistory.search(
                snapshots = ScanHistory.all(),
                severity = args?.get("severity")?.asString,
                ruleId = args?.get("rule")?.asString,
                category = args?.get("category")?.asString,
                sinceEpochMillis = since
            )
        )
    }

    // ------------------------------------------------------------- the work

    private fun report(refresh: Boolean): com.blanktick.core.ScanReport {
        cachedScan?.takeIf { !refresh }?.let { return it }
        val collector = DesktopCollector.forCurrentOs()
            ?: throw IllegalStateException("this operating system is not one Blanktick can inspect")
        val intel = DesktopIntel.load().snapshot(LocalDate.now().toString())
        val snap = collector.collect(intel)
        return BlanktickScanner().scan(snap).also {
            cachedScan = it
            // Append to the searchable history — a no-op unless the user turned
            // it on (keepHistory), and never for an unfinished collection, which
            // must not become a stored "all clear". The only write the MCP path
            // makes.
            if (snap.desktop?.collectionCompleted != false) ScanHistory.record(it)
        }
    }

    private fun scanText(refresh: Boolean): String {
        val r = report(refresh)
        val result = r.result
        val snapshot = DesktopCollector.forCurrentOs()

        return buildString {
            appendLine("BLANKTICK SCAN")
            appendLine("=".repeat(60))
            appendLine("checks run:    ${result.checksRun}")
            appendLine("not checkable: ${result.checksSkipped} " +
                "(${r.skippedWrongPlatform.size} not written for this kind of device, " +
                "${r.skippedUnobservable.size} this machine would not answer)")
            appendLine("score:         ${result.score}/100 (${result.grade})")
            appendLine()
            appendLine("A score is deductions subtracted from 100, so it is only meaningful")
            appendLine("alongside the coverage above. Many checks not performed means a high")
            appendLine("score describes how little was read, not how safe the machine is.")
            appendLine()

            if (result.actionableFindings.isEmpty()) {
                appendLine("FINDINGS: none among the checks that ran.")
            } else {
                appendLine("FINDINGS (${result.actionableFindings.size}):")
                result.actionableFindings
                    .sortedBy { it.finding.severity.ordinal }
                    .forEach { s ->
                        val f = s.finding
                        appendLine()
                        appendLine("[${f.severity}] ${f.ruleId}  ${f.title}   (-${s.deduction})")
                        appendLine("  what:  ${f.detail}")
                        appendLine("  fix:   ${f.remediation}")
                    }
            }

            appendLine()
            appendLine("NOT CHECKED — the machine would not answer these. They are NOT passes:")
            r.skippedUnobservable.forEach { appendLine("  ${it.ruleId}  ${it.description}") }
            if (snapshot != null) appendLine()
        }
    }

    private fun factsText(): String {
        val collector = DesktopCollector.forCurrentOs()
            ?: throw IllegalStateException("this operating system is not one Blanktick can inspect")
        val intel = DesktopIntel.load().snapshot(LocalDate.now().toString())
        val d = collector.collect(intel).desktop
            ?: throw IllegalStateException("no desktop facts were produced")

        return buildString {
            appendLine("BLANKTICK FACTS — null means the machine would not answer, not 'no'.")
            appendLine("=".repeat(60))
            appendLine(d.toString().replace(", ", ",\n  "))
        }
    }

    private fun scriptText(): String = buildString {
        appendLine("The exact commands Blanktick runs on this machine. Every one is a query;")
        appendLine("nothing here changes a setting or writes a file.")
        appendLine("=".repeat(60))
        appendLine(
            when (DesktopCollector.detectOs()) {
                com.blanktick.core.model.DesktopOs.WINDOWS -> WindowsProbe.SCRIPT
                else -> "The macOS and Linux collectors call individual command-line tools " +
                    "rather than one script; read MacCollector.kt / LinuxCollector.kt."
            }
        )
    }

    private fun coverageText(): String {
        val r = report(refresh = false)
        return buildString {
            appendLine("BLANKTICK COVERAGE on this platform")
            appendLine("=".repeat(60))
            appendLine("Checks that ran:            ${r.result.checksRun}")
            appendLine("Not written for this device: ${r.skippedWrongPlatform.size}")
            r.skippedWrongPlatform.forEach { appendLine("   ${it.ruleId}  ${it.description}") }
            appendLine("This machine would not say:  ${r.skippedUnobservable.size}")
            r.skippedUnobservable.forEach { appendLine("   ${it.ruleId}  ${it.description}") }
        }
    }

    // ----------------------------------------------------------- JSON-RPC

    private fun success(id: JsonValue, result: JsonValue): JsonValue = Json.obj(
        "jsonrpc" to Json.str("2.0"),
        "id" to id,
        "result" to result
    )

    private fun error(id: JsonValue, code: Int, message: String): JsonValue = Json.obj(
        "jsonrpc" to Json.str("2.0"),
        "id" to id,
        "error" to Json.obj("code" to Json.num(code), "message" to Json.str(message))
    )
}
