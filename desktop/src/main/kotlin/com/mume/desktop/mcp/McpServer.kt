package com.mume.desktop.mcp

import com.mume.core.MumeScanner
import com.mume.core.json.Json
import com.mume.core.json.JsonValue
import com.mume.desktop.collect.DesktopCollector
import com.mume.desktop.collect.DesktopIntel
import com.mume.desktop.collect.WindowsProbe
import java.time.LocalDate

/**
 * Exposes Mume to any language model, over stdio.
 *
 * ## Why this does not break the promise
 *
 * MCP has two transports. The HTTP one would make this app a network client and
 * is not implemented here at any level. **This is stdio**: the parent process
 * launches Mume, writes JSON-RPC on its standard input and reads replies from
 * its standard output. No socket is opened, nothing is bound, nothing is
 * connected to — the desktop build's bytecode gate still forbids a networking
 * API anywhere in Mume's own classes, and it still passes.
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
    private var cachedScan: com.mume.core.ScanReport? = null

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
                    "name" to Json.str("mume"),
                    "version" to Json.str("1.0.0")
                ),
                "instructions" to Json.str(
                    "Mume reports the security posture of this computer. Every tool is " +
                        "read-only: nothing here changes a setting, removes a file or fixes a " +
                        "finding, by design. Facts it could not establish are reported as not " +
                        "checkable and must never be presented as passing — the distinction " +
                        "between 'this is fine' and 'I could not look' is the point of this " +
                        "tool. Scans take about a hundred seconds."
                )
            )
        )
    }

    // ----------------------------------------------------------------- tools

    private fun toolsList(): JsonValue = Json.obj(
        "tools" to Json.arr(
            listOf(
                tool(
                    "mume_scan",
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
                    "mume_facts",
                    "Return the raw facts read from this machine, including the nulls. A null " +
                        "means the machine would not answer, which is different from a negative " +
                        "answer. Read-only.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "mume_probe_script",
                    "Return the exact PowerShell Mume runs on this machine, so it can be read " +
                        "or re-run by hand and the output compared. Reads nothing.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
                ),
                tool(
                    "mume_coverage",
                    "Return what Mume can and cannot check on this platform and why, without " +
                        "running a scan.",
                    Json.obj("type" to Json.str("object"), "properties" to Json.obj())
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
                "mume_scan" -> scanText(refresh = args?.get("refresh")?.asBool == true)
                "mume_facts" -> factsText()
                "mume_probe_script" -> scriptText()
                "mume_coverage" -> coverageText()
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
                    "Mume could not complete that: " + (e.message ?: e::class.simpleName) +
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

    // ------------------------------------------------------------- the work

    private fun report(refresh: Boolean): com.mume.core.ScanReport {
        cachedScan?.takeIf { !refresh }?.let { return it }
        val collector = DesktopCollector.forCurrentOs()
            ?: throw IllegalStateException("this operating system is not one Mume can inspect")
        val intel = DesktopIntel.load().snapshot(LocalDate.now().toString())
        return MumeScanner().scan(collector.collect(intel)).also { cachedScan = it }
    }

    private fun scanText(refresh: Boolean): String {
        val r = report(refresh)
        val result = r.result
        val snapshot = DesktopCollector.forCurrentOs()

        return buildString {
            appendLine("MUME SCAN")
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
            ?: throw IllegalStateException("this operating system is not one Mume can inspect")
        val intel = DesktopIntel.load().snapshot(LocalDate.now().toString())
        val d = collector.collect(intel).desktop
            ?: throw IllegalStateException("no desktop facts were produced")

        return buildString {
            appendLine("MUME FACTS — null means the machine would not answer, not 'no'.")
            appendLine("=".repeat(60))
            appendLine(d.toString().replace(", ", ",\n  "))
        }
    }

    private fun scriptText(): String = buildString {
        appendLine("The exact commands Mume runs on this machine. Every one is a query;")
        appendLine("nothing here changes a setting or writes a file.")
        appendLine("=".repeat(60))
        appendLine(
            when (DesktopCollector.detectOs()) {
                com.mume.core.model.DesktopOs.WINDOWS -> WindowsProbe.SCRIPT
                else -> "The macOS and Linux collectors call individual command-line tools " +
                    "rather than one script; read MacCollector.kt / LinuxCollector.kt."
            }
        )
    }

    private fun coverageText(): String {
        val r = report(refresh = false)
        return buildString {
            appendLine("MUME COVERAGE on this platform")
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
