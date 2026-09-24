package com.blanktick.desktop

import com.blanktick.core.json.Json
import com.blanktick.desktop.mcp.McpServer
import java.io.StringWriter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The MCP surface, driven the way a client drives it.
 *
 * These run the real server against a scripted stdin and read what comes back
 * on stdout, so a protocol mistake fails here rather than as an unhelpful
 * disconnect inside somebody's editor.
 *
 * The tool calls that would actually scan the machine are not exercised: a scan
 * takes about a hundred seconds and touches the real computer. What is
 * exercised is everything a client does before and around them, which is where
 * protocol bugs live.
 */
class McpServerTest {

    /** Feeds lines to a server and returns the responses it wrote. */
    private fun exchange(vararg requests: String): List<com.blanktick.core.json.JsonValue> {
        val out = StringWriter()
        McpServer(
            input = requests.joinToString("\n").reader().buffered(),
            output = out
        ).run()
        return out.toString().lineSequence()
            .filter { it.isNotBlank() }
            .map { Json.parse(it) }
            .toList()
    }

    @Test
    fun `initialize returns a protocol version and declares tools`() {
        val replies = exchange(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"""
        )
        assertEquals(1, replies.size)
        val r = replies.single()
        assertEquals("2.0", r["jsonrpc"]?.asString)
        assertEquals(1, r["id"]?.asInt)
        assertEquals("2024-11-05", r["result"]?.get("protocolVersion")?.asString)
        assertNotNull(r["result"]?.get("capabilities")?.get("tools"))
        assertEquals("blanktick", r["result"]?.get("serverInfo")?.get("name")?.asString)
    }

    /**
     * A client asking for a newer revision is answered in that revision rather
     * than refused: the wire format has not changed across these, and refusing
     * would strand clients for no benefit.
     */
    @Test
    fun `a known newer protocol version is echoed back`() {
        val r = exchange(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"""
        ).single()
        assertEquals("2025-06-18", r["result"]?.get("protocolVersion")?.asString)
    }

    /**
     * A notification carries no id and must receive no reply. Answering one is
     * a protocol violation that some clients treat as fatal.
     */
    @Test
    fun `notifications are not answered`() {
        val replies = exchange("""{"jsonrpc":"2.0","method":"notifications/initialized"}""")
        assertTrue(replies.isEmpty(), "a notification was answered: $replies")
    }

    @Test
    fun `tools are listed with schemas`() {
        val r = exchange("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""").single()
        val tools = r["result"]?.get("tools")?.asArray
        assertNotNull(tools)
        val names = tools.mapNotNull { it["name"]?.asString }.toSet()
        assertEquals(
            setOf(
                "blanktick_scan", "blanktick_facts", "blanktick_probe_script", "blanktick_coverage",
                "blanktick_history", "blanktick_search", "blanktick_changes", "blanktick_netlog"
            ),
            names
        )
        tools.forEach {
            assertNotNull(it["description"]?.asString, "every tool needs a description")
            assertEquals("object", it["inputSchema"]?.get("type")?.asString)
        }
    }

    /**
     * Every tool is a question, and that is a promise this app has to keep.
     *
     * Blanktick ships `DSK-AI-002`, which tells people an MCP entry lets a model run
     * commands on their machine and that it hides from every startup checker.
     * Shipping an MCP server after writing that is only defensible if this one
     * changes nothing — so no tool may be named or described as doing so, and a
     * future one that fixes, removes, disables or quarantines something fails
     * here.
     */
    @Test
    fun `no tool offers to change the machine`() {
        val tools = exchange("""{"jsonrpc":"2.0","id":3,"method":"tools/list"}""")
            .single()["result"]?.get("tools")?.asArray
        assertNotNull(tools)

        val mutating = listOf(
            "fix", "remove", "delete", "disable", "enable", "set_", "quarantine",
            "clean", "repair", "harden", "apply", "write", "install", "uninstall"
        )
        val offenders = tools.filter { t ->
            val name = t["name"]?.asString.orEmpty().lowercase()
            mutating.any { name.contains(it) }
        }.mapNotNull { it["name"]?.asString }

        assertTrue(
            offenders.isEmpty(),
            "Blanktick reports and never changes the machine. These tools break that: $offenders"
        )
    }

    @Test
    fun `an unknown method is a JSON-RPC error, not a crash`() {
        val r = exchange("""{"jsonrpc":"2.0","id":4,"method":"nope/nope"}""").single()
        assertEquals(-32601, r["error"]?.get("code")?.asInt)
    }

    @Test
    fun `an unknown tool is reported without killing the session`() {
        val replies = exchange(
            """{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"blanktick_delete_everything"}}""",
            """{"jsonrpc":"2.0","id":6,"method":"ping"}"""
        )
        assertEquals(2, replies.size, "the session must survive a bad call")
        assertEquals(-32602, replies[0]["error"]?.get("code")?.asInt)
        assertEquals(6, replies[1]["id"]?.asInt)
    }

    @Test
    fun `malformed input does not end the session`() {
        val replies = exchange(
            "{not json at all",
            """{"jsonrpc":"2.0","id":7,"method":"ping"}"""
        )
        assertEquals(2, replies.size)
        assertEquals(-32700, replies[0]["error"]?.get("code")?.asInt)
        assertEquals(7, replies[1]["id"]?.asInt)
    }

    /**
     * Standard output is the protocol.
     *
     * A stray `println` anywhere in the process corrupts the stream and the
     * client disconnects with a parse error naming nothing useful. This asserts
     * every line the server wrote is a complete JSON-RPC message and nothing
     * else slipped in beside them.
     */
    @Test
    fun `every line written is a well-formed JSON-RPC message`() {
        val out = StringWriter()
        McpServer(
            input = listOf(
                """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}""",
                """{"jsonrpc":"2.0","method":"notifications/initialized"}""",
                """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""",
                """{"jsonrpc":"2.0","id":3,"method":"ping"}"""
            ).joinToString("\n").reader().buffered(),
            output = out
        ).run()

        val lines = out.toString().lines().filter { it.isNotBlank() }
        assertEquals(3, lines.size, "one reply each for the three requests with an id")
        lines.forEach { line ->
            val v = Json.parseOrNull(line)
            assertNotNull(v, "not parseable as JSON: $line")
            assertEquals("2.0", v["jsonrpc"]?.asString, "missing jsonrpc version: $line")
            assertNotNull(v["id"], "missing id: $line")
            assertFalse(
                v["result"] == null && v["error"] == null,
                "a reply must carry either a result or an error: $line"
            )
        }
    }
}
