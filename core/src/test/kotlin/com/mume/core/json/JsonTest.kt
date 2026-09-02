package com.mume.core.json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The hand-written JSON codec.
 *
 * It exists so `:core` can keep its zero production dependencies, which means
 * it has to be right rather than approximately right — a library would have
 * been tested by thousands of people and this has been tested by these.
 *
 * Everything it parses arrives from another process.
 */
class JsonTest {

    private fun roundTrip(text: String): String = Json.write(Json.parse(text))

    @Test
    fun `round-trips the shapes JSON-RPC uses`() {
        listOf(
            """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""",
            """{"a":[1,2,3],"b":{"c":true,"d":null},"e":"x"}""",
            """[]""",
            """{}""",
            """{"nested":{"deep":{"deeper":[{"x":1}]}}}"""
        ).forEach { assertEquals(it, roundTrip(it), "did not round-trip: $it") }
    }

    /**
     * An id of 1 must not come back as 1.0 — some JSON-RPC clients match the
     * response id strictly and would never see the reply.
     */
    @Test
    fun `whole numbers keep their integer form`() {
        assertEquals("""{"id":1}""", roundTrip("""{"id":1}"""))
        assertEquals("""{"id":-42}""", roundTrip("""{"id":-42}"""))
        assertEquals("""{"x":1.5}""", roundTrip("""{"x":1.5}"""))
    }

    @Test
    fun `parses every string escape`() {
        val v = Json.parse(""" {"s":"a\"b\\c\/d\be\ff\ng\rh\ti\u0041j"} """)
        assertEquals("a\"b\\c/d\be\u000Cf\ng\rh\ti" + "A" + "j", v["s"]?.asString)
    }

    /**
     * Strings written here carry file paths and program names read off the
     * machine being scanned. Text somebody else chose must not be able to alter
     * the structure of the message carrying it — the same reasoning as the
     * probe's field sanitiser, where an unescaped tab forged a publisher.
     */
    @Test
    fun `control characters cannot escape the string that contains them`() {
        val hostile = "name\nwith\r\nbreaks\tand\u0000a null"
        val written = Json.write(Json.obj("k" to Json.str(hostile)))

        assertTrue('\n' !in written, "a raw newline in output is invalid JSON")
        assertTrue('\t' !in written, "a raw tab in output is invalid JSON")
        assertTrue('\u0000' !in written, "a raw NUL reached the output")
        assertEquals(hostile, Json.parse(written)["k"]?.asString, "escaping lost the value")
    }

    @Test
    fun `quotes and backslashes survive a round trip`() {
        val nasty = """C:\Users\x\"quoted"\path\"""
        assertEquals(nasty, Json.parse(Json.write(Json.obj("p" to Json.str(nasty))))["p"]?.asString)
    }

    // -------------------------------------------------------------- refusal

    @Test
    fun `malformed input is rejected, not guessed at`() {
        listOf(
            "{", "}", "[1,2", """{"a"}""", """{"a":}""", """{a:1}""",
            """{"a":1,}""", "tru", """"unterminated""", "", "  "
        ).forEach {
            assertFailsWith<Json.ParseException>("should have rejected: '$it'") { Json.parse(it) }
        }
    }

    @Test
    fun `trailing content is rejected`() {
        assertFailsWith<Json.ParseException> { Json.parse("""{"a":1} extra""") }
    }

    /**
     * A parser reachable from another process must not be able to exhaust the
     * stack. Without the depth ceiling this is a StackOverflowError, which is
     * an Error rather than an Exception and takes the whole process with it.
     */
    @Test
    fun `deep nesting is refused rather than overflowing the stack`() {
        val deep = "[".repeat(5000) + "]".repeat(5000)
        assertFailsWith<Json.ParseException> { Json.parse(deep) }
    }

    @Test
    fun `parseOrNull returns null instead of throwing`() {
        assertNull(Json.parseOrNull("{nope"))
        assertEquals(1, Json.parseOrNull("""{"a":1}""")?.get("a")?.asInt)
    }

    // ------------------------------------------------------------ accessors

    @Test
    fun `accessors return null on the wrong type rather than throwing`() {
        val v = Json.parse("""{"s":"x","n":5,"b":true,"a":[1],"o":{}}""")
        assertEquals("x", v["s"]?.asString)
        assertEquals(5, v["n"]?.asInt)
        assertEquals(true, v["b"]?.asBool)
        assertEquals(1, v["a"]?.asArray?.size)
        assertNull(v["s"]?.asInt, "a string asked for as a number must be null")
        assertNull(v["missing"], "an absent key is null, not an exception")
        assertNull(v["n"]?.asString)
    }
}
