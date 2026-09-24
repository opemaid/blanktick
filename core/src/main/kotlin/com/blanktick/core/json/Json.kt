package com.blanktick.core.json

/**
 * A small, complete JSON reader and writer.
 *
 * ## Why this is here rather than a dependency
 *
 * `:core` has **no production dependencies at all**, and the desktop build pins
 * every jar on its runtime classpath so a new one has to be reviewed by a person
 * before it can land. Pulling in a JSON library to speak one protocol would
 * expand the audited surface of a security product for the sake of about two
 * hundred lines — and this codebase already hand-writes a Bloom filter, a
 * punycode encoder, an EXIF reader and a sorted hash table for the same reason.
 *
 * ## Scope
 *
 * Enough for JSON-RPC: objects, arrays, strings with escapes, numbers,
 * booleans, null. No streaming, no comments, no trailing commas, no big-decimal
 * precision. Depth is bounded, because a parser reachable from another process
 * should not be able to exhaust the stack on a nested array.
 */
sealed interface JsonValue {
    data object Null : JsonValue
    data class Bool(val value: Boolean) : JsonValue
    data class Num(val value: Double) : JsonValue
    data class Str(val value: String) : JsonValue
    data class Arr(val items: List<JsonValue>) : JsonValue
    data class Obj(val fields: Map<String, JsonValue>) : JsonValue

    // ---- Convenience accessors. All return null rather than throwing, because
    // every caller here is handling input from another process and a missing
    // field is an ordinary case, not an exception.
    operator fun get(key: String): JsonValue? = (this as? Obj)?.fields?.get(key)
    val asString: String? get() = (this as? Str)?.value
    val asInt: Int? get() = (this as? Num)?.value?.toInt()
    val asBool: Boolean? get() = (this as? Bool)?.value
    val asArray: List<JsonValue>? get() = (this as? Arr)?.items
}

object Json {

    /** Nesting ceiling. A hostile input should not be able to exhaust the stack. */
    private const val MAX_DEPTH = 64

    class ParseException(message: String) : Exception(message)

    // ------------------------------------------------------------------ read

    /** @throws ParseException on malformed input. Never throws anything else. */
    fun parse(text: String): JsonValue {
        val p = Parser(text)
        val v = p.value(0)
        p.skipWhitespace()
        if (!p.atEnd) throw ParseException("trailing content at ${p.pos}")
        return v
    }

    /** @return the parsed value, or `null` if the text is not valid JSON. */
    fun parseOrNull(text: String): JsonValue? =
        runCatching { parse(text) }.getOrNull()

    private class Parser(private val s: String) {
        var pos = 0
        val atEnd: Boolean get() = pos >= s.length

        fun skipWhitespace() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        fun value(depth: Int): JsonValue {
            if (depth > MAX_DEPTH) throw ParseException("nested deeper than $MAX_DEPTH")
            skipWhitespace()
            if (atEnd) throw ParseException("unexpected end of input")
            return when (s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> JsonValue.Str(string())
                't' -> literal("true").let { JsonValue.Bool(true) }
                'f' -> literal("false").let { JsonValue.Bool(false) }
                'n' -> literal("null").let { JsonValue.Null }
                else -> number()
            }
        }

        private fun literal(word: String) {
            if (!s.startsWith(word, pos)) throw ParseException("bad literal at $pos")
            pos += word.length
        }

        private fun obj(depth: Int): JsonValue.Obj {
            pos++   // {
            val fields = LinkedHashMap<String, JsonValue>()
            skipWhitespace()
            if (!atEnd && s[pos] == '}') { pos++; return JsonValue.Obj(fields) }
            while (true) {
                skipWhitespace()
                if (atEnd || s[pos] != '"') throw ParseException("expected key at $pos")
                val key = string()
                skipWhitespace()
                if (atEnd || s[pos] != ':') throw ParseException("expected ':' at $pos")
                pos++
                fields[key] = value(depth + 1)
                skipWhitespace()
                if (atEnd) throw ParseException("unterminated object")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return JsonValue.Obj(fields) }
                    else -> throw ParseException("expected ',' or '}' at $pos")
                }
            }
        }

        private fun arr(depth: Int): JsonValue.Arr {
            pos++   // [
            val items = mutableListOf<JsonValue>()
            skipWhitespace()
            if (!atEnd && s[pos] == ']') { pos++; return JsonValue.Arr(items) }
            while (true) {
                items += value(depth + 1)
                skipWhitespace()
                if (atEnd) throw ParseException("unterminated array")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return JsonValue.Arr(items) }
                    else -> throw ParseException("expected ',' or ']' at $pos")
                }
            }
        }

        private fun string(): String {
            pos++   // opening quote
            val sb = StringBuilder()
            while (true) {
                if (atEnd) throw ParseException("unterminated string")
                when (val c = s[pos]) {
                    '"' -> { pos++; return sb.toString() }
                    '\\' -> {
                        pos++
                        if (atEnd) throw ParseException("dangling escape")
                        when (val e = s[pos]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 >= s.length) throw ParseException("short \\u escape")
                                val hex = s.substring(pos + 1, pos + 5)
                                val code = hex.toIntOrNull(16)
                                    ?: throw ParseException("bad \\u escape: $hex")
                                sb.append(code.toChar())
                                pos += 4
                            }
                            else -> throw ParseException("unknown escape \\$e")
                        }
                        pos++
                    }
                    else -> { sb.append(c); pos++ }
                }
            }
        }

        private fun number(): JsonValue.Num {
            val start = pos
            if (!atEnd && (s[pos] == '-' || s[pos] == '+')) pos++
            while (!atEnd && (s[pos].isDigit() || s[pos] in ".eE+-")) pos++
            val text = s.substring(start, pos)
            val d = text.toDoubleOrNull() ?: throw ParseException("bad number '$text' at $start")
            return JsonValue.Num(d)
        }
    }

    // ----------------------------------------------------------------- write

    fun write(value: JsonValue): String = StringBuilder().also { render(value, it) }.toString()

    private fun render(v: JsonValue, sb: StringBuilder) {
        when (v) {
            is JsonValue.Null -> sb.append("null")
            is JsonValue.Bool -> sb.append(if (v.value) "true" else "false")
            is JsonValue.Num -> {
                // Whole numbers render without a decimal point: an id of 1 must
                // not come back as 1.0, which some JSON-RPC clients reject.
                if (v.value == v.value.toLong().toDouble() && !v.value.isInfinite()) {
                    sb.append(v.value.toLong())
                } else {
                    sb.append(v.value)
                }
            }
            is JsonValue.Str -> escape(v.value, sb)
            is JsonValue.Arr -> {
                sb.append('[')
                v.items.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    render(item, sb)
                }
                sb.append(']')
            }
            is JsonValue.Obj -> {
                sb.append('{')
                var first = true
                v.fields.forEach { (k, value) ->
                    if (!first) sb.append(',')
                    first = false
                    escape(k, sb)
                    sb.append(':')
                    render(value, sb)
                }
                sb.append('}')
            }
        }
    }

    /**
     * Escapes a string for JSON.
     *
     * Every control character below 0x20 is escaped, not just the named ones —
     * a raw newline inside a string is invalid JSON, and the strings written
     * here include file paths and program names that came from the machine
     * being scanned. This is the same reasoning as the probe's field
     * sanitiser: text someone else chose must not be able to alter the
     * structure of the message carrying it.
     */
    private fun escape(s: String, sb: StringBuilder) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c.code < 0x20 || c.code == 0x7F -> sb.append("\\u%04x".format(c.code))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }

    // ------------------------------------------------------------- builders

    fun obj(vararg pairs: Pair<String, JsonValue>): JsonValue.Obj =
        JsonValue.Obj(linkedMapOf(*pairs))

    fun arr(items: List<JsonValue>): JsonValue.Arr = JsonValue.Arr(items)
    fun str(value: String): JsonValue.Str = JsonValue.Str(value)
    fun num(value: Int): JsonValue.Num = JsonValue.Num(value.toDouble())
    fun bool(value: Boolean): JsonValue.Bool = JsonValue.Bool(value)
}
