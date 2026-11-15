package com.huelake.connectivitizer.internal

/**
 * The JSON the protocol needs, without a library: objects become [Map], arrays [List], numbers [Long] or
 * [Double], and the rest [String], [Boolean] or null. Unknown members are kept and ignored by the callers.
 */
internal object Json {
    fun parse(text: String): Any? {
        val parser = Parser(text)
        val value = parser.value()
        parser.skipWhitespace()
        if (parser.position != text.length) throw IllegalArgumentException("Trailing characters in JSON.")
        return value
    }

    fun write(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    private fun write(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is String -> string(out, value)
            is Boolean -> out.append(value)
            is Int, is Long, is Short, is Byte -> out.append(value.toString())
            is Number -> {
                val d = value.toDouble()
                if (d == Math.floor(d) && !d.isInfinite() && Math.abs(d) < 1e15) out.append(d.toLong()) else out.append(d)
            }
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((k, v) in value) {
                    if (v == null) continue // absent and null are equivalent in the protocol
                    if (!first) out.append(',')
                    first = false
                    string(out, k.toString())
                    out.append(':')
                    write(out, v)
                }
                out.append('}')
            }
            is Iterable<*> -> {
                out.append('[')
                var first = true
                for (v in value) {
                    if (!first) out.append(',')
                    first = false
                    write(out, v)
                }
                out.append(']')
            }
            is Array<*> -> write(out, value.toList())
            else -> string(out, value.toString())
        }
    }

    private fun string(out: StringBuilder, text: String) {
        out.append('"')
        for (c in text) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> out.append(String.format("\\u%04x", c.code))
                else -> out.append(c)
            }
        }
        out.append('"')
    }

    private class Parser(val text: String) {
        var position = 0

        fun skipWhitespace() {
            while (position < text.length && text[position].isWhitespace()) position++
        }

        fun value(): Any? {
            skipWhitespace()
            if (position >= text.length) throw IllegalArgumentException("Unexpected end of JSON.")
            return when (val c = text[position]) {
                '{' -> obj()
                '[' -> array()
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) number() else throw IllegalArgumentException("Unexpected '$c' in JSON.")
            }
        }

        private fun literal(word: String, value: Any?): Any? {
            if (!text.startsWith(word, position)) throw IllegalArgumentException("Invalid JSON literal.")
            position += word.length
            return value
        }

        private fun number(): Any {
            val start = position
            if (text[position] == '-') position++
            while (position < text.length && (text[position].isDigit() || text[position] in ".eE+-")) position++
            val token = text.substring(start, position)
            return token.toLongOrNull() ?: token.toDouble()
        }

        private fun string(): String {
            position++ // opening quote
            val out = StringBuilder()
            while (true) {
                if (position >= text.length) throw IllegalArgumentException("Unterminated JSON string.")
                val c = text[position++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        val escaped = text[position++]
                        when (escaped) {
                            '"', '\\', '/' -> out.append(escaped)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                out.append(text.substring(position, position + 4).toInt(16).toChar())
                                position += 4
                            }
                            else -> throw IllegalArgumentException("Invalid JSON escape.")
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        private fun array(): List<Any?> {
            position++
            val list = ArrayList<Any?>()
            skipWhitespace()
            if (text.getOrNull(position) == ']') {
                position++
                return list
            }
            while (true) {
                list.add(value())
                skipWhitespace()
                when (text.getOrNull(position++)) {
                    ',' -> continue
                    ']' -> return list
                    else -> throw IllegalArgumentException("Invalid JSON array.")
                }
            }
        }

        private fun obj(): Map<String, Any?> {
            position++
            val map = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (text.getOrNull(position) == '}') {
                position++
                return map
            }
            while (true) {
                skipWhitespace()
                if (text.getOrNull(position) != '"') throw IllegalArgumentException("Invalid JSON object key.")
                val key = string()
                skipWhitespace()
                if (text.getOrNull(position++) != ':') throw IllegalArgumentException("Invalid JSON object.")
                map[key] = value()
                skipWhitespace()
                when (text.getOrNull(position++)) {
                    ',' -> continue
                    '}' -> return map
                    else -> throw IllegalArgumentException("Invalid JSON object.")
                }
            }
        }
    }
}

@Suppress("UNCHECKED_CAST")
internal fun Any?.asMap(): Map<String, Any?>? = this as? Map<String, Any?>

internal fun Any?.asList(): List<Any?>? = this as? List<Any?>

internal fun Map<String, Any?>.string(name: String): String? = this[name] as? String

internal fun Map<String, Any?>.long(name: String): Long? = (this[name] as? Number)?.toLong()

internal fun Map<String, Any?>.map(name: String): Map<String, Any?>? = this[name].asMap()

internal fun Map<String, Any?>.strings(name: String): List<String>? = this[name].asList()?.filterIsInstance<String>()
