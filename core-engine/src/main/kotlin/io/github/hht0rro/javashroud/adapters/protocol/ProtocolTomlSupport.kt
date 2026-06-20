package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.protocol.EngineEvent

internal fun buildEventTomlLine(event: EngineEvent): String = buildString {
    append("event = {")
    append(" level = ")
    append(formatTomlString(event.level))
    append(", type = ")
    append(formatTomlString(event.type))
    append(", message = ")
    append(formatTomlString(event.message))
    event.progress?.let { progress ->
        append(", progress = ")
        append(progress)
    }
    event.outPath?.let { outPath ->
        append(", outPath = ")
        append(formatTomlString(outPath))
    }
    append(" }")
}

internal fun formatTomlString(value: String): String = buildString {
    append('"')
    for (char in value) {
        when (char) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\b' -> append("\\b")
            '\t' -> append("\\t")
            '\n' -> append("\\n")
            '\u000C' -> append("\\f")
            '\r' -> append("\\r")
            else -> append(char)
        }
    }
    append('"')
}
