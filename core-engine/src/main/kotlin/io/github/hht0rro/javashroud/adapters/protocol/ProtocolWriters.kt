package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.model.protocol.JarInspectionPayload
import io.github.hht0rro.javashroud.model.schema.EngineSchemaPayload

fun writeEvent(event: EngineEvent): Unit {
    writeProtocolTextLine(buildEventTomlLine(event))
}

fun writeEngineSchemaPayload(payload: EngineSchemaPayload): Unit {
    writeProtocolLine(buildEngineSchemaProtocolPayload(payload))
}

fun writeJarInspectionPayload(payload: JarInspectionPayload): Unit {
    writeProtocolLine(buildJarInspectionProtocolPayload(payload))
}
