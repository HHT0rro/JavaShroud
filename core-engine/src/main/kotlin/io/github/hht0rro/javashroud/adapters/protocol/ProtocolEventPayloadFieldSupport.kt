package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.protocol.EngineEvent

internal fun buildEventPayloadFields(event: EngineEvent): Map<String, Any?> = mapOf(
    "level" to event.level,
    "type" to event.type,
    "message" to event.message,
    "progress" to event.progress,
    "outPath" to event.outPath,
)

internal fun buildEventPayload(event: EngineEvent): Map<String, Any?> = buildEventPayloadFields(event)
