package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.schema.EngineSchemaPayload

internal fun buildEngineSchemaProtocolPayload(payload: EngineSchemaPayload): Map<String, Any> = buildMap {
    put("schemaVersion", payload.schemaVersion)
    put("engineVersion", payload.engineVersion)
    put("vbcVersion", payload.vbcVersion)
    put("tags", buildSchemaTagPayloads(payload))
    put("modules", buildSchemaModulePayloads(payload))
    put("compatibility", buildSchemaCompatibilityPayloads(payload))
    if (payload.defaultPipeline.isNotEmpty()) {
        put("defaultPipeline", payload.defaultPipeline)
    }
    if (payload.orderingConstraints.isNotEmpty()) {
        put("orderingConstraints", buildSchemaOrderingConstraintPayloads(payload))
    }
}
