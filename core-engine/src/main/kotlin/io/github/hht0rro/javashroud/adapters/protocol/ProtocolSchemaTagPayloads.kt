package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.schema.ModuleTagDefinition
import io.github.hht0rro.javashroud.model.schema.toJsonMap

internal fun buildSchemaTagPayload(tag: ModuleTagDefinition): Map<String, Any> =
    tag.toJsonMap()
