package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.toJsonMap

internal fun buildSchemaModulePayload(module: ModuleDefinition): Map<String, Any> =
    module.toJsonMap()
