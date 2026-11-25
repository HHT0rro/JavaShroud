package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema
import io.github.hht0rro.javashroud.model.schema.toJsonMap

internal fun buildSchemaParamPayloads(module: ModuleDefinition): List<Map<String, Any?>> =
    module.params.map(ParamSchema::toJsonMap)
