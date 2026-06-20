package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.schema.EngineSchemaPayload
import io.github.hht0rro.javashroud.model.schema.toJsonMap

internal fun buildSchemaTagPayloads(payload: EngineSchemaPayload): List<Map<String, Any>> =
    payload.tags.map { it.toJsonMap() }

internal fun buildSchemaModulePayloads(payload: EngineSchemaPayload): List<Map<String, Any>> =
    payload.modules.map { it.toJsonMap() }

internal fun buildSchemaCompatibilityPayloads(payload: EngineSchemaPayload): List<Map<String, Any>> =
    payload.compatibility.map { it.toJsonMap() }

internal fun buildSchemaOrderingConstraintPayloads(payload: EngineSchemaPayload): List<Map<String, Any>> =
    payload.orderingConstraints.map { it.toJsonMap() }
