package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.protocol.JarInspectionPayload

internal fun buildJarInspectionProtocolPayload(payload: JarInspectionPayload): Map<String, Any> = mapOf(
    "jarPath" to payload.jarPath,
    "classCount" to payload.classCount,
    "packageCount" to payload.packageCount,
    "nodes" to buildInspectionNodePayloads(payload),
)

internal fun buildInspectionNodePayloads(payload: JarInspectionPayload): List<Map<String, Any>> =
    payload.nodes.map(::buildClassTreeNodePayload)
