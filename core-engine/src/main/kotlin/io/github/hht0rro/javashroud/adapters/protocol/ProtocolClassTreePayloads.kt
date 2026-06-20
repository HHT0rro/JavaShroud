package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.model.protocol.ClassTreeNode

internal fun buildClassTreeNodePayload(node: ClassTreeNode): Map<String, Any> {
    return mapOf(
        "id" to node.id,
        "label" to node.label,
        "qualifiedName" to node.qualifiedName,
        "internalName" to node.internalName,
        "kind" to node.kind,
        "children" to node.children.map(::buildClassTreeNodePayload),
    )
}
