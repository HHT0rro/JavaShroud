package io.github.hht0rro.javashroud.model.protocol

data class ClassTreeNode(
    val id: String,
    val label: String,
    val qualifiedName: String,
    val internalName: String,
    val kind: String,
    val children: List<ClassTreeNode>,
)

data class JarInspectionPayload(
    val jarPath: String,
    val classCount: Int,
    val packageCount: Int,
    val nodes: List<ClassTreeNode>,
)
