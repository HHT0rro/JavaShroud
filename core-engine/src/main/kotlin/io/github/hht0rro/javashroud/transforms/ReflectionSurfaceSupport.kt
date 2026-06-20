package io.github.hht0rro.javashroud.transforms

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode

private val reflectionSurfaceMethodNames = setOf(
    "getDeclaredMethods",
    "getMethods",
    "getDeclaredMethod",
    "getMethod",
    "getDeclaredFields",
    "getFields",
    "getDeclaredField",
    "getField",
    "getDeclaredConstructors",
    "getConstructors",
    "getDeclaredConstructor",
    "getConstructor",
)

internal fun reflectionSurfaceSensitiveClassNames(artifact: BytecodeArtifact): Set<String> {
    val knownClassNames = artifact.classArtifactIndex.keys
    if (knownClassNames.isEmpty()) return emptySet()

    val sensitiveClassNames = linkedSetOf<String>()
    for (classArtifact in artifact.classArtifacts) {
        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        } catch (_: RuntimeException) {
            continue
        }

        for (method in classNode.methods) {
            val instructions = method.instructions ?: continue
            val classLiterals = linkedSetOf<String>()
            var usesReflectionSurfaceApi = false

            for (instruction in instructions.toArray()) {
                if (instruction is LdcInsnNode) {
                    classLiteralInternalName(instruction.cst)?.let { classLiterals += it }
                }
                if (instruction is MethodInsnNode && isReflectionSurfaceCall(instruction)) {
                    usesReflectionSurfaceApi = true
                }
            }

            if (usesReflectionSurfaceApi) {
                sensitiveClassNames += classLiterals.filter { it in knownClassNames }
            }
        }
    }
    return sensitiveClassNames
}

internal fun excludeReflectionSurfaceSensitiveClasses(
    artifact: BytecodeArtifact,
    matchedClassNames: Set<String>,
): Set<String> {
    if (matchedClassNames.isEmpty()) return matchedClassNames
    val sensitiveClassNames = reflectionSurfaceSensitiveClassNames(artifact)
    if (sensitiveClassNames.isEmpty()) return matchedClassNames
    return matchedClassNames - sensitiveClassNames
}

private fun classLiteralInternalName(value: Any?): String? {
    val type = value as? Type ?: return null
    return when (type.sort) {
        Type.OBJECT -> type.internalName
        Type.ARRAY -> type.elementType.takeIf { it.sort == Type.OBJECT }?.internalName
        else -> null
    }
}

private fun isReflectionSurfaceCall(instruction: MethodInsnNode): Boolean =
    instruction.owner == "java/lang/Class" && instruction.name in reflectionSurfaceMethodNames
