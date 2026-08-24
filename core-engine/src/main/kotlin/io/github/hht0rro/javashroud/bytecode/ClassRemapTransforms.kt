package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.commons.ClassRemapper

fun remapClasses(classBytes: ByteArray, classRenameMap: Map<String, String>): ByteArray = try {
    remapClassesStrict(classBytes, classRenameMap)
} catch (_: Exception) {
    // Ordinary optional rename passes preserve their existing resilience model.
    // Current-format fixed-name cleanup uses [remapClassesStrict] directly.
    classBytes
}

/**
 * Fail-closed class remapping for release-required relocations. A caller that
 * removes fixed generated names must never retain source bytes after a remap
 * error, because retaining them would emit a forbidden class name.
 */
internal fun remapClassesStrict(classBytes: ByteArray, classRenameMap: Map<String, String>): ByteArray {
    val resourcePathRemapper = buildResourcePathRemapper(classRenameMap)
    val classReader = ClassReader(classBytes)
    val classWriter = frameComputingWriter()
    val classVisitor = ClassRemapper(
        classWriter,
        createRemapper(
            mapInternalName = { internalName: String -> classRenameMap[internalName] ?: internalName },
            mapResourcePath = resourcePathRemapper,
            mapStringValue = { value -> remapSupportedReflectionClassString(value, classRenameMap) },
        ),
    )
    classReader.accept(classVisitor, 0)
    val remappedBytes = classWriter.toByteArray()

    // Strip dead constant-pool entries so stale class-name constants do not
    // survive a successful remap.
    val cleanReader = ClassReader(remappedBytes)
    // Build a fresh constant pool. ClassWriter(ClassReader, 0) intentionally
    // copies the source pool, which can retain stale UTF8 constants for the
    // retired fixed-r names even when no live instruction references them.
    val cleanWriter = frameComputingWriter()
    cleanReader.accept(cleanWriter, 0)
    return cleanWriter.toByteArray()
}

private fun frameComputingWriter(): ClassWriter = object : ClassWriter(ClassWriter.COMPUTE_FRAMES) {
    override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
}

/**
 * Maps only structured reflection forms that are known to carry an owner class
 * followed by a member selector. Exact binary names, internal names, .class
 * resource strings, and slash resource paths remain covered by [createRemapper].
 */
private fun remapSupportedReflectionClassString(value: String, classRenameMap: Map<String, String>): String {
    val ordered = classRenameMap.entries.sortedByDescending { it.key.length }
    for ((oldInternalName, newInternalName) in ordered) {
        val oldBinaryName = oldInternalName.replace('/', '.')
        val newBinaryName = newInternalName.replace('/', '.')
        val isMemberReference = value.startsWith("$oldBinaryName#") ||
            value.startsWith("$oldBinaryName::") ||
            value.startsWith("$oldBinaryName.m_")
        if (isMemberReference) {
            return newBinaryName + value.removePrefix(oldBinaryName)
        }
    }
    return value
}

internal fun buildResourcePathRemapper(classRenameMap: Map<String, String>): (String) -> String {
    val packageRenamePrefixes = classRenameMap.entries
        .mapNotNull { (originalClassName, renamedClassName) ->
            val originalPackage = originalClassName.substringBeforeLast('/', "")
            val renamedPackage = renamedClassName.substringBeforeLast('/', "")
            if (originalPackage.isNotEmpty() && originalPackage != renamedPackage) originalPackage to renamedPackage else null
        }
        .distinct()
        .sortedByDescending { it.first.length }

    if (packageRenamePrefixes.isEmpty()) {
        return { resourcePath -> resourcePath }
    }

    return { resourcePath ->
        val leadingSlash = resourcePath.startsWith('/')
        val normalizedPath = if (leadingSlash) resourcePath.drop(1) else resourcePath
        var mappedPath = resourcePath
        for ((originalPackage, renamedPackage) in packageRenamePrefixes) {
            val prefix = "$originalPackage/"
            if (normalizedPath.startsWith(prefix)) {
                val renamedPath = "$renamedPackage/${normalizedPath.removePrefix(prefix)}"
                mappedPath = if (leadingSlash) "/$renamedPath" else renamedPath
                break
            }
        }
        mappedPath
    }
}
