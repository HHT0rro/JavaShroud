package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.commons.ClassRemapper

fun remapClasses(classBytes: ByteArray, classRenameMap: Map<String, String>): ByteArray = try {
    // First pass: apply ClassRemapper to rewrite class/package references.
    // Use ClassWriter(0) WITHOUT ClassReader so the new constant pool is built
    // from scratch, avoiding copy of old unreferenced entries.
    val resourcePathRemapper = buildResourcePathRemapper(classRenameMap)
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(0)
    val classVisitor = ClassRemapper(classWriter, createRemapper(
        mapInternalName = { internalName: String -> classRenameMap[internalName] ?: internalName },
        mapResourcePath = resourcePathRemapper,
    ))
    classReader.accept(classVisitor, 0)
    val remappedBytes = classWriter.toByteArray()

    // Second pass: read back through a fresh ClassReader/ClassWriter cycle to
    // strip any dead constant pool entries that survived the remap pass.  This
    // guarantees the output pool contains only entries reachable from the final
    // bytecode and class metadata, eliminating original-name leakage.
    val cleanReader = ClassReader(remappedBytes)
    val cleanWriter = ClassWriter(cleanReader, 0)
    cleanReader.accept(cleanWriter, 0)
    cleanWriter.toByteArray()
} catch (_: Exception) {
    // If remapping fails (e.g. corrupted descriptors from prior transforms),
    // return the original bytes so the engine does not crash.
    classBytes
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
