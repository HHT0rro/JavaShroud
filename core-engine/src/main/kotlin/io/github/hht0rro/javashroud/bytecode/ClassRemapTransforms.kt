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
    // ClassRemapper maps the type names in existing stack frames along with
    // the instructions. A fresh writer also drops unused constant-pool entries.
    val classWriter = ClassWriter(0)
    val classVisitor = ClassRemapper(
        classWriter,
        createRemapper(
            mapInternalName = { internalName: String -> classRenameMap[internalName] ?: internalName },
            mapResourcePath = resourcePathRemapper,
            mapStringValue = { value -> remapSupportedReflectionClassString(value, classRenameMap) },
        ),
    )
    classReader.accept(classVisitor, 0)
    return classWriter.toByteArray()
}

/**
 * Maps only structured reflection forms that are known to carry an owner class
 * followed by a member selector. Exact binary names, internal names, .class
 * resource strings, and slash resource paths remain covered by [createRemapper].
 */
private fun remapSupportedReflectionClassString(value: String, classRenameMap: Map<String, String>): String {
    // Check longest candidate owners first without sorting and scanning every class for each LDC.
    for (index in value.indices.reversed()) {
        val separator = value[index] == '#' || value.startsWith("::", index) || value.startsWith(".m_", index)
        if (!separator) continue
        val owner = value.substring(0, index).replace('.', '/')
        val replacement = classRenameMap[owner] ?: continue
        return replacement.replace('/', '.') + value.substring(index)
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
