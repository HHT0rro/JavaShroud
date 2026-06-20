package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.artifact.JarEntryData

internal fun renamedJarEntries(
    jarEntries: List<JarEntryData>,
    classRenameMap: Map<String, String>,
): List<JarEntryData> {
    val renamedEntries = jarEntries.map { jarEntryData: JarEntryData ->
        val originalClassName = jarEntryData.name.removeSuffix(".class")
        val renamedClassName = classRenameMap[originalClassName]
        if (jarEntryData.name.endsWith(".class") && renamedClassName != null) {
            jarEntryData.copy(name = "$renamedClassName.class")
        } else if (jarEntryData.name.equals("META-INF/MANIFEST.MF", ignoreCase = true)) {
            updateManifestClassRefs(jarEntryData, classRenameMap)
        } else {
            jarEntryData
        }
    }

    return addResourceCompatibilityAliases(renamedEntries, jarEntries, classRenameMap)
}

private fun addResourceCompatibilityAliases(
    renamedEntries: List<JarEntryData>,
    originalEntries: List<JarEntryData>,
    classRenameMap: Map<String, String>,
): List<JarEntryData> {
    if (classRenameMap.isEmpty()) return renamedEntries
    val byName = renamedEntries.associateBy { it.name }.toMutableMap()
    addRenamedPackageResourceAliases(byName, originalEntries, classRenameMap)
    return byName.values.toList()
}

private fun addRenamedPackageResourceAliases(
    entriesByName: MutableMap<String, JarEntryData>,
    originalEntries: List<JarEntryData>,
    classRenameMap: Map<String, String>,
) {
    val packageRenameMap = classRenameMap.entries
        .mapNotNull { (originalClassName, renamedClassName) ->
            val originalPackage = originalClassName.substringBeforeLast('/', "")
            val renamedPackage = renamedClassName.substringBeforeLast('/', "")
            if (originalPackage.isNotEmpty() && originalPackage != renamedPackage) originalPackage to renamedPackage else null
        }
        .distinct()
        .sortedByDescending { it.first.length }
    if (packageRenameMap.isEmpty()) return

    val originalClassEntryNames = originalEntries.asSequence()
        .filter { it.name.endsWith(".class") }
        .map { it.name }
        .toSet()
    for (entry in originalEntries) {
        if (entry.name.endsWith("/") || entry.name.endsWith(".class") || entry.name.equals("META-INF/MANIFEST.MF", ignoreCase = true)) {
            continue
        }
        for ((originalPackage, renamedPackage) in packageRenameMap) {
            val prefix = "$originalPackage/"
            if (!entry.name.startsWith(prefix)) continue
            val aliasName = "$renamedPackage/${entry.name.removePrefix(prefix)}"
            if (aliasName !in entriesByName && aliasName !in originalClassEntryNames) {
                entriesByName[aliasName] = entry.copy(name = aliasName)
                entriesByName.remove(entry.name)
            }
            break
        }
    }
}


private val MANIFEST_CLASS_ATTRS = listOf(
    "Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class",
)

private fun updateManifestClassRefs(
    manifestEntry: JarEntryData,
    classRenameMap: Map<String, String>,
): JarEntryData {
    val content = String(manifestEntry.bytes, Charsets.UTF_8)
    var updated = content
    for (attr in MANIFEST_CLASS_ATTRS) {
        val pattern = Regex("(?m)^($attr:\\s*)(.+?)\\s*$")
        updated = pattern.replace(updated) { match ->
            val currentValue = match.groupValues[2].trim()
            val internalName = currentValue.replace('.', '/')
            val newName = classRenameMap[internalName] ?: return@replace match.value
            "${match.groupValues[1]}${newName.replace('/', '.')}"
        }
    }
    // Ensure manifest ends with the required trailing blank line (CRLF CRLF).
    // The regex replacement can strip trailing line endings, so re-add them.
    updated = updated.trimEnd('\r', '\n') + "\r\n\r\n"
    return if (updated != content) {
        manifestEntry.copy(bytes = updated.toByteArray(Charsets.UTF_8))
    } else {
        manifestEntry
    }
}

