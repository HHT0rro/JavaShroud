package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.artifact.JarEntryData

internal fun renamedJarEntries(
    jarEntries: List<JarEntryData>,
    classRenameMap: Map<String, String>,
): List<JarEntryData> {
    val renamedEntries = jarEntries.map { jarEntryData: JarEntryData ->
        val originalClassName = jarEntryData.name.removeSuffix(".class")
        val renamedClassName = classRenameMap[originalClassName]
        when {
            jarEntryData.name.endsWith(".class") && renamedClassName != null ->
                jarEntryData.copy(name = "$renamedClassName.class")
            jarEntryData.name.equals("META-INF/MANIFEST.MF", ignoreCase = true) ->
                updateManifestClassRefs(jarEntryData, classRenameMap)
            jarEntryData.name.startsWith(SERVICES_PREFIX) ->
                updateServiceProviderClassRefs(jarEntryData, classRenameMap)
            isSupportedClassBindingMetadataResource(jarEntryData.name) ->
                updateClassBindingMetadataRefs(jarEntryData, classRenameMap)
            else -> jarEntryData
        }
    }

    require(renamedEntries.map { it.name }.distinct().size == renamedEntries.size) {
        "class relocation produced duplicate JAR entry paths"
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
                // Use the already-remapped metadata bytes when creating the
                // relocated package alias.  Copying directly from
                // [originalEntries] would re-introduce fixed class names that
                // updateClassBindingMetadataRefs removed from the primary
                // entry, defeating the release gate.
                val remappedEntry = entriesByName[entry.name] ?: entry
                entriesByName[aliasName] = remappedEntry.copy(name = aliasName)
                entriesByName.remove(entry.name)
            }
            break
        }
    }
}

private const val SERVICES_PREFIX = "META-INF/services/"

private val MANIFEST_CLASS_ATTRS = listOf(
    "Main-Class", "Start-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class",
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
    updated = updated.trimEnd('\r', '\n') + "\r\n\r\n"
    return if (updated != content) {
        manifestEntry.copy(bytes = updated.toByteArray(Charsets.UTF_8))
    } else {
        manifestEntry
    }
}

private fun updateServiceProviderClassRefs(
    serviceEntry: JarEntryData,
    classRenameMap: Map<String, String>,
): JarEntryData {
    val originalServiceBinaryName = serviceEntry.name.removePrefix(SERVICES_PREFIX)
    val renamedServiceBinaryName = classRenameMap[originalServiceBinaryName.replace('.', '/')]
        ?.replace('/', '.')
        ?: originalServiceBinaryName
    val content = String(serviceEntry.bytes, Charsets.UTF_8)
    val lineEnding = if (content.contains("\r\n")) "\r\n" else "\n"
    val updatedContent = content.lineSequence().joinToString(lineEnding) { line ->
        val leading = line.takeWhile(Char::isWhitespace)
        val trailing = line.takeLastWhile(Char::isWhitespace)
        val candidate = line.trim()
        if (candidate.isEmpty() || candidate.startsWith("#")) {
            line
        } else {
            val mapped = classRenameMap[candidate.replace('.', '/')]?.replace('/', '.') ?: candidate
            leading + mapped + trailing
        }
    }.let { rebuilt -> if (content.endsWith("\n")) rebuilt + lineEnding else rebuilt }
    val updatedName = SERVICES_PREFIX + renamedServiceBinaryName
    return if (updatedName != serviceEntry.name || updatedContent != content) {
        serviceEntry.copy(name = updatedName, bytes = updatedContent.toByteArray(Charsets.UTF_8))
    } else {
        serviceEntry
    }
}

/**
 * Only metadata resources with an explicit binding-oriented name are rewritten.
 * Mapping arbitrary prose resources would alter application content without a
 * reliable class-binding contract.
 */
internal fun isSupportedClassBindingMetadataResource(entryName: String): Boolean {
    val name = entryName.substringAfterLast('/').lowercase()
    val supportedExtension = listOf(
        ".properties", ".cfg", ".conf", ".ini", ".json", ".xml",
        ".yml", ".yaml", ".idx", ".list", ".txt",
    ).any(name::endsWith)
    return supportedExtension && (
        name.contains("binding") || name.contains("metadata") || name.contains("manifest") ||
            name.contains("catalog") || name.contains("service") || name.contains("class")
        )
}

private fun updateClassBindingMetadataRefs(
    metadataEntry: JarEntryData,
    classRenameMap: Map<String, String>,
): JarEntryData {
    var updated = String(metadataEntry.bytes, Charsets.UTF_8)
    for ((oldInternalName, newInternalName) in classRenameMap.entries.sortedByDescending { it.key.length }) {
        updated = replaceClassToken(updated, oldInternalName, newInternalName)
        updated = replaceClassToken(updated, oldInternalName.replace('/', '.'), newInternalName.replace('/', '.'))
    }
    return if (updated != String(metadataEntry.bytes, Charsets.UTF_8)) {
        metadataEntry.copy(bytes = updated.toByteArray(Charsets.UTF_8))
    } else {
        metadataEntry
    }
}

private fun replaceClassToken(text: String, oldName: String, newName: String): String =
    Regex("(?<![A-Za-z0-9_$])${Regex.escape(oldName)}(?![A-Za-z0-9_$])").replace(text, newName)
