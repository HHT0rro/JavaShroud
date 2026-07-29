package io.github.hht0rro.javashroud.naming

import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import java.util.Locale

fun buildClassRenameMap(
    classArtifacts: List<ClassArtifact>,
    matchedClassNames: Set<String>,
    config: RenameConfig = RenameConfig(),
): Map<String, String> {
    val selectedClassArtifacts = classArtifacts
        .filter { matchedClassNames.contains(it.summary.internalName) }
        .sortedBy { it.summary.internalName }

    val generator = NameGenerator(config)
    val existingClassNames = classArtifacts
        .mapTo(mutableSetOf()) { it.summary.internalName.lowercase(Locale.ROOT) }
    val allocatedClassNames = mutableSetOf<String>()

    return selectedClassArtifacts.mapNotNull { classArtifact ->
        val original = classArtifact.summary.internalName
        val packageName = original.substringBeforeLast('/', "")
        var fullNewName: String
        do {
            val newName = generator.generateSimpleName("C")
            fullNewName = if (packageName.isBlank()) newName else "$packageName/$newName"
        } while (fullNewName.lowercase(Locale.ROOT) in existingClassNames || fullNewName.lowercase(Locale.ROOT) in allocatedClassNames)
        allocatedClassNames += fullNewName.lowercase(Locale.ROOT)
        if (original == fullNewName) null else original to fullNewName
    }.toMap()
}

fun buildPackageRenameMap(
    classArtifacts: List<ClassArtifact>,
    matchedClassNames: Set<String>,
    config: RenameConfig = RenameConfig(),
): Map<String, String> {
    val selectedPackages = classArtifacts
        .filter { matchedClassNames.contains(it.summary.internalName) }
        .map { it.summary.internalName.substringBeforeLast('/', "") }
        .filter { it.isNotBlank() }
        .distinct()
        .sorted()

    val generator = NameGenerator(config)
    val immutableFinalNames = classArtifacts
        .filterNot { it.summary.internalName in matchedClassNames }
        .mapTo(mutableSetOf()) { it.summary.internalName.lowercase(Locale.ROOT) }
    val allocatedFinalNames = mutableSetOf<String>()
    val renameMap = linkedMapOf<String, String>()

    for (packageName in selectedPackages) {
        val packageClasses = classArtifacts.filter { classArtifact ->
            classArtifact.summary.internalName in matchedClassNames &&
                classArtifact.summary.internalName.substringBeforeLast('/', "") == packageName
        }
        val caseFoldedSimpleNames = packageClasses.map { classArtifact ->
            classArtifact.summary.internalName.substringAfterLast('/').lowercase(Locale.ROOT)
        }
        require(caseFoldedSimpleNames.size == caseFoldedSimpleNames.toSet().size) {
            "selected package '$packageName' contains a case-insensitive class path collision"
        }
        val segments = packageName.split('/')
        val preserveCount = config.preservePackageDepth.coerceIn(0, segments.size)
        val preserved = segments.take(preserveCount)
        val toRename = segments.drop(preserveCount)
        val renamedSegmentCount = if (config.shufflePackageSegmentCount && toRename.size > 1) 1 else toRename.size
        if (renamedSegmentCount == 0) continue
        var newPackageName: String
        var candidateNames: List<String>
        do {
            val renamedSegments = preserved + List(renamedSegmentCount) { generator.generatePackageSegment() }
            newPackageName = renamedSegments.joinToString("/")
            candidateNames = packageClasses.map { classArtifact ->
                "$newPackageName/${classArtifact.summary.internalName.substringAfterLast('/')}".lowercase(Locale.ROOT)
            }
        } while (
            newPackageName == packageName ||
            candidateNames.any { it in immutableFinalNames || it in allocatedFinalNames }
        )
        renameMap[packageName] = newPackageName
        allocatedFinalNames += candidateNames
    }
    return renameMap
}

fun applyPackageRenameMap(
    classArtifacts: List<ClassArtifact>,
    packageRenameMap: Map<String, String>,
    selectedClassNames: Set<String>? = null,
): Map<String, String> {
    if (packageRenameMap.isEmpty()) {
        return emptyMap()
    }

    val projected = classArtifacts
        .map { classArtifact ->
            val originalName = classArtifact.summary.internalName
            val packageName = originalName.substringBeforeLast('/', "")
            val simpleName = originalName.substringAfterLast('/')
            val renamedPackageName = if (selectedClassNames == null || originalName in selectedClassNames) {
                packageRenameMap[packageName]
            } else {
                null
            }
            val renamedName = if (renamedPackageName == null) originalName else "$renamedPackageName/$simpleName"
            originalName to renamedName
        }
    val caseFoldedNames = projected.map { (_, renamedName) -> renamedName.lowercase(Locale.ROOT) }
    require(caseFoldedNames.size == caseFoldedNames.toSet().size) {
        "package rename plan produces a case-insensitive class path collision"
    }
    return projected
        .filter { it.first != it.second }
        .toMap()
}
