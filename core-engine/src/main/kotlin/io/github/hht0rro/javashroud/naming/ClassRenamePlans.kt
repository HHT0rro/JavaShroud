package io.github.hht0rro.javashroud.naming

import io.github.hht0rro.javashroud.model.artifact.ClassArtifact

fun buildClassRenameMap(
    classArtifacts: List<ClassArtifact>,
    matchedClassNames: Set<String>,
    config: RenameConfig = RenameConfig(),
): Map<String, String> {
    val selectedClassArtifacts = classArtifacts
        .filter { matchedClassNames.contains(it.summary.internalName) }
        .sortedBy { it.summary.internalName }

    val generator = NameGenerator(config)
    val existingClassNames = classArtifacts.map { it.summary.internalName }.toSet()
    val allocatedClassNames = mutableSetOf<String>()

    return selectedClassArtifacts.mapNotNull { classArtifact ->
        val original = classArtifact.summary.internalName
        val packageName = original.substringBeforeLast('/', "")
        var fullNewName: String
        do {
            val newName = generator.generateSimpleName("C")
            fullNewName = if (packageName.isBlank()) newName else "$packageName/$newName"
        } while (fullNewName in existingClassNames || fullNewName in allocatedClassNames)
        allocatedClassNames += fullNewName
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

    return selectedPackages
        .map { packageName ->
            val segments = packageName.split('/')
            val preserveCount = config.preservePackageDepth.coerceIn(0, segments.size)
            val preserved = segments.take(preserveCount)
            val toRename = segments.drop(preserveCount)
            val renamedSegmentCount = if (config.shufflePackageSegmentCount && toRename.size > 1) 1 else toRename.size
            val renamedSegments = preserved + List(renamedSegmentCount) { generator.generatePackageSegment() }
            val newPackageName = renamedSegments.joinToString("/")
            packageName to newPackageName
        }
        .filter { it.first != it.second }
        .toMap()
}

fun applyPackageRenameMap(classArtifacts: List<ClassArtifact>, packageRenameMap: Map<String, String>): Map<String, String> {
    if (packageRenameMap.isEmpty()) {
        return emptyMap()
    }

    return classArtifacts
        .map { classArtifact ->
            val originalName = classArtifact.summary.internalName
            val packageName = originalName.substringBeforeLast('/', "")
            val simpleName = originalName.substringAfterLast('/')
            val renamedPackageName = packageRenameMap[packageName]
            val renamedName = if (renamedPackageName == null) originalName else "$renamedPackageName/$simpleName"
            originalName to renamedName
        }
        .filter { it.first != it.second }
        .toMap()
}
