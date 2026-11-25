package io.github.hht0rro.javashroud.naming

import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import java.util.Locale

/**
 * Builds one artifact-local class relocation map. Retired fixed generated names
 * are relocated out of their original package rather than merely having their
 * simple class name changed, because [r/<number>/] itself is forbidden.
 */
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
    val relocatedPackages = linkedMapOf<String, String>()
    val allocatedPackages = mutableSetOf<String>()

    fun relocationPackageFor(originalPackage: String): String = relocatedPackages.getOrPut(originalPackage) {
        var candidate: String
        do {
            // Two generated segments remove both the fixed root package and its
            // numeric second segment, while remaining artifact-local.
            candidate = listOf(generator.generatePackageSegment(), generator.generatePackageSegment()).joinToString("/")
        } while (
            isFixedGeneratedInternalName("$candidate/C") ||
                candidate.lowercase(Locale.ROOT) in allocatedPackages
        )
        allocatedPackages += candidate.lowercase(Locale.ROOT)
        candidate
    }

    return selectedClassArtifacts.mapNotNull { classArtifact ->
        val original = classArtifact.summary.internalName
        val originalPackage = original.substringBeforeLast('/', "")
        val packageName = if (isFixedGeneratedInternalName(original)) {
            relocationPackageFor(originalPackage)
        } else {
            originalPackage
        }
        var fullNewName: String
        do {
            val newName = generator.generateSimpleName("C")
            fullNewName = if (packageName.isBlank()) newName else "$packageName/$newName"
        } while (
            isFixedGeneratedInternalName(fullNewName) ||
                fullNewName.lowercase(Locale.ROOT) in existingClassNames ||
                fullNewName.lowercase(Locale.ROOT) in allocatedClassNames
        )
        allocatedClassNames += fullNewName.lowercase(Locale.ROOT)
        if (original == fullNewName) null else original to fullNewName
    }.toMap()
}

/**
 * Explicit helper for the post-rename cleanup stage. It shares the ordinary
 * [NameGenerator] allocation and collision rules while guaranteeing that every
 * selected name moves out of the retired fixed namespace.
 */
fun buildFixedGeneratedClassRelocationMap(
    classArtifacts: List<ClassArtifact>,
    fixedGeneratedClassNames: Set<String>,
    config: RenameConfig = RenameConfig(),
): Map<String, String> {
    require(fixedGeneratedClassNames.all(::isFixedGeneratedInternalName)) {
        "fixed generated name relocation received a non-fixed class name"
    }
    return buildClassRenameMap(classArtifacts, fixedGeneratedClassNames, config).also { map ->
        require(map.keys == fixedGeneratedClassNames) {
            "fixed generated name relocation did not allocate every fixed class"
        }
        require(map.values.none(::isFixedGeneratedInternalName)) {
            "fixed generated name relocation produced a reserved r/<number>/ name"
        }
    }
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
        require(packageClasses.none { isFixedGeneratedInternalName(it.summary.internalName) }) {
            "fixed generated package '$packageName' requires class relocation before package rename"
        }
        // A selected package may legitimately contain simple names that differ
        // only by case (pre-obfuscated inputs such as `a`/`A` are common). The
        // package rename keeps such names grouped; per-class disambiguation in
        // [applyPackageRenameMap] restores the case-folded uniqueness invariant.
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
                candidateNames.any { isFixedGeneratedInternalName(it) || it in immutableFinalNames || it in allocatedFinalNames }
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
    config: RenameConfig = RenameConfig(),
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
    require(projected.none { (_, renamedName) -> isFixedGeneratedInternalName(renamedName) }) {
        "package rename plan would emit a reserved r/<number>/ class name"
    }
    // Simple names that differ only by case survive a package rename grouped
    // together (a/A in one input package stay together in the renamed package).
    // Dex and ART are case-sensitive, but the artifact-level case-folded
    // uniqueness invariant is load-bearing for downstream tooling, so a renamed
    // entry whose case-folded final name was already taken receives a fresh
    // generated simple name. Entries that keep their original name (unselected
    // classes) are never moved here; package-level planning already guarantees
    // they cannot collide with renamed finals.
    val generator = NameGenerator(config)
    val allocatedCaseFolded = mutableSetOf<String>()
    val disambiguated = projected.map { (originalName, renamedName) ->
        var finalName = renamedName
        if (renamedName != originalName && renamedName.lowercase(Locale.ROOT) in allocatedCaseFolded) {
            val renamedPackage = renamedName.substringBeforeLast('/', "")
            do {
                val generatedSimpleName = generator.generateSimpleName("C")
                finalName = if (renamedPackage.isBlank()) generatedSimpleName else "$renamedPackage/$generatedSimpleName"
            } while (
                isFixedGeneratedInternalName(finalName) ||
                    finalName.lowercase(Locale.ROOT) in allocatedCaseFolded
            )
        }
        allocatedCaseFolded += finalName.lowercase(Locale.ROOT)
        originalName to finalName
    }
    // Real-world pre-obfuscated inputs routinely carry case-variant pairs
    // (k2/d + K2/d, E/v + E/V) that Android tolerates everywhere. Collisions
    // among entries that KEPT their original names are therefore accepted as
    // long as no rename CREATED one: a renamed final must not case-collide
    // with any other final name.
    val renamedFinals = disambiguated.filter { it.first != it.second }
    val renamedCaseFolded = renamedFinals.map { it.second.lowercase(Locale.ROOT) }
    val allCaseFolded = disambiguated.map { it.second.lowercase(Locale.ROOT) }
    val remainingCaseFolded = (allCaseFolded - renamedCaseFolded.toSet()).toSet()
    val createdCollisions = renamedCaseFolded.groupingBy { it }.eachCount().filterValues { it > 1 }.keys +
        renamedCaseFolded.filter { it in remainingCaseFolded }
    require(createdCollisions.isEmpty()) {
        "package rename plan creates a case-insensitive class path collision: ${createdCollisions.sorted()}"
    }
    return disambiguated
        .filter { it.first != it.second }
        .toMap()
}
