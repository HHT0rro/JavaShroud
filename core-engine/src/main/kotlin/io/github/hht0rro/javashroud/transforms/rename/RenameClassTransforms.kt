package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.remapClasses
import io.github.hht0rro.javashroud.bytecode.remapClassesStrict
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.naming.RenameConfig
import io.github.hht0rro.javashroud.naming.applyPackageRenameMap
import io.github.hht0rro.javashroud.naming.buildClassRenameMap
import io.github.hht0rro.javashroud.naming.buildFixedGeneratedClassRelocationMap
import io.github.hht0rro.javashroud.naming.buildPackageRenameMap
import io.github.hht0rro.javashroud.naming.buildRenameConfig
import io.github.hht0rro.javashroud.naming.isFixedGeneratedInternalName
import io.github.hht0rro.javashroud.transforms.protection.hasPriorSealedRuntimeDependency
import io.github.hht0rro.javashroud.transforms.protection.isPriorJavaShroudGeneratedRuntimeClass
import io.github.hht0rro.javashroud.transforms.renamedArtifactTransformResult
import io.github.hht0rro.javashroud.transforms.renamedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode

fun renameClasses(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val config = buildRenameConfig(params)
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "rename-classes")
    val fixedGeneratedNames = fixedGeneratedClassNames(artifact)
    val runtimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
    val classRenameCandidates = matchedClassNames
        .filterNot { it in fixedGeneratedNames || it.startsWith("dev/aide/jvmobf/") || it in runtimeBoundClassNames }
        .toSet()
    val ordinaryResult = applyClassRenameMap(
        artifact,
        buildClassRenameMap(artifact.classArtifacts, classRenameCandidates, config),
    )
    return applyFixedGeneratedNameRemoval(ordinaryResult, config)
}

fun renamePackages(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val config = buildRenameConfig(params)
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "rename-packages")
    val fixedGeneratedNames = fixedGeneratedClassNames(artifact)
    val runtimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
    val packageRenameCandidates = matchedClassNames
        .filterNot { it in fixedGeneratedNames || it.startsWith("dev/aide/jvmobf/") || it in runtimeBoundClassNames }
        .toSet()
    val packageRenameMap = buildPackageRenameMap(artifact.classArtifacts, packageRenameCandidates, config)
    val classRenameMap = applyPackageRenameMap(artifact.classArtifacts, packageRenameMap, packageRenameCandidates)
    val ordinaryResult = applyClassRenameMap(artifact, classRenameMap)
    return applyFixedGeneratedNameRemoval(ordinaryResult, config)
}

/**
 * Release-required cleanup stage. It is intentionally not user-toggleable:
 * when a rename stage executes, every legacy r/<number>/ class is relocated
 * even if rules excluded it or prior runtime binding analysis marked it bound.
 */
internal fun removeFixedGeneratedNames(artifact: BytecodeArtifact, config: RenameConfig = RenameConfig()): TransformResult {
    val fixedNames = fixedGeneratedClassNames(artifact)
    if (fixedNames.isEmpty()) return unchangedTransformResult(artifact)

    val externallyBoundFixedNames = fixedNames.intersect(priorRuntimeBoundClassNames(artifact))
    require(externallyBoundFixedNames.isEmpty()) {
        "fixed generated class has an existing sealed runtime/native binding that cannot be relocated safely: " +
            externallyBoundFixedNames.sorted().joinToString(",")
    }

    val relocationMap = buildFixedGeneratedClassRelocationMap(artifact.classArtifacts, fixedNames, config)
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        renamedClassArtifact(classArtifact, remapClassesStrict(classArtifact.bytes, relocationMap))
    }
    val result = renamedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        classRenameMap = relocationMap,
    )
    check(fixedGeneratedClassNames(result.artifact).isEmpty()) {
        "fixed generated name removal left a reserved r/<number>/ class after relocation"
    }
    return result
}

private fun applyFixedGeneratedNameRemoval(ordinaryResult: TransformResult, config: RenameConfig): TransformResult {
    val cleanupResult = removeFixedGeneratedNames(ordinaryResult.artifact, config)
    if (cleanupResult.transformedClassCount == 0) return ordinaryResult
    return TransformResult(
        artifact = cleanupResult.artifact,
        transformedClassCount = ordinaryResult.transformedClassCount + cleanupResult.transformedClassCount,
        transformedMemberCount = ordinaryResult.transformedMemberCount + cleanupResult.transformedMemberCount,
    )
}

private fun fixedGeneratedClassNames(artifact: BytecodeArtifact): Set<String> = artifact.classArtifacts
    .asSequence()
    .map { it.summary.internalName }
    .filter(::isFixedGeneratedInternalName)
    .toSet()

internal fun priorRuntimeBoundClassNames(artifact: BytecodeArtifact): Set<String> = artifact.classArtifacts
    .filter { classArtifact ->
        val classNode = ClassNode()
        ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        // A fixed `r/<digits>/` name is itself the release-gate target and is
        // not sufficient evidence of a previously sealed runtime helper.  The
        // fixed-name cleanup stage must be able to relocate ordinary input
        // classes; only an explicit sealed dependency keeps the fail-closed
        // guard active for a fixed-name class.
        val fixedGenerated = isFixedGeneratedInternalName(classArtifact.summary.internalName)
        (!fixedGenerated && isPriorJavaShroudGeneratedRuntimeClass(classNode)) ||
            hasPriorSealedRuntimeDependency(classNode)
    }
    .map { it.summary.internalName }
    .toSet()

private fun applyClassRenameMap(artifact: BytecodeArtifact, classRenameMap: Map<String, String>): TransformResult {
    if (classRenameMap.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        renamedClassArtifact(classArtifact, remapClasses(classArtifact.bytes, classRenameMap))
    }

    return renamedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        classRenameMap = classRenameMap,
    )
}
