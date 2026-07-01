package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.remapClasses
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.naming.applyPackageRenameMap
import io.github.hht0rro.javashroud.naming.buildClassRenameMap
import io.github.hht0rro.javashroud.naming.buildPackageRenameMap
import io.github.hht0rro.javashroud.naming.buildRenameConfig
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
 val runtimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
 val classRenameCandidates = matchedClassNames.filterNot { it.startsWith("dev/aide/jvmobf/") || it in runtimeBoundClassNames }.toSet() 
 val classRenameMap = buildClassRenameMap(artifact.classArtifacts, classRenameCandidates, config) 
 return applyClassRenameMap(artifact, classRenameMap) 
}

fun renamePackages(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val config = buildRenameConfig(params)
 val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "rename-packages") 
 val runtimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
 val packageRenameCandidates = matchedClassNames.filterNot { it.startsWith("dev/aide/jvmobf/") || it in runtimeBoundClassNames }.toSet() 
 val packageRenameMap = buildPackageRenameMap(artifact.classArtifacts, packageRenameCandidates, config) 
    val classRenameMap = applyPackageRenameMap(artifact.classArtifacts, packageRenameMap)
 .filterKeys { packageRenameCandidates.contains(it) } 
    return applyClassRenameMap(artifact, classRenameMap)
}

internal fun priorRuntimeBoundClassNames(artifact: BytecodeArtifact): Set<String> = artifact.classArtifacts
    .filter { classArtifact ->
        val classNode = ClassNode()
        ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        isPriorJavaShroudGeneratedRuntimeClass(classNode) || hasPriorSealedRuntimeDependency(classNode)
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
