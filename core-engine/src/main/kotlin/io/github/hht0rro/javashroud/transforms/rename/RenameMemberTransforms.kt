package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.bytecode.remapFields
import io.github.hht0rro.javashroud.bytecode.remapMethods
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.naming.MemberRename
import io.github.hht0rro.javashroud.naming.buildFieldRenameMap
import io.github.hht0rro.javashroud.naming.buildMethodRenameMap
import io.github.hht0rro.javashroud.naming.buildRenameConfig
import io.github.hht0rro.javashroud.naming.canRenameMethod
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun renameMethods(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val config = buildRenameConfig(params)
    val runtimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
    val externallyBoundSignatures = externallyBoundMethodSignatures(artifact)
    val inArtifactOverrideSignatures = inArtifactOverrideMethodSignatures(artifact)
    val protectedSignatures = externallyBoundSignatures + inArtifactOverrideSignatures
    val matchedMembers = eligibleMembersForAction(artifact.classArtifacts, ruleMatches, "rename-methods")
        .filter { it.kind == MemberKind.METHOD }
        .filter { it.owner !in runtimeBoundClassNames }
        .filter { canRenameMethod(it.name) }
        .filter { artifact.classArtifactIndex[it.owner]?.summary?.accessFlags?.and(org.objectweb.asm.Opcodes.ACC_ENUM) == 0 }
        .filter { methodSignature(it.name, it.descriptor) !in protectedSignatures }
    val methodRenameMap = buildMethodRenameMap(matchedMembers, config)
    if (methodRenameMap.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val entryPointMethodKeys = entryPointMethodKeys(artifact).intersect(methodRenameMap.keys)
    val bridgeMethodKeys = methodRenameMap.keys.filter { key ->
        methodSignature(key.name, key.descriptor) in externallyBoundSignatures
    }.toSet() + entryPointMethodKeys
    val nativeMethodKeys = nativeMethodKeys(artifact).intersect(methodRenameMap.keys)
    val methodStringRewriteMap = methodReflectionStringRewriteMap(methodRenameMap)
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        reanalyzedClassArtifact(
            classArtifact,
            remapMethods(
                classArtifact.bytes,
                methodRenameMap,
                bridgeMethodKeys,
                methodStringRewriteMap,
                nativeMethodKeys,
            ),
        )
    }

    val updatedArtifact = updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = affectedOwnerCount(methodRenameMap),
        transformedMemberCount = methodRenameMap.size,
    ).artifact

    return updatedArtifactTransformResult(
        artifact = updatedArtifact.copy(jarEntries = mergeMethodRenameMapEntry(updatedArtifact.jarEntries, methodRenameMap)),
        updatedClassArtifacts = updatedArtifact.classArtifacts,
        transformedClassCount = affectedOwnerCount(methodRenameMap),
        transformedMemberCount = methodRenameMap.size,
    )
}

fun renameFields(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val config = buildRenameConfig(params)
    val runtimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
    val matchedMembers = eligibleMembersForAction(artifact.classArtifacts, ruleMatches, "rename-fields")
        .filter { it.kind == MemberKind.FIELD }
        .filter { it.owner !in runtimeBoundClassNames }
    val fieldRenameMap = buildFieldRenameMap(matchedMembers, config)
    if (fieldRenameMap.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val fieldStringRewriteMap = fieldRenameMap.values.associate { it.originalName to it.renamedName }
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        reanalyzedClassArtifact(classArtifact, remapFields(classArtifact.bytes, fieldRenameMap, fieldStringRewriteMap))
    }

    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = affectedOwnerCount(fieldRenameMap),
        transformedMemberCount = fieldRenameMap.size,
    )
}

internal const val METHOD_RENAME_BINDINGS_RESOURCE = "META-INF/.javashroud/method-renames.idx"

private fun mergeMethodRenameMapEntry(
    jarEntries: List<JarEntryData>,
    methodRenameMap: Map<MemberKey, MemberRename>,
): List<JarEntryData> {
    val existingLines = jarEntries
        .firstOrNull { it.name == METHOD_RENAME_BINDINGS_RESOURCE }
        ?.bytes
        ?.toString(Charsets.UTF_8)
        ?.lineSequence()
        ?.filter { it.isNotBlank() }
        ?.toList()
        .orEmpty()
    val newLines = methodRenameMap.values.map { rename ->
        listOf(rename.owner, rename.originalName, rename.descriptor, rename.renamedName).joinToString("|")
    }
    val merged = (existingLines + newLines).distinct().joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
    return jarEntries.filterNot { it.name == METHOD_RENAME_BINDINGS_RESOURCE } + JarEntryData(METHOD_RENAME_BINDINGS_RESOURCE, merged)
}

private fun entryPointMethodKeys(artifact: BytecodeArtifact): Set<MemberKey> = artifact.classArtifacts

    .flatMap { classArtifact ->

        classArtifact.summary.methodSummaries

            .filter { method ->

                method.name == "main" &&

                    method.descriptor == "([Ljava/lang/String;)V" &&

                    method.accessFlags and org.objectweb.asm.Opcodes.ACC_PUBLIC != 0 &&

                    method.accessFlags and org.objectweb.asm.Opcodes.ACC_STATIC != 0

            }

            .map { method -> MemberKey(classArtifact.summary.internalName, method.name, method.descriptor) }

    }

    .toSet()

private fun affectedOwnerCount(memberRenameMap: Map<MemberKey, MemberRename>): Int {
    return memberRenameMap.keys.map { it.owner }.toSet().size
}

private fun methodReflectionStringRewriteMap(methodRenameMap: Map<MemberKey, MemberRename>): Map<String, Map<String, String>> =
    methodRenameMap.values
        .groupBy { rename -> rename.originalName }
        .mapValues { (_, renames) ->
            renames
                .groupBy { rename -> methodParameterDescriptor(rename.descriptor) }
                .mapValues { (_, sameParameters) ->
                    sameParameters.map { rename -> rename.renamedName }.distinct().singleOrNull() ?: sameParameters.last().renamedName
                }
        }
        .filterValues { it.isNotEmpty() }

private fun methodParameterDescriptor(methodDescriptor: String): String {
    val closeIndex = methodDescriptor.indexOf(')')
    return if (closeIndex >= 0) methodDescriptor.substring(0, closeIndex + 1) else methodDescriptor
}


private val JVM_SPECIAL_METHOD_NAMES = setOf("<init>", "<clinit>")

private fun nativeMethodKeys(artifact: BytecodeArtifact): Set<MemberKey> = artifact.classArtifacts
    .flatMap { classArtifact ->
        classArtifact.summary.methodSummaries
            .filter { method -> method.accessFlags and org.objectweb.asm.Opcodes.ACC_NATIVE != 0 }
            .map { method -> MemberKey(classArtifact.summary.internalName, method.name, method.descriptor) }
    }
    .toSet()

