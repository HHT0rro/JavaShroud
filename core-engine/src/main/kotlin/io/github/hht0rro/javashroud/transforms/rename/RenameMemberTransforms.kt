package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.bytecode.isResolverMemberName
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
import io.github.hht0rro.javashroud.transforms.reflectionEnumerationSensitiveClassNames
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode

fun renameMethods(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val config = buildRenameConfig(params)
    val originalMatchedMembers = eligibleMembersForAction(artifact.classArtifacts, ruleMatches, "rename-methods")
        .filter { it.kind == MemberKind.METHOD }
    val initialRuntimeBoundClassNames = priorRuntimeBoundClassNames(artifact)
    val reflectionEnumeratedClassNames = reflectionEnumerationSensitiveClassNames(artifact)
    val initialProtectedSignatures = externallyBoundMethodSignatures(artifact) + inArtifactOverrideMethodSignatures(artifact)
    val parameterCandidates = originalMatchedMembers
        .filterNot { isResolverMemberName(it.name) }
        .filter { it.owner !in initialRuntimeBoundClassNames }
        .filter { it.owner !in reflectionEnumeratedClassNames }
        .filter { canRenameMethod(it.name) }
        .filter { artifact.classArtifactIndex[it.owner]?.summary?.accessFlags?.and(org.objectweb.asm.Opcodes.ACC_ENUM) == 0 }
        .filter { methodSignature(it.name, it.descriptor) !in initialProtectedSignatures }
    val parameterResult = applyMethodDescriptorPadding(artifact, parameterCandidates, params)
    val workingArtifact = parameterResult.artifact
    val runtimeBoundClassNames = priorRuntimeBoundClassNames(workingArtifact)
    val externallyBoundSignatures = externallyBoundMethodSignatures(workingArtifact)
    val inArtifactOverrideSignatures = inArtifactOverrideMethodSignatures(workingArtifact)
    val protectedSignatures = externallyBoundSignatures + inArtifactOverrideSignatures
    val matchedMembers = originalMatchedMembers
        .map { member ->
            val key = MemberKey(member.owner, member.name, member.descriptor)
            parameterResult.descriptors[key]?.let { descriptor -> member.copy(descriptor = descriptor) } ?: member
        }
        .filterNot { isResolverMemberName(it.name) }
        .filter { it.owner !in runtimeBoundClassNames }
        .filter { it.owner !in reflectionEnumeratedClassNames }
        .filter { canRenameMethod(it.name) }
        .filter { workingArtifact.classArtifactIndex[it.owner]?.summary?.accessFlags?.and(org.objectweb.asm.Opcodes.ACC_ENUM) == 0 }
        .filter { methodSignature(it.name, it.descriptor) !in protectedSignatures }
    val returnSensitiveNaming = (params["returnSensitiveNaming"] as? Boolean) == true
    val occupiedMethodKeys = declaredMethodKeys(workingArtifact)
    val methodRenameMap = buildMethodRenameMap(
        matchedMembers,
        config,
        returnSensitive = returnSensitiveNaming,
        occupiedMethodKeys = occupiedMethodKeys,
    )
    if (methodRenameMap.isEmpty()) {
        return if (parameterResult.transformedMemberCount == 0) {
            unchangedTransformResult(artifact)
        } else {
            updatedArtifactTransformResult(
                artifact = artifact,
                updatedClassArtifacts = workingArtifact.classArtifacts,
                transformedClassCount = workingArtifact.classArtifacts.count { updated ->
                    artifact.classArtifactIndex[updated.summary.internalName]?.bytes?.contentEquals(updated.bytes) == false
                },
                transformedMemberCount = parameterResult.transformedMemberCount,
            )
        }
    }

    val entryPointMethodKeys = entryPointMethodKeys(workingArtifact).intersect(methodRenameMap.keys)
    val reflectionLookupNames = reflectionLookupMethodNames(workingArtifact)
    val reflectionBridgeMethodKeys = methodRenameMap.keys
        .filter { key -> key.name in reflectionLookupNames }
        .toSet()
    val bridgeMethodKeys = methodRenameMap.keys.filter { key ->
        methodSignature(key.name, key.descriptor) in externallyBoundSignatures
    }.toSet() + entryPointMethodKeys + reflectionBridgeMethodKeys
    val nativeMethodKeys = nativeMethodKeys(workingArtifact).intersect(methodRenameMap.keys)
    val methodStringRewriteMap = methodReflectionStringRewriteMap(methodRenameMap)
    val updatedClassArtifacts = workingArtifact.classArtifacts.map { classArtifact ->
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
        artifact = workingArtifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = affectedOwnerCount(methodRenameMap),
        transformedMemberCount = methodRenameMap.size + parameterResult.transformedMemberCount,
    ).artifact

    return updatedArtifactTransformResult(
        artifact = updatedArtifact.copy(jarEntries = mergeMethodRenameMapEntry(updatedArtifact.jarEntries, methodRenameMap)),
        updatedClassArtifacts = updatedArtifact.classArtifacts,
        transformedClassCount = affectedOwnerCount(methodRenameMap),
        transformedMemberCount = methodRenameMap.size + parameterResult.transformedMemberCount,
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

    val fieldStringRewriteMap = fieldRenameMap.values
        .groupBy { it.owner }
        .mapValues { (_, renames) -> renames.associate { it.originalName to it.renamedName } }
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        reanalyzedClassArtifact(classArtifact, remapFields(classArtifact.bytes, fieldRenameMap, fieldStringRewriteMap))
    }

    val transformed = updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = affectedOwnerCount(fieldRenameMap),
        transformedMemberCount = fieldRenameMap.size,
    )
    return transformed.copy(
        artifact = transformed.artifact.copy(
            jarEntries = mergeFieldRenameMapEntry(
                jarEntries = transformed.artifact.jarEntries,
                fieldRenameMap = fieldRenameMap,
            ),
        ),
    )
}

internal const val METHOD_RENAME_BINDINGS_RESOURCE = "META-INF/.javashroud/method-renames.idx"
internal const val FIELD_RENAME_BINDINGS_RESOURCE = "META-INF/.javashroud/field-renames.idx"

private fun mergeFieldRenameMapEntry(
    jarEntries: List<JarEntryData>,
    fieldRenameMap: Map<MemberKey, MemberRename>,
): List<JarEntryData> {
    val existingLines = jarEntries
        .firstOrNull { it.name == FIELD_RENAME_BINDINGS_RESOURCE }
        ?.bytes
        ?.toString(Charsets.UTF_8)
        ?.lineSequence()
        ?.filter { it.isNotBlank() }
        ?.toList()
        .orEmpty()
    val newLines = fieldRenameMap.values.map { rename ->
        listOf(rename.owner, rename.originalName, rename.descriptor, rename.renamedName).joinToString("|")
    }
    val merged = (existingLines + newLines).distinct().joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
    return jarEntries.filterNot { it.name == FIELD_RENAME_BINDINGS_RESOURCE } + JarEntryData(FIELD_RENAME_BINDINGS_RESOURCE, merged)
}

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

private fun declaredMethodKeys(artifact: BytecodeArtifact): Set<MemberKey> = buildSet {
    artifact.classArtifacts.forEach { classArtifact ->
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        node.methods.forEach { method -> add(MemberKey(node.name, method.name, method.desc)) }
    }
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
