package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.artifact.classSummaryIndex
import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.rename.METHOD_RENAME_BINDINGS_RESOURCE
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.Opcodes
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.Remapper
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Mac

private const val LEGACY_SEALED_NATIVE_INDEX_RESOURCE = "META-INF/.r/0.dat"
private const val LEGACY_DELAYED_METHOD_RESOURCE_ROOT = "__jmd/"
private const val LEGACY_CLASS_ENCRYPTION_RESOURCE_ROOT = "__jse/"
private const val LEGACY_CLASS_ENCRYPTION_MANIFEST_RESOURCE = "__jse/index.tab"
private const val LEGACY_NATIVE_RESOURCE_ROOT = "META-INF/js-native/"
private const val PROTECTION_HELPER_PACKAGE = "io/github/hht0rro/javashroud/transforms/protection"
private val BOOTSTRAP_NATIVE_INDEX_MAGIC = byteArrayOf(0x4A, 0x53, 0x42, 0x49) // JSBI
private const val BOOTSTRAP_NATIVE_INDEX_VERSION = 1
private const val BOOTSTRAP_NATIVE_INDEX_HEADER_SIZE = 9
private const val BOOTSTRAP_NATIVE_INDEX_MAC_LENGTH = 32

private val AUTO_SEALED_HELPER_PASSES = setOf(
    "anti-dump-protection",
    "anti-instrumentation",
    "anti-symbolic-execution",
    "callsite-rotation-protection",
    "class-encryption-loader",
    "environment-bound-keys",
    "exception-semantic-virtualization",
    "jni-microkernel-loader",
    "method-body-delayed-decryption",
    "method-virtualization",
)

private val SEALED_RUNTIME_HELPERS = listOf(
    "$PROTECTION_HELPER_PACKAGE/ClassEncryptionLoaderHelper",
    "$PROTECTION_HELPER_PACKAGE/ClassEncryptionLoaderHelper${"$"}ParsedMetadata",
    "$PROTECTION_HELPER_PACKAGE/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader",
    "$PROTECTION_HELPER_PACKAGE/MethodBodyDecryptionHelper",
    "$PROTECTION_HELPER_PACKAGE/MethodBodyDecryptionHelper${"$"}ParsedMetadata",
    "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper",
    "$PROTECTION_HELPER_PACKAGE/BootstrapEncryptionHelper",
    "$PROTECTION_HELPER_PACKAGE/EnvironmentBindingHelper",
    "$PROTECTION_HELPER_PACKAGE/AntiDumpHelper",
    "$PROTECTION_HELPER_PACKAGE/ExceptionVirtualizationHelper",
    "$PROTECTION_HELPER_PACKAGE/FlowControlException",
    "$PROTECTION_HELPER_PACKAGE/AntiSymbolicExecutionHelper",
    "$PROTECTION_HELPER_PACKAGE/CallsiteRotationHelper",
    "$PROTECTION_HELPER_PACKAGE/AntiInstrumentationHelper",
    "$PROTECTION_HELPER_PACKAGE/AntiJvmTiHelper",
    "$PROTECTION_HELPER_PACKAGE/AntiDumpRuntimeHelper",
    "$PROTECTION_HELPER_PACKAGE/AntiByteBuddyHelper",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}RuntimeResourceMetadata",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}SealedNativeLibrary",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}TypeParseResult",
)

/**
 * Final output sealing for high-sensitivity runtime artifacts.
 *
 * This intentionally runs after helper/native injection, because regular pass
 * execution happens before embedded helpers are added to the artifact.
 */
object RuntimeArtifactSealing {
    fun isRequested(config: ObfuscationConfig): Boolean {
        val enabledPassIds = config.passes.filter { it.enabled }.map { it.id }.toSet()
        return enabledPassIds.any { it in AUTO_SEALED_HELPER_PASSES }
    }

    fun sealIfRequested(artifact: BytecodeArtifact, config: ObfuscationConfig): BytecodeArtifact =
        if (isRequested(config)) seal(artifact, seedFromConfig(config), rewritesVmRuntime = config.enablesPass("method-virtualization")) else artifact

    internal fun seal(artifact: BytecodeArtifact, seed: Long, rewritesVmRuntime: Boolean = true): BytecodeArtifact {
        val reservedEntryNames = artifact.jarEntries.map { it.name }.toMutableSet()
        val rewritesCurrentVmRuntime = rewritesVmRuntime && artifact.jarEntries.any { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }
        val preservesExistingVmRuntime = !rewritesCurrentVmRuntime && artifact.jarEntries.any { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE }
        val sealedNativeIndexResource = uniqueSealedResourceName(
            seed = seed,
            kind = "i",
            originalName = "native-index",
            index = 0,
            preferredName = sealedNativeIndexResourceName(seed),
            reservedEntryNames = reservedEntryNames,
        )
        val helperClassRenameMap = if (preservesExistingVmRuntime) emptyMap() else sealedRuntimeHelperRenameMap(artifact, seed)
        val helperMemberRenamePlan = if (preservesExistingVmRuntime) {
            SealedHelperMemberRenamePlan(methodRenames = emptyMap(), fieldRenames = emptyMap())
        } else {
            sealedJavaOnlyHelperMemberRenamePlan(seed, helperClassRenameMap)
        }
        val resourceRenameMap = linkedMapOf<String, String>()
        val vmResourceRenameMap = linkedMapOf<String, String>()
        val priorRuntimeResourceKey = if (rewritesCurrentVmRuntime) priorRuntimeResourceKey(artifact) else null
        val legacyVmResourceNames = if (rewritesCurrentVmRuntime) legacyVirtualMachineResourceNames(artifact.jarEntries, priorRuntimeResourceKey) else emptySet()
        val helperStringRewriteMap = linkedMapOf(LEGACY_SEALED_NATIVE_INDEX_RESOURCE to sealedNativeIndexResource)
        if (!preservesExistingVmRuntime) {
            helperStringRewriteMap.putAll(sealedHelperStringRewriteMap(seed, helperClassRenameMap))
        }
        val resourceStringRewriteMap = linkedMapOf(
            LEGACY_CLASS_ENCRYPTION_RESOURCE_ROOT to sealedSemanticText(seed, "class-encryption-root"),
            ".enc" to sealedSemanticText(seed, "encrypted-resource-suffix"),
        )
        val sealedNativeSpecs = mutableListOf<SealedNativeSpec>()
        val methodRenameBindings = parseMethodRenameBindings(artifact.jarEntries)

        // Parse class encryption manifest to get encryption keys for bytecode rewriting
        val classEncryptionKeys = parseClassEncryptionManifest(artifact.jarEntries)

        val renamedJarEntries = artifact.jarEntries.mapIndexedNotNull { index, entry ->
            when {
                isDelayedMethodResource(entry.name) || isClassEncryptionResource(entry.name) -> {
                    val sealedName = uniqueSealedResourceName(seed, "v", entry.name, index, sealedResourceName(seed, "v", entry.name, index), reservedEntryNames)
                    reservedEntryNames += sealedName
                    resourceRenameMap[entry.name] = sealedName
                    // Rewrite encrypted class bytecode to update helper references
                    val rewrittenBytes = rewriteEncryptedClassBytes(
                        entry.bytes, entry.name, sealedName, classEncryptionKeys,
                        helperStringRewriteMap + resourceStringRewriteMap + resourceRenameMap,
                        seed,
                        helperClassRenameMap,
                        helperMemberRenamePlan,
                    )
                    entry.copy(name = sealedName, bytes = rewrittenBytes)
                }
                entry.name == VBC4_VM_PRELOAD_INDEX_RESOURCE -> if (rewritesCurrentVmRuntime) null else entry
                entry.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE -> entry
                entry.name in legacyVmResourceNames -> {
                    val sealedName = uniqueSealedResourceName(seed, "v", entry.name, index, sealedResourceName(seed, "v", entry.name, index), reservedEntryNames)
                    reservedEntryNames += sealedName
                    vmResourceRenameMap[entry.name] = sealedName
                    val rewrittenBytes = decodeRuntimeResourceWithPriorKey(entry.bytes, priorRuntimeResourceKey)?.let { decoded ->
                        RuntimeResourceCodec.encode(
                            bytes = decoded,
                            kind = RuntimeResourceKind.VmBytecode,
                            seed = sealedDigest(seed, "vm", entry.name, index).take(8).toLong(16).toInt(),
                            variantId = index.coerceAtLeast(1),
                            layerCount = 4,
                            compress = true,
                        )
                    } ?: entry.bytes
                    entry.copy(name = sealedName, bytes = rewrittenBytes)
                }
                isNativeKernelResource(entry.name) -> {
                    val nativeSpec = nativeSpecFor(entry.name)
                    val sealedName = uniqueSealedNativeResourceName(seed, entry.name, index, nativeSpec.storageSuffix, reservedEntryNames)
                    reservedEntryNames += sealedName
                    sealedNativeSpecs += nativeSpec.copy(resourceName = sealedName)
                    entry.copy(name = sealedName, bytes = RuntimeResourceCodec.decode(entry.bytes) ?: entry.bytes)
                }
                isClassEncryptionManifestResource(entry.name) -> {
                    val sealedName = uniqueSealedResourceName(seed, "m", entry.name, index, sealedResourceName(seed, "m", entry.name, index), reservedEntryNames)
                    reservedEntryNames += sealedName
                    resourceRenameMap[entry.name] = sealedName
                    entry.copy(name = sealedName, bytes = encodeSealedClassEncryptionManifest(entry.bytes, resourceRenameMap))
                }
                entry.name == LEGACY_SEALED_NATIVE_INDEX_RESOURCE -> entry.takeIf { preservesExistingVmRuntime }
                entry.name == METHOD_RENAME_BINDINGS_RESOURCE -> null
                else -> renamedClassEntry(entry, helperClassRenameMap)
            }
        }

        if (resourceRenameMap.isEmpty() && vmResourceRenameMap.isEmpty() && sealedNativeSpecs.isEmpty() && helperClassRenameMap.isEmpty()) return artifact

        val rewrittenClassArtifacts = artifact.classArtifacts.map { classArtifact ->
            rewriteClassArtifact(
                classArtifact = classArtifact,
                seed = seed,
                helperStringRewriteMap = helperStringRewriteMap,
                resourceStringRewriteMap = resourceStringRewriteMap + resourceRenameMap,
                helperClassRenameMap = helperClassRenameMap,
                helperMemberRenamePlan = helperMemberRenamePlan,
            ) ?: classArtifact
        }
        val rewrittenClassBytesByEntry = rewrittenClassArtifacts.flatMap { classArtifact ->
            listOf(
                classArtifact.entryName to classArtifact.bytes,
                "${classArtifact.summary.internalName}.class" to classArtifact.bytes,
            )
        }.toMap()
        val synchronizedJarEntries = renamedJarEntries.map { entry ->
            val synchronizedEntry = rewrittenClassBytesByEntry[entry.name]?.let { bytes -> entry.copy(bytes = bytes) } ?: entry
            synchronizedEntry
        }.let { entries ->
            val runtimeEntries = entries.toMutableList()
            if (rewritesCurrentVmRuntime && vmResourceRenameMap.isNotEmpty()) {
                val rewrittenVmIndex = rewriteVirtualMachinePreloadIndex(artifact.jarEntries, vmResourceRenameMap, priorRuntimeResourceKey)
                if (rewrittenVmIndex != null) runtimeEntries += JarEntryData(
                    name = VBC4_VM_PRELOAD_INDEX_RESOURCE,
                    bytes = rewrittenVmIndex,
                )
            }
            if (sealedNativeSpecs.isNotEmpty() || helperClassRenameMap.isNotEmpty()) {
                val applicationMethodBindings = expandMethodRenameBindingsAcrossFinalOwners(methodRenameBindings, rewrittenClassArtifacts) +
                    collectApplicationMethodRenameBindings(rewrittenClassArtifacts, helperClassRenameMap)
                runtimeEntries += JarEntryData(
                    name = sealedNativeIndexResource,
                    bytes = encodeSealedNativeIndex(sealedNativeSpecs, helperClassRenameMap, helperMemberRenamePlan, applicationMethodBindings),
                )
            }
            runtimeEntries
        }
        val rewrittenSummaries = rewrittenClassArtifacts.map { it.summary }
        return artifact.copy(
            jarEntries = synchronizedJarEntries,
            classArtifacts = rewrittenClassArtifacts,
            classArtifactIndex = classArtifactIndex(rewrittenClassArtifacts),
            analysisSummary = artifact.analysisSummary.copy(
                classCount = rewrittenClassArtifacts.size,
                resourceCount = resourceCount(synchronizedJarEntries, rewrittenClassArtifacts.size),
                classSummaries = rewrittenSummaries,
                classNameIndex = classSummaryIndex(rewrittenSummaries),
            ),
        )
    }
}

private data class SealedNativeSpec(
    val platform: String,
    val resourceName: String,
    val loadSuffix: String,
    val storageSuffix: String,
)

private data class SealedMemberRef(
    val owner: String,
    val name: String,
    val descriptor: String,
)

private data class SealedHelperMemberRenamePlan(
    val methodRenames: Map<SealedMemberRef, String>,
    val fieldRenames: Map<SealedMemberRef, String>,
) {
    fun methodName(owner: String?, name: String?, descriptor: String?): String? =
        if (owner == null || name == null || descriptor == null) {
            name
        } else if (name == "<init>" || name == "<clinit>") {
            name
        } else {
            methodRenames[SealedMemberRef(owner, name, descriptor)] ?: name
        }

    fun fieldName(owner: String?, name: String?, descriptor: String?): String? =
        if (owner == null || name == null || descriptor == null) {
            name
        } else {
            fieldRenames[SealedMemberRef(owner, name, descriptor)] ?: name
        }
}

private const val RUNTIME_SEALING_SEED = 0x4A53524CL

private fun seedFromConfig(config: ObfuscationConfig): Long = RUNTIME_SEALING_SEED

private fun ObfuscationConfig.enablesPass(passId: String): Boolean =
    passes.any { it.enabled && it.id == passId }

private fun renamedClassEntry(entry: JarEntryData, classRenameMap: Map<String, String>): JarEntryData {
    val internalName = entry.name.takeIf { it.endsWith(".class") }?.removeSuffix(".class") ?: return entry
    val renamedInternalName = classRenameMap[internalName] ?: return entry
    return entry.copy(name = "$renamedInternalName.class")
}

private fun sealedRuntimeHelperRenameMap(artifact: BytecodeArtifact, seed: Long): Map<String, String> {
    val presentClassNames = artifact.classArtifacts.map { it.summary.internalName }.toSet()
    val reservedClassNames = artifact.jarEntries
        .asSequence()
        .filter { it.name.endsWith(".class") }
        .map { it.name.removeSuffix(".class") }
        .toMutableSet()
    val renameMap = linkedMapOf<String, String>()
    SEALED_RUNTIME_HELPERS.forEachIndexed { index, helperName ->
        if (helperName in presentClassNames) {
            val outerName = helperName.substringBefore('$')
            val sealedOuterName = renameMap[outerName]
            val preferredName = if (sealedOuterName != null && '$' in helperName) {
                sealedNestedHelperInternalName(seed, sealedOuterName, helperName, index)
            } else {
                sealedHelperInternalName(seed, helperName, index)
            }
            val sealedName = uniqueSealedHelperName(seed, helperName, index, preferredName, reservedClassNames)
            renameMap[helperName] = sealedName
            reservedClassNames += sealedName
        }
    }
    return renameMap
}

private fun uniqueSealedHelperName(
    seed: Long,
    originalName: String,
    index: Int,
    preferredName: String,
    reservedClassNames: Set<String>,
): String {
    if (preferredName !in reservedClassNames || preferredName == originalName) return preferredName
    for (attempt in 1..1024) {
        val digest = sealedDigest(seed, "hc", "$originalName#$attempt", index)
        val candidate = "r/${digest.take(2)}/C${digest.drop(2).take(24)}"
        if (candidate !in reservedClassNames) return candidate
    }
    error("Unable to allocate collision-free sealed helper name for $originalName")
}



internal fun sealedRuntimeHelperInternalName(originalName: String): String {
    val index = SEALED_RUNTIME_HELPERS.indexOf(originalName)
    require(index >= 0) { "Unknown sealed runtime helper: $originalName" }
    return sealedHelperInternalName(RUNTIME_SEALING_SEED, originalName, index)
}

internal fun sealedRuntimeHelperMethodName(owner: String, name: String, descriptor: String): String =
    sealedMemberName(RUNTIME_SEALING_SEED, owner, name, descriptor, "m")

internal fun sealedRuntimeHelperFieldName(owner: String, name: String, descriptor: String): String =
    sealedMemberName(RUNTIME_SEALING_SEED, owner, name, descriptor, "f")
private fun sealedJavaOnlyHelperMemberRenamePlan(
    seed: Long,
    helperClassRenameMap: Map<String, String>,
): SealedHelperMemberRenamePlan {
    val methodRenames = linkedMapOf<SealedMemberRef, String>()
    val fieldRenames = linkedMapOf<SealedMemberRef, String>()

    fun addMethod(owner: String, name: String, descriptor: String) {
        val sealedOwner = helperClassRenameMap[owner] ?: return
        if (name == "<init>" || name == "<clinit>") return
        val sealedMethodName = sealedMemberName(seed, owner, name, descriptor, "m")
        for (candidate in listOf(owner, sealedOwner)) {
            methodRenames[SealedMemberRef(candidate, name, descriptor)] = sealedMethodName
        }
    }

    fun addField(owner: String, name: String, descriptor: String) {
        val sealedOwner = helperClassRenameMap[owner] ?: return
        val sealedFieldName = sealedMemberName(seed, owner, name, descriptor, "f")
        for (candidate in listOf(owner, sealedOwner)) {
            fieldRenames[SealedMemberRef(candidate, name, descriptor)] = sealedFieldName
        }
    }

    val exceptionHelper = "$PROTECTION_HELPER_PACKAGE/ExceptionVirtualizationHelper"
    addMethod(exceptionHelper, "shouldVirtualize", "()Z")
    addField(exceptionHelper, "enabled", "Z")
    val flowControlException = "$PROTECTION_HELPER_PACKAGE/FlowControlException"
    addMethod(flowControlException, "<init>", "()V")
    addMethod(flowControlException, "<init>", "(I)V")
    addMethod(flowControlException, "getState", "()I")
    addField(flowControlException, "state", "I")

    val stringStringVoid = "(Ljava/lang/String;Ljava/lang/String;)V"
    val stringVoid = "(Ljava/lang/String;)V"
    val byteArrayByteArray = "([B[B)[B"
    val antiDump = "$PROTECTION_HELPER_PACKAGE/AntiDumpHelper"
    addMethod(antiDump, "buildString", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[B)Ljava/lang/String;")
    addMethod(antiDump, "buildStringFromB64", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;)Ljava/lang/String;")
    addMethod(antiDump, "buildStringFromB64Condy", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;")
    addMethod(antiDump, "decodeString", "(Ljava/lang/String;)Ljava/lang/String;")
    addMethod(antiDump, "nativeBuildString", "([B)Ljava/lang/String;")
    addMethod(antiDump, "nativeBuildStringFromB64", "(Ljava/lang/String;)Ljava/lang/String;")
    addMethod(antiDump, "nativeDecodeString", "(Ljava/lang/String;)Ljava/lang/String;")

    val antiInstrumentation = "$PROTECTION_HELPER_PACKAGE/AntiInstrumentationHelper"
    addMethod(antiInstrumentation, "checkInstrumentation", stringStringVoid)
    addMethod(antiInstrumentation, "checkInstrumentationEx", stringStringVoid)
    addMethod(antiInstrumentation, "checkInstrumentationExSafe", stringStringVoid)
    addMethod(antiInstrumentation, "nativeCheckInstrumentation", stringStringVoid)

    val antiJvmTi = "$PROTECTION_HELPER_PACKAGE/AntiJvmTiHelper"
    addMethod(antiJvmTi, "checkJvmTiAgents", stringStringVoid)
    addMethod(antiJvmTi, "nativeCheckJvmTiAgents", stringStringVoid)

    val antiByteBuddy = "$PROTECTION_HELPER_PACKAGE/AntiByteBuddyHelper"
    addMethod(antiByteBuddy, "checkByteBuddy", stringVoid)
    addMethod(antiByteBuddy, "nativeCheckByteBuddy", stringVoid)

    val antiDumpRuntime = "$PROTECTION_HELPER_PACKAGE/AntiDumpRuntimeHelper"
    addMethod(antiDumpRuntime, "initializeProtection", stringVoid)
    addMethod(antiDumpRuntime, "initializeProtection", "(Ljava/lang/String;Ljava/lang/Class;)V")
    addMethod(antiDumpRuntime, "nativeInitializeProtection", stringVoid)
    addMethod(antiDumpRuntime, "nativeInitializeProtection", "(Ljava/lang/String;Ljava/lang/Class;)V")
    addMethod(antiDumpRuntime, "scrambleString", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
    addMethod(antiDumpRuntime, "unscrambleString", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
    addMethod(antiDumpRuntime, "scrambleBytes", "([BLjava/lang/String;Ljava/lang/String;)[B")
    addMethod(antiDumpRuntime, "unscrambleBytes", "([BLjava/lang/String;Ljava/lang/String;)[B")
    addMethod(antiDumpRuntime, "scrambleChars", "([CLjava/lang/String;Ljava/lang/String;)[C")
    addMethod(antiDumpRuntime, "unscrambleChars", "([CLjava/lang/String;Ljava/lang/String;)[C")

    val jniHelper = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
    addMethod(jniHelper, "loadKernel", "(Ljava/lang/String;Ljava/lang/String;)V")
    addMethod(jniHelper, "loadKernel", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")
    addMethod(jniHelper, "executeVmResource", "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(jniHelper, "executeVmResource", "(J[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(jniHelper, "executeVmResourceVoid", "(J)V")
    addMethod(jniHelper, "executeVmResourceIntVoid", "(JI)V")
    addMethod(jniHelper, "nativeInit", "(Ljava/lang/String;)I")
    addMethod(jniHelper, "nativeVerify", "([B[B)I")
    addMethod(jniHelper, "nativeHeartbeat", "()I")
    addMethod(jniHelper, "nativeGetVersion", "()Ljava/lang/String;")
    addMethod(jniHelper, "nativeGetBootToken", "()J")
    addMethod(jniHelper, "nativeInstallRuntimeResourceKey", "([B)V")
    addMethod(jniHelper, "nativePreloadRuntimeResources", "()V")
    addMethod(jniHelper, "nativeDecryptAes", "([B[B[B)[B")
    addMethod(jniHelper, "nativeExecuteVmResource", "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(jniHelper, "nativeExecuteVmResourceByToken", "(J[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(jniHelper, "nativeExecuteVmResourceVoid", "(J)V")
    addMethod(jniHelper, "nativeExecuteVmResourceIntVoid", "(JI)V")

    val bootstrap = "$PROTECTION_HELPER_PACKAGE/BootstrapEncryptionHelper"
    addMethod(bootstrap, "decryptBytes", "(Ljava/lang/String;Ljava/lang/String;)[B")
    addMethod(bootstrap, "encryptedBootstrap", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;")

    val classEncryption = "$PROTECTION_HELPER_PACKAGE/ClassEncryptionLoaderHelper"
    addMethod(classEncryption, "initializeClass", "(Ljava/lang/String;Ljava/lang/String;)V")

    val stringEncryption = "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper"
    addMethod(stringEncryption, "nativeDecodeString", "([BII)[B")

    val methodBody = "$PROTECTION_HELPER_PACKAGE/MethodBodyDecryptionHelper"
    addMethod(methodBody, "invokeEncrypted", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Class;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(methodBody, "invokeEncrypted", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Class;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(methodBody, "decryptBytes", "([B[BLjava/lang/String;)[B")

    val environment = "$PROTECTION_HELPER_PACKAGE/EnvironmentBindingHelper"
    addMethod(environment, "deriveKey", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
    addMethod(environment, "verifyEnvironment", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")
    addMethod(environment, "nativeDeriveKey", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
    addMethod(environment, "nativeVerifyEnvironment", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")


    return SealedHelperMemberRenamePlan(methodRenames = methodRenames, fieldRenames = fieldRenames)
}
private fun sealedHelperStringRewriteMap(seed: Long, helperClassRenameMap: Map<String, String>): Map<String, String> {
    val rewriteMap = linkedMapOf<String, String>()
    for ((originalName, sealedName) in helperClassRenameMap) {
        rewriteMap[originalName] = sealedName
        rewriteMap[originalName.replace('/', '.')] = sealedName.replace('/', '.')
    }
    val optionalJniHelper = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
    if (optionalJniHelper !in helperClassRenameMap) {
        rewriteMap[optionalJniHelper] = sealedSemanticText(seed, "optional-jni-helper-internal")
        rewriteMap[optionalJniHelper.replace('/', '.')] = sealedSemanticText(seed, "optional-jni-helper-binary")
    }
    if ("$PROTECTION_HELPER_PACKAGE/FlowControlException" in helperClassRenameMap) {
        rewriteMap["Flow control"] = sealedSemanticText(seed, "flow-control")
    }
    rewriteMap["__nvmr1__"] = sealedSemanticText(seed, "native-vm-result-marker")
    rewriteMap["native:abi-missing:nativeExecuteVmResource"] = sealedSemanticText(seed, "native-vm-abi-error")
    return rewriteMap
}

private fun sealedHelperMethodStringRewriteMap(helperMemberRenamePlan: SealedHelperMemberRenamePlan): Map<String, String> {
    val rewriteMap = linkedMapOf<String, String>()
    for ((ref, sealedName) in helperMemberRenamePlan.methodRenames) {
        if (ref.owner.startsWith(PROTECTION_HELPER_PACKAGE) && ref.name.startsWith("native")) {
            rewriteMap.putIfAbsent(ref.name, sealedName)
        }
    }
    return rewriteMap
}

private fun isDelayedMethodResource(entryName: String): Boolean =
    entryName.startsWith(LEGACY_DELAYED_METHOD_RESOURCE_ROOT) && entryName.endsWith(".enc")

private fun isClassEncryptionResource(entryName: String): Boolean =
    entryName.startsWith(LEGACY_CLASS_ENCRYPTION_RESOURCE_ROOT) && entryName.endsWith(".enc")

private fun isClassEncryptionManifestResource(entryName: String): Boolean =
    entryName == LEGACY_CLASS_ENCRYPTION_MANIFEST_RESOURCE

private fun isNativeKernelResource(entryName: String): Boolean =
    entryName.startsWith(LEGACY_NATIVE_RESOURCE_ROOT) &&
        (entryName.endsWith(".dll") || entryName.endsWith(".so") || entryName.endsWith(".dylib"))

private fun nativeSpecFor(entryName: String): SealedNativeSpec {
    val fileName = entryName.substringAfterLast('/')
    val loadSuffix = when {
        fileName.endsWith(".dll") -> ".dll"
        fileName.endsWith(".dylib") -> ".dylib"
        else -> ".so"
    }
    val platform = fileName
        .removePrefix("js_kernel_")
        .removeSuffix(".dll")
        .removeSuffix(".so")
        .removeSuffix(".dylib")
    return SealedNativeSpec(platform = platform, resourceName = entryName, loadSuffix = loadSuffix, storageSuffix = ".bin")
}

private fun sealedNativeIndexResourceName(seed: Long): String =
    sealedResourceName(seed, "i", "native-index", 0)

private fun sealedResourceRoot(seed: Long): String {
    val digest = sealedDigest(seed, "rr", "runtime-artifacts", 0)
    return "META-INF/${digest.take(2)}/${digest.drop(2).take(14)}"
}

private fun sealedResourceName(seed: Long, kind: String, originalName: String, index: Int): String {
    val digest = sealedDigest(seed, kind, originalName, index)
    return "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}${sealedInnocuousExtension(digest)}"
}

private fun sealedNativeResourceName(seed: Long, originalName: String, index: Int, suffix: String): String {
    val digest = sealedDigest(seed, "n", originalName, index)
    return "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}$suffix"
}

private fun uniqueSealedResourceName(
    seed: Long,
    kind: String,
    originalName: String,
    index: Int,
    preferredName: String,
    reservedEntryNames: Set<String>,
): String {
    if (preferredName !in reservedEntryNames) return preferredName
    for (attempt in 1..1024) {
        val digest = sealedDigest(seed, "$kind-c", "$originalName#$attempt", index)
        val candidate = "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}${sealedInnocuousExtension(digest)}"
        if (candidate !in reservedEntryNames) return candidate
    }
    error("Unable to allocate collision-free sealed resource name for $originalName")
}

private fun uniqueSealedNativeResourceName(
    seed: Long,
    originalName: String,
    index: Int,
    suffix: String,
    reservedEntryNames: Set<String>,
): String {
    val preferredName = sealedNativeResourceName(seed, originalName, index, suffix)
    if (preferredName !in reservedEntryNames) return preferredName
    for (attempt in 1..1024) {
        val digest = sealedDigest(seed, "n-c", "$originalName#$attempt", index)
        val candidate = "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}$suffix"
        if (candidate !in reservedEntryNames) return candidate
    }
    error("Unable to allocate collision-free sealed native resource name for $originalName")
}

private fun sealedHelperInternalName(seed: Long, originalName: String, index: Int): String {
    val digest = sealedDigest(seed, "h", originalName, index)
    return "r/${digest.take(2)}/C${digest.drop(2).take(24)}"
}

private fun sealedNestedHelperInternalName(seed: Long, sealedOuterName: String, originalName: String, index: Int): String {
    val digest = sealedDigest(seed, "hi", originalName, index)
    return "$sealedOuterName\$I${digest.take(16)}"
}

private fun sealedMemberName(seed: Long, owner: String, name: String, descriptor: String, kind: String): String {
    val digest = sealedDigest(seed, kind, "$owner#$name$descriptor", 0)
    return "${kind}_${digest.take(16)}"
}

private fun sealedSemanticText(seed: Long, value: String): String {
    val digest = sealedDigest(seed, "s", value, 0)
    return "x_${digest.take(16)}"
}

private fun sealedDigest(seed: Long, kind: String, value: String, index: Int): String =
    MessageDigest.getInstance("SHA-256")
        .digest("$seed|$kind|$index|$value".toByteArray(Charsets.UTF_8))
        .toHexLower()

private val SEALED_RESOURCE_EXTENSIONS = listOf(
    "properties", "xml", "json", "yml", "cfg", "conf", "ini", "txt"
)

private fun sealedInnocuousExtension(digest: String): String {
    val idx = (digest.hashCode() and 0x7FFFFFFF) % SEALED_RESOURCE_EXTENSIONS.size
    return "." + SEALED_RESOURCE_EXTENSIONS[idx]
}
private fun encodeSealedNativeIndex(
    specs: List<SealedNativeSpec>,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
    applicationMethodBindings: Map<SealedMemberRef, String> = emptyMap(),
): ByteArray {
    val lines = mutableListOf<String>()
    lines += specs.map { spec -> listOf(spec.platform, spec.resourceName, spec.loadSuffix).joinToString("|") }
    lines += helperClassRenameMap.map { (originalName, sealedName) -> listOf("B", sealedBindingKey(originalName), sealedName).joinToString("|") }
    lines += helperMemberRenamePlan.methodRenames
        .filter { (ref, _) -> ref.owner in helperClassRenameMap.keys }
        .map { (ref, sealedName) -> listOf("M", sealedBindingKey("${ref.owner}#${ref.name}#${ref.descriptor}"), sealedName).joinToString("|") }
    lines += applicationMethodBindings
        .map { (ref, renamedName) -> listOf("M", sealedBindingKey("${ref.owner}#${ref.name}#${ref.descriptor}"), renamedName).joinToString("|") }
    val plain = lines.joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
    return encodeBootstrapNativeIndex(plain)
}

private fun parseMethodRenameBindings(jarEntries: List<JarEntryData>): Map<SealedMemberRef, String> {
    val entry = jarEntries.firstOrNull { it.name == METHOD_RENAME_BINDINGS_RESOURCE } ?: return emptyMap()
    return entry.bytes.toString(Charsets.UTF_8)
        .lineSequence()
        .mapNotNull { line ->
            val parts = line.split('|')
            if (parts.size != 4) return@mapNotNull null
            SealedMemberRef(parts[0], parts[1], parts[2]) to parts[3]
        }
        .toMap(LinkedHashMap())
}

private fun expandMethodRenameBindingsAcrossFinalOwners(
    methodRenameBindings: Map<SealedMemberRef, String>,
    classArtifacts: List<ClassArtifact>,
): Map<SealedMemberRef, String> {
    if (methodRenameBindings.isEmpty()) return emptyMap()
    val expanded = LinkedHashMap<SealedMemberRef, String>()
    expanded.putAll(methodRenameBindings)
    val methodsByRenamedSignature = linkedMapOf<Pair<String, String>, MutableList<String>>()
    for (classArtifact in classArtifacts) {
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        for (method in node.methods) {
            val name = method.name ?: continue
            val desc = method.desc ?: continue
            methodsByRenamedSignature.getOrPut(name to desc) { mutableListOf() } += classArtifact.summary.internalName
        }
    }
    for ((ref, renamedName) in methodRenameBindings) {
        for (finalOwner in methodsByRenamedSignature[renamedName to ref.descriptor].orEmpty()) {
            expanded.putIfAbsent(SealedMemberRef(finalOwner, ref.name, ref.descriptor), renamedName)
            expanded.putIfAbsent(SealedMemberRef(finalOwner, renamedName, ref.descriptor), ref.name)
        }
    }
    return expanded
}

private fun collectApplicationMethodRenameBindings(
    classArtifacts: List<ClassArtifact>,
    helperClassRenameMap: Map<String, String>,
): Map<SealedMemberRef, String> {
    val helperNames = helperClassRenameMap.keys + helperClassRenameMap.values
    val bindings = linkedMapOf<SealedMemberRef, String>()
    for (classArtifact in classArtifacts) {
        val owner = classArtifact.summary.internalName
        if (owner in helperNames) continue
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        val declared = node.methods.map { it.name to it.desc }.toSet()
        for (method in node.methods) {
            val bridgeName = method.name ?: continue
            val descriptor = method.desc ?: continue
            val targetCall = pureSameOwnerForwarderTarget(owner, bridgeName, descriptor, method.access, method.instructions.asSequence().toList()) ?: continue
            if ((targetCall.name to descriptor) !in declared) continue
            bindings.putIfAbsent(SealedMemberRef(owner, bridgeName, descriptor), targetCall.name)
            bindings.putIfAbsent(SealedMemberRef(owner, targetCall.name, descriptor), bridgeName)
        }
    }
    return bindings
}


private fun pureSameOwnerForwarderTarget(
    owner: String,
    bridgeName: String,
    descriptor: String,
    access: Int,
    instructions: List<AbstractInsnNode>,
): MethodInsnNode? {
    val meaningful = instructions.filter { instruction ->
        instruction.opcode >= 0 && instruction.type != AbstractInsnNode.LINE && instruction.type != AbstractInsnNode.FRAME && instruction.type != AbstractInsnNode.LABEL
    }
    if (meaningful.isEmpty()) return null
    val callIndex = meaningful.indexOfFirst { instruction ->
        instruction is MethodInsnNode && instruction.owner == owner && instruction.desc == descriptor && instruction.name != bridgeName
    }
    if (callIndex < 0) return null
    val targetCall = meaningful[callIndex] as MethodInsnNode
    if (meaningful.count { it is MethodInsnNode } != 1) return null
    val argumentTypes = Type.getArgumentTypes(descriptor)
    val expectedLoads = mutableListOf<Int>()
    var localIndex = if (access and Opcodes.ACC_STATIC != 0) 0 else 1
    if (access and Opcodes.ACC_STATIC == 0) expectedLoads += Opcodes.ALOAD
    for (argumentType in argumentTypes) {
        expectedLoads += argumentType.getOpcode(Opcodes.ILOAD)
        localIndex += argumentType.size
    }
    val beforeCall = meaningful.take(callIndex)
    if (beforeCall.size != expectedLoads.size) return null
    for ((index, instruction) in beforeCall.withIndex()) {
        val load = instruction as? VarInsnNode ?: return null
        if (load.opcode != expectedLoads[index]) return null
    }
    val afterCall = meaningful.drop(callIndex + 1)
    if (afterCall.size != 1) return null
    val returnInsn = afterCall.single() as? InsnNode ?: return null
    if (returnInsn.opcode != Type.getReturnType(descriptor).getOpcode(Opcodes.IRETURN)) return null
    return targetCall
}

private fun encodeBootstrapNativeIndex(plain: ByteArray): ByteArray {
    val out = ByteArray(BOOTSTRAP_NATIVE_INDEX_HEADER_SIZE + plain.size + BOOTSTRAP_NATIVE_INDEX_MAC_LENGTH + 1)
    System.arraycopy(BOOTSTRAP_NATIVE_INDEX_MAGIC, 0, out, 0, BOOTSTRAP_NATIVE_INDEX_MAGIC.size)
    out[4] = BOOTSTRAP_NATIVE_INDEX_VERSION.toByte()
    writeBootstrapLe32(out, 5, plain.size)
    System.arraycopy(plain, 0, out, BOOTSTRAP_NATIVE_INDEX_HEADER_SIZE, plain.size)
    val tag = hmacBootstrapNativeIndex(out, 0, BOOTSTRAP_NATIVE_INDEX_HEADER_SIZE + plain.size)
    System.arraycopy(tag, 0, out, BOOTSTRAP_NATIVE_INDEX_HEADER_SIZE + plain.size, tag.size)
    out[out.lastIndex] = BOOTSTRAP_NATIVE_INDEX_MAC_LENGTH.toByte()
    return out
}

private fun hmacBootstrapNativeIndex(bytes: ByteArray, offset: Int, length: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    val key = requireVbc4BuildContext().copyRuntimeResourceKey()
    return try {
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        mac.update("jsbi-auth".toByteArray(Charsets.US_ASCII))
        mac.update(bytes, offset, length)
        mac.doFinal()
    } finally {
        Arrays.fill(key, 0)
    }
}

private fun writeBootstrapLe32(out: ByteArray, offset: Int, value: Int) {
    out[offset] = (value and 0xFF).toByte()
    out[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    out[offset + 2] = ((value ushr 16) and 0xFF).toByte()
    out[offset + 3] = ((value ushr 24) and 0xFF).toByte()
}

private fun sealedBindingKey(value: String): String {
    var hash = 0xCBF29CE484222325UL
    for (byte in value.toByteArray(Charsets.UTF_8)) {
        hash = hash xor (byte.toUByte().toULong())
        hash *= 0x100000001B3UL
    }
    return hash.toString(16).padStart(16, '0')
}


private fun isVirtualMachineRuntimeResource(bytes: ByteArray): Boolean {
    if (bytes.size >= 4 && bytes[0] == 'V'.code.toByte() && bytes[1] == 'B'.code.toByte() && bytes[2] == 'C'.code.toByte() && bytes[3] == '4'.code.toByte()) return true
    return bytes.decodeToString().startsWith("VBC4S|1|")
}

private fun legacyVirtualMachineResourceNames(jarEntries: List<JarEntryData>, priorRuntimeResourceKey: ByteArray?): Set<String> {
    val indexEntry = jarEntries.find { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE } ?: return emptySet()
    val decodedIndex = decodeRuntimeResourceWithPriorKey(indexEntry.bytes, priorRuntimeResourceKey) ?: return emptySet()
    return decodedIndex.decodeToString()
        .lineSequence()
        .mapNotNull { line ->
            val parts = line.split('|')
            if (parts.size >= 2 && parts[0] != "A") parts[1] else null
        }
        .toSet()
}

internal fun decodeRuntimeResourceWithPriorKey(bytes: ByteArray, priorRuntimeResourceKey: ByteArray?): ByteArray? {
    RuntimeResourceCodec.decode(bytes)?.let { return it }
    if (priorRuntimeResourceKey == null) return null
    return RuntimeResourceCodec.decodeWithKey(bytes, priorRuntimeResourceKey.copyOf())
}

internal fun priorRuntimeResourceKey(artifact: BytecodeArtifact): ByteArray? {
    val jniHelperName = sealedRuntimeHelperInternalName("$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper")
    val candidateBytes = buildList {
        artifact.classArtifacts.firstOrNull { it.summary.internalName == jniHelperName }?.let { add(it.bytes) }
        artifact.jarEntries.firstOrNull { it.name == "$jniHelperName.class" }?.let { add(it.bytes) }
        artifact.classArtifacts.forEach { classArtifact ->
            if (classArtifact.summary.internalName.startsWith("r/")) add(classArtifact.bytes)
        }
        artifact.jarEntries.forEach { entry ->
            if (entry.name.startsWith("r/") && entry.name.endsWith(".class")) add(entry.bytes)
        }
    }
    for (bytes in candidateBytes.distinctBy { it.contentHashCode() }) {
        val classNode = ClassNode()
        try {
            ClassReader(bytes).accept(classNode, ClassReader.SKIP_FRAMES)
            extractRuntimeResourceKeyFromHelper(classNode)?.let { return it }
        } catch (_: Exception) {
        }
    }
    return null
}

private fun extractRuntimeResourceKeyFromHelper(classNode: ClassNode): ByteArray? {
    val shareMethods = classNode.methods
        .filter { it.desc == "()[B" }
        .associateBy { it.name }
    val runtimeKeyMethod = shareMethods.values.firstOrNull { method ->
        method.instructions?.toArray().orEmpty().any { insn ->
            insn is MethodInsnNode && insn.owner == classNode.name && insn.name.startsWith("jsRrkShare") && insn.desc == "()[B"
        }
    } ?: return null
    val shareNames = runtimeKeyMethod.instructions.toArray()
        .filterIsInstance<MethodInsnNode>()
        .filter { it.owner == classNode.name && it.desc == "()[B" && it.name.startsWith("jsRrkShare") }
        .map { it.name }
    if (shareNames.isEmpty()) return null
    val shares = shareNames.map { name -> extractByteArrayReturn(shareMethods[name] ?: return null) ?: return null }
    val keySize = shares.first().size
    if (keySize != 32 || shares.any { it.size != keySize }) return null
    return ByteArray(keySize) { index ->
        shares.fold(0) { acc, share -> acc xor (share[index].toInt() and 0xFF) }.toByte()
    }
}

private fun extractByteArrayReturn(method: MethodNode): ByteArray? {
    val instructions = method.instructions?.toArray().orEmpty()
    val newArrayIndex = instructions.indexOfFirst { it is IntInsnNode && it.opcode == Opcodes.NEWARRAY && it.operand == Opcodes.T_BYTE }
    if (newArrayIndex <= 0) return null
    val size = pushIntValue(instructions[newArrayIndex - 1]) ?: return null
    if (size <= 0 || size > 4096) return null
    val bytes = ByteArray(size)
    var index = newArrayIndex + 1
    while (index < instructions.size) {
        if (instructions[index].opcode == Opcodes.ARETURN) return bytes
        if (index + 3 < instructions.size && instructions[index].opcode == Opcodes.DUP) {
            val byteIndex = pushIntValue(instructions[index + 1])
            val byteValue = pushIntValue(instructions[index + 2])
            if (byteIndex != null && byteValue != null && byteIndex in bytes.indices && instructions[index + 3].opcode == Opcodes.BASTORE) {
                bytes[byteIndex] = byteValue.toByte()
                index += 4
                continue
            }
        }
        index++
    }
    return null
}

private fun pushIntValue(insn: AbstractInsnNode): Int? = when (insn.opcode) {
    Opcodes.ICONST_M1 -> -1
    Opcodes.ICONST_0 -> 0
    Opcodes.ICONST_1 -> 1
    Opcodes.ICONST_2 -> 2
    Opcodes.ICONST_3 -> 3
    Opcodes.ICONST_4 -> 4
    Opcodes.ICONST_5 -> 5
    Opcodes.BIPUSH, Opcodes.SIPUSH -> (insn as? IntInsnNode)?.operand
    Opcodes.LDC -> (insn as? LdcInsnNode)?.cst as? Int
    else -> null
}


private fun rewriteVirtualMachineManifestEntry(entry: JarEntryData, resourceRenameMap: Map<String, String>): JarEntryData {
    if (resourceRenameMap.isEmpty()) return entry
    val decoded = RuntimeResourceCodec.decode(entry.bytes) ?: return entry
    val text = decoded.decodeToString()
    if (!text.startsWith("VBC4S|1|")) return entry
    val lines = text.trimEnd(0x0A.toChar(), 0x0D.toChar()).lines()
    if (lines.isEmpty()) return entry
    val rewritten = buildString {
        append(lines.first()).append("\n")
        for (line in lines.drop(1)) {
            if (line.isBlank()) continue
            val parts = line.split('|').toMutableList()
            if (parts.size >= 5) parts[4] = resourceRenameMap[parts[4]] ?: parts[4]
            append(parts.joinToString("|")).append("\n")
        }
    }
    val resourceSeed = MessageDigest.getInstance("SHA-256")
        .digest(rewritten.toByteArray(Charsets.UTF_8))
        .take(4)
        .fold(0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }
    return entry.copy(bytes = RuntimeResourceCodec.encode(
        bytes = rewritten.toByteArray(Charsets.UTF_8),
        kind = RuntimeResourceKind.VmBytecode,
        seed = resourceSeed,
        variantId = resourceRenameMap.size.coerceAtLeast(1),
        layerCount = 3,
        compress = true,
    ))
}

private fun rewriteVirtualMachinePreloadIndex(jarEntries: List<JarEntryData>, resourceRenameMap: Map<String, String>, priorRuntimeResourceKey: ByteArray?): ByteArray? {
    val indexEntry = jarEntries.find { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE } ?: return null
    val decodedIndex = decodeRuntimeResourceWithPriorKey(indexEntry.bytes, priorRuntimeResourceKey) ?: return null
    val rewrittenLines = decodedIndex.decodeToString()
        .lineSequence()
        .filter { it.isNotBlank() }
        .map { line ->
            val parts = line.split('|')
            if (parts.size < 2) return@map line
            val resourcePath = parts[1]
            val manifestPath = parts.getOrNull(2) ?: resourcePath
            val shardCount = parts.getOrNull(3) ?: "0"
            val sealedResourcePath = resourceRenameMap[resourcePath] ?: resourcePath
            val sealedManifestPath = resourceRenameMap[manifestPath] ?: manifestPath
            listOf(parts[0], sealedResourcePath, sealedManifestPath, shardCount, resourcePath, manifestPath).joinToString("|")
        }
        .toList()
    val aliasLines = resourceRenameMap.entries.map { (original, sealed) -> listOf("A", original, sealed).joinToString("|") }
    val lineBreak = 0x0A.toChar().toString()
    val rewrittenIndex = (rewrittenLines + aliasLines).joinToString(separator = lineBreak, postfix = lineBreak)
    val resourceSeed = MessageDigest.getInstance("SHA-256")
        .digest(rewrittenIndex.toByteArray(Charsets.UTF_8))
        .take(4)
        .fold(0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }
    return RuntimeResourceCodec.encode(
        bytes = rewrittenIndex.toByteArray(Charsets.UTF_8),
        kind = RuntimeResourceKind.NativeIndex,
        seed = resourceSeed,
        variantId = resourceRenameMap.size.coerceAtLeast(1),
        layerCount = 3,
        compress = true,
    )
}

private fun encodeSealedClassEncryptionManifest(bytes: ByteArray, resourceRenameMap: Map<String, String>): ByteArray {
    val rewritten = String(bytes, Charsets.UTF_8)
        .lineSequence()
        .filter { it.isNotEmpty() }
        .joinToString(separator = "\n", postfix = "\n") { line ->
            val columns = line.split('	')
            if (columns.size < 3) {
                line
            } else {
                val className = columns[0]
                val originalResourcePath = columns[1]
                val sealedResourcePath = resourceRenameMap[originalResourcePath] ?: originalResourcePath
                val metadata = rewriteClassEncryptionMetadataForResource(className, originalResourcePath, sealedResourcePath, columns[2])
                listOf(className, sealedResourcePath, metadata).joinToString("	")
            }
        }
        .toByteArray(Charsets.UTF_8)
    val resourceSeed = MessageDigest.getInstance("SHA-256")
        .digest(rewritten)
        .take(4)
        .fold(0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }
    return RuntimeResourceCodec.encode(
        bytes = rewritten,
        kind = RuntimeResourceKind.Manifest,
        seed = resourceSeed,
        variantId = resourceRenameMap.size.coerceAtLeast(1),
        layerCount = 3,
        compress = true,
    )
}

private fun rewriteClassEncryptionMetadataForResource(
    className: String,
    originalResourcePath: String,
    sealedResourcePath: String,
    keyMetadata: String,
): String {
    if (originalResourcePath == sealedResourcePath) return keyMetadata
    val parts = keyMetadata.split(':')
    if (parts.size != 6 || parts[0] != "v2") return keyMetadata
    val strategy = parts[1]
    val expectedHash = runCatching { Base64.getDecoder().decode(parts[5]) }.getOrNull() ?: return keyMetadata
    val keyMode = listOf("per-class", "global")
        .firstOrNull { candidate ->
            Arrays.equals(
                MessageDigest.getInstance("SHA-256").digest(classEncryptionRewriteAad(className, originalResourcePath, strategy, candidate)),
                expectedHash,
            )
        }
        ?: return keyMetadata
    val sealedAadHash = MessageDigest.getInstance("SHA-256")
        .digest(classEncryptionRewriteAad(className, sealedResourcePath, strategy, keyMode))
    return listOf(
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
        Base64.getEncoder().encodeToString(sealedAadHash),
    ).joinToString(":")
}

private fun rewriteClassArtifact(
    classArtifact: ClassArtifact,
    seed: Long,
    helperStringRewriteMap: Map<String, String>,
    resourceStringRewriteMap: Map<String, String>,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
): ClassArtifact? {
    if (isPriorSealedRuntimeArtifact(classArtifact)) return null
    var currentArtifact = classArtifact
    var modified = false
    rewriteSealedNativeVmDispatchCallsites(currentArtifact, helperClassRenameMap)?.let { rewrittenArtifact ->
        currentArtifact = rewrittenArtifact
        modified = true
    }
    remapHelperReferences(currentArtifact, helperClassRenameMap, helperMemberRenamePlan)?.let { remappedArtifact ->
        currentArtifact = remappedArtifact
        modified = true
    }
    scrubRelocatedHelperMetadata(currentArtifact, helperClassRenameMap)?.let { scrubbedArtifact ->
        currentArtifact = scrubbedArtifact
        modified = true
    }
    val effectiveStringRewriteMap = if (currentArtifact.summary.internalName in helperClassRenameMap.values) {
        helperStringRewriteMap + resourceStringRewriteMap + sealedHelperMethodStringRewriteMap(helperMemberRenamePlan)
    } else {
        resourceStringRewriteMap
    }
    rewriteClassStringConstants(currentArtifact, seed, effectiveStringRewriteMap)?.let { rewrittenArtifact ->
        currentArtifact = rewrittenArtifact
        modified = true
    }
    return if (modified) currentArtifact else null
}

private fun isPriorSealedRuntimeArtifact(classArtifact: ClassArtifact): Boolean {
    if (!classArtifact.summary.internalName.startsWith("r/")) return false
    if (hasPriorSealedRuntimeNameShape(classArtifact.summary.internalName)) return true
    val classNode = ClassNode()
    return try {
        ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        isPriorSealedRuntimeClassNode(classNode)
    } catch (_: Exception) {
        false
    }
}

private fun hasPriorSealedRuntimeNameShape(internalName: String): Boolean {
    val parts = internalName.split('/')
    if (parts.size != 3 || parts[1].length != 2) return false
    val simpleName = parts[2]
    if (!simpleName.startsWith('C')) return false
    val outerName = simpleName.substringBefore('$')
    if (outerName.length < 10) return false
    return '$' !in simpleName || simpleName.substringAfter('$').startsWith('I')
}

private fun isPriorSealedRuntimeClassNode(classNode: ClassNode): Boolean {
    var hasKernelComponentString = false
    var hasKernelPlatformString = false
    var hasKernelVmModeString = false
    var invokesKernelLoaderShape = false
    var invokesVmDispatchShape = false
    for (method in classNode.methods) {
        for (instruction in method.instructions?.toArray().orEmpty()) {
            when (instruction) {
                is org.objectweb.asm.tree.LdcInsnNode -> {
                    val value = instruction.cst as? String ?: continue
                    if (value in setOf("loader", "decrypt", "vm", "guards", "all")) hasKernelComponentString = true
                    if (value in setOf("auto", "windows-x64", "linux-x64", "macos-x64", "macos-arm64")) hasKernelPlatformString = true
                    if (value in setOf("vm-diverse", "vm-off")) hasKernelVmModeString = true
                }
                is MethodInsnNode -> {
                    if (instruction.opcode == Opcodes.INVOKESTATIC && instruction.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V") {
                        invokesKernelLoaderShape = true
                    }
                    if (instruction.opcode == Opcodes.INVOKESTATIC && instruction.owner.startsWith("r/") && instruction.name.startsWith("m_") &&
                        instruction.desc in setOf(
                            "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
                            "(J[Ljava/lang/Object;)Ljava/lang/Object;",
                            "(J)V",
                            "(JI)V",
                        )
                    ) {
                        invokesVmDispatchShape = true
                    }
                }
            }
        }
    }
    return invokesVmDispatchShape || (invokesKernelLoaderShape && hasKernelComponentString && hasKernelPlatformString && hasKernelVmModeString)
}

private fun remapHelperReferences(
    classArtifact: ClassArtifact,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
): ClassArtifact? {
    if (helperClassRenameMap.isEmpty() && helperMemberRenamePlan.methodRenames.isEmpty() && helperMemberRenamePlan.fieldRenames.isEmpty()) return null
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val remapper = object : Remapper(Opcodes.ASM9) {
        override fun map(internalName: String?): String? {
            val replacement = internalName?.let { helperClassRenameMap[it] }
            if (replacement != null) modified = true
            return replacement ?: internalName
        }

        override fun mapMethodName(owner: String?, name: String?, descriptor: String?): String? {
            val replacement = helperMemberRenamePlan.methodName(owner, name, descriptor)
            if (replacement != name) modified = true
            return replacement
        }

        override fun mapFieldName(owner: String?, name: String?, descriptor: String?): String? {
            val replacement = helperMemberRenamePlan.fieldName(owner, name, descriptor)
            if (replacement != name) modified = true
            return replacement
        }
    }
    return try {
        reader.accept(ClassRemapper(writer, remapper), 0)
        var updatedBytes = if (modified) writer.toByteArray() else classArtifact.bytes
        val remappedClassName = ClassReader(updatedBytes).className
        if (
            classArtifact.summary.internalName in helperClassRenameMap.keys ||
            classArtifact.summary.internalName in helperClassRenameMap.values ||
            remappedClassName in helperClassRenameMap.values
        ) {
            val classNode = ClassNode()
            ClassReader(updatedBytes).accept(classNode, 0)
            var helperMemberModified = false
            for (field in classNode.fields) {
                val replacement = helperMemberRenamePlan.fieldName(classNode.name, field.name, field.desc)
                if (replacement != null && replacement != field.name) {
                    field.name = replacement
                    helperMemberModified = true
                }
            }
            for (method in classNode.methods) {
                val replacement = helperMemberRenamePlan.methodName(classNode.name, method.name, method.desc)
                if (replacement != null && replacement != method.name) {
                    method.name = replacement
                    helperMemberModified = true
                }
            }
            if (helperMemberModified) {
                val helperWriter = ClassWriter(0)
                classNode.accept(helperWriter)
                updatedBytes = helperWriter.toByteArray()
                modified = true
            }
        }
        if (!modified) {
            null
        } else {
            val updatedSummary = analyzeClassBytes(updatedBytes)
            classArtifact.copy(
                entryName = "${updatedSummary.internalName}.class",
                summary = updatedSummary,
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}

private fun scrubRelocatedHelperMetadata(
    classArtifact: ClassArtifact,
    helperClassRenameMap: Map<String, String>,
): ClassArtifact? {
    if (classArtifact.summary.internalName !in helperClassRenameMap.values) return null
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
        override fun visitSource(source: String?, debug: String?) {
            if (source != null || debug != null) {
                modified = true
                return
            }
            super.visitSource(source, debug)
        }
    }
    return try {
        reader.accept(visitor, 0)
        if (!modified) {
            null
        } else {
            val updatedBytes = writer.toByteArray()
            classArtifact.copy(
                summary = analyzeClassBytes(updatedBytes),
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}
private fun rewriteSealedNativeVmDispatchCallsites(
    classArtifact: ClassArtifact,
    helperClassRenameMap: Map<String, String>,
): ClassArtifact? {
    val originalOwner = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
    val sealedOwner = helperClassRenameMap[originalOwner] ?: return null
    if (classArtifact.summary.internalName == originalOwner || classArtifact.summary.internalName == sealedOwner) return null
    val legacyVmDispatchDescriptor = "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"
    val tokenVmDispatchDescriptor = "(J[Ljava/lang/Object;)Ljava/lang/Object;"
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<String>?,
        ): MethodVisitor {
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, mv) {
                override fun visitMethodInsn(
                    opcode: Int,
                    owner: String,
                    name: String,
                    methodDescriptor: String,
                    isInterface: Boolean,
                ) {
                    if (
                        opcode == Opcodes.INVOKESTATIC &&
                        (owner == originalOwner || owner == sealedOwner) &&
                        ((name == "nativeExecuteVmResource" && methodDescriptor == legacyVmDispatchDescriptor) ||
                            (name == "nativeExecuteVmResourceByToken" && methodDescriptor == tokenVmDispatchDescriptor))
                    ) {
                        modified = true
                        super.visitMethodInsn(opcode, owner, "executeVmResource", methodDescriptor, false)
                    } else {
                        super.visitMethodInsn(opcode, owner, name, methodDescriptor, isInterface)
                    }
                }
            }
        }
    }
    return try {
        reader.accept(visitor, 0)
        if (!modified) {
            null
        } else {
            val updatedBytes = writer.toByteArray()
            classArtifact.copy(
                summary = analyzeClassBytes(updatedBytes),
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}
private fun rewriteClassStringConstants(
    classArtifact: ClassArtifact,
    seed: Long,
    stringRewriteMap: Map<String, String>,
): ClassArtifact? {
    if (stringRewriteMap.isEmpty()) return null
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
        override fun visitField(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            value: Any?,
        ): FieldVisitor {
            val replacement = if (value is String) sealedReplacementForString(value, seed, stringRewriteMap) else null
            return if (replacement != null) {
                modified = true
                super.visitField(access, name, descriptor, signature, replacement)
            } else {
                super.visitField(access, name, descriptor, signature, value)
            }
        }

        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<String>?,
        ): MethodVisitor {
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, mv) {
                override fun visitLdcInsn(value: Any?) {
                    val replacement = if (value is String) sealedReplacementForString(value, seed, stringRewriteMap) else null
                    if (replacement != null) {
                        modified = true
                        super.visitLdcInsn(replacement)
                    } else {
                        super.visitLdcInsn(value)
                    }
                }
            }
        }
    }
    return try {
        reader.accept(visitor, 0)
        if (!modified) {
            null
        } else {
            val updatedBytes = writer.toByteArray()
            classArtifact.copy(
                summary = analyzeClassBytes(updatedBytes),
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}


// --- Encrypted class bytecode rewriting ---

/**
 * Parse the class encryption manifest to extract encryption keys for each encrypted class.
 * Returns a map of resourcePath -> AEAD rewrite key material.
 */
private data class ClassEncryptionRewriteKey(
    val className: String,
    val strategy: String,
    val keyMode: String,
    val keyId: ByteArray,
    val salt: ByteArray,
    val key: ByteArray,
    val nonce: ByteArray,
    val aad: ByteArray,
)

private fun parseClassEncryptionManifest(jarEntries: List<JarEntryData>): Map<String, ClassEncryptionRewriteKey> {
    val manifest = jarEntries.find { isClassEncryptionManifestResource(it.name) } ?: return emptyMap()
    val buildContext = requireVbc4BuildContext()
    val result = linkedMapOf<String, ClassEncryptionRewriteKey>()
    for (line in String(manifest.bytes, Charsets.UTF_8).lines()) {
        if (line.isEmpty()) continue
        val cols = line.split('\t')
        if (cols.size < 3) continue
        val className = cols[0]
        val resourcePath = cols[1]
        val keyMetadata = cols[2]
        val parts = keyMetadata.split(':')
        if (parts.size != 6 || parts[0] != "v2") continue
        val strategy = parts[1]
        val keyId = Base64.getDecoder().decode(parts[2])
        val salt = Base64.getDecoder().decode(parts[3])
        val nonce = Base64.getDecoder().decode(parts[4])
        val expectedHash = Base64.getDecoder().decode(parts[5])
        val aad = listOf("per-class", "global")
            .map { keyMode -> keyMode to classEncryptionRewriteAad(className, resourcePath, strategy, keyMode) }
            .firstOrNull { (_, candidate) -> Arrays.equals(MessageDigest.getInstance("SHA-256").digest(candidate), expectedHash) }
            ?: continue
        if (nonce.size != 12) continue
        val key = deriveClassEncryptionKey(buildContext, strategy, keyId, salt)
        result[resourcePath] = ClassEncryptionRewriteKey(
            className = className,
            strategy = strategy,
            keyMode = aad.first,
            keyId = keyId,
            salt = salt,
            key = key,
            nonce = nonce,
            aad = aad.second,
        )
    }
    return result
}

/**
 * Rewrite encrypted class bytecode to update helper class references after sealing.
 * Decrypts the class, rewrites string constants, and re-encrypts.
 */
private fun rewriteEncryptedClassBytes(
    encryptedBytes: ByteArray,
    resourceName: String,
    sealedResourceName: String,
    classEncryptionKeys: Map<String, ClassEncryptionRewriteKey>,
    stringRewriteMap: Map<String, String>,
    seed: Long,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
): ByteArray {
    if (classEncryptionKeys.isEmpty() || stringRewriteMap.isEmpty()) return encryptedBytes
    val keyInfo = classEncryptionKeys[resourceName] ?: return encryptedBytes
    val sealedKeyInfo = keyInfo.copy(
        aad = classEncryptionRewriteAad(keyInfo.className, sealedResourceName, keyInfo.strategy, keyInfo.keyMode),
    )
    // Decrypt the class bytecode
    val decryptedBytes = try {
        decryptClassBytesForRewrite(encryptedBytes, keyInfo)
    } catch (_: Exception) {
        return encryptedBytes
    } ?: return encryptedBytes
    // Rewrite string constants and helper references in the decrypted bytecode
    val rewrittenBytes = try {
        rewriteEncryptedClassBytecode(decryptedBytes, seed, stringRewriteMap, helperClassRenameMap, helperMemberRenamePlan)
    } catch (_: Exception) {
        decryptedBytes
    }
    // Re-encrypt the rewritten bytecode
    return try {
        encryptClassBytesForSealing(rewrittenBytes, sealedKeyInfo)
    } catch (_: Exception) {
        encryptedBytes
    }
}

private fun decryptClassBytesForRewrite(data: ByteArray, keyInfo: ClassEncryptionRewriteKey): ByteArray? {
    require(keyInfo.strategy == "aes-128" || keyInfo.strategy == "aes-256") { "Unsupported encryption strategy: ${keyInfo.strategy}" }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(keyInfo.key, "AES")
    cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, keyInfo.nonce))
    cipher.updateAAD(keyInfo.aad)
    return cipher.doFinal(data)
}

private fun encryptClassBytesForSealing(data: ByteArray, keyInfo: ClassEncryptionRewriteKey): ByteArray {
    require(keyInfo.strategy == "aes-128" || keyInfo.strategy == "aes-256") { "Unsupported encryption strategy: ${keyInfo.strategy}" }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(keyInfo.key, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, keyInfo.nonce))
    cipher.updateAAD(keyInfo.aad)
    return cipher.doFinal(data)
}

private fun classEncryptionRewriteAad(className: String, resourcePath: String, strategy: String, keyMode: String): ByteArray =
    "javashroud:class-encryption:v2:$className:$resourcePath:$strategy:$keyMode:sealed-runtime".toByteArray(Charsets.UTF_8)

/**
 * Rewrite string constants and helper references in decrypted class bytecode.
 */
private fun rewriteEncryptedClassBytecode(
    classBytes: ByteArray,
    seed: Long,
    stringRewriteMap: Map<String, String>,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
): ByteArray {
    val reader = ClassReader(classBytes)
    val writer = ClassWriter(0)
    var modified = false
    // First remap helper class references
    val remapper = object : org.objectweb.asm.commons.Remapper(org.objectweb.asm.Opcodes.ASM9) {
        override fun map(internalName: String?): String? {
            val replacement = internalName?.let { helperClassRenameMap[it] }
            if (replacement != null) modified = true
            return replacement ?: internalName
        }
        override fun mapMethodName(owner: String?, name: String?, descriptor: String?): String? {
            val replacement = helperMemberRenamePlan.methodName(owner, name, descriptor)
            if (replacement != name) modified = true
            return replacement
        }
        override fun mapFieldName(owner: String?, name: String?, descriptor: String?): String? {
            val replacement = helperMemberRenamePlan.fieldName(owner, name, descriptor)
            if (replacement != name) modified = true
            return replacement
        }
    }
    val remappedWriter = ClassWriter(0)
    reader.accept(org.objectweb.asm.commons.ClassRemapper(remappedWriter, remapper), 0)
    val remappedBytes = if (modified) remappedWriter.toByteArray() else classBytes
    // Then rewrite string constants
    val stringReader = ClassReader(remappedBytes)
    val stringWriter = ClassWriter(0)
    var stringModified = false
    val visitor = object : ClassVisitor(org.objectweb.asm.Opcodes.ASM9, stringWriter) {
        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?): MethodVisitor {
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(org.objectweb.asm.Opcodes.ASM9, mv) {
                override fun visitLdcInsn(value: Any?) {
                    val replacement = if (value is String) sealedReplacementForString(value, seed, stringRewriteMap) else null
                    if (replacement != null) {
                        stringModified = true
                        super.visitLdcInsn(replacement)
                    } else {
                        super.visitLdcInsn(value)
                    }
                }
            }
        }
    }
    stringReader.accept(visitor, 0)
    return if (stringModified) stringWriter.toByteArray() else remappedBytes
}

private fun sealedReplacementForString(value: String, seed: Long, stringRewriteMap: Map<String, String>): String? {
    stringRewriteMap[value]?.let { return it }
    return null
}
