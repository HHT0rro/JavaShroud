package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.artifact.classSummaryIndex
import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import org.objectweb.asm.*

/**
 * Embedded Runtime Helper Deployment.
 *
 * Generates standalone Java helper classes using ASM and injects them into
 * the output JAR so that protection transforms have their runtime dependencies
 * available when the obfuscated JAR runs.
 *
 * Each helper is a self-contained Java class with zero external dependencies
 * beyond the JDK standard library. No Kotlin runtime required.
 */
object EmbeddedHelperDeployment {

    private const val PKG = "io/github/hht0rro/javashroud/transforms/protection"
    private const val HELPER_RESOURCE_ROOT = "META-INF/javashroud-helpers"
    /**
     * New AKEN v4 outputs must not retain a legacy boot envelope or an embedded
     * boot-KEK sidecar from an input/intermediate artifact.  These paths are
     * cleanup-only; this deployment layer does not emit a replacement manifest
     * until the native handle ABI can consume one.
     */
    private val legacyBootResourcePaths = setOf(
        "META-INF/.r/boot.dat",
        "META-INF/.r/kek.dat",
    )
    /**
     * The AKEN v4 helper set deliberately omits legacy boot/resource decoder
     * nested classes.  The outer helper is regenerated below with only the
     * typed current-page surface and its relocation/lambda support closure.
     */
    private val akenRuntimeHelpers = listOf(
        "$PKG/JniMicrokernelHelper",
        "$PKG/JniMicrokernelHelper${"$"}AkenNativeLibrary",
        "$PKG/JniMicrokernelHelper${"$"}TypeParseResult",
        "$PKG/JniMicrokernelHelper${"$"}SamLambdaOptions",
        "$PKG/JniMicrokernelHelper${"$"}SamInvocationHandler",
    )
    /**
     * Class-encryption uses this set only for its per-class AKEN descriptor
     * route. The helper has no central catalog or generic resource decoder;
     * nested classes are emitted explicitly so the relocated runtime can resolve
     * the parser's private implementation types.
     */
    private val akenClassPageRuntimeHelpers = listOf(
        "$PKG/AkenClassPageRuntimeDescriptor",
        "$PKG/AkenClassPageRuntimeDescriptor${"$"}PageBinding",
        "$PKG/AkenClassPageRuntimeDescriptor${"$"}DescriptorReader",
        "$PKG/AkenClassPageRuntimeDescriptor${"$"}WipableByteAccumulator",
    )

    /**
     * Entries that are regenerated for an AKEN production closure. A
     * pre-existing legacy helper must not short-circuit generation of the
     * typed-only replacement or leak its nested metadata carrier into output.
     */
    private val akenProductionHelperEntryNames = (
        akenRuntimeHelpers +
            akenClassPageRuntimeHelpers +
            listOf(
                "$PKG/ClassEncryptionLoaderHelper",
                "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader",
                "$PKG/ClassEncryptionLoaderHelper${"$"}ParsedMetadata",
                "$PKG/JniMicrokernelHelper${"$"}RuntimeResourceMetadata",
                "$PKG/JniMicrokernelHelper${"$"}SealedNativeLibrary",
            )
        ).mapTo(linkedSetOf()) { "$it.class" }

    private val passToHelpers: Map<String, List<String>> = mapOf(
        "class-encryption-loader" to listOf(
            "$PKG/ClassEncryptionLoaderHelper",
            "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader",
        ) + akenClassPageRuntimeHelpers + akenRuntimeHelpers,
        "string-encryption" to listOf(
            "$PKG/StringEncryptionHelper",
            "$PKG/StringEncryptionHelper${"$"}CachePolicy",
        ),
        "method-body-delayed-decryption" to listOf(
            "$PKG/MethodBodyDecryptionHelper",
            "$PKG/MethodBodyDecryptionHelper${"$"}ParsedMetadata",
        ) + akenRuntimeHelpers,
        "callsite-rotation-protection" to listOf("$PKG/CallsiteRotationHelper"),
        "environment-bound-keys" to listOf("$PKG/EnvironmentBindingHelper"),
        "anti-symbolic-execution" to listOf("$PKG/AntiSymbolicExecutionHelper"),
        "exception-semantic-virtualization" to listOf(
            "$PKG/ExceptionVirtualizationHelper",
            "$PKG/FlowControlException",
        ),
        "anti-instrumentation" to listOf("$PKG/AntiInstrumentationHelper"),
        "anti-dump-protection" to listOf("$PKG/AntiDumpRuntimeHelper"),
        "jni-microkernel-loader" to akenRuntimeHelpers,
        "method-virtualization" to emptyList(),
    )
    private val helperGenerators: Map<String, () -> ByteArray> by lazy {
        mapOf(
            "$PKG/ClassEncryptionLoaderHelper" to { loadClasspathHelperByName("ClassEncryptionLoaderHelper") },
            "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader" to { loadClasspathHelperByName("ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader") },
            "$PKG/AkenClassPageRuntimeDescriptor" to { loadClasspathHelperByName("AkenClassPageRuntimeDescriptor") },
            "$PKG/AkenClassPageRuntimeDescriptor${"$"}PageBinding" to { loadClasspathHelperByName("AkenClassPageRuntimeDescriptor${"$"}PageBinding") },
            "$PKG/AkenClassPageRuntimeDescriptor${"$"}DescriptorReader" to { loadClasspathHelperByName("AkenClassPageRuntimeDescriptor${"$"}DescriptorReader") },
            "$PKG/AkenClassPageRuntimeDescriptor${"$"}WipableByteAccumulator" to { loadClasspathHelperByName("AkenClassPageRuntimeDescriptor${"$"}WipableByteAccumulator") },
            "$PKG/MethodBodyDecryptionHelper" to { loadClasspathHelperByName("MethodBodyDecryptionHelper") },
            "$PKG/MethodBodyDecryptionHelper${"$"}ParsedMetadata" to { loadClasspathHelperByName("MethodBodyDecryptionHelper${"$"}ParsedMetadata") },
            "$PKG/StringEncryptionHelper" to { loadClasspathHelperByName("StringEncryptionHelper") },
            "$PKG/StringEncryptionHelper${"$"}CachePolicy" to { loadClasspathHelperByName("StringEncryptionHelper${"$"}CachePolicy") },
            "$PKG/BootstrapEncryptionHelper" to { loadClasspathHelperByName("BootstrapEncryptionHelper") },
            "$PKG/CallsiteRotationHelper" to ::generateCallsiteRotationHelper,
            "$PKG/EnvironmentBindingHelper" to { loadClasspathHelperByName("EnvironmentBindingHelper") },
            "$PKG/AntiDumpRuntimeHelper" to { loadClasspathHelperByName("AntiDumpRuntimeHelper") },
            "$PKG/AntiSymbolicExecutionHelper" to { generateSimpleHelper("$PKG/AntiSymbolicExecutionHelper") },
            "$PKG/ExceptionVirtualizationHelper" to ::generateExceptionVirtualizationHelper,
            "$PKG/FlowControlException" to ::generateFlowControlException,
            "$PKG/AntiInstrumentationHelper" to { loadClasspathHelperByName("AntiInstrumentationHelper") },
            "$PKG/AntiJvmTiHelper" to { loadClasspathHelperByName("AntiJvmTiHelper") },
            "$PKG/AntiDumpHelper" to { loadClasspathHelperByName("AntiDumpHelper") },
            "$PKG/AntiByteBuddyHelper" to { loadClasspathHelperByName("AntiByteBuddyHelper") },
            "$PKG/JniMicrokernelHelper" to { loadClasspathHelperByName("JniMicrokernelHelper") },
            "$PKG/JniMicrokernelHelper${"$"}RuntimeResourceMetadata" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}RuntimeResourceMetadata") },
            "$PKG/JniMicrokernelHelper${"$"}SealedNativeLibrary" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}SealedNativeLibrary") },
            "$PKG/JniMicrokernelHelper${"$"}AkenNativeLibrary" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}AkenNativeLibrary") },
            "$PKG/JniMicrokernelHelper${"$"}TypeParseResult" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}TypeParseResult") },
            "$PKG/JniMicrokernelHelper${"$"}SamLambdaOptions" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}SamLambdaOptions") },
            "$PKG/JniMicrokernelHelper${"$"}SamInvocationHandler" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}SamInvocationHandler") },
        )
    }

    /**
     * Inject required runtime helper classes into the bytecode artifact.
     */
    fun injectRequiredHelpers(
        artifact: BytecodeArtifact,
        executedPassIds: List<String>,
    ): BytecodeArtifact {
        val resolvedPassIds = resolvePassIdsWithSchemaDependencies(executedPassIds)
        val akenRuntimeDeployment = "jni-microkernel-loader" in resolvedPassIds
        val existingEntries = artifact.jarEntries
            .asSequence()
            .filterNot { entry -> akenRuntimeDeployment && entry.name in akenProductionHelperEntryNames }
            .map { entry -> entry.name }
            .toSet()
        val neededHelpers = sortedSetOf<String>()
        for (passId in resolvedPassIds) {
            passToHelpers[passId]?.let { neededHelpers.addAll(it) }
        }
        if (neededHelpers.isEmpty()) return artifact
        val newEntries = mutableListOf<JarEntryData>()
        val generationFailures = mutableListOf<String>()
        for (helperInternalName in neededHelpers) {
            val entryName = "$helperInternalName.class"
            if (entryName in existingEntries) continue
            val classBytes = try {
                loadHelperBytes(helperInternalName, akenRuntimeDeployment)
            } catch (error: Exception) {
                generationFailures.add("$entryName (${error::class.java.simpleName}: ${error.message ?: "unknown error"})")
                continue
            }
            newEntries.add(JarEntryData(name = entryName, bytes = classBytes))
        }
        if (generationFailures.isNotEmpty()) {
            throw IllegalStateException(
                "Failed to embed runtime helpers for passes ${executedPassIds.sorted()}: ${generationFailures.joinToString("; ")}"
            )
        }
        val retainedJarEntries = if (akenRuntimeDeployment) {
            artifact.jarEntries.filterNot { entry ->
                entry.name in legacyBootResourcePaths || entry.name in akenProductionHelperEntryNames
            }
        } else {
            artifact.jarEntries
        }
        val retainedClassArtifacts = if (akenRuntimeDeployment) {
            artifact.classArtifacts.filterNot { classArtifact -> classArtifact.entryName in akenProductionHelperEntryNames }
        } else {
            artifact.classArtifacts
        }
        if (newEntries.isEmpty() && retainedJarEntries.size == artifact.jarEntries.size && retainedClassArtifacts.size == artifact.classArtifacts.size) {
            return artifact
        }
        val injectedClassArtifacts = newEntries.filter { entry -> entry.name.endsWith(".class") }.map { entry: JarEntryData ->
            ClassArtifact(
                entryName = entry.name,
                summary = analyzeClassBytes(entry.bytes),
                bytes = entry.bytes,
            )
        }
        val updatedJarEntries = retainedJarEntries + newEntries
        val updatedClassArtifacts = retainedClassArtifacts + injectedClassArtifacts
        val updatedClassSummaries = updatedClassArtifacts.map { classArtifact: ClassArtifact -> classArtifact.summary }
        return artifact.copy(
            jarEntries = updatedJarEntries,
            classArtifacts = updatedClassArtifacts,
            classArtifactIndex = classArtifactIndex(updatedClassArtifacts),
            analysisSummary = artifact.analysisSummary.copy(
                classCount = updatedClassArtifacts.size,
                resourceCount = resourceCount(updatedJarEntries, updatedClassArtifacts.size),
                classSummaries = updatedClassSummaries,
                classNameIndex = classSummaryIndex(updatedClassSummaries),
            ),
        )
    }

    private fun resolvePassIdsWithSchemaDependencies(passIds: List<String>): Set<String> {
        val schemaModuleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val resolvedPassIds = linkedSetOf<String>()
        val queue = ArrayDeque(passIds)
        while (queue.isNotEmpty()) {
            val passId = queue.removeFirst()
            if (!resolvedPassIds.add(passId)) continue
            val requiredPassIds = schemaModuleIndex[passId]?.requiredPassIds.orEmpty()
            for (requiredPassId in requiredPassIds) {
                queue.addLast(requiredPassId)
            }
        }
        return resolvedPassIds
    }

    private fun loadHelperBytes(helperInternalName: String, akenRuntimeDeployment: Boolean = false): ByteArray {
        val generator = helperGenerators[helperInternalName]
            ?: throw IllegalStateException("missing generator")
        val generated = generator()
        return when {
            akenRuntimeDeployment && helperInternalName == "$PKG/JniMicrokernelHelper" ->
                emitAkenOnlyJniMicrokernelHelper(generated)
            akenRuntimeDeployment && helperInternalName == "$PKG/ClassEncryptionLoaderHelper" ->
                emitAkenOnlyClassEncryptionLoaderHelper(generated)
            akenRuntimeDeployment && helperInternalName == "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader" ->
                emitAkenOnlySharedDecryptingClassLoader(generated)
            else -> generated
        }
    }

    /**
     * Copies the public/current-page closure of the source helper into a new
     * class file, rather than shipping the source helper's legacy boot protocol
     * methods and constant-pool entries in a new AKEN artifact.  The original
     * helper remains in the build process for old-engine tests; new output gets
     * this lean runtime implementation only.
     */
    private fun emitAkenOnlyJniMicrokernelHelper(source: ByteArray): ByteArray {
        val owner = "$PKG/JniMicrokernelHelper"
        val allowedNested = setOf(
            "$owner${"$"}AkenNativeLibrary",
            "$owner${"$"}TypeParseResult",
            "$owner${"$"}SamLambdaOptions",
            "$owner${"$"}SamInvocationHandler",
        )
        val allowedFields = setOf(
            "LOAD_FAILED",
            "LOAD_UNTRIED",
            "LOAD_LOADING",
            "LOAD_READY",
            "loadState",
            "loadMessage",
            "akenLoadState",
            "akenLoadMessage",
            "diversifiedVmEnabled",
            "vmSelfCheck",
            "nativeSelfCheckFailed",
            "sealedNativeBindingsPublished",
            "AKEN_NATIVE_LOCATOR_RESOURCE",
            "AKEN_NATIVE_BINDINGS_LOCATOR_RESOURCE",
            "AKEN_NATIVE_RESOURCE_ROOT",
            "AKEN_NATIVE_LOCATOR_RECORD",
            "AKEN_NATIVE_BINDINGS_LOCATOR_RECORD",
            "AKEN_NATIVE_LOCATOR_MAX_BYTES",
            "AKEN_NATIVE_MAX_LIBRARY_BYTES",
            "AKEN_NATIVE_SHA256_LENGTH",
            "AKEN_NATIVE_BINDINGS_MAX_BYTES",
            "LAMBDA_FLAG_SERIALIZABLE",
            "LAMBDA_FLAG_MARKERS",
            "LAMBDA_FLAG_BRIDGES",
            "LAMBDA_SUPPORTED_FLAGS",
            "SAM_LAMBDA_CACHE",
            "SAM_BRIDGE_INTERFACE_CACHE",
        )
        val removedNames = setOf(
            // AKEN keeps only the native loader handshake (nativeInit,
            // nativeHeartbeat, and nativeInstallAkenSessionNonce) plus the
            // typed page bridge below.  All generic verification, machine-
            // fingerprint, key-taking, and legacy class/resource entrypoints
            // are compatibility-only and must not enter a production helper.
            "nativeVerify",
            "nativeGetVersion",
            "nativeGetBootToken",
            "nativeInstallBootMaterial",
            "nativeInstallBootEnvelope",
            "nativeIsBootMaterialReady",
            "nativeAbortBootMaterial",
            "nativePreloadRuntimeResources",
            "nativeDecodeRuntimeResource",
            "nativeDecryptAes",
            "nativeDeriveClassEncryptionKey",
            "nativeDecryptClassBytes",
            "nativeSealedBindingKey",
            "nativeGetMachineFingerprint",
            "nativeExecuteVmResource",
            "nativeExecuteVmResourceByToken",
            "nativeExecuteVmResourceVoid",
            "nativeExecuteVmResourceInt",
            "nativeExecuteVmResourceIntInt",
            "nativeExecuteVmResourceIntVoid",
            "executeVmResource",
            "executeVmResourceVoid",
            "executeVmResourceInt",
            "executeVmResourceIntInt",
            "executeVmResourceIntVoid",
            "verifyNativeAbiAfterLoad",
            "verifyBootTokenAfterLoad",
            "computeExpectedBootToken",
            "fnv1a32",
            "preloadRuntimeResourcesIntoNative",
            "hasVmCatalogResource",
            "verifyVmPreloadIndexBeforeNative",
            "verifiedVmCatalogPayload",
            "openCatalogJar",
            "readRequiredResource",
            "vmPreloadEntryAuthTag",
            "installBootMaterialIntoNative",
            "readBoot" + "KekSidecarBinary",
            "prepareJavaBootMaterialForLoad",
            "loadBootSecret",
            "decodeBootSecretBytes",
            "unmaskBootSecret",
            "deriveBootEnvMask",
            "constantTimeStringEqual",
            "bootSidecarBinding",
            "isBoot" + "KekSidecar",
            "decodeBoot" + "KekSidecar",
            "decryptBootMaterial",
            "validateAndPublishJavaBootMaterial",
            "clearJavaBootMaterial",
            "publishNativeShellBootSecret",
            "clearNativeShellBootSecret",
            "takeBootSecretForNativeShell",
            "clearExpectedShellBindingCommitment",
            "takeExpectedShellBindingCommitment",
            "verifyShellBindingHandoffAfterLoad",
            "shellBindingPlatformId",
            "tryLoadBundledNative",
            "tryLoadBundledNativeResource",
            "ensureSealedNativeBindingsPublished",
            "legacySealedNativeBindingsResource",
            "sealedNativeIndexText",
            "sealedBundledLibraryNames",
            "decodeSealedNativeResource",
            "decodeRuntimeResourceForNative",
            "decodeRuntimeResourceEnvelope",
            "runtimeResourcePartitionCount",
            "anchorResourcePartition",
            "partitionResourceKey",
            "decodeRuntimeResourceEnvelope",
            "decodeRuntimeResource",
            "hasRuntimeResourceHeader",
            "decodeRuntimeResourceCurrent",
            "decompressEmbeddedZstd",
            "readZstdFrameContentSize",
            "runtimeResourceAesCtr",
            "runtimeResourceAesCtrWithDomains",
            "parseRuntimeResourceMetadata",
            "aesXtime",
            "aesSbox",
            "aesExpandKey",
            "aesMixColumn",
            "aesEncryptBlock",
            "aesCtrCrypt",
            "hmacSha256",
            "parsePositiveInt",
            "lastIndexOf",
            "hasPartitionedRuntimeResourceHeader",
            "vmCatalogLeaf",
            "vmCatalogMerkleRoot",
            "vmCatalogRoot",
            "compareUnsigned",
            "sortVmCatalogDirectories",
            "sortByteArrays",
            "frame",
            "longBytes",
            "concat",
            "intBytes",
            "constantTimeEquals",
            "readSealedResourceLe16",
            "readSealedResourceLe32",
            "readSealedResourceBe32",
            "deriveClassEncryptionKey",
            "decryptClassBytes",
        )
        fun dropMethod(name: String, descriptor: String): Boolean =
            name in removedNames ||
                (name == "publishSealedNativeBindings" && descriptor == "()V") ||
                (name == "sealedNativeBindingText" && descriptor == "()Ljava/lang/String;")
        fun replaceMethod(name: String, descriptor: String): Boolean =
            (name == "loadKernel" && descriptor in setOf(
                "(Ljava/lang/String;Ljava/lang/String;)V",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            )) ||
                (name == "isKernelIntegrityReady" && descriptor == "()Z") ||
                (name == "requireHealthyKernel" && descriptor == "()V")

        val reader = ClassReader(source)
        val writer = ClassWriter(0)
        val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visitField(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                value: Any?,
            ): FieldVisitor? = if (name in allowedFields) {
                super.visitField(access, name, descriptor, signature, value)
            } else {
                null
            }

            override fun visitNestMember(nestMember: String) {
                if (nestMember in allowedNested) super.visitNestMember(nestMember)
            }

            override fun visitInnerClass(name: String, outerName: String?, innerName: String?, access: Int) {
                if (name == owner || name in allowedNested) {
                    super.visitInnerClass(name, outerName, innerName, access)
                }
            }

            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name == "<clinit>" || dropMethod(name, descriptor) || replaceMethod(name, descriptor)) return null
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }

            override fun visitEnd() {
                emitAkenOnlyJniHelperClinit(writer, owner)
                emitAkenOnlyJniHelperLoadMethods(writer, owner)
                emitAkenOnlyJniHelperIntegrityMethods(writer, owner)
                super.visitEnd()
            }
        }
        reader.accept(visitor, 0)
        return writer.toByteArray()
    }

    private fun emitAkenOnlyJniHelperClinit(writer: ClassWriter, owner: String) {
        val mv = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        mv.visitCode()
        mv.visitTypeInsn(Opcodes.NEW, "java/util/concurrent/ConcurrentHashMap")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/concurrent/ConcurrentHashMap", "<init>", "()V", false)
        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, "SAM_LAMBDA_CACHE", "Ljava/util/concurrent/ConcurrentMap;")
        mv.visitTypeInsn(Opcodes.NEW, "java/util/concurrent/ConcurrentHashMap")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/concurrent/ConcurrentHashMap", "<init>", "()V", false)
        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, "SAM_BRIDGE_INTERFACE_CACHE", "Ljava/util/concurrent/ConcurrentMap;")
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(2, 0)
        mv.visitEnd()
    }

    private fun emitAkenOnlyJniHelperLoadMethods(writer: ClassWriter, owner: String) {
        writer.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "loadKernel",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            null,
            null,
        ).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitVarInsn(Opcodes.ALOAD, 1)
            visitLdcInsn("vm-off")
            visitMethodInsn(
                Opcodes.INVOKESTATIC,
                owner,
                "loadKernel",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                false,
            )
            visitInsn(Opcodes.RETURN)
            visitMaxs(3, 2)
            visitEnd()
        }
        writer.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNCHRONIZED,
            "loadKernel",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
            null,
            null,
        ).apply {
            visitCode()
            visitLdcInsn("vm-diverse")
            visitVarInsn(Opcodes.ALOAD, 2)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false)
            visitFieldInsn(Opcodes.PUTSTATIC, owner, "diversifiedVmEnabled", "Z")
            visitMethodInsn(Opcodes.INVOKESTATIC, owner, "ensureAkenNativeKernel", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 3)
            visitEnd()
        }
    }

    private fun emitAkenOnlyJniHelperIntegrityMethods(writer: ClassWriter, owner: String) {
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "isKernelIntegrityReady", "()Z", null, null).apply {
            visitCode()
            visitInsn(Opcodes.ICONST_1)
            visitFieldInsn(Opcodes.GETSTATIC, owner, "nativeSelfCheckFailed", "Z")
            visitInsn(Opcodes.IXOR)
            visitMethodInsn(Opcodes.INVOKESTATIC, owner, "isNativeLoaded", "()Z", false)
            visitInsn(Opcodes.IAND)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(2, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "requireHealthyKernel", "()V", null, null).apply {
            visitCode()
            visitMethodInsn(Opcodes.INVOKESTATIC, owner, "ensureAkenNativeKernel", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
    }

    /**
     * Emits the class-encryption helper closure used by a new AKEN artifact.
     *
     * The source helper still contains the pre-AKEN manifest/resource decoder
     * for old artifacts, but that surface must not be copied into a new JAR.
     * Keeping the required methods and fields at the bytecode level also avoids
     * accidentally retaining a constant-pool reference to ParsedMetadata or a
     * generic key/resource entrypoint.
     */
    private fun emitAkenOnlyClassEncryptionLoaderHelper(source: ByteArray): ByteArray {
        val owner = "$PKG/ClassEncryptionLoaderHelper"
        val sharedLoader = "$owner${"$"}SharedDecryptingClassLoader"
        val allowedFields = setOf("sharedLoader", "unsafe", "methodCache", "instanceCache")
        val allowedMethods = setOf(
            "<init>()V",
            "loadAkenClass(Ljava/lang/String;)Ljava/lang/Class;",
            "invokeMethod([Ljava/lang/Object;)Ljava/lang/Object;",
            "createInstance(Ljava/lang/Class;)Ljava/lang/Object;",
            "sharedLoader()L$sharedLoader;",
            "parseParamTypes(Ljava/lang/ClassLoader;Ljava/lang/String;)[Ljava/lang/Class;",
        )

        val reader = ClassReader(source)
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visitField(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                value: Any?,
            ): FieldVisitor? = if (name in allowedFields) {
                super.visitField(access, name, descriptor, signature, value)
            } else {
                null
            }

            override fun visitNestMember(nestMember: String) {
                if (nestMember == sharedLoader) super.visitNestMember(nestMember)
            }

            override fun visitInnerClass(name: String, outerName: String?, innerName: String?, access: Int) {
                if (name == owner || name == sharedLoader) {
                    super.visitInnerClass(name, outerName, innerName, access)
                }
            }

            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name == "<clinit>") return null
                return if ("$name$descriptor" in allowedMethods) {
                    super.visitMethod(access, name, descriptor, signature, exceptions)
                } else {
                    null
                }
            }

            override fun visitEnd() {
                emitAkenOnlyClassEncryptionHelperClinit(writer, owner)
                super.visitEnd()
            }
        }
        reader.accept(visitor, 0)
        return writer.toByteArray()
    }

    private fun emitAkenOnlyClassEncryptionHelperClinit(writer: ClassWriter, owner: String) {
        val mv = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        val tryStart = Label()
        val tryEnd = Label()
        val catchLabel = Label()
        val done = Label()
        mv.visitTryCatchBlock(tryStart, tryEnd, catchLabel, "java/lang/Throwable")
        mv.visitCode()

        mv.visitTypeInsn(Opcodes.NEW, "java/util/concurrent/ConcurrentHashMap")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "java/util/concurrent/ConcurrentHashMap",
            "<init>",
            "()V",
            false,
        )
        mv.visitFieldInsn(
            Opcodes.PUTSTATIC,
            owner,
            "methodCache",
            "Ljava/util/concurrent/ConcurrentHashMap;",
        )
        mv.visitTypeInsn(Opcodes.NEW, "java/util/concurrent/ConcurrentHashMap")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "java/util/concurrent/ConcurrentHashMap",
            "<init>",
            "()V",
            false,
        )
        mv.visitFieldInsn(
            Opcodes.PUTSTATIC,
            owner,
            "instanceCache",
            "Ljava/util/concurrent/ConcurrentHashMap;",
        )

        mv.visitLabel(tryStart)
        mv.visitLdcInsn(Type.getType("Lsun/misc/Unsafe;"))
        mv.visitLdcInsn("theUnsafe")
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredField",
            "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
            false,
        )
        mv.visitVarInsn(Opcodes.ASTORE, 0)
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitInsn(Opcodes.ICONST_1)
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/AccessibleObject",
            "setAccessible",
            "(Z)V",
            false,
        )
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitInsn(Opcodes.ACONST_NULL)
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            false,
        )
        mv.visitTypeInsn(Opcodes.CHECKCAST, "sun/misc/Unsafe")
        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, "unsafe", "Lsun/misc/Unsafe;")
        mv.visitLabel(tryEnd)
        mv.visitJumpInsn(Opcodes.GOTO, done)
        mv.visitLabel(catchLabel)
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.ACONST_NULL)
        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, "unsafe", "Lsun/misc/Unsafe;")
        mv.visitLabel(done)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(3, 1)
        mv.visitEnd()
    }

    /**
     * Emits the shared loader without the legacy findClass/manifest path.  The
     * only fallback is the normal parent ClassLoader; encrypted application
     * classes must arrive through defineAkenClassIfPresent.
     */
    private fun emitAkenOnlySharedDecryptingClassLoader(source: ByteArray): ByteArray {
        val owner = "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader"
        val allowedMethods = setOf(
            "<init>(Ljava/lang/ClassLoader;)V",
            "loadAkenClass(Ljava/lang/String;)Ljava/lang/Class;",
            "defineAkenClassIfPresent(Ljava/lang/String;)Ljava/lang/Class;",
            "defineClassBytes(Ljava/lang/String;[B)Ljava/lang/Class;",
        )
        val typedLoadAccessorDescriptor = "(L$owner;Ljava/lang/String;)Ljava/lang/Class;"
        val reader = ClassReader(source)
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name == "findClass") return null
                if (name == "loadClass" && descriptor == "(Ljava/lang/String;Z)Ljava/lang/Class;") return null
                val isTypedLoadAccessor =
                    name.startsWith("access$") && descriptor == typedLoadAccessorDescriptor
                return if ("$name$descriptor" in allowedMethods || isTypedLoadAccessor) {
                    super.visitMethod(access, name, descriptor, signature, exceptions)
                } else {
                    null
                }
            }

            override fun visitInnerClass(name: String, outerName: String?, innerName: String?, access: Int) {
                if (name == owner || name == "$PKG/ClassEncryptionLoaderHelper") {
                    super.visitInnerClass(name, outerName, innerName, access)
                }
            }

            override fun visitEnd() {
                emitAkenOnlySharedDecryptingClassLoaderLoadClass(writer, owner)
                super.visitEnd()
            }
        }
        reader.accept(visitor, 0)
        return writer.toByteArray()
    }

    private fun emitAkenOnlySharedDecryptingClassLoaderLoadClass(writer: ClassWriter, owner: String) {
        val mv = writer.visitMethod(
            Opcodes.ACC_PROTECTED or Opcodes.ACC_SYNCHRONIZED,
            "loadClass",
            "(Ljava/lang/String;Z)Ljava/lang/Class;",
            null,
            arrayOf("java/lang/ClassNotFoundException"),
        )
        val loaded = Label()
        val resolve = Label()
        mv.visitCode()
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/ClassLoader",
            "findLoadedClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            false,
        )
        mv.visitVarInsn(Opcodes.ASTORE, 3)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitJumpInsn(Opcodes.IFNONNULL, loaded)

        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            owner,
            "defineAkenClassIfPresent",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            false,
        )
        mv.visitVarInsn(Opcodes.ASTORE, 3)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitJumpInsn(Opcodes.IFNONNULL, loaded)

        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "java/lang/ClassLoader",
            "loadClass",
            "(Ljava/lang/String;Z)Ljava/lang/Class;",
            false,
        )
        mv.visitVarInsn(Opcodes.ASTORE, 3)

        mv.visitLabel(loaded)
        mv.visitVarInsn(Opcodes.ILOAD, 2)
        mv.visitJumpInsn(Opcodes.IFEQ, resolve)
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/ClassLoader",
            "resolveClass",
            "(Ljava/lang/Class;)V",
            false,
        )
        mv.visitLabel(resolve)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(3, 4)
        mv.visitEnd()
    }

    private fun pushInt(mv: MethodVisitor, value: Int) {
        when (value) {
            -1 -> mv.visitInsn(Opcodes.ICONST_M1)
            0 -> mv.visitInsn(Opcodes.ICONST_0)
            1 -> mv.visitInsn(Opcodes.ICONST_1)
            2 -> mv.visitInsn(Opcodes.ICONST_2)
            3 -> mv.visitInsn(Opcodes.ICONST_3)
            4 -> mv.visitInsn(Opcodes.ICONST_4)
            5 -> mv.visitInsn(Opcodes.ICONST_5)
            in Byte.MIN_VALUE..Byte.MAX_VALUE -> mv.visitIntInsn(Opcodes.BIPUSH, value)
            in Short.MIN_VALUE..Short.MAX_VALUE -> mv.visitIntInsn(Opcodes.SIPUSH, value)
            else -> mv.visitLdcInsn(value)
        }
    }
    // --- Native Library Bundling ---

    private val NATIVE_RESOURCE_ROOT = "META-INF/js-native"
    private val REQUIRED_SEALED_NATIVE_ABI_MARKERS = listOf(
        "JNI_OnLoad",
        "j.l",
        "j.b",
        "j.m",
        "Resource",
        "entryToken",
        "RegisterNatives",
        "Runtime",
        "Resources",
        "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
    )

    private val REJECTED_LEGACY_NATIVE_ABI_MARKERS = listOf(
        "Java_io_github_hht0rro_javashroud_transforms_protection_",
        "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper",
        "nativeInit",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
        "nativeCheckInstrumentation",
        "nativeCheckJvmTiAgents",
        "nativeCheckByteBuddy",
        "nativeInstall" + "RuntimeResourceKey",
        "nativePreloadRuntimeResources",
        "nativeExecuteVmResource",
    )
    internal fun bundleNativeLibrariesIfAvailable(
        artifact: BytecodeArtifact,
        executedPassIds: List<String>,
        config: io.github.hht0rro.javashroud.model.config.ObfuscationConfig? = null,
        emit: (EngineEvent) -> Unit = {},
    ): BytecodeArtifact {
        if ("jni-microkernel-loader" !in executedPassIds) return artifact

        val recompiledNatives = compileNativeLibrariesOrThrow(config, emit)
        return try {
            val retainedJarEntries = artifact.jarEntries.filterNot { entry ->
                isNativeKernelResource(entry.name) ||
                    entry.name in legacyBootResourcePaths
            }
            val existingEntries = retainedJarEntries.map { it.name }.toSet()
            val newEntries = mutableListOf<JarEntryData>()
            for (rn in recompiledNatives) {
                val entryName = "$NATIVE_RESOURCE_ROOT/${rn.libName}"
                if (entryName in existingEntries) continue
                if (!nativeLibraryContainsRequiredJniVmAbi(rn.bytes)) {
                    throw IllegalStateException("Zig-compiled JNI microkernel for ${rn.platform} does not contain the required sealed JNI ABI")
                }
                newEntries.add(JarEntryData(name = entryName, bytes = rn.bytes))
            }
            if (newEntries.isEmpty()) {
                throw IllegalStateException("Zig compilation produced no loadable JNI microkernel libraries")
            }
            val updatedJarEntries = retainedJarEntries + newEntries
            artifact.copy(
                jarEntries = updatedJarEntries,
                analysisSummary = artifact.analysisSummary.copy(
                    resourceCount = resourceCount(updatedJarEntries, artifact.classArtifacts.size),
                ),
            )
        } finally {
            recompiledNatives.forEach { native -> native.shellBindingCommitment?.fill(0) }
        }
    }

    internal fun nativeLibraryContainsRequiredJniVmAbi(bytes: ByteArray): Boolean =
        bytes.isNotEmpty() &&
            REJECTED_LEGACY_NATIVE_ABI_MARKERS.none { marker -> bytes.containsAscii(marker) } &&
            (
                REQUIRED_SEALED_NATIVE_ABI_MARKERS.all { marker -> bytes.containsAscii(marker) } ||
                    nativeLibraryContainsMaxShellStubAbi(bytes)
            )

    internal fun nativeLibraryContainsMaxShellStubAbi(bytes: ByteArray): Boolean =
        bytes.containsAscii("JNI_OnLoad") &&
            bytes.containsAscii(NativeKernelShellPacker.MAX_STUB_MARKER) &&
            bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)

    internal fun hasLoadableNativeKernel(): Boolean = hasBundledNativeSources()

    private fun hasBundledNativeSources(): Boolean = listOf(
        "js_kernel.c",
        "js_helpers.c",
        "js_native_common.c",
        "js_machine_id.c",
        "native_secrets.inc",
        "zstd/zstd.h",
        "zstd/zstd_errors.h",
        "zstd/decompress/zstd_decompress.c",
        "cross-compile/jni.h",
        "cross-compile/jni_md_linux.h",
    ).all { name -> loadClasspathResource("META-INF/native-src/$name") != null }

    private fun isNativeKernelResource(entryName: String): Boolean =
        entryName.startsWith("$NATIVE_RESOURCE_ROOT/js_kernel_") &&
            (entryName.endsWith(".dll") || entryName.endsWith(".so") || entryName.endsWith(".dylib"))

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > size) return false
        val lastStart = size - needle.size
        for (start in 0..lastStart) {
            var matched = true
            for (offset in needle.indices) {
                if (this[start + offset] != needle[offset]) {
                    matched = false
                    break
                }
            }
            if (matched) return true
        }
        return false
    }

    /**
     * Compile native microkernels from bundled C source. This path is intentionally
     * fail-closed: jni-microkernel-loader no longer falls back to prebuilt native binaries.
     */
    private fun compileNativeLibrariesOrThrow(
        config: io.github.hht0rro.javashroud.model.config.ObfuscationConfig?,
        emit: (EngineEvent) -> Unit = {},
    ): List<NativeRecompilationTransforms.RecompiledNative> {
        if (config == null) {
            throw IllegalStateException("jni-microkernel-loader requires an obfuscation config for Zig compilation")
        }
        val loaderPass = config.passes.find { it.id == "jni-microkernel-loader" && it.enabled }
            ?: throw IllegalStateException("jni-microkernel-loader pass config is missing")
        val recompileEnabled = (loaderPass.params["nativeRecompilation"] as? com.fasterxml.jackson.databind.node.BooleanNode)?.booleanValue() ?: true
        if (!recompileEnabled) {
            throw IllegalStateException("jni-microkernel-loader requires 混淆时编译; nativeRecompilation=false is no longer supported")
        }

        val targetPlatformParam = (loaderPass.params["targetPlatform"] as? com.fasterxml.jackson.databind.node.TextNode)?.textValue() ?: "auto"
        val nativeProtectionLevel = (loaderPass.params["nativeProtectionLevel"] as? com.fasterxml.jackson.databind.node.TextNode)?.textValue() ?: "standard"
        val nativePackingLevel = (loaderPass.params["nativePackingLevel"] as? com.fasterxml.jackson.databind.node.TextNode)?.textValue() ?: "max"
        val request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = nativeProtectionLevel,
            nativePackingLevel = NativeKernelShellPacker.Level.parse(nativePackingLevel),
            targetPlatforms = resolveNativeCompileTargetPlatforms(targetPlatformParam),
        )

        val seedNode = loaderPass.params["seed"]
        val seed = (seedNode as? com.fasterxml.jackson.databind.node.NumericNode)?.longValue()
            ?: config.outputJarPath.hashCode().toLong()

        val classLoader = this::class.java.classLoader
        try {
            val diagnostics = NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = seed,
                classLoader = classLoader,
                request = request,
                onMessage = { message -> emitNativeRecompilationMessage(emit, message) },
            )
            if (diagnostics.results.isEmpty()) {
                throw IllegalStateException("Zig toolchain is unavailable or native compilation produced no loadable libraries")
            }
            return requireCompleteNativeCompileTargets(
                request.routes.map(NativeRecompilationRoute::platform),
                diagnostics.results,
            )
        } catch (error: Exception) {
            emitNativeRecompilationFailure(emit, error.message ?: error::class.java.simpleName)
            throw error
        }
    }

    internal fun resolveNativeCompileTargetPlatforms(
        targetPlatformParam: String,
        osName: String = System.getProperty("os.name"),
        osArch: String = System.getProperty("os.arch"),
    ): List<String> {
        val trimmed = targetPlatformParam.trim()
        if (trimmed == "auto") {
            val detected = NativeToolchainProvisioner.detectPlatform(osName, osArch)
                ?: throw IllegalArgumentException("target platform is unsupported: auto ($osName/$osArch)")
            val normalized = detected
                .replace("-x86_64", "-x64")
                .replace("-aarch64", "-arm64")
            if (normalized !in NativeRecompilationTransforms.ZIG_TARGETS) {
                throw IllegalArgumentException("target platform is unsupported: auto ($detected)")
            }
            return listOf(normalized)
        }
        if (trimmed == "all") {
            return NativeRecompilationTransforms.ZIG_TARGETS.keys.toList()
        }
        val platforms = if (',' in trimmed) {
            trimmed.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        } else {
            listOf(trimmed)
        }
        val unsupported = platforms.filter { it !in NativeRecompilationTransforms.ZIG_TARGETS }
        if (unsupported.isNotEmpty()) {
            throw IllegalArgumentException("target platform is unsupported: $targetPlatformParam")
        }
        return platforms
    }

    internal fun requireCompleteNativeCompileTargets(
        requestedPlatforms: List<String>,
        results: List<NativeRecompilationTransforms.RecompiledNative>,
    ): List<NativeRecompilationTransforms.RecompiledNative> {
        val requested = requestedPlatforms.distinct()
        val resultsByPlatform = results.groupBy { it.platform }
        val missing = requested.filterNot(resultsByPlatform::containsKey)
        val unexpected = resultsByPlatform.keys.filterNot(requested::contains)
        val duplicates = resultsByPlatform.filterValues { it.size != 1 }.keys
        if (missing.isNotEmpty() || unexpected.isNotEmpty() || duplicates.isNotEmpty()) {
            throw IllegalStateException(
                buildString {
                    append("Zig compilation did not produce exactly the requested target platforms")
                    if (missing.isNotEmpty()) append("; missing=${missing.joinToString(",")}")
                    if (unexpected.isNotEmpty()) append("; unexpected=${unexpected.joinToString(",")}")
                    if (duplicates.isNotEmpty()) append("; duplicate=${duplicates.joinToString(",")}")
                },
            )
        }
        return requested.map { platform -> resultsByPlatform.getValue(platform).single() }
    }

    private fun emitNativeRecompilationMessage(
        emit: (EngineEvent) -> Unit,
        message: NativeToolchainProvisioner.ResolutionMessage,
    ) {
        val level = if (message.level == "warn") "warn" else "info"
        emit(
            EngineEvent(
                level = level,
                type = if (level == "warn") "warn" else "log",
                message = message.message,
                progress = message.progress,
                outPath = null,
            )
        )
    }

    private fun emitNativeRecompilationFailure(emit: (EngineEvent) -> Unit, reason: String) {
        emit(
            EngineEvent(
                level = "error",
                type = "error",
                message = "JNI microkernel Zig compilation failed ($reason). No prebuilt native fallback is available.",
                progress = 94,
                outPath = null,
            )
        )
    }

    private fun loadClasspathResource(resourcePath: String): ByteArray? {
        val loader = EmbeddedHelperDeployment::class.java.classLoader
        loader?.getResourceAsStream(resourcePath)?.use { stream -> return stream.readBytes() }
        EmbeddedHelperDeployment::class.java.getResourceAsStream("/$resourcePath")?.use { stream -> return stream.readBytes() }
        return null
    }

    // --- ASM Generators (all use COMPUTE_MAXS only) ---

    private fun generateCallsiteRotationHelper(): ByteArray {

        val owner = "$PKG/CallsiteRotationHelper"
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null)
        emitCtor(cw)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "createRotatingCallSite",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/invoke/CallSite;",
            null, arrayOf("java/lang/Exception"))
        mv.visitCode()
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitIntInsn(Opcodes.BIPUSH, '/'.code); mv.visitIntInsn(Opcodes.BIPUSH, '.'.code)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "replace", "(CC)Ljava/lang/String;", false)
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false)
        mv.visitVarInsn(Opcodes.ASTORE, 5)
        mv.visitVarInsn(Opcodes.ALOAD, 2); mv.visitInsn(Opcodes.ICONST_0); mv.visitInsn(Opcodes.ICONST_1)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodType", "dropParameterTypes", "(II)Ljava/lang/invoke/MethodType;", false)
        mv.visitVarInsn(Opcodes.ASTORE, 6)
        mv.visitVarInsn(Opcodes.ALOAD, 0); mv.visitVarInsn(Opcodes.ALOAD, 5); mv.visitVarInsn(Opcodes.ALOAD, 1); mv.visitVarInsn(Opcodes.ALOAD, 6)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles\$Lookup", "findVirtual", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false)
        mv.visitVarInsn(Opcodes.ASTORE, 7)
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/invoke/MutableCallSite"); mv.visitInsn(Opcodes.DUP); mv.visitVarInsn(Opcodes.ALOAD, 2)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/invoke/MutableCallSite", "<init>", "(Ljava/lang/invoke/MethodType;)V", false)
        mv.visitVarInsn(Opcodes.ASTORE, 8)
        mv.visitVarInsn(Opcodes.ALOAD, 8); mv.visitVarInsn(Opcodes.ALOAD, 7)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MutableCallSite", "setTarget", "(Ljava/lang/invoke/MethodHandle;)V", false)
        mv.visitVarInsn(Opcodes.ALOAD, 8); mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(4, 9); mv.visitEnd()
        cw.visitEnd(); return cw.toByteArray()
    }

    private fun generateFlowControlException(): ByteArray {
        val owner = "$PKG/FlowControlException"
        val stateFieldName = sealedRuntimeHelperFieldName(owner, "state", "I")
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/RuntimeException", null)
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "serialVersionUID", "J", null, 1L).visitEnd()
        cw.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, stateFieldName, "I", null, null).visitEnd()

        val init0 = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init0.visitCode()
        init0.visitVarInsn(Opcodes.ALOAD, 0)
        init0.visitInsn(Opcodes.ICONST_0)
        init0.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", "(I)V", false)
        init0.visitInsn(Opcodes.RETURN)
        init0.visitMaxs(2, 1)
        init0.visitEnd()

        val init1 = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null)
        init1.visitCode()
        init1.visitVarInsn(Opcodes.ALOAD, 0)
        init1.visitLdcInsn("Flow control")
        init1.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "(Ljava/lang/String;)V", false)
        init1.visitVarInsn(Opcodes.ALOAD, 0)
        init1.visitVarInsn(Opcodes.ILOAD, 1)
        init1.visitFieldInsn(Opcodes.PUTFIELD, owner, stateFieldName, "I")
        init1.visitInsn(Opcodes.RETURN)
        init1.visitMaxs(2, 2)
        init1.visitEnd()

        val getter = cw.visitMethod(Opcodes.ACC_PUBLIC, "getState", "()I", null, null)
        getter.visitCode()
        getter.visitVarInsn(Opcodes.ALOAD, 0)
        getter.visitFieldInsn(Opcodes.GETFIELD, owner, stateFieldName, "I")
        getter.visitInsn(Opcodes.IRETURN)
        getter.visitMaxs(1, 1)
        getter.visitEnd()

        cw.visitEnd(); return cw.toByteArray()
    }

    private fun generateExceptionVirtualizationHelper(): ByteArray {
        val owner = "$PKG/ExceptionVirtualizationHelper"
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null)
        emitCtor(cw)
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "enabled", "Z", null, null).visitEnd()
        val clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode(); clinit.visitInsn(Opcodes.ICONST_1)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, owner, "enabled", "Z")
        clinit.visitInsn(Opcodes.RETURN); clinit.visitMaxs(1, 0); clinit.visitEnd()
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "shouldVirtualize", "()Z", null, null)
        mv.visitCode(); mv.visitFieldInsn(Opcodes.GETSTATIC, owner, "enabled", "Z")
        mv.visitInsn(Opcodes.IRETURN); mv.visitMaxs(1, 0); mv.visitEnd()
        cw.visitEnd(); return cw.toByteArray()
    }

    /** Load a pre-compiled helper .class from the classpath by simple name. */
    private fun loadClasspathHelperByName(simpleName: String): ByteArray {
        val resourceName = "$PKG/$simpleName.class"
        return readHelperResource(resourceName)
            ?: throw IllegalStateException("$simpleName.class not found on classpath at /$resourceName")
    }

    private fun readHelperResource(resourceName: String): ByteArray? {
        val helperResourceName = "$HELPER_RESOURCE_ROOT/$resourceName"
        val helperBinaryResourceName = helperResourceName.removeSuffix(".class") + ".bin"
        EmbeddedHelperDeployment::class.java.classLoader
            ?.getResourceAsStream(resourceName)
            ?.use { stream -> return stream.readBytes() }
        EmbeddedHelperDeployment::class.java.getResourceAsStream("/$resourceName")
            ?.use { stream -> return stream.readBytes() }
        EmbeddedHelperDeployment::class.java.classLoader
            ?.getResourceAsStream(helperBinaryResourceName)
            ?.use { stream -> return stream.readBytes() }
        EmbeddedHelperDeployment::class.java.getResourceAsStream("/$helperBinaryResourceName")
            ?.use { stream -> return stream.readBytes() }
        EmbeddedHelperDeployment::class.java.classLoader
            ?.getResourceAsStream(helperResourceName)
            ?.use { stream -> return stream.readBytes() }
        EmbeddedHelperDeployment::class.java.getResourceAsStream("/$helperResourceName")
            ?.use { stream -> return stream.readBytes() }
        return readLocalHelperResource(resourceName, helperBinaryResourceName, helperResourceName)
    }

    private fun readLocalHelperResource(vararg resourceNames: String): ByteArray? {
        val roots = listOf(
            "build/classes/java/main",
            "build/core-engine/classes/java/main",
            "../build/core-engine/classes/java/main",
            "bin/main",
            "core-engine/bin/main",
            "build/resources/main",
            "build/core-engine/resources/main",
            "../build/core-engine/resources/main",
        )
        for (root in roots) {
            for (resourceName in resourceNames) {
                val path = java.nio.file.Path.of(root).resolve(resourceName).normalize()
                if (java.nio.file.Files.isRegularFile(path)) return java.nio.file.Files.readAllBytes(path)
            }
        }
        return null
    }

    /** Generates a minimal helper class with the given internal name. */
    private fun generateSimpleHelper(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        emitCtor(cw)
        cw.visitEnd(); return cw.toByteArray()
    }

    private fun emitCtor(cw: ClassWriter) {
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        mv.visitCode(); mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        mv.visitInsn(Opcodes.RETURN); mv.visitMaxs(1, 1); mv.visitEnd()
    }


}
