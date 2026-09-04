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
import io.github.hht0rro.javashroud.transforms.protection.qp.RETIRED_CATALOG_INDEX
import io.github.hht0rro.javashroud.transforms.protection.qp.RETIRED_CATALOG_PREFIX
import io.github.hht0rro.javashroud.transforms.protection.qp.RETIRED_DIRECTORY_FILE
import io.github.hht0rro.javashroud.transforms.protection.qp.RETIRED_RESOURCE_DIR
import io.github.hht0rro.javashroud.transforms.protection.qp.qpCatalogIndexPath
import io.github.hht0rro.javashroud.transforms.protection.qp.qpCatalogPrefix
import io.github.hht0rro.javashroud.transforms.protection.qp.qpDirectoryFileName
import io.github.hht0rro.javashroud.transforms.protection.qp.qpResourceDir
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
    private val legacyBootResourcePaths = setOf(
        "META-INF/.r/boot.dat",
        "META-INF/.r/kek.dat",
    )
    private const val QP_PKG = "$PKG/qp"
    private const val HELPER_RESOURCE_ROOT = "META-INF/javashroud-helpers"
    /**
     * The current helper set omits legacy boot/resource decoder nested classes.
     * The outer helper is regenerated below with only the typed current-page
     * surface and its relocation support closure.
     */
    private val qpRuntimeHelpers = listOf(
        "$QP_PKG/QpBridge",
        "$QP_PKG/QpBridge${"$"}QpNativeLibrary",
        "$QP_PKG/QpBridge${"$"}CatalogBundle",
        // The final target-token wrapper uses QpBootstrap even when the
        // invoke-dynamic-indirection pass is disabled. Keep it in the same
        // helper closure so sealing relocates the bootstrap and QpBridge in
        // one transaction instead of appending a canonical late copy.
        "$QP_PKG/QpBootstrap",
    )
    /** Entries regenerated for an Qp production closure. */
    private val qpProductionHelperEntryNames = (
        qpRuntimeHelpers +
            listOf(
                "$QP_PKG/QpGuard",
                "$QP_PKG/QpBridge${"$"}RuntimeResourceMetadata",
                "$QP_PKG/QpBridge${"$"}SealedNativeLibrary",
            )
        ).mapTo(linkedSetOf()) { "$it.class" }

    private val passToHelpers: Map<String, List<String>> = mapOf(
        "string-encryption" to listOf("$QP_PKG/QpTextBridge"),
        "callsite-rotation-protection" to listOf("$QP_PKG/QpCallsiteBridge", "$QP_PKG/QpBootstrap", "$QP_PKG/QpBridge"),
        "invoke-dynamic-indirection" to listOf("$QP_PKG/QpBootstrap", "$QP_PKG/QpBridge"),
        "exception-semantic-virtualization" to listOf(
            "$PKG/ExceptionVirtualizationHelper",
            "$PKG/FlowControlException",
        ),
        "os-anti-debug" to listOf("$QP_PKG/QpGuard") + qpRuntimeHelpers,
        "os-anti-vm" to listOf("$QP_PKG/QpGuard") + qpRuntimeHelpers,
        "jni-microkernel-loader" to qpRuntimeHelpers,
        "method-virtualization" to emptyList(),
    )
    private val helperGenerators: Map<String, () -> ByteArray> by lazy {
        mapOf(
            "$QP_PKG/QpTextBridge" to { loadClasspathHelperByName("QpTextBridge") },
            "$QP_PKG/QpCallsiteBridge" to { loadClasspathHelperByName("QpCallsiteBridge") },
            "$QP_PKG/QpBootstrap" to { loadClasspathHelperByName("QpBootstrap") },
            "$PKG/ExceptionVirtualizationHelper" to ::generateExceptionVirtualizationHelper,
            "$PKG/FlowControlException" to ::generateFlowControlException,
            "$QP_PKG/QpGuard" to { loadClasspathHelperByName("QpGuard") },
            "$QP_PKG/QpBridge" to { loadClasspathHelperByName("QpBridge") },
            "$QP_PKG/QpBridge${"$"}RuntimeResourceMetadata" to { loadClasspathHelperByName("QpBridge${"$"}RuntimeResourceMetadata") },
            "$QP_PKG/QpBridge${"$"}SealedNativeLibrary" to { loadClasspathHelperByName("QpBridge${"$"}SealedNativeLibrary") },
            "$QP_PKG/QpBridge${"$"}QpNativeLibrary" to { loadClasspathHelperByName("QpBridge${"$"}QpNativeLibrary") },
            "$QP_PKG/QpBridge${"$"}CatalogBundle" to { loadClasspathHelperByName("QpBridge${"$"}CatalogBundle") },
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
        val qpRuntimeDeployment = "jni-microkernel-loader" in resolvedPassIds
        val existingEntries = artifact.jarEntries
            .asSequence()
            .filterNot { entry ->
                qpRuntimeDeployment &&
                    entry.name in qpProductionHelperEntryNames
            }
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
                loadHelperBytes(helperInternalName, qpRuntimeDeployment)
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
        val retainedJarEntries = if (qpRuntimeDeployment) {
            artifact.jarEntries.filterNot { entry ->
                entry.name in qpProductionHelperEntryNames || entry.name in legacyBootResourcePaths
            }
        } else {
            artifact.jarEntries
        }
        val retainedClassArtifacts = if (qpRuntimeDeployment) {
            artifact.classArtifacts.filterNot { classArtifact ->
                classArtifact.entryName in qpProductionHelperEntryNames
            }
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

    private fun loadHelperBytes(helperInternalName: String, qpRuntimeDeployment: Boolean = false): ByteArray {
        val generator = helperGenerators[helperInternalName]
            ?: throw IllegalStateException("missing generator")
        val generated = generator()
        return if (qpRuntimeDeployment && helperInternalName == "$QP_PKG/QpBridge") {
            emitQpOnlyQpBridge(generated)
        } else {
            generated
        }
    }

    /**
     * Copies the public/current-page closure of the source helper into a new
     * class file, rather than shipping the source helper's legacy boot protocol
     * methods and constant-pool entries in a new Qp artifact.  The original
     * helper remains in the build process for old-engine tests; new output gets
     * this lean runtime implementation only.
     */
    private fun emitQpOnlyQpBridge(source: ByteArray): ByteArray {
        val owner = "$QP_PKG/QpBridge"
        val allowedNested = setOf(
            "$owner${"$"}QpNativeLibrary",
            "$owner${"$"}CatalogBundle",
        )
        val allowedFields = setOf(
            "LOAD_FAILED",
            "LOAD_UNTRIED",
            "LOAD_LOADING",
            "LOAD_READY",
            "KERNEL_UNINITIALIZED",
            "KERNEL_BINDINGS_VERIFIED",
            "KERNEL_NATIVE_READY",
            "KERNEL_DEFENSE_READY",
            "KERNEL_SUSPECT",
            "KERNEL_TAMPERED",
            "KERNEL_FAILED",
            "kernelState",
            "defenseRequired",
            "loadState",
            "loadMessage",
            "nativeLoadState",
            "nativeLoadMessage",
            "diversifiedVmEnabled",
            "loadedNativePlatformKey",
            "vmSelfCheckCode",
            "nativeSelfCheckFailed",
            "sealedNativeBindingsPublished",
            "QP_NATIVE_LOCATOR_RESOURCE",
            "QP_NATIVE_BINDINGS_LOCATOR_RESOURCE",
            "QP_NATIVE_RESOURCE_ROOT",
            "QP_NATIVE_LOCATOR_MAGIC_0",
            "QP_NATIVE_LOCATOR_MAGIC_1",
            "QP_NATIVE_LOCATOR_MAGIC_2",
            "QP_NATIVE_LOCATOR_MAGIC_3",
            "QP_NATIVE_LOCATOR_COMMITMENT_DOMAIN",
            "QP_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN",
            "QP_NATIVE_LOCATOR_VERSION",
            "QP_NATIVE_LOCATOR_HEADER_BYTES",
            "QP_NATIVE_LOCATOR_COMMITMENT_BYTES",
            "QP_NATIVE_LOCATOR_RECORD_FIXED_BYTES",
            "QP_NATIVE_LOCATOR_MAX_RECORDS",
            "QP_NATIVE_LOCATOR_MAX_ROUTE_BYTES",
            "QP_NATIVE_LOCATOR_KIND_LIBRARY",
            "QP_NATIVE_LOCATOR_KIND_BINDINGS",
            "QP_NATIVE_LOCATOR_MAX_BYTES",
            "QP_NATIVE_MAX_LIBRARY_BYTES",
            "QP_NATIVE_SHA256_LENGTH",
            "QP_NATIVE_BINDINGS_MAX_BYTES",
        )
        val removedNames = setOf(
            // Qp keeps only the native loader handshake (nativeInit,
            // nativeHeartbeat, and nativeInstallSessionNonce) plus the
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
            ))

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
                super.visitField(access, name, descriptor, signature, rewriteRetiredResourceString(value))
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
                val mv = super.visitMethod(access, name, descriptor, signature, exceptions) ?: return null
                return object : MethodVisitor(Opcodes.ASM9, mv) {
                    override fun visitLdcInsn(value: Any?) {
                        super.visitLdcInsn(rewriteRetiredResourceString(value))
                    }
                }
            }

            override fun visitEnd() = super.visitEnd()
        }
        reader.accept(visitor, 0)
        return writer.toByteArray()
    }

    private fun emitQpOnlyJniHelperLoadMethods(writer: ClassWriter, owner: String) {
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
            visitMethodInsn(Opcodes.INVOKESTATIC, owner, "ensureQpNativeKernel", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 3)
            visitEnd()
        }
    }

    private fun emitQpOnlyJniHelperIntegrityMethods(writer: ClassWriter, owner: String) {
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
            visitMethodInsn(Opcodes.INVOKESTATIC, owner, "ensureQpNativeKernel", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
    }

    private fun emitQpOnlyClassEncryptionHelperClinit(writer: ClassWriter, owner: String) {
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

    private fun emitQpOnlySharedDecryptingClassLoaderLoadClass(writer: ClassWriter, owner: String) {
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
            "defineQpClassIfPresent",
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

    private fun rewriteRetiredResourceString(value: Any?): Any? {
        if (value !is String) return value
        return when (value) {
            RETIRED_CATALOG_INDEX -> qpCatalogIndexPath()
            RETIRED_CATALOG_PREFIX -> qpCatalogPrefix()
            RETIRED_DIRECTORY_FILE -> qpDirectoryFileName()
            else -> value.replace(RETIRED_RESOURCE_DIR, qpResourceDir())
        }
    }

    private val NATIVE_RESOURCE_ROOT: String
        get() = io.github.hht0rro.javashroud.transforms.protection.qp.qpResourceDir()
    private val REQUIRED_NATIVE_ABI_EXPORTS = listOf(
        "JNI_OnLoad",
        "JNI_OnUnload",
        "qp_r1_runtime_binding_digest",
        "qp_r1_open_frame",
    )

    private val REJECTED_LEGACY_NATIVE_ABI_MARKERS = listOf(
        "Java_io_github_hht0rro_javashroud_transforms_protection_",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
        "nativeCheckInstrumentation",
        "nativeCheckJvmTiAgents",
        "nativeCheckByteBuddy",
        "nativeInstall" + "RuntimeResourceKey",
        "nativeInstallBootMaterial",
        "nativeInstallBootEnvelope",
        "nativeDecodeRuntimeResource",
        "nativePreloadRuntimeResources",
        "nativeExecuteVmResource",
        "js_native_abi_table_v1",
        "jsn_k13",
        "js_shell_",
        "js_kernel_",
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
                isNativeKernelResource(entry.name) || entry.name in legacyBootResourcePaths
            }
            val existingEntries = retainedJarEntries.map { it.name }.toSet()
            val newEntries = mutableListOf<JarEntryData>()
            for (rn in recompiledNatives) {
                val route = NativeRecompilationRoute.forPlatform(rn.platform)
                require(rn.libName == route.outputName) {
                    "Qp Rust runtime name is not canonical for ${rn.platform}: ${rn.libName}"
                }
                val entryName = route.preSealResourcePath
                if (entryName in existingEntries) continue
                if (!nativeLibraryContainsRequiredJniVmAbi(rn.bytes)) {
                    throw IllegalStateException(
                        "Qp Rust JNI runtime for ${rn.platform} does not contain the required qp_r1 ABI exports",
                    )
                }
                newEntries.add(JarEntryData(name = entryName, bytes = rn.bytes))
            }
            if (newEntries.isEmpty()) {
                throw IllegalStateException("Qp Rust compilation produced no loadable JNI runtime libraries")
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
            REQUIRED_NATIVE_ABI_EXPORTS.all { export -> bytes.containsAscii(export) }

    /**
     * This is a build-time preflight, not a Java fallback gate. Host validation
     * happens inside RustToolchainProvisioner before executable discovery or any
     * compiler/version probe, so macOS and non-x86 hosts fail closed first.
     */
    internal fun hasLoadableNativeKernel(): Boolean {
        val resolution = runCatching {
            RustToolchainProvisioner.resolve(
                osName = System.getProperty("os.name"),
                osArch = System.getProperty("os.arch"),
            )
        }.getOrNull() ?: return false
        return resolution.toolchain != null
    }

    private fun isNativeKernelResource(entryName: String): Boolean {
        val lowerEntryName = entryName.lowercase()
        if (!lowerEntryName.startsWith("meta-inf/")) return false
        val lowerFileName = lowerEntryName.substringAfterLast('/')
        val dynamicSuffix = lowerFileName.endsWith(".dll") ||
            lowerFileName.endsWith(".so") ||
            lowerFileName.endsWith(".dylib")
        return (lowerEntryName.startsWith("${NATIVE_RESOURCE_ROOT.lowercase()}/") ||
            lowerEntryName.startsWith("meta-inf/jsrt/") ||
            lowerEntryName.startsWith("meta-inf/js-native/")) && dynamicSuffix ||
            lowerFileName.startsWith("js_kernel_") && dynamicSuffix
    }

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
     * Compile the current Rust JNI runtime. The request has already rejected
     * retired platforms, and QpNativeCompilerPass owns the isolated
     * Cargo workspace and locked toolchain invocation.
     */
    private fun compileNativeLibrariesOrThrow(
        config: io.github.hht0rro.javashroud.model.config.ObfuscationConfig?,
        emit: (EngineEvent) -> Unit = {},
    ): List<QpNativeCompilerPass.RecompiledNative> {
        if (config == null) {
            throw IllegalStateException("jni-microkernel-loader requires an obfuscation config for Qp Rust compilation")
        }
        val loaderPass = config.passes.find { it.id == "jni-microkernel-loader" && it.enabled }
            ?: throw IllegalStateException("jni-microkernel-loader pass config is missing")
        val recompileEnabled = (loaderPass.params["nativeRecompilation"] as? com.fasterxml.jackson.databind.node.BooleanNode)
            ?.booleanValue() ?: true
        if (!recompileEnabled) {
            throw IllegalStateException("jni-microkernel-loader requires native recompilation; nativeRecompilation=false is no longer supported")
        }

        val targetPlatformParam = (loaderPass.params["targetPlatform"] as? com.fasterxml.jackson.databind.node.TextNode)
            ?.textValue() ?: "auto"
        val nativeProtectionLevel = (loaderPass.params["nativeProtectionLevel"] as? com.fasterxml.jackson.databind.node.TextNode)
            ?.textValue() ?: "standard"
        val nativePackingLevel = (loaderPass.params["nativePackingLevel"] as? com.fasterxml.jackson.databind.node.TextNode)
            ?.textValue() ?: "max"
        val request = QpNativeCompilerRequest.forTargets(
            nativeProtectionLevel = nativeProtectionLevel,
            nativePackingLevel = QpPackingLevel.parse(nativePackingLevel),
            targetPlatforms = resolveNativeCompileTargetPlatforms(targetPlatformParam),
        )

        val seedNode = loaderPass.params["seed"]
        val seed = (seedNode as? com.fasterxml.jackson.databind.node.NumericNode)?.longValue()
            ?: config.outputJarPath.hashCode().toLong()

        val classLoader = this::class.java.classLoader
        try {
            val diagnostics = QpNativeCompilerPass.recompileWithDiagnostics(
                seed = seed,
                classLoader = classLoader,
                request = request,
                onMessage = { message ->
                    emitNativeRecompilationMessage(
                        emit = emit,
                        level = message.level,
                        text = message.message,
                        progress = message.progress,
                    )
                },
            )
            if (diagnostics.results.isEmpty()) {
                throw IllegalStateException("Qp Rust toolchain is unavailable or produced no loadable libraries")
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
        val host = try {
            RustToolchainProvisioner.hostPlatform(osName, osArch)
        } catch (error: RustToolchainProvisioner.RustToolchainException) {
            throw IllegalArgumentException("Qp Rust target host is unsupported: $osName/$osArch", error)
        }
        val trimmed = targetPlatformParam.trim()
        if (trimmed.equals("auto", ignoreCase = true)) {
            return listOf(
                when (host) {
                    RustToolchainProvisioner.HostPlatform.WINDOWS_X64 -> RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS
                    RustToolchainProvisioner.HostPlatform.LINUX_X64 -> RustToolchainProvisioner.RUNTIME_TARGET_LINUX
                },
            )
        }
        if (trimmed.equals("all", ignoreCase = true)) {
            return NativeRecompilationRoute.canonicalPlatformOrder
        }
        val requested = if (',' in trimmed) {
            trimmed.split(',').map(String::trim).filter(String::isNotEmpty)
        } else {
            listOf(trimmed)
        }
        require(requested.isNotEmpty()) { "Qp Rust target platform is empty" }
        return requested.map(NativeRecompilationRoute::normalizePlatform).distinct()
    }

    internal fun requireCompleteNativeCompileTargets(
        requestedPlatforms: List<String>,
        results: List<QpNativeCompilerPass.RecompiledNative>,
    ): List<QpNativeCompilerPass.RecompiledNative> {
        val requested = requestedPlatforms.distinct()
        val resultsByPlatform = results.groupBy { it.platform }
        val missing = requested.filterNot(resultsByPlatform::containsKey)
        val unexpected = resultsByPlatform.keys.filterNot(requested::contains)
        val duplicates = resultsByPlatform.filterValues { it.size != 1 }.keys
        if (missing.isNotEmpty() || unexpected.isNotEmpty() || duplicates.isNotEmpty()) {
            throw IllegalStateException(
                buildString {
                    append("Qp Rust compilation did not produce exactly the requested target platforms")
                    if (missing.isNotEmpty()) append("; missing=${missing.joinToString(",")}")
                    if (unexpected.isNotEmpty()) append("; unexpected=${unexpected.joinToString(",")}")
                    if (duplicates.isNotEmpty()) append("; duplicate=${duplicates.joinToString(",")}")
                },
            )
        }
        val ordered = requested.map { platform -> resultsByPlatform.getValue(platform).single() }
        val nonCanonicalNames = ordered.filter { result ->
            result.libName != NativeRecompilationRoute.forPlatform(result.platform).outputName
        }
        require(nonCanonicalNames.isEmpty()) {
            "Qp Rust compilation produced non-canonical runtime names: " +
                nonCanonicalNames.joinToString { "${it.platform}=${it.libName}" }
        }
        return ordered
    }

    private fun emitNativeRecompilationMessage(
        emit: (EngineEvent) -> Unit,
        level: String,
        text: String,
        progress: Int?,
    ) {
        val normalizedLevel = if (level == "warn") "warn" else "info"
        emit(
            EngineEvent(
                level = normalizedLevel,
                type = if (normalizedLevel == "warn") "warn" else "log",
                message = text,
                progress = progress,
                outPath = null,
            ),
        )
    }

    private fun emitNativeRecompilationFailure(emit: (EngineEvent) -> Unit, reason: String) {
        emit(
            EngineEvent(
                level = "error",
                type = "error",
                message = "Qp Rust JNI runtime compilation failed ($reason). No legacy native fallback is available.",
                progress = 94,
                outPath = null,
            )
        )
    }


    // --- ASM Generators (all use COMPUTE_MAXS only) ---

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
        val pkg = if (simpleName.startsWith("Qp")) QP_PKG else PKG
        val resourceName = "$pkg/$simpleName.class"
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
