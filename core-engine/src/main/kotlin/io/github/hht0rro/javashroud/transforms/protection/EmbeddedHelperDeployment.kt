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
    private val runtimeResourceDecodeHelpers = listOf(
        "$PKG/JniMicrokernelHelper",
        "$PKG/JniMicrokernelHelper${"$"}RuntimeResourceMetadata",
        "$PKG/JniMicrokernelHelper${"$"}SealedNativeLibrary",
        "$PKG/JniMicrokernelHelper${"$"}TypeParseResult",
    )

    private val passToHelpers: Map<String, List<String>> = mapOf(
        "class-encryption-loader" to listOf(
            "$PKG/ClassEncryptionLoaderHelper",
            "$PKG/ClassEncryptionLoaderHelper${"$"}ParsedMetadata",
            "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader",
        ) + runtimeResourceDecodeHelpers,
        "string-encryption" to listOf("$PKG/StringEncryptionHelper"),
        "method-body-delayed-decryption" to listOf(
            "$PKG/MethodBodyDecryptionHelper",
            "$PKG/MethodBodyDecryptionHelper${"$"}ParsedMetadata",
        ) + runtimeResourceDecodeHelpers,
        "callsite-rotation-protection" to listOf("$PKG/CallsiteRotationHelper"),
        "environment-bound-keys" to listOf("$PKG/EnvironmentBindingHelper"),
        "anti-symbolic-execution" to listOf("$PKG/AntiSymbolicExecutionHelper"),
        "exception-semantic-virtualization" to listOf(
            "$PKG/ExceptionVirtualizationHelper",
            "$PKG/FlowControlException",
        ),
        "anti-instrumentation" to listOf("$PKG/AntiInstrumentationHelper"),
        "anti-dump-protection" to listOf("$PKG/AntiDumpRuntimeHelper"),
        "jni-microkernel-loader" to runtimeResourceDecodeHelpers,
        "method-virtualization" to emptyList(),
    )
    private val helperGenerators: Map<String, () -> ByteArray> by lazy {
        mapOf(
            "$PKG/ClassEncryptionLoaderHelper" to { loadClasspathHelperByName("ClassEncryptionLoaderHelper") },
            "$PKG/ClassEncryptionLoaderHelper${"$"}ParsedMetadata" to { loadClasspathHelperByName("ClassEncryptionLoaderHelper${"$"}ParsedMetadata") },
            "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader" to { loadClasspathHelperByName("ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader") },
            "$PKG/MethodBodyDecryptionHelper" to { loadClasspathHelperByName("MethodBodyDecryptionHelper") },
            "$PKG/MethodBodyDecryptionHelper${"$"}ParsedMetadata" to { loadClasspathHelperByName("MethodBodyDecryptionHelper${"$"}ParsedMetadata") },
            "$PKG/StringEncryptionHelper" to { loadClasspathHelperByName("StringEncryptionHelper") },
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
            "$PKG/JniMicrokernelHelper${"$"}TypeParseResult" to { loadClasspathHelperByName("JniMicrokernelHelper${"$"}TypeParseResult") },
        )
    }

    /**
     * Inject required runtime helper classes into the bytecode artifact.
     */
    fun injectRequiredHelpers(
        artifact: BytecodeArtifact,
        executedPassIds: List<String>,
    ): BytecodeArtifact {
        val existingEntries = artifact.jarEntries.map { it.name }.toSet()
        val neededHelpers = sortedSetOf<String>()
        val resolvedPassIds = resolvePassIdsWithSchemaDependencies(executedPassIds)
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
                loadHelperBytes(helperInternalName)
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
        if (newEntries.isEmpty()) return artifact
        val injectedClassArtifacts = newEntries.map { entry: JarEntryData ->
            ClassArtifact(
                entryName = entry.name,
                summary = analyzeClassBytes(entry.bytes),
                bytes = entry.bytes,
            )
        }
        val updatedJarEntries = artifact.jarEntries + newEntries
        val updatedClassArtifacts = artifact.classArtifacts + injectedClassArtifacts
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

    private fun loadHelperBytes(helperInternalName: String): ByteArray {
        val generator = helperGenerators[helperInternalName]
            ?: throw IllegalStateException("missing generator")
        val helperBytes = generator()
        return if (helperInternalName == "$PKG/JniMicrokernelHelper") {
            injectRuntimeResourceKey(helperBytes, requireVbc4BuildContext().copyRuntimeResourceKey())
        } else {
            helperBytes
        }
    }

    internal fun injectRuntimeResourceKey(helperBytes: ByteArray, runtimeKey: ByteArray): ByteArray {
        require(runtimeKey.size == VBC4_RUNTIME_RESOURCE_KEY_SIZE) { "runtime resource key must be 32 bytes" }
        val random = java.security.SecureRandom()
        // Per-build share split: the per-build root key is never emitted as a
        // single contiguous literal. It is XOR-split into N shares (N and the
        // generated method names randomized per build), each share emitted into
        // its own generated method, and the key is reassembled only transiently
        // at runtime, after which the share temporaries are wiped.
        val shareCount = 3 + random.nextInt(4)
        val shares = Array(shareCount) { ByteArray(runtimeKey.size) }
        for (index in 0 until shareCount - 1) random.nextBytes(shares[index])
        val last = shares[shareCount - 1]
        for (byteIndex in runtimeKey.indices) {
            var acc = runtimeKey[byteIndex].toInt()
            for (index in 0 until shareCount - 1) acc = acc xor shares[index][byteIndex].toInt()
            last[byteIndex] = acc.toByte()
        }
        val suffix = ByteArray(5).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        val shareMethodNames = (0 until shareCount).map { "jsRrkShare${it}_$suffix" }
        val reader = ClassReader(helperBytes)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
        var ownerName = "$PKG/JniMicrokernelHelper"
        reader.accept(object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visit(
                version: Int,
                access: Int,
                name: String,
                signature: String?,
                superName: String?,
                interfaces: Array<String>?,
            ) {
                ownerName = name
                super.visit(version, access, name, signature, superName, interfaces)
            }

            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name != "runtimeResourceKey" || descriptor != "()[B") {
                    return super.visitMethod(access, name, descriptor, signature, exceptions)
                }
                val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
                emitReassembly(mv, ownerName, shareMethodNames, runtimeKey.size)
                return null
            }

            override fun visitEnd() {
                for (shareIndex in shareMethodNames.indices) {
                    emitShareMethod(this, shareMethodNames[shareIndex], shares[shareIndex])
                }
                super.visitEnd()
            }
        }, 0)
        return writer.toByteArray()
    }

    private fun emitReassembly(
        mv: MethodVisitor,
        ownerName: String,
        shareMethodNames: List<String>,
        keyLength: Int,
    ) {
        mv.visitCode()
        val shareCount = shareMethodNames.size
        for (shareIndex in 0 until shareCount) {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, ownerName, shareMethodNames[shareIndex], "()[B", false)
            mv.visitVarInsn(Opcodes.ASTORE, shareIndex)
        }        // result array in local `shareCount`
        pushInt(mv, keyLength)
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        mv.visitVarInsn(Opcodes.ASTORE, shareCount)
        for (byteIndex in 0 until keyLength) {
            mv.visitVarInsn(Opcodes.ALOAD, shareCount)
            pushInt(mv, byteIndex)
            // XOR all shares at this position
            mv.visitVarInsn(Opcodes.ALOAD, 0)
            pushInt(mv, byteIndex)
            mv.visitInsn(Opcodes.BALOAD)
            for (shareIndex in 1 until shareCount) {
                mv.visitVarInsn(Opcodes.ALOAD, shareIndex)
                pushInt(mv, byteIndex)
                mv.visitInsn(Opcodes.BALOAD)
                mv.visitInsn(Opcodes.IXOR)
            }
            mv.visitInsn(Opcodes.I2B)
            mv.visitInsn(Opcodes.BASTORE)
        }
        for (shareIndex in 0 until shareCount) {
            mv.visitVarInsn(Opcodes.ALOAD, shareIndex)
            mv.visitInsn(Opcodes.ICONST_0)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Arrays", "fill", "([BB)V", false)
        }
        mv.visitVarInsn(Opcodes.ALOAD, shareCount)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
    }
    private fun emitShareMethod(cv: ClassVisitor, methodName: String, share: ByteArray) {
        val mv = cv.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, methodName, "()[B", null, null)
            ?: return
        mv.visitCode()
        pushInt(mv, share.size)
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        for ((index, byte) in share.withIndex()) {
            mv.visitInsn(Opcodes.DUP)
            pushInt(mv, index)
            pushInt(mv, byte.toInt())
            mv.visitInsn(Opcodes.BASTORE)
        }
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
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
        "nativeInstallRuntimeResourceKey",
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
        val retainedJarEntries = artifact.jarEntries.filterNot { entry -> isNativeKernelResource(entry.name) }
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
        return artifact.copy(
            jarEntries = updatedJarEntries,
            analysisSummary = artifact.analysisSummary.copy(
                resourceCount = resourceCount(updatedJarEntries, artifact.classArtifacts.size),
            ),
        )
    }

    internal fun nativeLibraryContainsRequiredJniVmAbi(bytes: ByteArray): Boolean =
        bytes.isNotEmpty() &&
            REQUIRED_SEALED_NATIVE_ABI_MARKERS.all { marker -> bytes.containsAscii(marker) } &&
            REJECTED_LEGACY_NATIVE_ABI_MARKERS.none { marker -> bytes.containsAscii(marker) }

    internal fun hasLoadableNativeKernel(): Boolean = hasBundledNativeSources()

    private fun hasBundledNativeSources(): Boolean = listOf(
        "js_kernel.c",
        "js_helpers.c",
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
        require(nativeProtectionLevel in setOf("standard", "aggressive")) {
            "jni-microkernel-loader nativeProtectionLevel '$nativeProtectionLevel' is not supported"
        }
        val targetPlatforms = resolveNativeCompileTargetPlatforms(targetPlatformParam)
        if (targetPlatforms.isEmpty() || targetPlatforms.any { it !in NativeRecompilationTransforms.ZIG_TARGETS }) {
            throw IllegalArgumentException("target platform is unsupported: $targetPlatformParam")
        }

        val seedNode = loaderPass.params["seed"]
        val seed = (seedNode as? com.fasterxml.jackson.databind.node.NumericNode)?.longValue()
            ?: config.outputJarPath.hashCode().toLong()

        val classLoader = this::class.java.classLoader
        try {
            val diagnostics = NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = seed,
                classLoader = classLoader,
                targetPlatforms = targetPlatforms,
                nativeProtectionLevel = nativeProtectionLevel,
                onMessage = { message -> emitNativeRecompilationMessage(emit, message) },
            )
            if (diagnostics.results.isEmpty()) {
                throw IllegalStateException("Zig toolchain is unavailable or native compilation produced no loadable libraries")
            }
            return diagnostics.results
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
        if (targetPlatformParam != "auto") return listOf(targetPlatformParam)
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
