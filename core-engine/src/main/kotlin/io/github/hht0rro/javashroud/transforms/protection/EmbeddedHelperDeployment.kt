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
import java.util.HexFormat

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
        "$PKG/JniMicrokernelHelper${"$"}SamLambdaOptions",
        "$PKG/JniMicrokernelHelper${"$"}SamInvocationHandler",
    )

    private val passToHelpers: Map<String, List<String>> = mapOf(
        "class-encryption-loader" to listOf(
            "$PKG/ClassEncryptionLoaderHelper",
            "$PKG/ClassEncryptionLoaderHelper${"$"}ParsedMetadata",
            "$PKG/ClassEncryptionLoaderHelper${"$"}SharedDecryptingClassLoader",
        ) + runtimeResourceDecodeHelpers,
        "string-encryption" to listOf(
            "$PKG/StringEncryptionHelper",
            "$PKG/StringEncryptionHelper${"$"}CachePolicy",
        ),
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
        if ("jni-microkernel-loader" in resolvedPassIds) {
            val context = requireVbc4BuildContext()
            val bootSecret = context.copyBootSecretForBuild()
            try {
                newEntries.removeAll { it.name == BootMaterialEnvelope.RESOURCE_PATH }
                newEntries.add(
                    JarEntryData(
                        name = BootMaterialEnvelope.RESOURCE_PATH,
                        bytes = BootMaterialEnvelope.encode(context, bootSecret),
                    )
                )
            } finally {
                java.util.Arrays.fill(bootSecret, 0)
            }
        }
        if (generationFailures.isNotEmpty()) {
            throw IllegalStateException(
                "Failed to embed runtime helpers for passes ${executedPassIds.sorted()}: ${generationFailures.joinToString("; ")}"
            )
        }
        if (newEntries.isEmpty()) return artifact
        val injectedClassArtifacts = newEntries.filter { entry -> entry.name.endsWith(".class") }.map { entry: JarEntryData ->
            ClassArtifact(
                entryName = entry.name,
                summary = analyzeClassBytes(entry.bytes),
                bytes = entry.bytes,
            )
        }
        val retainedJarEntries = if ("jni-microkernel-loader" in resolvedPassIds) {
            artifact.jarEntries.filterNot { entry -> entry.name == BootMaterialEnvelope.RESOURCE_PATH }
        } else {
            artifact.jarEntries
        }
        val updatedJarEntries = retainedJarEntries + newEntries
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
        return generator()
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
            val shellBindings = recompiledNatives.mapNotNull { native ->
                native.shellBindingCommitment?.let { commitment -> native.platform to commitment }
            }.toMap(linkedMapOf())
            require(shellBindings.isEmpty() || shellBindings.size == recompiledNatives.size) {
                "Zig compilation produced an incomplete native shell binding set"
            }
            val retainedJarEntries = artifact.jarEntries.filterNot { entry ->
                isNativeKernelResource(entry.name) ||
                    entry.name == BootMaterialEnvelope.RESOURCE_PATH ||
                    entry.name == BootKekSidecar.EMBEDDED_RESOURCE_PATH
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
            val bootSecret = requireVbc4BuildContext().copyBootSecretForBuild()
            try {
                newEntries.add(
                    JarEntryData(
                        name = BootMaterialEnvelope.RESOURCE_PATH,
                        bytes = BootMaterialEnvelope.encode(requireVbc4BuildContext(), bootSecret, shellBindings),
                    )
                )
            } finally {
                java.util.Arrays.fill(bootSecret, 0)
            }
            if (bootKeyDelivery(config) == BootKekSidecar.DELIVERY_EMBEDDED) {
                newEntries.add(
                    JarEntryData(
                        name = BootKekSidecar.EMBEDDED_RESOURCE_PATH,
                        bytes = embeddedBootKekBytes(requireNotNull(config)),
                    ),
                )
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

    private fun bootKeyDelivery(config: io.github.hht0rro.javashroud.model.config.ObfuscationConfig?): String {
        val loaderPass = config?.passes?.firstOrNull { it.id == "jni-microkernel-loader" && it.enabled }
            ?: return BootKekSidecar.DELIVERY_EXTERNAL_FILE
        val delivery = loaderPass.params["bootKeyDelivery"]?.asText() ?: BootKekSidecar.DELIVERY_EXTERNAL_FILE
        require(delivery == BootKekSidecar.DELIVERY_EXTERNAL_FILE || delivery == BootKekSidecar.DELIVERY_EMBEDDED) {
            "jni-microkernel-loader bootKeyDelivery '$delivery' is not supported"
        }
        return delivery
    }

    private fun embeddedBootKekBytes(config: io.github.hht0rro.javashroud.model.config.ObfuscationConfig): ByteArray {
        val loaderPass = config.passes.first { it.id == "jni-microkernel-loader" && it.enabled }
        val maxHardening = loaderPass.params["nativePackingLevel"]?.asText() == "max-hardening"
        val context = requireVbc4BuildContext()
        val secret = context.copyBootSecretForBuild()
        return try {
            if (maxHardening) {
                val binding = context.copyBootSidecarBindingForBuild()
                try {
                    BootKekSidecar.encodeText(secret, binding).toByteArray(Charsets.US_ASCII)
                } finally {
                    binding.fill(0)
                }
            } else {
                HexFormat.of().formatHex(secret).toByteArray(Charsets.US_ASCII)
            }
        } finally {
            secret.fill(0)
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
        require(nativeProtectionLevel in setOf("standard", "aggressive")) {
            "jni-microkernel-loader nativeProtectionLevel '$nativeProtectionLevel' is not supported"
        }
        val nativePackingLevel = (loaderPass.params["nativePackingLevel"] as? com.fasterxml.jackson.databind.node.TextNode)?.textValue() ?: "max"
        NativeKernelShellPacker.Level.parse(nativePackingLevel)
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
                nativePackingLevel = nativePackingLevel,
                onMessage = { message -> emitNativeRecompilationMessage(emit, message) },
            )
            if (diagnostics.results.isEmpty()) {
                throw IllegalStateException("Zig toolchain is unavailable or native compilation produced no loadable libraries")
            }
            return requireCompleteNativeCompileTargets(targetPlatforms, diagnostics.results)
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
