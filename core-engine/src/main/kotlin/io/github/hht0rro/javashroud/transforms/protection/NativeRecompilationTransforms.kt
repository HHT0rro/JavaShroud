package io.github.hht0rro.javashroud.transforms.protection

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object NativeRecompilationTransforms {

    private val zigCompileLock = Any()

    private const val NATIVE_SRC_RESOURCE_ROOT = "META-INF/native-src"

    internal val ZIG_TARGETS = mapOf(
        "windows-x64" to "x86_64-windows-gnu",
        "linux-x64" to "x86_64-linux-gnu",
        "macos-x64" to "x86_64-macos-none",
        "macos-arm64" to "aarch64-macos-none",
    )

    private val OUTPUT_NAMES = mapOf(
        "windows-x64" to "js_kernel_windows-x64.dll",
        "linux-x64" to "js_kernel_linux-x64.so",
        "macos-x64" to "js_kernel_macos-x64.dylib",
        "macos-arm64" to "js_kernel_macos-arm64.dylib",
    )

    private val NATIVE_SOURCE_FILES = listOf(
        "js_kernel.c",
        "js_helpers.c",
        "js_native_common.c",
        "js_native_common.h",
        "js_crypto.c",
        "js_crypto.h",
        "js_antidebug.c",
        "js_antidebug.h",
        "js_protected_section.c",
        "js_protected_section.h",
        "js_protected_section_linux.ld",
        "js_vm_core.c",
        "js_vm_core.h",
        "js_vm_resource.c",
        "js_vm_resource.h",
        "js_vm_symbol.c",
        "js_vm_symbol.h",
        "js_vm_internal.h",
        "js_jni_runtime.c",
        "js_jni_runtime.h",
        "native_secrets.inc",
        "js_shell_stub.c",
        "js_shell_stub.h",
        "js_shell_crypto.c",
        "js_shell_crypto.h",
        "js_shell_loader.h",
        "js_shell_loader_pe.c",
        "js_shell_loader_elf.c",
        "js_shell_loader_macho.c",
    )

    private val NATIVE_DIVERSIFICATION_TARGETS = listOf("js_kernel.c", "js_vm_core.c")

    data class RecompiledNative(
        val platform: String,
        val libName: String,
        val bytes: ByteArray,
        val shellBindingCommitment: ByteArray? = null,
    )

    fun recompile(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatforms: Collection<String> = ZIG_TARGETS.keys,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
    ): List<RecompiledNative> = recompileWithDiagnostics(seed, classLoader, targetPlatforms, nativeProtectionLevel, nativePackingLevel).results

    data class RecompilationDiagnostics(
        val results: List<RecompiledNative>,
        val messages: List<NativeToolchainProvisioner.ResolutionMessage>,
    )

    internal fun compileInnerForCfgEvidence(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatform: String = "windows-x64",
        nativeProtectionLevel: String = "standard",
        evidenceRandom: Random? = null,
    ): RecompiledNative? = recompileWithDiagnosticsInternal(
        seed = seed,
        classLoader = classLoader,
        targetPlatforms = listOf(targetPlatform),
        nativeProtectionLevel = nativeProtectionLevel,
        nativePackingLevel = "off",
        cfgEvidenceExports = true,
        evidenceRandom = evidenceRandom,
    ).results.singleOrNull()

    fun recompileWithDiagnostics(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatforms: Collection<String> = ZIG_TARGETS.keys,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
        onMessage: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
    ): RecompilationDiagnostics = recompileWithDiagnosticsInternal(
        seed = seed,
        classLoader = classLoader,
        targetPlatforms = targetPlatforms,
        nativeProtectionLevel = nativeProtectionLevel,
        nativePackingLevel = nativePackingLevel,
        onMessage = onMessage,
    )

    private fun recompileWithDiagnosticsInternal(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatforms: Collection<String>,
        nativeProtectionLevel: String,
        nativePackingLevel: String,
        onMessage: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
        cfgEvidenceExports: Boolean = false,
        evidenceRandom: Random? = null,
    ): RecompilationDiagnostics {
        require(nativeProtectionLevel in setOf("standard", "aggressive")) {
            "jni-microkernel-loader nativeProtectionLevel '$nativeProtectionLevel' is not supported"
        }
        val parsedNativePackingLevel = NativeKernelShellPacker.Level.parse(nativePackingLevel)
        val messages = mutableListOf<NativeToolchainProvisioner.ResolutionMessage>()
        fun report(message: NativeToolchainProvisioner.ResolutionMessage) {
            messages += message
            onMessage(message)
        }
        val resolution = NativeToolchainProvisioner.resolveWithMessages(onMessage = ::report)
        val toolchain = resolution.toolchain ?: return RecompilationDiagnostics(emptyList(), messages)
        val workDir = Files.createTempDirectory("javashroud-native-recompile-")
        return try {
            val results = doRecompile(seed, classLoader, toolchain, workDir, targetPlatforms, nativeProtectionLevel, parsedNativePackingLevel, cfgEvidenceExports, evidenceRandom, ::report)
            RecompilationDiagnostics(results, messages)
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    private fun doRecompile(
        seed: Long,
        classLoader: ClassLoader,
        toolchain: NativeToolchainProvisioner.ZigToolchain,
        workDir: Path,
        targetPlatforms: Collection<String>,
        nativeProtectionLevel: String,
        nativePackingLevel: NativeKernelShellPacker.Level,
        cfgEvidenceExports: Boolean,
        evidenceRandom: Random?,
        report: (NativeToolchainProvisioner.ResolutionMessage) -> Unit,
    ): List<RecompiledNative> {
        val vbc4BuildContext = requireVbc4BuildContext()
        require(!cfgEvidenceExports || evidenceRandom != null) { "CFG evidence compilation requires an explicit deterministic random stream" }
        require(cfgEvidenceExports || evidenceRandom == null) { "Evidence-only random stream must not enter production native recompilation" }
        val rng: Random = evidenceRandom ?: nativeBuildSecureRandom(seed, vbc4BuildContext)
        val results = mutableListOf<RecompiledNative>()
        val srcDir = workDir.resolve("src")
        Files.createDirectories(srcDir)
        val crossCompileDir = srcDir.resolve("cross-compile")
        Files.createDirectories(crossCompileDir)

        for (name in NATIVE_SOURCE_FILES) {
            val bytes = loadResource(classLoader, "${NATIVE_SRC_RESOURCE_ROOT}/${name}") ?: return emptyList()
            Files.write(srcDir.resolve(name), bytes)
        }
        for (name in listOf("jni.h", "jni_md_linux.h")) {
            val bytes = loadResource(classLoader, "${NATIVE_SRC_RESOURCE_ROOT}/cross-compile/${name}") ?: return emptyList()
            Files.write(crossCompileDir.resolve(name), bytes)
        }
        copyNativeResourceTree(classLoader, "zstd", srcDir.resolve("zstd"))

        val secretsSeed = (rng.nextInt().toLong() and 0xFFFFFFFFL)
        val protectedSectionKey = ByteArray(32).also(rng::nextBytes)
        return try {
        val secretsContent = generateDiversifiedSecrets(secretsSeed, rng, vbc4BuildContext, protectedSectionKey)
        Files.write(srcDir.resolve("native_secrets.inc"), secretsContent.toByteArray(StandardCharsets.UTF_8))

        for (name in NATIVE_DIVERSIFICATION_TARGETS) {
            val original = Files.readString(srcDir.resolve(name), StandardCharsets.UTF_8)
            val diversified = applyNativeInterpreterCodegen(applySourceDiversification(original, rng), rng)
            Files.writeString(srcDir.resolve(name), diversified, StandardCharsets.UTF_8)
        }

        val guardCode = generateAntiReverseGuards(rng, nativeProtectionLevel)
        Files.writeString(srcDir.resolve("js_native_guards.h"), guardCode, StandardCharsets.UTF_8)


        val kernelSrc = Files.readString(srcDir.resolve("js_kernel.c"), StandardCharsets.UTF_8)
        val guardInclude = "\n#include \"js_native_guards.h\"\n"
        val injectPoint = kernelSrc.indexOf("#include <string.h>")
        if (injectPoint >= 0) {
            val endOfLine = kernelSrc.indexOf('\n', injectPoint)
            val injected = kernelSrc.substring(0, endOfLine + 1) + guardInclude + kernelSrc.substring(endOfLine + 1)
            Files.writeString(srcDir.resolve("js_kernel.c"), injected, StandardCharsets.UTF_8)
        }

        val nativeSourceDigest = digestNativeSourceTree(srcDir)
        val toolchainIdentity = zigToolchainIdentity(toolchain)
        val compileTasks = targetPlatforms.mapNotNull { platform ->
            val target = ZIG_TARGETS[platform] ?: return@mapNotNull null
            val outputName = OUTPUT_NAMES[platform] ?: return@mapNotNull null
            val outputPath = workDir.resolve(platform).resolve(outputName)
            val cacheKey = nativeArtifactCacheKey(
                taskPlatform = platform,
                zigTarget = target,
                outputName = outputName,
                sourceDigest = nativeSourceDigest,
                toolchainIdentity = toolchainIdentity,
                seed = seed,
                vbc4BuildContext = vbc4BuildContext,
                protectedSectionKey = protectedSectionKey,
                nativeProtectionLevel = nativeProtectionLevel,
                nativePackingLevel = nativePackingLevel.name.lowercase(),
                nativeShellPackerVersion = NativeKernelShellPacker.PACKER_VERSION,
                nativeShellPayloadProfile = "${nativePackingLevel.name.lowercase()}-payload-v7-boot-dat-binding-encrypted-header-aesctr-hmac-chunks",
                nativeShellLoaderProfile = nativeShellLoaderProfile(platform),
            )
            NativeCompileTask(
                platform = platform,
                zigTarget = target,
                outputName = outputName,
                outputPath = outputPath,
                cachePath = nativeArtifactCacheDirectory().resolve("$cacheKey-$outputName"),
                nativeProtectionLevel = nativeProtectionLevel,
                nativePackingLevel = nativePackingLevel.name.lowercase(),
            )
        }
        // Zig's Windows cache has produced intermittent `file_open Unexpected`
        // failures when multiple target compilations share it concurrently. Native
        // builds are infrequent and correctness matters more than parallel startup.
        val compiledResults = compileTasks.map { task ->
            try {
                Files.createDirectories(task.outputPath.parent)
                // MAX output is encrypted for the current external boot KEK. Reusing a cached
                // outer library could bind the artifact to an earlier provider secret, so the
                // seed envelope is always rebuilt even outside production-evidence mode.
                val forceProductionCompile = task.nativePackingLevel == NativeKernelShellPacker.Level.MAX.name.lowercase()
                task to compileOrLoadNativeArtifact(
                    toolchain.zigPath,
                    srcDir,
                    workDir,
                    task,
                    cfgEvidenceExports,
                    forceProductionCompile,
                )
            } catch (error: Exception) {
                task to NativeArtifactBuildResult(false, error.message ?: error::class.java.simpleName, null, false)
            }
        }
        for ((task, compileResult) in compiledResults) {
            if (compileResult.success && compileResult.bytes != null && compileResult.bytes.isNotEmpty()) {
                if (cfgEvidenceExports) {
                    // CFG evidence must observe the compiler output itself. Returning before
                    // protected-section sealing also keeps the evidence hook out of every
                    // production cache and outer-shell path.
                    results.add(RecompiledNative(task.platform, task.outputName, compileResult.bytes))
                    report(NativeToolchainProvisioner.ResolutionMessage("info", "Compiled pre-seal inner JNI microkernel for ${task.platform} with Zig ${toolchain.zigPath}", 94))
                    continue
                }
                val preSealInner = compileResult.bytes.copyOf()
                var shellBindingCommitment: ByteArray? = null
                try {
                    val rawBytes = if (compileResult.fromCache) {
                        compileResult.bytes
                    } else {
                        // Item #4: native critical-region pre-decrypt protection. The compiled
                        // kernel emits selected pure, relocation-free hot functions into a
                        // dedicated, page-isolated ".jsx" code section plus a guarded runtime
                        // enter/leave lifecycle. Here we encrypt that section in-place for supported
                        // native formats and arm the in-binary seal marker. This protects
                        // the most analysis-relevant code against offline static analysis while
                        // keeping the library loadable. The patcher fails closed for responsible formats.
                        val sectionSealed = NativeProtectedSectionPacker.sealIfPossible(compileResult.bytes, protectedSectionKey, report, failClosed = true)
                        when (nativePackingLevel) {
                            NativeKernelShellPacker.Level.OFF -> sectionSealed
                            NativeKernelShellPacker.Level.STANDARD -> {
                                val shellKeyMaterial = protectedSectionKey + vbc4BuildContext.runtimeResourceKey
                                val shellPacked = try {
                                    NativeKernelShellPacker.pack(
                                        bytes = sectionSealed,
                                        platform = task.platform,
                                        outputName = task.outputName,
                                        seed = seed,
                                        level = nativePackingLevel,
                                        keyMaterial = shellKeyMaterial,
                                    )
                                } finally {
                                    shellKeyMaterial.fill(0)
                                }
                                report(NativeToolchainProvisioner.ResolutionMessage("info", "Applied standard native shell overlay for ${task.platform}", 94))
                                shellPacked
                            }
                            NativeKernelShellPacker.Level.MAX -> {
                                val bootSecret = vbc4BuildContext.copyBootSecretForBuild()
                                var bootstrapDigest: ByteArray? = null
                                try {
                                    val currentBootstrapDigest = nativeBootstrapIndexDigest(task.platform, task.outputName, vbc4BuildContext)
                                    bootstrapDigest = currentBootstrapDigest
                                    val shellKeyMaterial = protectedSectionKey + vbc4BuildContext.runtimeResourceKey + vbc4BuildContext.jarLayoutDigest
                                    val payloadBundle = try {
                                        NativeKernelShellPacker.buildMaxPayloadBundle(
                                            bytes = sectionSealed,
                                            platform = task.platform,
                                            outputName = task.outputName,
                                            seed = seed,
                                            keyMaterial = shellKeyMaterial,
                                            bootstrapNativeIndexDigest = currentBootstrapDigest,
                                            bootSecret = bootSecret,
                                        )
                                    } finally {
                                        shellKeyMaterial.fill(0)
                                    }
                                    try {
                                        shellBindingCommitment = payloadBundle.artifactBindingCommitment.copyOf()
                                        val renderedShellHeader = NativeKernelShellPacker.renderMaxPayloadHeader(payloadBundle)
                                        Files.writeString(srcDir.resolve("js_shell_payload.inc"), renderedShellHeader, StandardCharsets.UTF_8)
                                        val outerResult = compileShellStubWithZig(toolchain.zigPath, srcDir, task.zigTarget, task.outputPath, task.nativeProtectionLevel)
                                        if (!outerResult.success || !Files.exists(task.outputPath) || Files.size(task.outputPath) <= 0) {
                                            throw IllegalStateException("failed to compile max native shell stub for ${task.platform}: ${outerResult.output.take(600)}")
                                        }
                                    } catch (error: Exception) {
                                        shellBindingCommitment?.fill(0)
                                        shellBindingCommitment = null
                                        throw error
                                    } finally {
                                        payloadBundle.wipeSensitive()
                                    }
                                    report(NativeToolchainProvisioner.ResolutionMessage("info", "Applied max native stub shell for ${task.platform}; inner kernel is carried as authenticated payload", 94))
                                    Files.readAllBytes(task.outputPath)
                                } finally {
                                    bootstrapDigest?.fill(0)
                                    bootSecret.fill(0)
                                }
                            }
                        }
                    }
                    if (task.nativePackingLevel == NativeKernelShellPacker.Level.MAX.name.lowercase()) {
                        recordProductionNativeEvidence(
                            context = vbc4BuildContext,
                            task = task,
                            finalNative = rawBytes,
                            preSealInner = preSealInner,
                            diversifiedSource = Files.readAllBytes(srcDir.resolve("js_vm_core.c")),
                            nativeSourceDigest = nativeSourceDigest,
                        )
                    }
                    if (!cfgEvidenceExports && !compileResult.fromCache && EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(rawBytes)) {
                        writeNativeArtifactCache(task.cachePath, rawBytes)
                    }
                    results.add(RecompiledNative(task.platform, task.outputName, rawBytes, shellBindingCommitment))
                    val verb = if (compileResult.fromCache) "Reused cached" else "Compiled"
                    report(NativeToolchainProvisioner.ResolutionMessage("info", "$verb JNI microkernel for ${task.platform} with Zig ${toolchain.zigPath}", 94))
                    shellBindingCommitment = null
                } finally {
                    shellBindingCommitment?.fill(0)
                    preSealInner.fill(0)
                    if (task.nativePackingLevel == NativeKernelShellPacker.Level.MAX.name.lowercase()) {
                        compileResult.bytes.fill(0)
                    }
                }
            } else {
                val diagnosticLines = compileResult.output.lineSequence().filter { it.isNotBlank() }.toList()
                val diagnostic = when {
                    diagnosticLines.size <= 8 -> diagnosticLines
                    else -> diagnosticLines.take(3) + "..." + diagnosticLines.takeLast(5)
                }.joinToString(" | ").take(1_800)
                val suffix = if (diagnostic.isBlank()) "" else ": $diagnostic"
                report(NativeToolchainProvisioner.ResolutionMessage("warn", "Failed to compile JNI microkernel for ${task.platform} with Zig ${toolchain.zigPath}$suffix", 94))
            }
        }
        results
        } finally {
            protectedSectionKey.fill(0)
        }
    }


    private fun nativeBootstrapIndexDigest(platform: String, outputName: String, context: Vbc4BuildContext): ByteArray =
        MessageDigest.getInstance("SHA-256").apply {
            updateUtf8("javashroud-native-bootstrap-index-v1")
            updateUtf8(platform)
            updateUtf8(outputName)
            update(context.jarLayoutDigest)
            update(context.runtimeResourceKey)
        }.digest()

    private fun nativeShellLoaderProfile(platform: String): String = when {
        platform.startsWith("windows-") -> "pe64-memory-loader-headerdir-reloc-import-export-tlsrange-execbounds-v22"
        platform.startsWith("linux-") -> "elf64-anonymous-loader-dynnull-hashbounds-strbounds-rela-init-execbounds-v6"
        platform.startsWith("macos-") -> "macho64-validated-fail-closed-v2"
        else -> "unknown-loader-fail-closed-v1"
    }

    internal fun nativeShellLoaderProfileForTest(platform: String): String = nativeShellLoaderProfile(platform)

    private data class NativeCompileTask(
        val platform: String,
        val zigTarget: String,
        val outputName: String,
        val outputPath: Path,
        val cachePath: Path,
        val nativeProtectionLevel: String,
        val nativePackingLevel: String,
    )

    private fun recordProductionNativeEvidence(
        context: Vbc4BuildContext,
        task: NativeCompileTask,
        finalNative: ByteArray,
        preSealInner: ByteArray,
        diversifiedSource: ByteArray,
        nativeSourceDigest: ByteArray,
    ) {
        val parserSource = extractProductionFunction(diversifiedSource, "js_vm_parse_program")
        val dispatcherSource = extractProductionFunction(diversifiedSource, "js_vm_execute_with_preset_locals")
        val parserProfileMaterial = byteArrayOf(context.nativeVmProfile.parserRowProfile.toByte()) + nativeSourceDigest
        val dispatcherProfileMaterial = byteArrayOf(context.nativeVmProfile.operandAccessProfile.toByte()) + nativeSourceDigest
        context.productionBuildEvidence.recordNative(
            CandidateProductionBuildEvidence.NativeObservation(
                platform = task.platform,
                outputName = task.outputName,
                finalNativeSha256 = CandidateProductionBuildEvidence.sha256Hex(finalNative),
                preSealInnerSha256 = CandidateProductionBuildEvidence.sha256Hex(preSealInner),
                parserProfileId = context.nativeVmProfile.parserRowProfile,
                operandProfileId = context.nativeVmProfile.operandAccessProfile,
                parserDiversifiedFunctionSourceSha256 = CandidateProductionBuildEvidence.sha256Hex(parserSource),
                parserProfileMappingSha256 = CandidateProductionBuildEvidence.framedDigest(
                    "javashroud-parser-production-profile-v2",
                    listOf(parserProfileMaterial, parserSource),
                ),
                dispatcherDiversifiedFunctionSourceSha256 = CandidateProductionBuildEvidence.sha256Hex(dispatcherSource),
                dispatcherProfileMappingSha256 = CandidateProductionBuildEvidence.framedDigest(
                    "javashroud-dispatcher-production-profile-v2",
                    listOf(dispatcherProfileMaterial, dispatcherSource),
                ),
            ),
        )
    }

    /** Extract the exact diversified production function, not an evidence fixture. */
    private fun extractProductionFunction(source: ByteArray, functionName: String): ByteArray {
        val text = source.toString(StandardCharsets.UTF_8)
        var searchOffset = 0
        var nameOffset = -1
        var open = -1
        while (true) {
            nameOffset = text.indexOf("$functionName(", searchOffset)
            require(nameOffset >= 0) { "production native function is missing: $functionName" }
            open = text.indexOf('{', nameOffset)
            require(open >= 0) { "production native function has no body: $functionName" }
            val semicolon = text.indexOf(';', nameOffset)
            if (semicolon < 0 || open < semicolon) break
            searchOffset = nameOffset + functionName.length
        }
        var depth = 0
        var index = open
        while (index < text.length) {
            when (text[index]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return text.substring(nameOffset, index + 1).toByteArray(StandardCharsets.UTF_8)
                }
            }
            index++
        }
        error("production native function body is truncated: $functionName")
    }

    private data class ZigCompileResult(val success: Boolean, val output: String)

    private data class NativeArtifactBuildResult(
        val success: Boolean,
        val output: String,
        val bytes: ByteArray?,
        val fromCache: Boolean,
    )

    private fun compileOrLoadNativeArtifact(
        zigPath: Path,
        srcDir: Path,
        workDir: Path,
        task: NativeCompileTask,
        cfgEvidenceExports: Boolean,
        forceProductionCompile: Boolean,
    ): NativeArtifactBuildResult {
        if (!cfgEvidenceExports && !forceProductionCompile) readNativeArtifactCache(task.cachePath)?.let { cachedBytes ->
            return NativeArtifactBuildResult(true, "cache-hit", cachedBytes, true)
        }
        val compileResult = compileWithZig(zigPath, srcDir, task.zigTarget, task.outputPath, task.nativeProtectionLevel, cfgEvidenceExports)
        if (!compileResult.success || !Files.exists(task.outputPath) || Files.size(task.outputPath) <= 0) {
            return NativeArtifactBuildResult(compileResult.success, compileResult.output, null, false)
        }
        return NativeArtifactBuildResult(true, compileResult.output, Files.readAllBytes(task.outputPath), false)
    }

    private fun readNativeArtifactCache(cachePath: Path): ByteArray? {
        if (!Files.isRegularFile(cachePath)) return null
        val bytes = try {
            Files.readAllBytes(cachePath)
        } catch (_: Exception) {
            return null
        }
        if (EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(bytes)) return bytes
        try {
            Files.deleteIfExists(cachePath)
        } catch (_: Exception) {
            // A locked invalid cache entry must not block recompilation.
        }
        return null
    }

    private fun writeNativeArtifactCache(cachePath: Path, bytes: ByteArray) {
        try {
            Files.createDirectories(cachePath.parent)
            val temp = Files.createTempFile(cachePath.parent, cachePath.fileName.toString(), ".tmp")
            Files.write(temp, bytes)
            try {
                Files.move(temp, cachePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: Exception) {
                Files.move(temp, cachePath, StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (_: Exception) {
            // Cache writes are opportunistic; a failed write must not affect native output.
        }
    }

    private fun nativeArtifactCacheDirectory(): Path =
        Path.of(System.getProperty("user.home"), ".javashroud", "native", "vbc4")

    private fun nativeBuildSecureRandom(seed: Long, context: Vbc4BuildContext): SecureRandom {
        val random = SecureRandom()
        val entropy = ByteArray(64).also(random::nextBytes)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.updateUtf8("javashroud-native-recompile-csprng-v1")
        digest.updateLong(seed)
        digest.updateLong(context.nativeSeed)
        digest.update(context.jarLayoutDigest)
        digest.update(context.runtimeResourceKey)
        digest.update(entropy)
        val personalization = digest.digest()
        return try {
            random.setSeed(personalization)
            random
        } finally {
            java.util.Arrays.fill(entropy, 0)
            java.util.Arrays.fill(personalization, 0)
        }
    }

    internal fun nativeArtifactCacheKey(
        taskPlatform: String,
        zigTarget: String,
        outputName: String,
        sourceDigest: ByteArray,
        toolchainIdentity: String,
        seed: Long,
        vbc4BuildContext: Vbc4BuildContext,
        protectedSectionKey: ByteArray,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
        nativeShellPackerVersion: Int = NativeKernelShellPacker.PACKER_VERSION,
        nativeShellPayloadProfile: String = "standard-overlay",
        nativeShellLoaderProfile: String = "direct-native-loader",
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("javashroud-native-vbc4-cache-v1".toByteArray(StandardCharsets.US_ASCII))
        digest.updateUtf8(taskPlatform)
        digest.updateUtf8(zigTarget)
        digest.updateUtf8(outputName)
        digest.updateUtf8(nativeCompileOptLevel())
        digest.updateUtf8(nativeProtectionLevel)
        digest.updateUtf8(nativePackingLevel)
        digest.updateInt(nativeShellPackerVersion)
        digest.updateUtf8(nativeShellPayloadProfile)
        digest.updateUtf8(nativeShellLoaderProfile)
        nativeCompileExtraFlags().forEach { flag -> digest.updateUtf8(flag) }
        digest.update(sourceDigest)
        digest.updateUtf8(toolchainIdentity)
        digest.updateLong(seed)
        digest.updateLong(vbc4BuildContext.nativeSeed)
        digest.update(vbc4BuildContext.jarLayoutDigest)
        digest.update(vbc4BuildContext.masterKey)
        digest.update(vbc4BuildContext.runtimeResourceKey)
        digest.update(protectedSectionKey)
        return digest.digest().toHexLower()
    }

    private fun digestNativeSourceTree(srcDir: Path): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.walk(srcDir).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .sorted(Comparator.comparing { path -> srcDir.relativize(path).toString().replace('\\', '/') })
                .forEach { path ->
                    val relative = srcDir.relativize(path).toString().replace('\\', '/')
                    digest.updateUtf8(relative)
                    digest.update(Files.readAllBytes(path))
                }
        }
        return digest.digest()
    }

    private fun zigToolchainIdentity(toolchain: NativeToolchainProvisioner.ZigToolchain): String {
        val path = toolchain.zigPath.toAbsolutePath().normalize()
        val size = runCatching { Files.size(path) }.getOrDefault(-1L)
        val mtime = runCatching { Files.getLastModifiedTime(path).toMillis() }.getOrDefault(-1L)
        val version = runCatching {
            val process = ProcessBuilder(path.toString(), "version").redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText().trim()
            if (process.waitFor(2, TimeUnit.SECONDS) && process.exitValue() == 0) output else "unknown"
        }.getOrDefault("unknown")
        return "${toolchain.source}|$path|$size|$mtime|$version"
    }

    private fun nativeCompileOptLevel(): String {
        val optOverride = System.getenv("JS_VBC4_OPT")
        return if (!optOverride.isNullOrBlank()) optOverride else "-O2"
    }

    private fun nativeCompileExtraFlags(): List<String> = listOf(
        "-fno-exceptions",
        "-fvisibility=hidden",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
    )

    private fun MessageDigest.updateUtf8(value: String) {
        update(value.toByteArray(StandardCharsets.UTF_8))
        update(0)
    }

    private fun MessageDigest.updateInt(value: Int) {
        update(((value ushr 24) and 0xFF).toByte())
        update(((value ushr 16) and 0xFF).toByte())
        update(((value ushr 8) and 0xFF).toByte())
        update((value and 0xFF).toByte())
    }

    private fun MessageDigest.updateLong(value: Long) {
        for (shift in 56 downTo 0 step 8) {
            update(((value ushr shift) and 0xFF).toByte())
        }
    }

    private fun compileWithZig(zigPath: Path, srcDir: Path, zigTarget: String, outputPath: Path, nativeProtectionLevel: String, cfgEvidenceExports: Boolean = false): ZigCompileResult {
        val optLevel = nativeCompileOptLevel()
        val extraFlags = nativeCompileExtraFlags()
        val cmd = mutableListOf(
            zigPath.toString(), "cc", "-target", zigTarget, optLevel, "-shared",
            // The VM interpreter implements Java arithmetic, where signed integer
            // overflow wraps (two's complement). Zig's clang traps signed overflow as
            // UB at lower opt levels (panic: "signed integer overflow"), which aborts
            // virtualized methods whose computations legitimately overflow (e.g. hash
            // mixers). -fwrapv mandates defined wraparound so semantics match the JVM.
            "-fwrapv",
            "-DZSTD_DISABLE_ASM=1",
            "-DZSTDLIB_VISIBLE=",
            "-DZSTDERRORLIB_VISIBLE=",
            "-DXXH_PUBLIC_API=",
            "-DJS_NATIVE_PROTECTION_${nativeProtectionLevel.uppercase()}=1",
            "-o", outputPath.toString(),
            srcDir.resolve("js_kernel.c").toString(),
            srcDir.resolve("js_helpers.c").toString(),
            srcDir.resolve("js_native_common.c").toString(),
            srcDir.resolve("js_crypto.c").toString(),
            srcDir.resolve("js_antidebug.c").toString(),
            srcDir.resolve("js_protected_section.c").toString(),
            srcDir.resolve("js_vm_core.c").toString(),
            srcDir.resolve("js_vm_resource.c").toString(),
            srcDir.resolve("js_vm_symbol.c").toString(),
            srcDir.resolve("js_jni_runtime.c").toString(),
            srcDir.resolve("zstd/common/debug.c").toString(),
            srcDir.resolve("zstd/common/entropy_common.c").toString(),
            srcDir.resolve("zstd/common/error_private.c").toString(),
            srcDir.resolve("zstd/common/fse_decompress.c").toString(),
            srcDir.resolve("zstd/common/xxhash.c").toString(),
            srcDir.resolve("zstd/common/zstd_common.c").toString(),
            srcDir.resolve("zstd/decompress/huf_decompress.c").toString(),
            srcDir.resolve("zstd/decompress/zstd_ddict.c").toString(),
            srcDir.resolve("zstd/decompress/zstd_decompress.c").toString(),
            srcDir.resolve("zstd/decompress/zstd_decompress_block.c").toString(),
            "-I", srcDir.toString(), "-I", srcDir.resolve("cross-compile").toString(),
            "-I", srcDir.resolve("zstd").toString(), "-I", srcDir.resolve("zstd/common").toString(), "-I", srcDir.resolve("zstd/decompress").toString(),
        )
        if (zigTarget.contains("macos")) {
            val exportList = srcDir.resolve("macos-exported-symbols.txt")
            Files.writeString(exportList, "_JNI_OnLoad\n_JNI_OnUnload\n_js_native_abi_table_v1\n", StandardCharsets.US_ASCII)
            cmd.add("-Wl,-exported_symbols_list,${exportList}")
        }
        if (zigTarget.contains("windows")) {
            cmd.add("-Wl,--no-entry")
        }
        if (zigTarget.contains("linux")) {
            cmd.add("-Wl,-T,${srcDir.resolve("js_protected_section_linux.ld")}")
        }
        if (cfgEvidenceExports) cmd.add("-DJS_NATIVE_CFG_EVIDENCE=1")
        cmd.addAll(extraFlags)
        return try {
            val pb = ProcessBuilder(cmd)
            configureZigCache(pb, outputPath)
            pb.redirectErrorStream(true)
            runZigCompileWithRetry(pb)
        } catch (error: Exception) {
            ZigCompileResult(false, error.message ?: error::class.java.simpleName)
        }
    }

    private fun compileShellStubWithZig(zigPath: Path, srcDir: Path, zigTarget: String, outputPath: Path, nativeProtectionLevel: String): ZigCompileResult {
        val optLevel = nativeCompileOptLevel()
        val extraFlags = nativeCompileExtraFlags()
        val loaderSource = when {
            zigTarget.contains("windows") -> "js_shell_loader_pe.c"
            zigTarget.contains("linux") -> "js_shell_loader_elf.c"
            zigTarget.contains("macos") -> "js_shell_loader_macho.c"
            else -> "js_shell_loader_elf.c"
        }
        val cmd = mutableListOf(
            zigPath.toString(), "cc", "-target", zigTarget, optLevel, "-shared",
            "-fwrapv",
            "-DZSTD_DISABLE_ASM=1",
            "-DZSTDLIB_VISIBLE=",
            "-DZSTDERRORLIB_VISIBLE=",
            "-DXXH_PUBLIC_API=",
            "-DJS_NATIVE_PROTECTION_${nativeProtectionLevel.uppercase()}=1",
            "-o", outputPath.toString(),
            srcDir.resolve("js_shell_stub.c").toString(),
            srcDir.resolve("js_shell_crypto.c").toString(),
            srcDir.resolve(loaderSource).toString(),
            srcDir.resolve("zstd/common/debug.c").toString(),
            srcDir.resolve("zstd/common/entropy_common.c").toString(),
            srcDir.resolve("zstd/common/error_private.c").toString(),
            srcDir.resolve("zstd/common/fse_decompress.c").toString(),
            srcDir.resolve("zstd/common/xxhash.c").toString(),
            srcDir.resolve("zstd/common/zstd_common.c").toString(),
            srcDir.resolve("zstd/decompress/huf_decompress.c").toString(),
            srcDir.resolve("zstd/decompress/zstd_ddict.c").toString(),
            srcDir.resolve("zstd/decompress/zstd_decompress.c").toString(),
            srcDir.resolve("zstd/decompress/zstd_decompress_block.c").toString(),
            "-I", srcDir.toString(), "-I", srcDir.resolve("cross-compile").toString(),
            "-I", srcDir.resolve("zstd").toString(), "-I", srcDir.resolve("zstd/common").toString(), "-I", srcDir.resolve("zstd/decompress").toString(),
        )
        if (zigTarget.contains("macos")) {
            val exportList = srcDir.resolve("macos-shell-exported-symbols.txt")
            Files.writeString(exportList, "_JNI_OnLoad\n_JNI_OnUnload\n", StandardCharsets.US_ASCII)
            cmd.add("-Wl,-exported_symbols_list,${exportList}")
        }
        if (zigTarget.contains("windows")) {
            cmd.add("-Wl,--no-entry")
        } else {
            cmd.add("-ldl")
        }
        cmd.addAll(extraFlags)
        return try {
            val pb = ProcessBuilder(cmd)
            configureZigCache(pb, outputPath)
            pb.redirectErrorStream(true)
            runZigCompileWithRetry(pb)
        } catch (error: Exception) {
            ZigCompileResult(false, error.message ?: error::class.java.simpleName)
        }
    }

    private fun runZigCompileWithRetry(processBuilder: ProcessBuilder): ZigCompileResult = synchronized(zigCompileLock) {
        var lastResult = ZigCompileResult(false, "Zig compilation did not start")
        val environment = processBuilder.environment()
        val globalCacheBase = environment["ZIG_GLOBAL_CACHE_DIR"]?.let(Path::of)
        val localCacheBase = environment["ZIG_LOCAL_CACHE_DIR"]?.let(Path::of)
        val retryScope = Integer.toUnsignedString(processBuilder.command().hashCode(), 16)
        repeat(3) { attempt ->
            if (attempt > 0) {
                globalCacheBase?.let { environment["ZIG_GLOBAL_CACHE_DIR"] = it.resolve("retry-$retryScope-$attempt").toString() }
                localCacheBase?.let { environment["ZIG_LOCAL_CACHE_DIR"] = it.resolve("retry-$retryScope-$attempt").toString() }
            }
            val process = processBuilder.start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            lastResult = ZigCompileResult(
                success = exitCode == 0,
                output = output.ifBlank { "Zig exited with code $exitCode without diagnostics" },
            )
            val transientFailure = output.isBlank() || isTransientZigFileOpenFailure(output)
            if (lastResult.success || !transientFailure || attempt == 2) return@synchronized lastResult
            Thread.sleep(250L)
        }
        lastResult
    }

    private fun configureZigCache(processBuilder: ProcessBuilder, outputPath: Path) {
        val buildRoot = outputPath.parent?.parent ?: return
        processBuilder.environment()["ZIG_GLOBAL_CACHE_DIR"] = buildRoot.resolve("zig-global-cache").toString()
        processBuilder.environment()["ZIG_LOCAL_CACHE_DIR"] = buildRoot.resolve("zig-local-cache").toString()
    }

    private fun isTransientZigFileOpenFailure(output: String): Boolean =
        output.contains("file_open Unexpected") ||
            output.contains("CacheCheckFailed") ||
            output.lineSequence().any { line ->
                line.trimEnd().endsWith("note: Unexpected") ||
                    Regex(""":\d+:\d+: error: Unexpected$""").containsMatchIn(line.trimEnd())
            }
    internal fun generateDiversifiedSecrets(
        seed: Long,
        rng: Random,
        vbc4BuildContext: Vbc4BuildContext,
        protectedSectionKey: ByteArray = ByteArray(32).also(rng::nextBytes),
    ): String {
        val secretSeed = (seed.toInt() and 0x7FFFFFFF).toUInt()
        val sb = StringBuilder()
        sb.appendLine("/* AUTO-GENERATED diversified native secrets - DO NOT EDIT */")
        sb.appendLine("#ifndef JS_NATIVE_SECRETS_H")
        sb.appendLine("#define JS_NATIVE_SECRETS_H")
        sb.appendLine("#include <string.h>")
        sb.appendLine("#define JS_SECRET_SEED ${secretSeed}u")
        sb.appendLine()
        val secretKey = ByteArray(16).also(rng::nextBytes)
        val secretIv = ByteArray(16).also(rng::nextBytes)
        sb.appendLine("static const unsigned char JS_SECRET_AES_KEY[16] = { ${cBytes(secretKey)} };")
        sb.appendLine("static const unsigned char JS_SECRET_AES_IV[16] = { ${cBytes(secretIv)} };")
        sb.appendLine()
        appendEncryptedStrings(sb, secretKey, secretIv)
        appendVbc4BuildProfile(sb, vbc4BuildContext, rng)
        appendProtectedSectionKey(sb, protectedSectionKey, rng)
        sb.appendLine("#endif")
        return sb.toString()
    }

    private fun appendEncryptedStrings(sb: StringBuilder, key: ByteArray, iv: ByteArray) {
        val secrets = listOf(
            "SECURITY_EXCEPTION_CLASS" to "java/lang/SecurityException",
            "MANAGEMENT_FACTORY_CLASS" to "java/lang/management/ManagementFactory",
            "THREAD_CLASS" to "java/lang/Thread",
            "SYSTEM_CLASS" to "java/lang/System",
            "RUNTIME_CLASS" to "java/lang/Runtime",
            "STACK_TRACE_ELEMENT_CLASS" to "java/lang/StackTraceElement",
            "ARRAY_LIST_CLASS" to "java/util/ArrayList",
            "IOEXCEPTION_CLASS" to "java/io/IOException",
            "GET_INPUT_ARGS" to "getInputArguments",
            "GET_STACK_TRACE" to "getStackTrace",
            "GET_CLASS_NAME" to "getClassName",
            "HASH_CODE" to "hashCode",
            "GET_CLASS_LOADER" to "getClassLoader",
            "LOAD_CLASS" to "loadClass",
            "FOR_NAME" to "forName",
            "GET_RESOURCEAsStream" to "getResourceAsStream",
            "GET_INPUT_ARGS_DESC" to "()Ljava/util/List;",
            "SIZE_METHOD" to "size",
            "SIZE_DESC" to "()I",
            "GET_METHOD" to "get",
            "GET_DESC" to "(I)Ljava/lang/Object;",
            "GET_STACK_TRACE_DESC" to "()[Ljava/lang/StackTraceElement;",
            "GET_CLASS_NAME_DESC" to "()Ljava/lang/String;",
            "HASH_CODE_DESC" to "()I",
            "OBJECT_CLASS" to "java/lang/Object",
            "STRING_CLASS" to "java/lang/String",
            "JAVA_LANG_CLASSLOADER" to "java/lang/ClassLoader",
            "GET_CLASS_LOADER_DESC" to "()Ljava/lang/ClassLoader;",
            "LOAD_CLASS_DESC" to "(Ljava/lang/String;)Ljava/lang/Class;",
            "FOR_NAME_DESC" to "(Ljava/lang/String;)Ljava/lang/Class;",
            "GET_RESOURCEAsStream_DESC" to "(Ljava/lang/String;)Ljava/io/InputStream;",
            "READ_METHOD" to "read",
            "READ_DESC" to "([B)I",
            "AVAILABLE_METHOD" to "available",
            "AVAILABLE_DESC" to "()I",
            "CLOSE_METHOD" to "close",
            "CLOSE_DESC" to "()V",
            "JNI_OnLoad_NAME" to "JNI_OnLoad",
        )
        for ((index, pair) in secrets.withIndex()) {
            val (name, plainText) = pair
            val plainBytes = plainText.toByteArray(StandardCharsets.UTF_8)
            val encrypted = aesCtrSecretCrypt(plainBytes, key, iv, index)
            sb.append("static const unsigned char js_secret_${name}[] = { ")
            sb.append(encrypted.toCByteArrayLiteral())
            sb.appendLine(" };")
            sb.appendLine("#define JS_SECRET_LEN_${name} ${plainBytes.size}")
            sb.appendLine("#define JS_SECRET_INDEX_${name} $index")
        }
        sb.appendLine()
        sb.appendLine("#define JS_SECRET_DECRYPT(id, buf) do { \\")
        sb.appendLine("    js_secret_aes_ctr_decode(js_secret_##id, JS_SECRET_LEN_##id, JS_SECRET_INDEX_##id, (buf)); \\")
        sb.appendLine("    (buf)[JS_SECRET_LEN_##id] = 0; \\")
        sb.appendLine("} while(0)")
        sb.appendLine()
        sb.appendLine("#define JS_SECRET_WIPE(buf, id) do { \\")
        sb.appendLine("    volatile unsigned char *_p = (volatile unsigned char*)(buf); \\")
        sb.appendLine("    for (int _i = 0; _i <= JS_SECRET_LEN_##id; _i++) _p[_i] = 0; \\")
        sb.appendLine("} while(0)")
    }


    private fun appendProtectedSectionKey(sb: StringBuilder, key: ByteArray, rng: Random) {
        require(key.size == 32) { "protected-section key must be 32 bytes" }
        val shareCount = 3 + rng.nextInt(4)
        val laneMask = ByteArray(key.size)
        val laneOrder = (0 until shareCount).toMutableList().also { java.util.Collections.shuffle(it, rng) }
        val laneWidths = intArrayOf(37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)
            .toList().shuffled(rng).take(shareCount).toIntArray()
        val indexStrides = IntArray(shareCount) { lane -> 1 + rng.nextInt(laneWidths[lane] - 1) }
        val indexOffsets = IntArray(shareCount) { lane -> rng.nextInt(laneWidths[lane]) }
        val rotateRight = 1 + rng.nextInt(7)
        val profileMask = rng.nextInt(256)
        val storedShares = Array(shareCount) { lane -> ByteArray(laneWidths[lane]).also(rng::nextBytes) }
        try {
            rng.nextBytes(laneMask)
            val controlledLane = laneOrder.last()
            for (keyIndex in key.indices) {
                val value = key[keyIndex].toInt() and 0xFF
                val rotated = ((value shl rotateRight) or (value ushr (8 - rotateRight))) and 0xFF
                var residual = rotated xor (laneMask[(keyIndex * 7 + 3) and 31].toInt() and 0xFF) xor profileMask
                for (lane in laneOrder.dropLast(1)) {
                    val storedIndex = (keyIndex * indexStrides[lane] + indexOffsets[lane]) % laneWidths[lane]
                    residual = residual xor (storedShares[lane][storedIndex].toInt() and 0xFF)
                }
                val storedIndex = (keyIndex * indexStrides[controlledLane] + indexOffsets[controlledLane]) % laneWidths[controlledLane]
                storedShares[controlledLane][storedIndex] = residual.toByte()
            }
            val reconstructed = ByteArray(key.size)
            try {
                for (keyIndex in reconstructed.indices) {
                    var value = (laneMask[(keyIndex * 7 + 3) and 31].toInt() and 0xFF) xor profileMask
                    for (lane in laneOrder) {
                        value = value xor (storedShares[lane][(keyIndex * indexStrides[lane] + indexOffsets[lane]) % laneWidths[lane]].toInt() and 0xFF)
                    }
                    reconstructed[keyIndex] = ((value ushr rotateRight) or (value shl (8 - rotateRight))).toByte()
                }
                require(reconstructed.contentEquals(key)) { "generated protected-section scoped key program diverged from the sealing key" }
            } finally {
                java.util.Arrays.fill(reconstructed, 0)
            }
            sb.appendLine()
            sb.appendLine("#define JS_PROTECTED_SECTION_KEY_PARTITIONS_GENERATED 1")
            storedShares.forEachIndexed { lane, share ->
                sb.appendLine("static const unsigned char js_protected_key_lane_$lane[${share.size}] = { ${cBytes(share)} };")
            }
            sb.appendLine("static const unsigned char js_protected_key_lane_mask[32] = { ${cBytes(laneMask)} };")
            sb.appendLine("#define JS_PROTECTED_KEY_LANE_COUNT $shareCount")
            sb.appendLine("#define JS_PROTECTED_COPY_SCOPED_KEY(out) do { \\")
            sb.appendLine("    static const unsigned char _js_ps_lane_order[$shareCount] = { ${laneOrder.joinToString(", ") { "${it}u" }} }; \\")
            sb.appendLine("    for (int _js_ps_i = 0; _js_ps_i < 32; _js_ps_i++) { \\")
            sb.appendLine("        unsigned char _js_ps_v = (unsigned char)(js_protected_key_lane_mask[(_js_ps_i * 7 + 3) & 31] ^ 0x${"%02X".format(profileMask)}u); \\")
            sb.appendLine("        for (int _js_ps_s = 0; _js_ps_s < $shareCount; _js_ps_s++) { \\")
            sb.appendLine("            int _js_ps_lane = _js_ps_lane_order[_js_ps_s]; \\")
            storedShares.indices.forEach { lane ->
                val prefix = if (lane == 0) "if" else "else if"
                sb.appendLine("            $prefix (_js_ps_lane == $lane) _js_ps_v = (unsigned char)(_js_ps_v ^ js_protected_key_lane_$lane[(_js_ps_i * ${indexStrides[lane]} + ${indexOffsets[lane]}) % ${laneWidths[lane]}]); \\")
            }
            sb.appendLine("        } \\")
            sb.appendLine("        (out)[_js_ps_i] = (unsigned char)((_js_ps_v >> $rotateRight) | (_js_ps_v << ${8 - rotateRight})); \\")
            sb.appendLine("    } \\")
            sb.appendLine("} while (0)")
        } finally {
            storedShares.forEach { java.util.Arrays.fill(it, 0) }
            java.util.Arrays.fill(laneMask, 0)
        }
    }

    private fun appendVbc4BuildProfile(sb: StringBuilder, context: Vbc4BuildContext, rng: Random) {
        sb.appendLine()
        sb.appendLine("/* Build diversity only. Root and layout material arrive through the one-shot boot ABI. */")
        sb.appendLine("#define JS_VBC4_RUNTIME_BOOT_MATERIAL 1")
        sb.appendLine("#define JS_VBC4_DISPATCH_MIX_A 0x${(rng.nextInt() or 1).toUInt().toString(16).uppercase()}u")
        sb.appendLine("#define JS_VBC4_DISPATCH_MIX_B 0x${(rng.nextInt() or 1).toUInt().toString(16).uppercase()}u")
        sb.appendLine("#define JS_VBC4_DISPATCH_MIX_C 0x${(rng.nextInt() or 1).toUInt().toString(16).uppercase()}u")
        sb.appendLine("#define JS_VBC4_DISPATCH_STEP_MASK ${listOf(7, 15, 31)[rng.nextInt(3)]}")
        sb.appendLine("#define JS_NATIVE_PARSER_PROFILE ${context.nativeVmProfile.parserRowProfile}")
        sb.appendLine("#define JS_NATIVE_OPERAND_PROFILE ${context.nativeVmProfile.operandAccessProfile}")
        sb.appendLine("#define JS_NATIVE_VM_PROFILE_ID 0x${context.nativeVmProfile.authenticatedId.toUInt().toString(16).uppercase()}u")
    }

    private fun cBytes(bytes: ByteArray): String = bytes.toCByteArrayLiteral()
    private fun aesCtrSecretCrypt(data: ByteArray, key: ByteArray, iv: ByteArray, index: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val counter = iv.copyOf()
        addCounterIndex(counter, index)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(counter))
        return cipher.doFinal(data)
    }

    private fun addCounterIndex(counter: ByteArray, index: Int) {
        var carry = index
        var offset = counter.lastIndex
        while (offset >= 0 && carry != 0) {
            val sum = (counter[offset].toInt() and 0xFF) + (carry and 0xFF)
            counter[offset] = (sum and 0xFF).toByte()
            carry = (carry ushr 8) + (sum ushr 8)
            offset--
        }
    }
    internal fun applySourceDiversification(source: String, rng: Random): String {
        val sb = StringBuilder(source)
        val junkFunctions = generateJunkFunctions(rng)
        if (sb.isNotEmpty() && sb.last() != '\n') sb.appendLine()
        sb.appendLine()
        sb.append(junkFunctions)
        return sb.toString()
    }

    internal fun applyNativeInterpreterCodegen(source: String, rng: Random): String {
        val withDispatchShape = rewriteVmDispatchMacros(source, rng.nextInt(3))
        return reorderVmDispatchHandlers(withDispatchShape, rng)
    }

    private fun rewriteVmDispatchMacros(source: String, shape: Int): String {
        val original = Regex("""(?s)#define JS_VM_DISPATCH\(insn_ptr\).*?\r?\n#define JS_VM_CASE\(x\).*?\r?\n#define JS_VM_BREAK.*?\r?\n#define JS_VM_DEFAULT.*?(?=\r?\n)""")
        val baseline = """
#define JS_VM_DISPATCH(insn_ptr) int js_vm_dispatch_opcode = (insn_ptr)->opcode; uint32_t js_vm_dispatch_salt_value = js_vm_poison_dispatch_salt(js_vm_profile_case_salt(js_vm_dispatch_profile, p, pc, vm_dispatch_drift_state, dispatch_step, sp), vm_trace_state); int js_vm_dispatch_matched = 0; if (0)
#define JS_VM_CASE(x) } if (!js_vm_dispatch_matched && js_vm_profile_case_matches(js_vm_dispatch_profile, js_vm_dispatch_opcode, (x), js_vm_dispatch_salt_value)) js_vm_dispatch_matched = 1; if (js_vm_dispatch_matched) {
#define JS_VM_BREAK do { js_vm_dispatch_matched = 0; goto js_vm_dispatch_done; } while (0)
#define JS_VM_DEFAULT } if (!js_vm_dispatch_matched) {
        """.trimIndent()
        val replacement = when (shape) {
            1 -> """
#define JS_VM_DISPATCH(insn_ptr) int js_vm_dispatch_opcode = (insn_ptr)->opcode; uint32_t js_vm_dispatch_salt_value = js_vm_poison_dispatch_salt(js_vm_profile_case_salt(js_vm_dispatch_profile, p, pc, vm_dispatch_drift_state, dispatch_step, sp), vm_trace_state); volatile uint32_t js_vm_dispatch_shape_token = (uint32_t)(js_vm_dispatch_salt_value ^ JS_VBC4_DISPATCH_MIX_B); int js_vm_dispatch_matched = 0; if (0)
#define JS_VM_CASE(x) } if (!js_vm_dispatch_matched && js_vm_profile_case_matches(js_vm_dispatch_profile, js_vm_dispatch_opcode, (x), js_vm_dispatch_salt_value + (uint32_t)(js_vm_dispatch_shape_token & 0u))) js_vm_dispatch_matched = 1; if (js_vm_dispatch_matched) {
#define JS_VM_BREAK do { js_vm_dispatch_matched = 0; goto js_vm_dispatch_done; } while (0)
#define JS_VM_DEFAULT } if (!js_vm_dispatch_matched) {
            """.trimIndent()
            2 -> """
#define JS_VM_DISPATCH(insn_ptr) int js_vm_dispatch_opcode = (insn_ptr)->opcode; uint32_t js_vm_dispatch_salt_value = js_vm_poison_dispatch_salt(js_vm_profile_case_salt(js_vm_dispatch_profile, p, pc, vm_dispatch_drift_state, dispatch_step, sp), vm_trace_state); volatile uint32_t js_vm_dispatch_shape_token = (uint32_t)(js_vm_dispatch_salt_value + JS_VBC4_DISPATCH_MIX_A); int js_vm_dispatch_phase = (int)(js_vm_dispatch_shape_token & 3u); int js_vm_dispatch_matched = 0; if (0)
#define JS_VM_CASE(x) } if (!js_vm_dispatch_matched) { uint32_t js_vm_case_salt = js_vm_dispatch_salt_value + (uint32_t)(js_vm_dispatch_phase & 0u); if (js_vm_profile_case_matches(js_vm_dispatch_profile, js_vm_dispatch_opcode, (x), js_vm_case_salt)) js_vm_dispatch_matched = 1; } if (js_vm_dispatch_matched) {
#define JS_VM_BREAK do { js_vm_dispatch_matched = 0; goto js_vm_dispatch_done; } while (0)
#define JS_VM_DEFAULT } if (!js_vm_dispatch_matched) {
            """.trimIndent()
            else -> baseline
        }
        return original.replaceFirst(source, replacement)
    }
    private fun reorderVmDispatchHandlers(source: String, rng: Random): String {
        val dispatchStartMarker = "        JS_VM_DISPATCH(insn) {"
        val defaultMarker = "            JS_VM_DEFAULT"
        val start = source.indexOf(dispatchStartMarker)
        if (start < 0) return source
        val regionStart = start + dispatchStartMarker.length
        val defaultStart = source.indexOf(defaultMarker, regionStart + 1)
        if (defaultStart < 0) return source

        val region = source.substring(regionStart, defaultStart)
        val caseRegex = Regex("""(?s)\r?\n\s*JS_VM_CASE\(.*?\r?\n\s*JS_VM_BREAK;""")
        val matches = caseRegex.findAll(region).toList()
        if (matches.size < 8) return source

        val leading = region.substring(0, matches.first().range.first)
        val trailing = region.substring(matches.last().range.last + 1)
        if ((leading + trailing).any { !it.isWhitespace() }) return source

        val handlers = matches.mapIndexed { index, match ->
            val relocated = addVmHandlerRelocation(match.value, index, rng)
            addVmHandlerVariant(relocated, index, rng)
        }.toMutableList()
        java.util.Collections.shuffle(handlers, rng)
        val signature = handlers.joinToString(separator = ",") { handler -> firstVmCaseName(handler) }
        val relocationSignature = handlers.joinToString(separator = ",") { handler -> firstVmRelocationEntry(handler) }
        val generatedRegion = buildString {
            append("\n        /* VBC4_INTERPRETER_CODEGEN handlers=")
            append(handlers.size)
            append(" order=")
            append(signature.hashCode().toUInt().toString(16))
            append(" relocation=")
            append(relocationSignature.hashCode().toUInt().toString(16))
            append(" */")
            handlers.forEach { append(it) }
        }
        return source.substring(0, regionStart) + generatedRegion + source.substring(defaultStart)
    }


    private fun addVmHandlerRelocation(block: String, index: Int, rng: Random): String {
        val firstCase = Regex("""(?m)^\s*JS_VM_CASE\([^\n]+""").find(block) ?: return block
        val insertOffset = block.indexOf('\n', firstCase.range.last + 1).takeIf { it >= 0 } ?: return block
        val token = rng.nextInt() or 1
        val tokenHex = token.toUInt().toString(16).uppercase()
        val entryLabel = "js_vm_handler_reloc_entry_${index}_${tokenHex}"
        val padLabel = "js_vm_handler_reloc_pad_${index}_${tokenHex}"
        val keyName = "js_vm_handler_reloc_key_${index}_${tokenHex}"
        val shape = rng.nextInt(3)
        val relocationGate = buildString {
            append("\n                /* VBC4_HANDLER_RELOCATION index=$index shape=$shape token=0x${tokenHex}u */\n")
            append("                volatile uint32_t $keyName = (uint32_t)(js_vm_dispatch_salt_value ^ 0x${tokenHex}u ^ JS_VBC4_DISPATCH_MIX_C);\n")
            when (shape) {
                0 -> {
                    append("                if (($keyName ^ $keyName) != 0u) goto $padLabel;\n")
                    append("                goto $entryLabel;\n")
                }
                1 -> {
                    append("                if (((($keyName | 1u) & 0u) + ($keyName - $keyName)) != 0u) goto $padLabel;\n")
                    append("                goto $entryLabel;\n")
                }
                else -> {
                    append("                switch (($keyName ^ $keyName) & 1u) { case 0u: goto $entryLabel; default: goto $padLabel; }\n")
                }
            }
            append("                $padLabel:\n")
            append("                $keyName ^= (uint32_t)(JS_VBC4_DISPATCH_MIX_A + JS_VBC4_DISPATCH_MIX_B);\n")
            append("                $entryLabel:")
        }
        return block.substring(0, insertOffset) + relocationGate + block.substring(insertOffset)
    }

    private fun addVmHandlerVariant(block: String, index: Int, rng: Random): String {
        val variant = rng.nextInt(3)
        if (variant == 0) return block
        val firstLineEnd = block.indexOf('\n')
        if (firstLineEnd < 0) return block
        val firstLine = block.substring(0, firstLineEnd + 1)
        if (firstLine.contains("JS_VM_BREAK") || firstLine.contains(" ok =") || firstLine.contains(" pc =") || firstLine.contains("*ret")) return block
        val token = rng.nextInt() or 1
        val tokenHex = token.toUInt().toString(16).uppercase()
        val variantLine = when (variant) {
            1 -> "                { volatile uint32_t js_vm_handler_variant_$index = (uint32_t)(JS_VBC4_DISPATCH_MIX_A + 0x${tokenHex}u); (void)js_vm_handler_variant_$index; }\n"
            else -> "                { volatile uint32_t js_vm_handler_variant_$index = (uint32_t)(js_vm_dispatch_salt_value ^ 0x${tokenHex}u); js_vm_handler_variant_$index += (uint32_t)(js_vm_dispatch_opcode & 0u); (void)js_vm_handler_variant_$index; }\n"
        }
        return firstLine + variantLine + block.substring(firstLineEnd + 1)
    }

    private fun firstVmCaseName(block: String): String =
        Regex("""JS_VM_CASE\(([^)]+)\)""").find(block)?.groupValues?.get(1) ?: "unknown"

    private fun firstVmRelocationEntry(block: String): String =
        Regex("""js_vm_handler_reloc_entry_[A-Za-z0-9_]+""").find(block)?.value ?: "none"

    private fun generateJunkFunctions(rng: Random): String {
        val sb = StringBuilder()
        val count = 3 + rng.nextInt(5)
        for (i in 0 until count) {
            val funcName = "_junk_${rng.nextInt(0xFFFFFF).toString(16)}_${i}"
            when (rng.nextInt(4)) {
                0 -> {
                    sb.appendLine("static int $funcName(int x) {")
                    sb.appendLine("    return (x * x + x) % 2 == 0;")
                    sb.appendLine("}")
                }
                1 -> {
                    sb.appendLine("static int $funcName(int a, int b) {")
                    sb.appendLine("    int c = a ^ b;")
                    sb.appendLine("    c = (c & 0xFF) | ((~c) & 0xFF);")
                    sb.appendLine("    return (c == 0xFF) ? 1 : 0;")
                    sb.appendLine("}")
                }
                2 -> {
                    sb.appendLine("static unsigned int $funcName(unsigned int x) {")
                    sb.appendLine("    return (x & 0xFFFFFFFFu) | (~x & 0xFFFFFFFFu) & x;")
                    sb.appendLine("}")
                }
                else -> {
                    val bogusCount = 1 + rng.nextInt(3)
                    sb.appendLine("static int $funcName(int x) {")
                    sb.appendLine("    int r = x;")
                    for (j in 0 until bogusCount) {
                        sb.appendLine("    r = (r ^ ${rng.nextInt(0xFFFF)}) & 0xFFFF;")
                        sb.appendLine("    r = r | (r >> 1);")
                    }
                    sb.appendLine("    return (r >= 0) ? x : x;")
                    sb.appendLine("}")
                }
            }
            sb.appendLine()
        }
        return sb.toString()
    }

    internal fun generateAntiReverseGuards(rng: Random, nativeProtectionLevel: String = "standard"): String {
        val timingThreshold = 500000 + rng.nextInt(2000000)
        val integrityHashSeed = rng.nextLong().toUInt()
        val obfConstant = rng.nextInt(0xFFFFFF)
        val sb = StringBuilder()
        sb.appendLine("/* AUTO-GENERATED anti-reverse engineering guards */")
        sb.appendLine("#ifndef JS_NATIVE_GUARDS_H")
        sb.appendLine("#define JS_NATIVE_GUARDS_H")
        sb.appendLine("#ifdef _WIN32")
        sb.appendLine("#include <windows.h>")
        sb.appendLine("#elif defined(__linux__) || defined(__ANDROID__)")
        sb.appendLine("#include <sys/ptrace.h>")
        sb.appendLine("#include <stdio.h>")
        sb.appendLine("#include <string.h>")
        sb.appendLine("#endif")
        sb.appendLine()
        sb.appendLine("static inline int _js_guard_is_debugged(void) {")
        sb.appendLine("#ifdef _WIN32")
        sb.appendLine("    if (IsDebuggerPresent()) return 1;")
        sb.appendLine("    BOOL remote = FALSE;")
        sb.appendLine("    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);")
        sb.appendLine("    if (remote) return 1;")
        sb.appendLine("#if defined(_MSC_VER) && defined(_M_X64)")
        sb.appendLine("    unsigned char *peb = (unsigned char *)__readgsqword(0x60);")
        sb.appendLine("    if (peb && peb[2]) return 1;")
        sb.appendLine("#endif")
        sb.appendLine("#elif defined(__linux__) || defined(__ANDROID__)")
        sb.appendLine("    FILE *f = fopen(\"/proc/self/status\", \"r\");")
        sb.appendLine("    if (f) { char line[256]; while (fgets(line, sizeof(line), f)) { if (strncmp(line, \"TracerPid:\", 10) == 0) { int pid = 0; sscanf(line + 10, \"%d\", &pid); fclose(f); return pid != 0; } } fclose(f); }")
        sb.appendLine("    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) return 1;")
        sb.appendLine("    ptrace(PTRACE_DETACH, 0, 0, 0);")
        sb.appendLine("#endif")
        sb.appendLine("    return 0;")
        sb.appendLine("}")
        sb.appendLine()
        sb.appendLine("static inline int _js_guard_timing_anomaly(void) {")
        sb.appendLine("#if defined(_MSC_VER) || defined(__x86_64__)")
        sb.appendLine("    unsigned long long t1, t2;")
        sb.appendLine("#ifdef _MSC_VER")
        sb.appendLine("    t1 = __rdtsc(); volatile int x = 0; x++; t2 = __rdtsc();")
        sb.appendLine("#else")
        sb.appendLine("    __asm__ volatile(\"rdtsc\" : \"=a\"(((unsigned int*)&t1)[0]), \"=d\"(((unsigned int*)&t1)[1]));")
        sb.appendLine("    volatile int x = 0; x++;")
        sb.appendLine("    __asm__ volatile(\"rdtsc\" : \"=a\"(((unsigned int*)&t2)[0]), \"=d\"(((unsigned int*)&t2)[1]));")
        sb.appendLine("#endif")
        sb.appendLine("    return (t2 - t1) > $timingThreshold;")
        sb.appendLine("#else")
        sb.appendLine("    return 0;")
        sb.appendLine("#endif")
        sb.appendLine("}")
        sb.appendLine()
        sb.appendLine("static inline int _js_guard_hw_breakpoints(void) {")
        sb.appendLine("#ifdef _WIN32")
        sb.appendLine("    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;")
        sb.appendLine("    if (GetThreadContext(GetCurrentThread(), &ctx)) { if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return 1; }")
        sb.appendLine("#endif")
        sb.appendLine("    return 0;")
        sb.appendLine("}")
        sb.appendLine()
        sb.appendLine("static inline int _js_guard_vm_detected(void) {")
        sb.appendLine("#ifdef _WIN32")
        sb.appendLine("    HKEY hKey;")
        sb.appendLine("    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, \"SOFTWARE\\\\VMware, Inc.\\\\VMware Tools\", 0, KEY_READ, &hKey) == ERROR_SUCCESS) { RegCloseKey(hKey); return 1; }")
        sb.appendLine("    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, \"SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions\", 0, KEY_READ, &hKey) == ERROR_SUCCESS) { RegCloseKey(hKey); return 1; }")
        sb.appendLine("#if defined(__GNUC__) || defined(__clang__)")
        sb.appendLine("    unsigned int eax = 1, ebx = 0, ecx = 0, edx = 0;")
        sb.appendLine("    __asm__ volatile(\"cpuid\" : \"+a\"(eax), \"=b\"(ebx), \"=c\"(ecx), \"=d\"(edx));")
        sb.appendLine("    if (ecx & (1u << 31)) return 1;")
        sb.appendLine("#elif defined(_MSC_VER)")
        sb.appendLine("    int cpuInfo[4] = {0}; __cpuid(cpuInfo, 1);")
        sb.appendLine("    if (cpuInfo[2] & (1 << 31)) return 1;")
        sb.appendLine("#endif")
        sb.appendLine("#endif")
        sb.appendLine("    return 0;")
        sb.appendLine("}")
        sb.appendLine()
        sb.appendLine("static inline int _js_guard_integrity_check(const void *code_region, size_t region_size, unsigned int expected_hash) {")
        sb.appendLine("    unsigned int hash = ${integrityHashSeed}u;")
        sb.appendLine("    const unsigned char *p = (const unsigned char *)code_region;")
        sb.appendLine("    for (size_t i = 0; i < region_size; i++) { hash ^= p[i]; hash *= 16777619u; }")
        sb.appendLine("    return hash != expected_hash;")
        sb.appendLine("}")
        sb.appendLine()
        sb.appendLine("static inline int _js_guard_all(void) {")
        sb.appendLine("    volatile int _seed_marker = $obfConstant; /* seed-dependent marker */")
        sb.appendLine("    if (_js_guard_is_debugged()) return 1;")
        sb.appendLine("    if (_js_guard_timing_anomaly()) return 1;")
        sb.appendLine("    if (_js_guard_hw_breakpoints()) return 1;")
        sb.appendLine("    if (_js_guard_vm_detected()) return 2;")
        if (nativeProtectionLevel == "aggressive") {
            sb.appendLine("    /* aggressive: fold sandbox, unpack, and dump-hardening probes into guard response */")
            sb.appendLine("    if (_js_guard_integrity_check((const void *)&_js_guard_all, 64, ${integrityHashSeed}u ^ ${obfConstant}u)) return 3;")
            sb.appendLine("#if defined(__linux__) || defined(__ANDROID__)")
            sb.appendLine("    FILE *maps = fopen(\"/proc/self/maps\", \"r\");")
            sb.appendLine("    if (maps) { char line[256]; while (fgets(line, sizeof(line), maps)) { if (strstr(line, \"frida\") || strstr(line, \"xposed\") || strstr(line, \"dump\")) { fclose(maps); return 4; } } fclose(maps); }")
            sb.appendLine("#endif")
        }
        sb.appendLine("    return 0;")
        sb.appendLine("}")
        sb.appendLine()
        sb.appendLine("#endif")
        return sb.toString()
    }

    private fun loadResource(classLoader: ClassLoader, resourcePath: String): ByteArray? {
        classLoader.getResourceAsStream(resourcePath)?.use { return it.readBytes() }
        this::class.java.getResourceAsStream("/$resourcePath")?.use { return it.readBytes() }
        return null
    }

    private fun copyNativeResourceTree(classLoader: ClassLoader, resourceRoot: String, outputRoot: Path) {
        val entries = listOf(
            "zstd.h", "zstd_errors.h",
            "common/allocations.h", "common/bits.h", "common/bitstream.h", "common/compiler.h", "common/cpu.h",
            "common/debug.c", "common/debug.h", "common/entropy_common.c", "common/error_private.c", "common/error_private.h",
            "common/fse.h", "common/fse_decompress.c", "common/huf.h", "common/mem.h", "common/portability_macros.h",
            "common/xxhash.c", "common/xxhash.h", "common/zstd_common.c", "common/zstd_deps.h", "common/zstd_internal.h", "common/zstd_trace.h",
            "decompress/huf_decompress.c", "decompress/zstd_ddict.c", "decompress/zstd_ddict.h", "decompress/zstd_decompress.c",
            "decompress/zstd_decompress_block.c", "decompress/zstd_decompress_block.h", "decompress/zstd_decompress_internal.h",
        )
        for (entry in entries) {
            val bytes = loadResource(classLoader, "${NATIVE_SRC_RESOURCE_ROOT}/$resourceRoot/$entry") ?: continue
            val target = outputRoot.resolve(entry)
            Files.createDirectories(target.parent)
            Files.write(target, bytes)
        }
    }
}
