package io.github.hht0rro.javashroud.transforms.protection

import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Random
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import io.github.hht0rro.javashroud.transforms.protection.qp.IMAGE_MEASUREMENT_MAGIC
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object QpNativeCompilerPass {

    /*
     * Qp has one production native path: copy the Rust workspace into a
     * build-private directory and invoke the locked Cargo command there.  The
     * lock is keyed by the complete specialization identity so two builds can
     * never share a mutable target directory or a partially-written cache entry.
     */
    private val rustCompileLocks = ConcurrentHashMap<String, Any>()
    private val rustToolchainIdentityCache = ConcurrentHashMap<String, String>()
    private const val DEFAULT_NATIVE_COMPILE_PARALLELISM = 2

    private const val NATIVE_CACHE_MAGIC = "QP-RUST-CACHE-V2"
    private const val NATIVE_CACHE_VERSION = 2
    private const val NATIVE_CACHE_HEADER_SIZE = 16 + 4 + 32 + 8 + 32
    private const val MAX_NATIVE_ARTIFACT_BYTES = 256L * 1024L * 1024L
    private const val MAX_RUST_DIAGNOSTIC_BYTES = 8_192
    private const val RUST_COMPILE_TIMEOUT_PROPERTY = "javashroud.rust.compile.timeout.ms"
    private const val RUST_COMPILE_TIMEOUT_ENV = "JS_QP_RUST_COMPILE_TIMEOUT_MS"
    private const val DEFAULT_RUST_COMPILE_TIMEOUT_MS = 15 * 60 * 1000L
    private const val PROCESS_OUTPUT_DRAIN_TIMEOUT_MS = 5_000L
    private const val PROCESS_CLEANUP_TIMEOUT_MS = 5_000L
    private const val RUST_WORKSPACE_PROPERTY = "javashroud.rust.workspace"
    private const val RUST_WORKSPACE_DIR = "src/main/rust"
    private const val RUST_FFI_PACKAGE = "qp-ffi"
    private const val RUST_FFI_LIBRARY = "qp_ffi"
    private const val RUST_SPECIALIZATION_DOMAIN = "JavaShroud/QP/RustSpecialization/v2"
    private val RUST_RELEASE_EXPORTS = setOf(
        "JNI_OnLoad",
        "JNI_OnUnload",
        "qp_r1_open_frame",
        "qp_r1_runtime_binding_digest",
    )

    /** Only the two locked Qp Rust runtime targets are accepted. */
    internal val RUST_TARGETS: Map<String, String> = linkedMapOf(
        RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS to RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
        RustToolchainProvisioner.RUNTIME_TARGET_LINUX to RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
    )

    data class RecompiledNative(
        val platform: String,
        val libName: String,
        val bytes: ByteArray,
        val specializationDigest: ByteArray,
        val shellBindingCommitment: ByteArray? = null,
    ) {
        init {
            require(specializationDigest.size == 32) { "native specialization digest must be 32 bytes" }
            require(specializationDigest.any { it != 0.toByte() }) { "native specialization digest must not be all-zero" }
        }
    }

    fun recompile(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatforms: Collection<String> = RUST_TARGETS.keys,
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
        request = QpNativeCompilerRequest.forTargets(
            nativeProtectionLevel = nativeProtectionLevel,
            nativePackingLevel = NativeKernelShellPacker.Level.OFF,
            targetPlatforms = listOf(targetPlatform),
        ),
        cfgEvidenceExports = true,
        evidenceRandom = evidenceRandom,
    ).results.singleOrNull()

    /**
     * Compatibility adapter for raw callers. Production configuration should
     * construct QpNativeCompilerRequest once at its boundary instead.
     */
    fun recompileWithDiagnostics(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatforms: Collection<String> = RUST_TARGETS.keys,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
        onMessage: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
    ): RecompilationDiagnostics {
        val request = QpNativeCompilerRequest.forTargets(
            nativeProtectionLevel = nativeProtectionLevel,
            nativePackingLevel = NativeKernelShellPacker.Level.parse(nativePackingLevel),
            targetPlatforms = targetPlatforms,
        )
        return recompileWithDiagnostics(
            seed = seed,
            classLoader = classLoader,
            request = request,
            onMessage = onMessage,
        )
    }

    internal fun recompileWithDiagnostics(
        seed: Long,
        classLoader: ClassLoader,
        request: QpNativeCompilerRequest,
        onMessage: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
    ): RecompilationDiagnostics = recompileWithDiagnosticsInternal(
        seed = seed,
        classLoader = classLoader,
        request = request,
        onMessage = onMessage,
    )

    private fun recompileWithDiagnosticsInternal(
        seed: Long,
        classLoader: ClassLoader,
        request: QpNativeCompilerRequest,
        onMessage: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
        cfgEvidenceExports: Boolean = false,
        evidenceRandom: Random? = null,
    ): RecompilationDiagnostics {
        val messages = mutableListOf<NativeToolchainProvisioner.ResolutionMessage>()
        fun report(message: NativeToolchainProvisioner.ResolutionMessage) {
            messages += message
            onMessage(message)
        }
        try {
            requireSupportedNativeRequest(request)
        } catch (error: Exception) {
            report(rustMessage("error", error.message.orEmpty()))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        val resolution = try {
            RustToolchainProvisioner.resolve(autoInstall = true)
        } catch (error: Exception) {
            report(rustMessage("error", "Qp Rust toolchain resolution failed: ${error.message.orEmpty()}"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        resolution.messages.forEach { message ->
            report(rustMessage(message.level, message.message))
        }
        val toolchain = resolution.toolchain ?: run {
            report(rustMessage("error", "Qp Rust toolchain is unavailable; native recompilation is disabled"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        val workspace = try {
            resolveRustWorkspace(classLoader)
        } catch (error: Exception) {
            report(rustMessage("error", "Qp Rust workspace resolution failed: ${error.message.orEmpty()}"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        val workDir = try {
            Files.createTempDirectory("javashroud-qp-rust-")
        } catch (error: Exception) {
            report(rustMessage("error", "Qp Rust build directory could not be created: ${error.message.orEmpty()}"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        return try {
            val results = doRecompile(
                seed = seed,
                classLoader = classLoader,
                toolchain = toolchain,
                workspace = workspace,
                workDir = workDir,
                request = request,
                cfgEvidenceExports = cfgEvidenceExports,
                evidenceRandom = evidenceRandom,
                report = ::report,
            )
            RecompilationDiagnostics(results, messages)
        } catch (error: Exception) {
            report(rustMessage("error", "Qp Rust native recompilation failed: ${error.message.orEmpty()}"))
            RecompilationDiagnostics(emptyList(), messages)
        } finally {
            val deleted = runCatching { workDir.toFile().deleteRecursively() }.getOrDefault(false)
            if (!deleted && Files.exists(workDir)) {
                report(rustMessage("error", "Qp Rust build directory cleanup failed; refusing to reuse it"))
            }
        }
    }

    private fun doRecompile(
        seed: Long,
        classLoader: ClassLoader,
        toolchain: RustToolchainProvisioner.RustToolchain,
        workspace: Path,
        workDir: Path,
        request: QpNativeCompilerRequest,
        cfgEvidenceExports: Boolean,
        evidenceRandom: Random?,
        report: (NativeToolchainProvisioner.ResolutionMessage) -> Unit,
    ): List<RecompiledNative> {
        requireSupportedNativeRequest(request)
        val context = QpBuildContexts.requireCurrent()
        require(!cfgEvidenceExports || evidenceRandom != null) {
            "CFG evidence compilation requires an explicit deterministic random stream"
        }
        require(cfgEvidenceExports || evidenceRandom == null) {
            "Evidence-only random stream must not enter production native recompilation"
        }
        val specializationNonce = ByteArray(32).also { nonce ->
            (evidenceRandom ?: nativeBuildSecureRandom(seed, context)).nextBytes(nonce)
        }
        var sourceDigest = ByteArray(0)
        var tasks: List<NativeCompileTask> = emptyList()
        val rustWorkspace = workDir.resolve("rust-workspace")
        var cryptoDomain = ByteArray(0)
        var layoutDigest = ByteArray(0)
        var targetTokenCommitment = ByteArray(0)
        var targetTokenNameSeed = ByteArray(0)
        var secretPackLiterals: io.github.hht0rro.javashroud.transforms.protection.qp.NativeSecretPackLiterals? = null
        try {
            copyRustWorkspace(workspace, rustWorkspace)
            check(Files.readString(rustWorkspace.resolve("crates/qp-ffi/src/lib.rs")).contains("fn JNI_OnLoad")) {
                "Qp isolated Rust workspace is missing JNI_OnLoad source"
            }
            sourceDigest = digestRustWorkspace(rustWorkspace)
            val toolchainIdentity = rustToolchainIdentity(toolchain)
            cryptoDomain = context.copyFrozenPackCryptoDomainOrNull()
                ?: QpInnerMaterial.copyCryptoDomainMaterial(context)
            layoutDigest = QpInnerMaterial.copyStateBindingLayoutDigest(context)
            targetTokenCommitment = context.qpFinalizationLayoutOrNull()?.copyArtifactCommitmentForBuild()
                ?: context.qpBuildPlanOrNull()?.artifactCanonicalCommitment
                ?: context.jarLayoutDigest.copyOf()
            targetTokenNameSeed = context.copyNameSeed()
            // The pack copy is wiped together with the shard literals in the
            // enclosing finally; the context draft outlives this compile so a
            // later pass can still verify against the same slots.
            context.withNativeVmSecretPackForSpecialization { pack ->
                secretPackLiterals = io.github.hht0rro.javashroud.transforms.protection.qp.NativeSecretPackLiterals
                    .prepare(
                        pack,
                        evidenceRandom ?: nativeBuildSecureRandom(seed, context),
                        cryptoDomain,
                        layoutDigest,
                    )
            }
            val packCommitment = secretPackLiterals?.commitment() ?: ByteArray(0)
            // Hardened builds carry per-artifact secret material and never
            // touch the persistent native cache.
            val cacheEnabled = request.nativePackingLevel != QpPackingLevel.MAX_HARDENING
            tasks = request.routes.map { route ->
                val target = rustTargetForPlatform(route.platform)
                val specializationDigest = rustSpecializationDigest(
                    seed = seed,
                    targetPlatform = route.platform,
                    targetTriple = target,
                    sourceDigest = sourceDigest,
                    context = context,
                    request = request,
                    specializationNonce = specializationNonce,
                    targetTokenCommitment = targetTokenCommitment,
                    targetTokenNameSeed = targetTokenNameSeed,
                    secretPackCommitment = packCommitment,
                )
                val outputName = route.outputName
                val cacheKey = nativeArtifactCacheKey(
                    taskPlatform = route.platform,
                    rustTarget = target,
                    outputName = outputName,
                    sourceDigest = sourceDigest,
                    toolchainIdentity = toolchainIdentity,
                    seed = seed,
                    qpBuildContext = context,
                    protectedSectionKey = specializationNonce,
                    nativeProtectionLevel = request.nativeProtectionLevel,
                    nativePackingLevel = request.nativePackingLevel.configValue,
                    nativeShellPackerVersion = 1,
                    nativeShellPayloadProfile = "qp-rust-ffi-v1",
                   nativeShellLoaderProfile = "rust-ffi-${route.platform}-v1",
                   specializationDigest = specializationDigest,
                    targetTokenCommitment = targetTokenCommitment,
                    targetTokenNameSeed = targetTokenNameSeed,
               )
                NativeCompileTask(
                    platform = route.platform,
                    rustTarget = target,
                    outputName = outputName,
                    outputPath = workDir.resolve("artifacts").resolve(outputName),
                    targetDir = workDir.resolve("cargo-target").resolve(route.platform),
                    workspace = workDir.resolve("rust-workspace").resolve(route.platform),
                    cachePath = rustArtifactCacheDirectory().resolve("$cacheKey-$outputName"),
                    cacheKey = cacheKey,
                    specializationDigest = specializationDigest,
                    protectionLevel = request.nativeProtectionLevel,
                    packingLevel = request.nativePackingLevel.configValue,
                    cryptoDomain = cryptoDomain.copyOf(),
                    layoutDigest = layoutDigest.copyOf(),
                    targetTokenCommitment = targetTokenCommitment.copyOf(),
                    targetTokenNameSeed = targetTokenNameSeed.copyOf(),
                    secretPack = secretPackLiterals,
                )
            }
            val compiled = compileNativeTasksBounded(
                compileTasks = tasks,
                toolchain = toolchain,
                rustWorkspace = rustWorkspace,
                cfgEvidenceExports = cfgEvidenceExports,
                cacheEnabled = cacheEnabled,
            )
            val results = ArrayList<RecompiledNative>(compiled.size)
            var failed = false
            for ((task, result) in compiled) {
                val bytes = result.bytes
                if (!result.success || bytes == null || bytes.isEmpty()) {
                    failed = true
                    report(rustMessage("error", "Qp Rust target ${task.platform} failed: ${sanitizeDiagnostic(result.output)}"))
                    continue
                }
                try {
                    validateRustArtifact(task.platform, task.outputName, bytes)
                    if (cacheEnabled && !cfgEvidenceExports && !result.fromCache) {
                        writeRustArtifactCache(task.cachePath, bytes, task.cacheKey, task.platform, task.outputName)
                    }
                    results += RecompiledNative(
                        task.platform,
                        task.outputName,
                        bytes,
                        task.specializationDigest.copyOf(),
                    )
                    report(rustMessage("info", "Built Qp Rust JNI runtime for ${task.platform}"))
                } catch (error: Exception) {
                    failed = true
                    bytes.fill(0)
                    report(rustMessage("error", "Qp Rust artifact for ${task.platform} was rejected: ${error.message.orEmpty()}"))
                }
            }
            if (failed || results.size != tasks.size) {
                results.forEach { result ->
                    result.bytes.fill(0)
                    result.specializationDigest.fill(0)
                }
                return emptyList()
            }
            if (secretPackLiterals != null) {
                val sealedPackBlobs = secretPackLiterals.blobByPlatform()
                require(sealedPackBlobs.keys == tasks.associate { it.platform to Unit }.keys) {
                    "Qp sealed secret pack blob was not sealed for every compiled platform"
                }
                context.publishNativeSealedPackBlobs(sealedPackBlobs)
            }
            context.publishNativeSpecializationDigests(
                results.associate { it.platform to it.specializationDigest.copyOf() },
            )
            return results
        } finally {
            tasks.forEach { task ->
                task.specializationDigest.fill(0)
                task.cryptoDomain.fill(0)
                task.layoutDigest.fill(0)
                task.targetTokenCommitment.fill(0)
                task.targetTokenNameSeed.fill(0)
            }
            sourceDigest.fill(0)
            specializationNonce.fill(0)
            cryptoDomain.fill(0)
            layoutDigest.fill(0)
            targetTokenCommitment.fill(0)
            targetTokenNameSeed.fill(0)
            secretPackLiterals?.wipe()
        }
    }

    private data class NativeCompileTask(
        val platform: String,
        val rustTarget: String,
        val outputName: String,
        val outputPath: Path,
        val targetDir: Path,
        val workspace: Path,
        val cachePath: Path,
        val cacheKey: String,
        val specializationDigest: ByteArray,
        val protectionLevel: String,
        val packingLevel: String,
        val cryptoDomain: ByteArray,
        val layoutDigest: ByteArray,
        val targetTokenCommitment: ByteArray,
        val targetTokenNameSeed: ByteArray,
        val secretPack: io.github.hht0rro.javashroud.transforms.protection.qp.NativeSecretPackLiterals?,
    )

    private data class NativeArtifactBuildResult(
        val success: Boolean,
        val output: String,
        val bytes: ByteArray?,
        val fromCache: Boolean,
    )

    private fun compileNativeTasksBounded(
        compileTasks: List<NativeCompileTask>,
        toolchain: RustToolchainProvisioner.RustToolchain,
        rustWorkspace: Path,
        cfgEvidenceExports: Boolean,
        cacheEnabled: Boolean,
    ): List<Pair<NativeCompileTask, NativeArtifactBuildResult>> {
        if (compileTasks.isEmpty()) return emptyList()
        val parallelism = minOf(compileTasks.size, nativeCompileParallelism())
        fun compileOne(task: NativeCompileTask): Pair<NativeCompileTask, NativeArtifactBuildResult> {
            return try {
                Files.createDirectories(task.outputPath.parent)
                copyRustWorkspace(rustWorkspace, task.workspace)
                writeSpecializationModule(task)
                task to compileOrLoadRustArtifact(
                    toolchain = toolchain,
                    rustWorkspace = task.workspace,
                    task = task,
                    cfgEvidenceExports = cfgEvidenceExports,
                    cacheEnabled = cacheEnabled,
                )
            } catch (error: Exception) {
                task to NativeArtifactBuildResult(false, error.message ?: error::class.java.simpleName, null, false)
            }
        }
        if (parallelism <= 1) return compileTasks.map(::compileOne)

        val executor = Executors.newFixedThreadPool(parallelism) { runnable ->
            Thread(runnable, "javashroud-qp-rust-compile").apply { isDaemon = true }
        }
        return try {
            compileTasks.map { task -> executor.submit(Callable { compileOne(task) }) }.map { future ->
                try {
                    future.get()
                } catch (error: Exception) {
                    throw IllegalStateException("Qp Rust compile worker failed", error)
                }
            }
        } finally {
            executor.shutdown()
            try {
                if (!executor.awaitTermination(1, TimeUnit.DAYS)) executor.shutdownNow()
            } catch (error: InterruptedException) {
                executor.shutdownNow()
                Thread.currentThread().interrupt()
                throw error
            }
        }
    }

    private fun nativeCompileParallelism(): Int {
        val configured = System.getProperty("javashroud.native.compile.parallelism")
            ?: System.getenv("JS_QP_NATIVE_COMPILE_PARALLELISM")
        return configured?.trim()?.toIntOrNull()?.takeIf { it > 0 }?.coerceAtMost(16)
            ?: minOf(DEFAULT_NATIVE_COMPILE_PARALLELISM, Runtime.getRuntime().availableProcessors().coerceAtLeast(1))
    }

    private fun compileOrLoadRustArtifact(
        toolchain: RustToolchainProvisioner.RustToolchain,
        rustWorkspace: Path,
        task: NativeCompileTask,
        cfgEvidenceExports: Boolean,
        cacheEnabled: Boolean,
    ): NativeArtifactBuildResult = withRustCompileLock(task.cachePath) {
        // Hardened builds carry per-artifact secret-pack material and never
        // read or write the persistent native cache.
        if (cacheEnabled && !cfgEvidenceExports) {
            readRustArtifactCache(task.cachePath, task.cacheKey, task.platform, task.outputName)?.let { cachedBytes ->
                return@withRustCompileLock NativeArtifactBuildResult(true, "cache-hit", cachedBytes, true)
            }
        }
        val specializationHex = HexEncodingSupport.toHexLower(task.specializationDigest)
        val compileResult = runRustCompile(
            toolchain = toolchain,
            workspace = rustWorkspace,
            targetDir = task.targetDir,
            target = task.rustTarget,
            specializationHex = specializationHex,
            cfgEvidenceExports = cfgEvidenceExports,
        )
        if (!compileResult.success) {
            return@withRustCompileLock NativeArtifactBuildResult(false, compileResult.output, null, false)
        }
        // cargo-zigbuild accepts the glibc floor in the command target
        // (`x86_64-unknown-linux-gnu.2.17`) but writes Cargo outputs below the
        // base target directory (`x86_64-unknown-linux-gnu`). Resolve the
        // on-disk path using the emitted target while retaining the exact
        // glibc-qualified target in the compile command and specialization.
        val outputTarget = if (task.rustTarget == "x86_64-unknown-linux-gnu.2.17") {
            "x86_64-unknown-linux-gnu"
        } else {
            task.rustTarget
        }
        val builtArtifact = task.targetDir.resolve(outputTarget).resolve("release").resolve(rustLibraryFileName(task.platform))
        if (!Files.isRegularFile(builtArtifact)) {
            return@withRustCompileLock NativeArtifactBuildResult(
                false,
                "Cargo completed without the expected Rust artifact: $builtArtifact",
                null,
                false,
            )
        }
        val bytes = Files.readAllBytes(builtArtifact)
        if (bytes.isEmpty() || bytes.size.toLong() > MAX_NATIVE_ARTIFACT_BYTES) {
            bytes.fill(0)
            return@withRustCompileLock NativeArtifactBuildResult(false, "Rust artifact is empty or exceeds the bounded size", null, false)
        }
        val measurementKey = task.secretPack?.measurementKey
        var commitment: ByteArray? = null
        try {
            if (measurementKey != null) {
                commitment = patchImageMeasurementCommitment(bytes, measurementKey)
                task.secretPack.sealForPlatform(task.platform, commitment)
                // Commitment-chain the shard key halves by content: locate each
                // pre-mask row (cm ^ R) in the image and XOR the patched image
                // commitment in place, then verify the runtime reconstruction.
                val shardCount = task.secretPack.shardCount()
                val maskRMaster = task.secretPack.maskRMaster()
                val maskedRows = ArrayList<ByteArray>(shardCount)
                for (shard in 0 until shardCount) {
                    val cm = task.secretPack.cmKeyAt(shard)
                    val mask = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement
                        .shardMask(maskRMaster, shard)
                    val row = ByteArray(32)
                    for (j in 0 until 32) row[j] = (cm[j].toInt() xor mask[j].toInt()).toByte()
                    maskedRows.add(row)
                    Arrays.fill(cm, 0)
                    Arrays.fill(mask, 0)
                }
                if (!io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement
                    .patchShardKeyMask(bytes, checkNotNull(commitment), shardCount, maskedRows)
                ) {
                    error("Qp shard key mask rows are missing from the compiled image")
                }
                for (shard in 0 until shardCount) {
                    println("jsh-key-build: " + task.secretPack.cmKeyAt(shard).joinToString("") { "%02x".format(it) })
                }
                maskedRows.forEach { Arrays.fill(it, 0) }
                Arrays.fill(maskRMaster, 0)
            }
        } catch (error: Exception) {
            bytes.fill(0)
            return@withRustCompileLock NativeArtifactBuildResult(
                false,
                "Qp image measurement commitment could not be bound: ${error.message}",
                null,
                false,
            )
        } finally {
            commitment?.fill(0)
            measurementKey?.fill(0)
        }
        NativeArtifactBuildResult(true, compileResult.output, bytes, false)
    }

    private fun <T> withRustCompileLock(cachePath: Path, block: () -> T): T {
        val lockKey = cachePath.toAbsolutePath().normalize().toString()
        val lock = rustCompileLocks.computeIfAbsent(lockKey) { Any() }
        return synchronized(lock, block)
    }

    private fun readRustArtifactCache(
        cachePath: Path,
        expectedCacheKey: String,
        platform: String,
        outputName: String,
    ): ByteArray? {
        if (!Files.isRegularFile(cachePath)) return null
        val encoded = try {
            val size = Files.size(cachePath)
            if (size < NATIVE_CACHE_HEADER_SIZE || size > NATIVE_CACHE_HEADER_SIZE + MAX_NATIVE_ARTIFACT_BYTES) return null
            Files.readAllBytes(cachePath)
        } catch (_: Exception) {
            return null
        }
        var payload: ByteArray? = null
        val valid = try {
            if (encoded.size < NATIVE_CACHE_HEADER_SIZE) {
                false
            } else {
                val magic = encoded.copyOfRange(0, 16).toString(StandardCharsets.US_ASCII)
                val version = java.nio.ByteBuffer.wrap(encoded, 16, 4).int
                val expectedKeyDigest = MessageDigest.getInstance("SHA-256")
                    .digest(expectedCacheKey.toByteArray(StandardCharsets.US_ASCII))
                val storedKeyDigest = encoded.copyOfRange(20, 52)
                val payloadLength = java.nio.ByteBuffer.wrap(encoded, 52, 8).long
                val storedPayloadDigest = encoded.copyOfRange(60, 92)
                val payloadStart = NATIVE_CACHE_HEADER_SIZE
                val payloadEnd = payloadLength.takeIf { it > 0L }
                    ?.let { length -> payloadStart.toLong().checkedAdd(length) }
                val inBounds = payloadEnd != null && payloadEnd <= encoded.size.toLong()
                if (!inBounds || payloadEnd != encoded.size.toLong()) {
                    false
                } else {
                    payload = encoded.copyOfRange(payloadStart, payloadEnd!!.toInt())
                    magic == NATIVE_CACHE_MAGIC &&
                        version == NATIVE_CACHE_VERSION &&
                        MessageDigest.isEqual(expectedKeyDigest, storedKeyDigest) &&
                        payloadLength <= MAX_NATIVE_ARTIFACT_BYTES &&
                        MessageDigest.isEqual(
                            storedPayloadDigest,
                            MessageDigest.getInstance("SHA-256").digest(payload),
                        ) &&
                        runCatching { validateRustArtifact(platform, outputName, payload!!) }.isSuccess
                }
            }
        } catch (_: Exception) {
            false
        } finally {
            encoded.fill(0)
        }
        if (valid) return payload
        payload?.fill(0)
        runCatching { Files.deleteIfExists(cachePath) }
        return null
    }

    private fun writeRustArtifactCache(
        cachePath: Path,
        bytes: ByteArray,
        cacheKey: String,
        platform: String,
        outputName: String,
    ) {
        require(bytes.isNotEmpty() && bytes.size.toLong() <= MAX_NATIVE_ARTIFACT_BYTES) {
            "Rust cache payload is outside the bounded artifact size"
        }
        validateRustArtifact(platform, outputName, bytes)
        Files.createDirectories(cachePath.parent)
        val payloadDigest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val keyDigest = MessageDigest.getInstance("SHA-256")
            .digest(cacheKey.toByteArray(StandardCharsets.US_ASCII))
        val header = java.nio.ByteBuffer.allocate(NATIVE_CACHE_HEADER_SIZE)
            .put(NATIVE_CACHE_MAGIC.toByteArray(StandardCharsets.US_ASCII))
            .putInt(NATIVE_CACHE_VERSION)
            .put(keyDigest)
            .putLong(bytes.size.toLong())
            .put(payloadDigest)
            .array()
        val encoded = ByteArray(header.size + bytes.size)
        var temporary: Path? = null
        try {
            header.copyInto(encoded, 0)
            bytes.copyInto(encoded, header.size)
            temporary = Files.createTempFile(cachePath.parent, ".qp-cache-", ".tmp")
            Files.write(temporary, encoded)
            try {
                Files.move(temporary, cachePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temporary, cachePath, StandardCopyOption.REPLACE_EXISTING)
            }
            temporary = null
        } finally {
            temporary?.let { runCatching { Files.deleteIfExists(it) } }
            encoded.fill(0)
            header.fill(0)
            payloadDigest.fill(0)
            keyDigest.fill(0)
        }
    }

    private fun rustArtifactCacheDirectory(): Path =
        Path.of(System.getProperty("user.home"), ".javashroud", "native", "qp-rust").toAbsolutePath().normalize()

    private data class RustCompileResult(
        val success: Boolean,
        val output: String,
    )

    private fun rustMessage(
        level: String,
        message: String,
        progress: Int? = 94,
    ): NativeToolchainProvisioner.ResolutionMessage =
        NativeToolchainProvisioner.ResolutionMessage(level, message, progress)

    private fun requireSupportedNativeRequest(request: QpNativeCompilerRequest) {
        val unsupported = request.routes.filterNot { route -> route.platform in RUST_TARGETS }
        require(unsupported.isEmpty()) {
            "Qp rejects macOS, Mach-O, .dylib, and legacy native routes: ${unsupported.joinToString { it.platform }}"
        }
        request.routes.forEach { route ->
            val expectedTarget = RUST_TARGETS.getValue(route.platform)
            require(expectedTarget == rustTargetForPlatform(route.platform)) {
                "Qp Rust target mapping is inconsistent for ${route.platform}"
            }
        }
    }

    private fun rustTargetForPlatform(platform: String): String =
        RUST_TARGETS[platform]
            ?: throw IllegalArgumentException(
                "Qp Rust target is unsupported: $platform; only Windows x64 and Linux x64 glibc 2.17 are accepted",
            )

    private fun rustLibraryFileName(platform: String): String = when (platform) {
        RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS -> "$RUST_FFI_LIBRARY.dll"
        RustToolchainProvisioner.RUNTIME_TARGET_LINUX -> "lib$RUST_FFI_LIBRARY.so"
        else -> throw IllegalArgumentException("Qp Rust artifact platform is unsupported: $platform")
    }

    private fun resolveRustWorkspace(classLoader: ClassLoader): Path {
        val candidates = LinkedHashSet<Path>()
        System.getProperty(RUST_WORKSPACE_PROPERTY)
            ?.trim()
            ?.takeIf(String::isNotEmpty)
            ?.let { candidates.add(Path.of(it)) }
        val userDir = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        var cursor: Path? = userDir
        repeat(8) {
            cursor?.let { root ->
                candidates.add(root.resolve(RUST_WORKSPACE_DIR))
                candidates.add(root.resolve("core-engine").resolve(RUST_WORKSPACE_DIR))
            }
            cursor = cursor?.parent
        }
        runCatching {
            val location = QpNativeCompilerPass::class.java.protectionDomain.codeSource.location.toURI()
            val codePath = Path.of(location).toAbsolutePath().normalize()
            var root: Path? = if (Files.isDirectory(codePath)) codePath else codePath.parent
            repeat(8) {
                root?.let { candidate ->
                    candidates.add(candidate.resolve(RUST_WORKSPACE_DIR))
                    candidates.add(candidate.resolve("core-engine").resolve(RUST_WORKSPACE_DIR))
                }
                root = root?.parent
            }
        }
        extractBundledRustWorkspace(classLoader)?.let(candidates::add)
        return candidates.asSequence()
            .map { it.toAbsolutePath().normalize() }
            .firstOrNull { isRustWorkspaceTemplate(it) }
            ?: throw IllegalStateException(
                "Qp Rust workspace is unavailable; expected core-engine/src/main/rust with Cargo.lock",
            )
    }

    private fun extractBundledRustWorkspace(classLoader: ClassLoader): Path? {
        val listBytes = classLoader.getResourceAsStream("META-INF/rust-runtime/file-list.txt")?.use { it.readBytes() }
            ?: return null
        val digest = HexEncodingSupport.toHexLower(MessageDigest.getInstance("SHA-256").digest(listBytes))
        val destination = Path.of(System.getProperty("user.home"), ".javashroud", "rust-workspace", "qp-$digest")
            .toAbsolutePath().normalize()
        if (isRustWorkspaceTemplate(destination)) return destination
        val files = String(listBytes, StandardCharsets.UTF_8).lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() && it != "file-list.txt" && ".." !in it }
            .toList()
        Files.createDirectories(destination.parent)
        val staging = Files.createTempDirectory(destination.parent, ".stage-rust-workspace-")
        return try {
            files.forEach { relative ->
                val output = staging.resolve(relative).normalize()
                require(output.startsWith(staging)) { "bundled Rust workspace entry escapes staging: $relative" }
                val input = classLoader.getResourceAsStream("META-INF/rust-runtime/$relative")
                    ?: throw IllegalStateException("bundled Rust workspace is missing $relative")
                input.use { stream ->
                    Files.createDirectories(output.parent)
                    Files.copy(stream, output, StandardCopyOption.REPLACE_EXISTING)
                }
            }
            if (!isRustWorkspaceTemplate(staging)) return null
            if (Files.exists(destination)) destination.toFile().deleteRecursively()
            try {
                Files.move(staging, destination, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: Exception) {
                Files.move(staging, destination, StandardCopyOption.REPLACE_EXISTING)
            }
            destination
        } finally {
            if (Files.exists(staging)) staging.toFile().deleteRecursively()
        }
    }

    private fun isRustWorkspaceTemplate(path: Path): Boolean {
        if (!Files.isDirectory(path) || !Files.isRegularFile(path.resolve("Cargo.toml")) ||
            !Files.isRegularFile(path.resolve("Cargo.lock"))
        ) return false
        return runCatching {
            Files.walk(path).use { stream ->
                stream.allMatch { entry ->
                    if (Files.isSymbolicLink(entry)) return@allMatch false
                    val relative = path.relativize(entry).toString().replace('\\', '/').lowercase()
                    relative.isEmpty() ||
                        relative == "target" ||
                        relative.startsWith("target/") ||
                        (!relative.endsWith(".c") &&
                            !relative.endsWith(".zig") &&
                            !relative.endsWith(".dylib") &&
                            !relative.contains("macho") &&
                            !relative.contains("native-src") &&
                            !relative.contains("js-native") &&
                            !relative.contains("js_kernel") &&
                            !relative.contains("js_jni_runtime") &&
                            !relative.contains("zstd/common") &&
                            !relative.contains("zstd/decompress"))
                }
            }
        }.getOrDefault(false)
    }

    private fun copyRustWorkspace(source: Path, destination: Path) {
        require(isRustWorkspaceTemplate(source)) { "Qp Rust workspace template is invalid: $source" }
        Files.createDirectories(destination)
        val normalizedDestination = destination.toAbsolutePath().normalize()
        Files.walk(source).use { stream ->
            stream.sorted().forEach { entry ->
                if (Files.isSymbolicLink(entry)) {
                    throw IllegalStateException("Qp rejects symlinked Rust workspace entries: $entry")
                }
                val relative = source.relativize(entry)
                val relativeText = relative.toString().replace('\\', '/')
                if (relativeText.split('/').any { part -> part == "target" || part.startsWith(".target") }) {
                    return@forEach
                }
                val target = normalizedDestination.resolve(relative.toString()).normalize()
                require(target.startsWith(normalizedDestination)) {
                    "Qp Rust workspace entry escapes its isolated build directory: $relative"
                }
                if (Files.isDirectory(entry)) {
                    Files.createDirectories(target)
                } else if (Files.isRegularFile(entry)) {
                    Files.createDirectories(target.parent)
                    Files.copy(entry, target, StandardCopyOption.REPLACE_EXISTING)
                } else {
                    throw IllegalStateException("Qp rejects non-regular Rust workspace entry: $entry")
                }
            }
        }
        require(Files.isRegularFile(normalizedDestination.resolve("Cargo.lock"))) {
            "Qp isolated Rust workspace is missing Cargo.lock"
        }
    }

    private fun writeSpecializationModule(task: NativeCompileTask) {
        val destination = task.workspace.resolve("crates").resolve("qp-ffi").resolve("src").resolve("specialization.rs")
        require(Files.isRegularFile(destination.parent.resolve("lib.rs"))) {
            "Qp isolated Rust workspace is missing qp-ffi/src/lib.rs"
        }
        val digestLiteral = task.specializationDigest.joinToString(", ") { byte ->
            "0x" + ((byte.toInt() and 0xFF).toString(16).padStart(2, '0'))
        }
        require(task.specializationDigest.size == 32) { "Qp specialization digest must be 32 bytes" }
        require(task.cryptoDomain.size == 32) { "Qp crypto domain must be 32 bytes" }
        require(task.layoutDigest.size == 32) { "Qp layout digest must be 32 bytes" }
        require(task.targetTokenCommitment.size == 32) { "Qp token commitment must be 32 bytes" }
        require(task.targetTokenNameSeed.size == 16) { "Qp token name seed must be 16 bytes" }
        fun bytesLiteral(values: ByteArray) = values.joinToString(", ") { byte ->
            "0x" + ((byte.toInt() and 0xFF).toString(16).padStart(2, '0'))
        }
        val source = buildString {
            append("//! Generated Qp nonsecret specialization. Contains no keys or plaintext.\n")
            append("pub const TARGET_TRIPLE: &str = \"")
            append(task.rustTarget)
            append("\";\n")
            append("pub const SPECIALIZATION_DIGEST: [u8; 32] = [")
            append(digestLiteral)
            append("];\n")
            append("pub const PAYLOAD_PROFILE: &str = \"qp-rust-ffi-v1\";\n")
            append("pub const PROTECTION_LEVEL: &str = \"")
            append(task.protectionLevel)
            append("\";\n")
            append("pub const PACKING_LEVEL: &str = \"")
            append(task.packingLevel)
            append("\";\n")
            append("pub const VM_CRYPTO_DOMAIN: [u8; 32] = [0; 32];\n")
            append("pub const VM_LAYOUT_DIGEST: [u8; 32] = [0; 32];\n")
            append("pub const TARGET_TOKEN_COMMITMENT: [u8; 32] = [")
            append(bytesLiteral(task.targetTokenCommitment))
            append("];\n")
            append("pub const TARGET_TOKEN_NAME_SEED: [u8; 16] = [")
            append(bytesLiteral(task.targetTokenNameSeed))
            append("];\n")
            appendSecretPackSection(task.secretPack)
        }
        require(!source.contains("masterKey", ignoreCase = true) && !source.contains("runtimeResourceKey", ignoreCase = true)) {
            "Qp specialization module must not contain secret field names"
        }
        Files.writeString(destination, source, StandardCharsets.US_ASCII)
    }

    /**
     * Emits the per-artifact secret-pack section. Slot seeds, VM crypto domain,
     * and layout digest are AEAD-wrapped. The wrap key is reconstructed from
     * MBA immediates; no XOR shard combiner is written.
     */
    private fun StringBuilder.appendSecretPackSection(pack: io.github.hht0rro.javashroud.transforms.protection.qp.NativeSecretPackLiterals?) {
        fun bytesLiteral(values: ByteArray) = values.joinToString(", ") { byte ->
            "0x" + ((byte.toInt() and 0xFF).toString(16).padStart(2, '0'))
        }
        fun u32Lit(value: Int) = "0x" + java.lang.Integer.toUnsignedString(value, 16) + "u32"
        val identity = pack?.nativeIdentity ?: ByteArray(32)
        val slotCount = pack?.slotCount ?: 0
        append("pub const SECRET_PACK_NATIVE_IDENTITY: [u8; 32] = [")
        append(bytesLiteral(identity))
        append("];\n")
        append("pub const SECRET_PACK_SLOT_COUNT: usize = ")
        append(slotCount)
        append(";\n")
        append("pub const SECRET_PACK_KIND_COUNT: usize = 5;\n")
        append("pub const SECRET_PACK_SHARD_COUNT: usize = ")
        append(pack?.shardMbaWords()?.size ?: 0)
        append(";\n")
        append("#[repr(C)]\n")
        append("pub struct ImageMeasurementSlot {\n")
        append("    pub magic: [u8; 8],\n")
        append("    pub commitment: [u8; 32],\n")
        append("}\n")
        append("#[used]\n")
        append("#[link_section = \".jsms\"]\n")
        append("pub static IMAGE_MEASUREMENT: ImageMeasurementSlot = ImageMeasurementSlot {\n")
        append("    magic: [")
        append(bytesLiteral(IMAGE_MEASUREMENT_MAGIC))
        append("],\n")
        append("    commitment: [0; 32],\n")
        append("};\n")
        append("#[inline(never)]\n")
        append("pub fn image_measurement_commitment() -> [u8; 32] {\n")
        append("    unsafe { core::ptr::read_volatile(&IMAGE_MEASUREMENT.commitment) }\n")
        append("}\n")
        // Commitment-chained shard key halves: the file stores cm ^ R ^ C
        // (C patched post-compile), so no contiguous shard key exists on disk.
        val maskRMaster = pack?.maskRMaster()
        val shardCount = pack?.shardCount() ?: 0
        append("pub const SHARD_MASK_R: [u8; 32] = [")
        append(bytesLiteral(maskRMaster ?: ByteArray(32)))
        append("];\n")
        append("#[used]\n")
        append("#[link_section = \".jsmk\"]\n")
        append("pub static SHARD_KEYS_MASKED: [u8; 32 * SECRET_PACK_SHARD_COUNT] = [")
        if (pack != null) {
            try {
                for (shardIndex in 0 until shardCount) {
                    val cmKey = pack.cmKeyAt(shardIndex)
                    val mask = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement
                        .shardMask(maskRMaster!!, shardIndex)
                    try {
                        val hexBytes = (0 until 32).joinToString(", ") { j ->
                            "0x" + ((cmKey[j].toInt() xor mask[j].toInt()) and 0xFF).toString(16).padStart(2, '0')
                        }
                        append(hexBytes)
                        if (shardIndex == 1) println("jsh-cm1-build: " + cmKey.joinToString("") { "%02x".format(it) }.take(16))
                        if (shardIndex != shardCount - 1) append(", ")
                    } finally {
                        Arrays.fill(cmKey, 0)
                        Arrays.fill(mask, 0)
                    }
                }
            } finally {
                Arrays.fill(maskRMaster, 0)
            }
        }
        append("];\n")
        append("#[inline(never)]\n")
            append("fn shard_mask_r(shard: usize) -> [u8; 32] {\n")
            append("    let mut mask = [0u8; 32];\n")
            append("    for (index, byte) in mask.iter_mut().enumerate() {\n")
            append("        *byte = SHARD_MASK_R[(index + 7 * shard + 3) % 32] ^ (shard as u8);\n")
            append("    }\n")
            append("    mask\n")
            append("}pub fn qp_sp_reconstruct_shard_key(shard: usize) -> [u8; 32] {\n")
            append("    if shard >= SECRET_PACK_SHARD_COUNT { return [0; 32]; }\n")
            append("    let commitment = image_measurement_commitment();\n")
            append("    let mask = shard_mask_r(shard);\n")
            append("    let base = shard * 32;\n")
            append("    let mut key = [0u8; 32];\n")
            append("    for index in 0..32 {\n")
            append("        key[index] = SHARD_KEYS_MASKED[base + index] ^ mask[index] ^ commitment[index % 32];\n")
            append("    }\n")
            append("    key\n")
            append("}")
        append("pub fn qp_secret_pack_seed(_slot: usize) -> Option<[u8; 32]> { None }\n")
        appendDialectCorpusSection()
    }

    private fun reconstructionOrder(words: List<io.github.hht0rro.javashroud.transforms.protection.qp.MbaWord>): IntArray {
        val order = IntArray(8) { it }
        if (words.size < 8) return order
        val seed = words[0].addend xor words[7].multiplier
        for (index in 7 downTo 1) {
            val swap = Integer.remainderUnsigned(seed xor (index * 0x9E3779B9.toInt()), index + 1)
            val tmp = order[index]
            order[index] = order[swap]
            order[swap] = tmp
        }
        return order
    }

    private fun patchImageMeasurementCommitment(bytes: ByteArray, measurementKey: ByteArray): ByteArray {
        val found = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement.locateMeasurementSlot(bytes)
        val commitmentStart = found + IMAGE_MEASUREMENT_MAGIC.size
        val digest = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement.digest(bytes)
        val commitment = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement.hmacCommitment(measurementKey, digest)
        require(commitment.size == 32)
        println("jsh-digest-build: " + digest.joinToString("") { "%02x".format(it) })
        System.arraycopy(commitment, 0, bytes, commitmentStart, 32)
        Arrays.fill(digest, 0)
        return commitment
    }

    /**
     * Emits the per-build VM semantic opcode corpus as an XOR-masked byte
     * serialization. The plain corpus table never appears in the generated
     * source or in the compiled artifact.
     */
    private fun StringBuilder.appendDialectCorpusSection() {
        fun bytesLiteral(values: ByteArray) = values.joinToString(", ") { byte ->
            "0x" + ((byte.toInt() and 0xFF).toString(16).padStart(2, '0'))
        }
        val semantic = io.github.hht0rro.javashroud.transforms.protection.hardening.QpDialectDescriptor
            .semanticOpcodesForSpecialization()
        val mask = ByteArray(semantic.size * 2).also { bytes -> SecureRandom().nextBytes(bytes) }
        val masked = ByteArray(semantic.size * 2)
        semantic.forEachIndexed { index, opcode ->
            masked[index * 2] =
                (((opcode ushr 8) and 0xFF).toInt() xor mask[index * 2].toInt()).toByte()
            masked[index * 2 + 1] =
                ((opcode and 0xFF).toInt() xor mask[index * 2 + 1].toInt()).toByte()
        }
        append("pub const VM_DIALECT_SEMANTIC_MASK: [u8; ")
        append(mask.size)
        append("] = [")
        append(bytesLiteral(mask))
        append("];\n")
        append("pub const VM_DIALECT_SEMANTIC_MASKED: [u8; ")
        append(masked.size)
        append("] = [")
        append(bytesLiteral(masked))
        append("];\n")
        append(
            "pub fn vm_dialect_semantic_opcodes() -> Vec<u16> {\n" +
                "    let mut corpus = Vec::with_capacity(VM_DIALECT_SEMANTIC_MASKED.len() / 2);\n" +
                "    for index in 0..corpus.capacity() {\n" +
                "        let high = VM_DIALECT_SEMANTIC_MASKED[index * 2] ^ VM_DIALECT_SEMANTIC_MASK[index * 2];\n" +
                "        let low = VM_DIALECT_SEMANTIC_MASKED[index * 2 + 1] ^ VM_DIALECT_SEMANTIC_MASK[index * 2 + 1];\n" +
                "        corpus.push((u16::from(high) << 8) | u16::from(low));\n" +
                "    }\n" +
                "    corpus\n}\n",
        )
    }

    private fun rustSpecializationDigest(
        seed: Long,
        targetPlatform: String,
        targetTriple: String,
        sourceDigest: ByteArray,
        context: QpBuildContext,
        request: QpNativeCompilerRequest,
        specializationNonce: ByteArray,
        targetTokenCommitment: ByteArray,
        targetTokenNameSeed: ByteArray,
        secretPackCommitment: ByteArray = ByteArray(0),
    ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update(RUST_SPECIALIZATION_DOMAIN.toByteArray(StandardCharsets.US_ASCII))
        updateUtf8(targetPlatform)
        updateUtf8(targetTriple)
        updateLong(seed)
        updateLong(context.nativeSeed)
        update(context.jarLayoutDigest)
        updateUtf8(request.nativeProtectionLevel)
        updateUtf8(request.nativePackingLevel.configValue)
        updateUtf8("qp-rust-ffi-v1")
        updateInt(context.nativeVmProfile.authenticatedId)
        require(targetTokenCommitment.size == 32) { "Qp token commitment must be 32 bytes" }
        require(targetTokenNameSeed.size == 16) { "Qp token name seed must be 16 bytes" }
        update(targetTokenCommitment)
        update(targetTokenNameSeed)
        update(sourceDigest)
        update(specializationNonce)
        if (secretPackCommitment.isNotEmpty()) {
            require(secretPackCommitment.size == 32) { "Qp secret pack commitment must be 32 bytes" }
            update(secretPackCommitment)
        }
    }.digest()

    private fun runRustCompile(
        toolchain: RustToolchainProvisioner.RustToolchain,
        workspace: Path,
        targetDir: Path,
        target: String,
        specializationHex: String,
        cfgEvidenceExports: Boolean,
    ): RustCompileResult {
        require(target in RUST_TARGETS.values) { "Qp Rust target is not locked: $target" }
        require(specializationHex.length == 64 && specializationHex.all { it in "0123456789abcdefABCDEF" }) {
            "Qp specialization digest is invalid"
        }
        Files.createDirectories(targetDir)
        val command = listOf(
            toolchain.cargoPath.toString(),
            "zigbuild",
            "--locked",
            "--package",
            "qp-ffi",
            "--lib",
            "--release",
            "--target",
            target,
            "--target-dir",
            targetDir.toString(),
        )
        val processBuilder = ProcessBuilder(command)
            .directory(workspace.toFile())
            .redirectErrorStream(false)
        processBuilder.environment().apply {
            putAll(toolchain.extraEnvironment)
            put("CARGO_TERM_COLOR", "never")
            put("RUSTC", toolchain.rustcPath.toAbsolutePath().normalize().toString())
            put("CARGO_TARGET_DIR", targetDir.toString())
            put("RUSTFLAGS", rustFlagsForCompile(target, specializationHex))
            prependPath(toolchain.extraPathEntries)
            if (cfgEvidenceExports) put("QP_CFG_EVIDENCE", "1") else remove("QP_CFG_EVIDENCE")
        }
        return runRustProcess(processBuilder, target)
    }

    private fun rustFlagsForCompile(target: String, specializationHex: String): String = buildString {
        append("-C metadata=qp_").append(specializationHex.take(16))
        if (target == RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET) {
            RUST_RELEASE_EXPORTS.sorted().forEach { export ->
                append(" -C link-arg=/EXPORT:").append(export)
            }
        }
    }

    internal fun rustFlagsForTest(target: String, specializationHex: String): String =
        rustFlagsForCompile(target, specializationHex)

    private fun MutableMap<String, String>.prependPath(entries: List<Path>) {
        if (entries.isEmpty()) return
        val pathKey = keys.firstOrNull { it.equals("PATH", ignoreCase = true) } ?: "PATH"
        val separator = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) ";" else ":"
        val prefix = entries.joinToString(separator) { it.toAbsolutePath().normalize().toString() }
        val existing = this[pathKey].orEmpty()
        this[pathKey] = if (existing.isBlank()) prefix else "$prefix$separator$existing"
    }

    internal fun rustCargoCommandForTest(cargoPath: Path, target: String, targetDir: Path): List<String> {
        require(target in RUST_TARGETS.values) { "Qp Rust target is not locked: $target" }
        val subcommand = "zigbuild"
        return listOf(
            cargoPath.toString(), subcommand, "--locked", "--package", "qp-ffi", "--lib", "--release",
            "--target", target, "--target-dir", targetDir.toString(),
        )
    }

    private fun runRustProcess(processBuilder: ProcessBuilder, target: String): RustCompileResult {
        val process = try {
            processBuilder.start()
        } catch (error: Exception) {
            return RustCompileResult(false, "failed to start Cargo $target build: ${error.message.orEmpty()}")
        }
        val stdout = ProcessOutputDrain(process.inputStream, "javashroud-rust-stdout")
        val stderr = ProcessOutputDrain(process.errorStream, "javashroud-rust-stderr")
        stdout.start()
        stderr.start()
        val timeoutMs = rustCompileTimeoutMs()
        val completed = try {
            process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            terminateProcessTree(process)
            return RustCompileResult(false, "Cargo $target build was interrupted")
        }
        if (!completed) {
            terminateProcessTree(process)
            val output = collectProcessOutput(process, stdout, stderr)
            return RustCompileResult(false, appendDiagnostic(output, "Cargo $target build timed out after ${timeoutMs}ms"))
        }
        val exitCode = process.exitValue()
        val output = collectProcessOutput(process, stdout, stderr)
        return RustCompileResult(
            success = exitCode == 0,
            output = output.ifBlank { "Cargo $target build exited with code $exitCode without diagnostics" },
        )
    }

    private fun rustCompileTimeoutMs(): Long =
        (System.getProperty(RUST_COMPILE_TIMEOUT_PROPERTY) ?: System.getenv(RUST_COMPILE_TIMEOUT_ENV))
            ?.trim()
            ?.toLongOrNull()
            ?.takeIf { it > 0L }
            ?: DEFAULT_RUST_COMPILE_TIMEOUT_MS

    private class ProcessOutputDrain(
        private val stream: InputStream,
        threadName: String,
    ) {
        @Volatile
        private var content = ""

        private val worker = Thread(
            { content = runCatching { stream.bufferedReader().use { it.readText() } }.getOrDefault("") },
            threadName,
        ).apply { isDaemon = true }

        fun start() = worker.start()

        fun await(timeoutMs: Long): Boolean = try {
            worker.join(timeoutMs)
            !worker.isAlive
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }

        fun close() = runCatching { stream.close() }

        fun output(): String = content
    }

    private fun collectProcessOutput(
        process: Process,
        stdout: ProcessOutputDrain,
        stderr: ProcessOutputDrain,
    ): String {
        val stdoutFinished = stdout.await(PROCESS_OUTPUT_DRAIN_TIMEOUT_MS)
        val stderrFinished = stderr.await(PROCESS_OUTPUT_DRAIN_TIMEOUT_MS)
        if (!stdoutFinished || !stderrFinished) {
            terminateProcessTree(process)
            stdout.close()
            stderr.close()
            stdout.await(PROCESS_OUTPUT_DRAIN_TIMEOUT_MS)
            stderr.await(PROCESS_OUTPUT_DRAIN_TIMEOUT_MS)
        }
        return sanitizeDiagnostic(
            listOf(stdout.output(), stderr.output()).filter(String::isNotBlank).joinToString("\\n"),
        )
    }

    private fun appendDiagnostic(output: String, diagnostic: String): String =
        sanitizeDiagnostic(if (output.isBlank()) diagnostic else "$output\\n$diagnostic")

    private fun terminateProcessTree(process: Process) {
        if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
            runCatching {
                val killer = ProcessBuilder("taskkill", "/PID", process.pid().toString(), "/T", "/F")
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start()
                if (!killer.waitFor(PROCESS_CLEANUP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) killer.destroyForcibly()
            }
        }
        runCatching {
            process.toHandle().descendants().forEach { handle -> if (handle.isAlive) handle.destroyForcibly() }
        }
        if (process.isAlive) {
            process.destroy()
            if (!process.waitFor(PROCESS_CLEANUP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) process.destroyForcibly()
        }
    }

    private fun sanitizeDiagnostic(value: String): String =
        value.replace(Regex("(?i)(master.?key|runtime.?resource.?key|secret|nonce)\\s*[:=].{0,160}"), "[redacted]")
            .take(MAX_RUST_DIAGNOSTIC_BYTES)

    private fun validateRustArtifact(platform: String, name: String, bytes: ByteArray) {
        require(bytes.isNotEmpty()) { "Rust artifact is empty" }
        require(bytes.size.toLong() <= MAX_NATIVE_ARTIFACT_BYTES) { "Rust artifact exceeds the bounded size" }
        require(!name.contains("macos", ignoreCase = true) && !name.contains("darwin", ignoreCase = true)) {
            "macOS and Mach-O artifact names are rejected"
        }
        require(!name.endsWith(".dylib", ignoreCase = true) && !name.contains("macho", ignoreCase = true)) {
            "Mach-O and .dylib artifact names are rejected"
        }
        require(name == NativeRecompilationRoute.forPlatform(platform).outputName) {
            "Rust artifact resource name is not canonical for $platform: $name"
        }
        when (platform) {
            RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS -> {
                validatePe64Artifact(bytes)
                val exportNames = readPeExportNames(bytes)
                require(exportNames.containsAll(RUST_RELEASE_EXPORTS)) {
                    "Rust Windows artifact export surface is missing the current Qp JNI ABI"
                }
                require(exportNames.none { it.startsWith("Java_") }) {
                    "Rust Windows artifact must not export Java_* business methods"
                }
            }
            RustToolchainProvisioner.RUNTIME_TARGET_LINUX -> validateElf64Artifact(bytes)
            else -> error("unsupported Qp Rust artifact platform: $platform")
        }
        require(bytes.containsAscii("qp_r1_runtime_binding_digest")) {
            "Rust artifact is missing qp_r1_runtime_binding_digest"
        }
        require(bytes.containsAscii("qp_r1_open_frame")) {
            "Rust artifact is missing qp_r1_open_frame"
        }
    }

    internal fun validateRustArtifactForTest(platform: String, name: String, bytes: ByteArray) =
        validateRustArtifact(platform, name, bytes)

    private fun validatePe64Artifact(bytes: ByteArray) {
        require(bytes.size >= 0x40 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte()) {
            "Rust Windows artifact is not a PE image"
        }
        val peOffset = readU32Le(bytes, 0x3C).toLong()
        requireRange(bytes, peOffset, 26, "PE header")
        require(bytes.copyOfRange(peOffset.toInt(), peOffset.toInt() + 4).contentEquals(byteArrayOf('P'.code.toByte(), 'E'.code.toByte(), 0, 0))) {
            "Rust Windows artifact has an invalid PE signature"
        }
        require(readU16Le(bytes, peOffset + 4) == 0x8664) { "Rust Windows artifact is not AMD64" }
        val sectionCount = readU16Le(bytes, peOffset + 6)
        require(sectionCount in 1..96) { "Rust Windows artifact has an invalid section count" }
        val optionalSize = readU16Le(bytes, peOffset + 20)
        require(optionalSize >= 112) { "Rust Windows artifact has a truncated PE64 optional header" }
        require(readU16Le(bytes, peOffset + 24) == 0x20B) { "Rust Windows artifact is not PE32+" }
        val sectionTable = peOffset.checkedAdd(24L).checkedAdd(optionalSize.toLong())
        requireRange(bytes, sectionTable, sectionCount.toLong() * 40L, "PE section table")
        for (index in 0 until sectionCount) {
            val section = sectionTable + index.toLong() * 40L
            val rawSize = readU32Le(bytes, section + 16).toLong()
            val rawOffset = readU32Le(bytes, section + 20).toLong()
            if (rawSize != 0L) requireRange(bytes, rawOffset, rawSize, "PE section data")
        }
    }

    private fun readPeExportNames(bytes: ByteArray): Set<String> {
        val peOffset = readU32Le(bytes, 0x3C)
        val sectionCount = readU16Le(bytes, peOffset + 6)
        val optionalSize = readU16Le(bytes, peOffset + 20)
        val optionalOffset = peOffset.checkedAdd(24L)
        val exportRva = readU32Le(bytes, optionalOffset + 112)
        require(exportRva != 0L) { "Rust Windows artifact has no PE export directory" }
        val sectionTable = optionalOffset.checkedAdd(optionalSize.toLong())
        val sections = (0 until sectionCount).map { index ->
            val section = sectionTable + index.toLong() * 40L
            val virtualSize = readU32Le(bytes, section + 8)
            val virtualAddress = readU32Le(bytes, section + 12)
            val rawSize = readU32Le(bytes, section + 16)
            val rawOffset = readU32Le(bytes, section + 20)
            PeSection(virtualAddress, maxOf(virtualSize, rawSize), rawOffset)
        }
        fun offsetForRva(rva: Long): Long {
            val section = sections.firstOrNull { candidate ->
                rva >= candidate.virtualAddress && rva - candidate.virtualAddress < candidate.span
            } ?: error("Rust Windows artifact PE export RVA is unmapped")
            val offset = section.rawOffset.checkedAdd(rva - section.virtualAddress)
            requireRange(bytes, offset, 1, "PE export RVA")
            return offset
        }
        val exportOffset = offsetForRva(exportRva)
        val nameCount = readU32Le(bytes, exportOffset + 24)
        require(nameCount in 1..65_536) { "Rust Windows artifact PE export count is invalid" }
        val nameTableOffset = offsetForRva(readU32Le(bytes, exportOffset + 32))
        requireRange(bytes, nameTableOffset, nameCount * 4L, "PE export name table")
        return (0 until nameCount.toInt()).mapTo(linkedSetOf()) { index ->
            val nameRva = readU32Le(bytes, nameTableOffset + index.toLong() * 4L)
            readAsciiCString(bytes, offsetForRva(nameRva), "PE export name")
        }
    }

    private data class PeSection(
        val virtualAddress: Long,
        val span: Long,
        val rawOffset: Long,
    )

    private fun readAsciiCString(bytes: ByteArray, offset: Long, label: String): String {
        requireRange(bytes, offset, 1, label)
        val start = offset.toInt()
        var end = start
        while (end < bytes.size && end - start <= 512 && bytes[end] != 0.toByte()) {
            require(bytes[end].toInt() and 0xFF in 0x20..0x7E) { "$label is not ASCII" }
            end++
        }
        require(end < bytes.size && bytes[end] == 0.toByte() && end > start) { "$label is unterminated or empty" }
        return String(bytes, start, end - start, StandardCharsets.US_ASCII)
    }

    private fun validateElf64Artifact(bytes: ByteArray) {
        require(bytes.size >= 64 && bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))) {
            "Rust Linux artifact is not an ELF image"
        }
        require(bytes[4].toInt() == 2 && bytes[5].toInt() == 1) { "Rust Linux artifact is not little-endian ELF64" }
        require(readU16Le(bytes, 16) == 3) { "Rust Linux artifact is not a shared object" }
        require(readU16Le(bytes, 18) == 0x3E) { "Rust Linux artifact is not AMD64" }
        val programOffset = readU64Le(bytes, 32)
        val programEntrySize = readU16Le(bytes, 54)
        val programCount = readU16Le(bytes, 56)
        require(programEntrySize >= 56 && programCount in 1..1024) { "Rust Linux artifact has invalid program headers" }
        requireRange(bytes, programOffset, programEntrySize.toLong() * programCount.toLong(), "ELF program headers")
        for (index in 0 until programCount) {
            val header = programOffset + index.toLong() * programEntrySize.toLong()
            val fileOffset = readU64Le(bytes, header + 8)
            val fileSize = readU64Le(bytes, header + 32)
            val memorySize = readU64Le(bytes, header + 40)
            require(fileSize <= memorySize) { "ELF program segment is smaller in memory than on disk" }
            requireRange(bytes, fileOffset, fileSize, "ELF program segment")
        }
        require(!bytes.containsAscii("musl")) {
            "Rust Linux artifact must target glibc, not musl"
        }
        for (minor in 18..50) {
            require(!bytes.containsAscii("GLIBC_2.$minor")) {
                "Rust Linux artifact requires a GLIBC symbol newer than ${RustToolchainProvisioner.LINUX_GLIBC_FLOOR}"
            }
        }
        require(!bytes.containsAscii("GLIBC_3.")) {
            "Rust Linux artifact requires GLIBC 3"
        }
    }

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(StandardCharsets.US_ASCII)
        if (needle.isEmpty() || needle.size > size) return false
        for (start in 0..(size - needle.size)) {
            if (needle.indices.all { index -> this[start + index] == needle[index] }) return true
        }
        return false
    }

    private fun requireRange(bytes: ByteArray, offset: Long, length: Long, label: String) {
        require(offset >= 0L && length >= 0L && offset <= bytes.size.toLong() && length <= bytes.size.toLong() - offset) {
            "$label is outside the Rust artifact bounds"
        }
    }

    private fun readU16Le(bytes: ByteArray, offset: Long): Int {
        requireRange(bytes, offset, 2, "u16")
        val index = offset.toInt()
        return (bytes[index].toInt() and 0xFF) or ((bytes[index + 1].toInt() and 0xFF) shl 8)
    }

    private fun readU32Le(bytes: ByteArray, offset: Long): Long {
        requireRange(bytes, offset, 4, "u32")
        val index = offset.toInt()
        return (bytes[index].toLong() and 0xFFL) or
            ((bytes[index + 1].toLong() and 0xFFL) shl 8) or
            ((bytes[index + 2].toLong() and 0xFFL) shl 16) or
            ((bytes[index + 3].toLong() and 0xFFL) shl 24)
    }

    private fun readU64Le(bytes: ByteArray, offset: Long): Long {
        requireRange(bytes, offset, 8, "u64")
        val index = offset.toInt()
        var value = 0L
        for (shift in 0 until 64 step 8) value = value or ((bytes[index + shift / 8].toLong() and 0xFFL) shl shift)
        return value
    }

    private fun Long.checkedAdd(other: Long): Long = Math.addExact(this, other)

    private fun nativeBuildSecureRandom(seed: Long, context: QpBuildContext): SecureRandom {
        val random = SecureRandom()
        val entropy = ByteArray(64).also(random::nextBytes)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.updateUtf8("javashroud-native-recompile-csprng-v1")
        digest.updateLong(seed)
        digest.updateLong(context.nativeSeed)
        digest.update(context.jarLayoutDigest)
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
        rustTarget: String,
        outputName: String,
        sourceDigest: ByteArray,
        toolchainIdentity: String,
        seed: Long,
        qpBuildContext: QpBuildContext,
        protectedSectionKey: ByteArray,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
        nativeShellPackerVersion: Int = 1,
        nativeShellPayloadProfile: String = "qp-rust-ffi-v1",
        nativeShellLoaderProfile: String = "direct-rust-loader",
        specializationDigest: ByteArray = sourceDigest,
        targetTokenCommitment: ByteArray = ByteArray(32),
        targetTokenNameSeed: ByteArray = ByteArray(16),
    ): String {
        require(taskPlatform in RUST_TARGETS) { "Qp target platform is unsupported: $taskPlatform" }
        require(rustTarget == RUST_TARGETS.getValue(taskPlatform)) {
            "Qp target triple does not match $taskPlatform: $rustTarget"
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(RUST_SPECIALIZATION_DOMAIN.toByteArray(StandardCharsets.US_ASCII))
        digest.updateUtf8(taskPlatform)
        digest.updateUtf8(rustTarget)
        digest.updateUtf8(outputName)
        digest.updateUtf8(RUST_FFI_PACKAGE)
        digest.updateUtf8(nativeProtectionLevel)
        digest.updateUtf8(nativePackingLevel)
        digest.updateInt(nativeShellPackerVersion)
        digest.updateUtf8(nativeShellPayloadProfile)
        digest.updateUtf8(nativeShellLoaderProfile)
        digest.update(sourceDigest)
        digest.update(specializationDigest)
        digest.updateUtf8(toolchainIdentity)
        digest.updateLong(seed)
        digest.updateLong(qpBuildContext.nativeSeed)
        digest.update(qpBuildContext.jarLayoutDigest)
        digest.updateInt(qpBuildContext.nativeVmProfile.authenticatedId)
        require(targetTokenCommitment.size == 32) { "Qp token commitment must be 32 bytes" }
        require(targetTokenNameSeed.size == 16) { "Qp token name seed must be 16 bytes" }
        digest.update(targetTokenCommitment)
        digest.update(targetTokenNameSeed)
        digest.update(protectedSectionKey)
        return HexEncodingSupport.toHexLower(digest.digest())
    }

    private fun digestRustWorkspace(workspace: Path): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.walk(workspace).use { stream ->
            stream.filter { path ->
                Files.isRegularFile(path) && !path.toString().replace('\\', '/').contains("/target/")
            }
                .sorted(Comparator.comparing { path -> workspace.relativize(path).toString().replace('\\', '/') })
                .forEach { path ->
                    val relative = workspace.relativize(path).toString().replace('\\', '/')
                    digest.updateUtf8(relative)
                    val bytes = Files.readAllBytes(path)
                    try {
                        digest.update(bytes)
                    } finally {
                        bytes.fill(0)
                    }
                }
        }
        return digest.digest()
    }

    private fun rustToolchainIdentity(toolchain: RustToolchainProvisioner.RustToolchain): String {
        val rustc = toolchain.rustcPath.toAbsolutePath().normalize()
        val cargo = toolchain.cargoPath.toAbsolutePath().normalize()
        val identityKey = "${toolchain.host}|$rustc|$cargo|" +
            "${runCatching { Files.size(rustc) }.getOrDefault(-1L)}|" +
            "${runCatching { Files.size(cargo) }.getOrDefault(-1L)}|" +
            "${runCatching { Files.getLastModifiedTime(rustc).toMillis() }.getOrDefault(-1L)}|" +
            "${runCatching { Files.getLastModifiedTime(cargo).toMillis() }.getOrDefault(-1L)}"
        return rustToolchainIdentityCache.computeIfAbsent(identityKey) {
            val rustcVersion = runCatching {
                val process = ProcessBuilder(rustc.toString(), "--version")
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().use { it.readText().trim() }
                if (process.waitFor(2, TimeUnit.SECONDS) && process.exitValue() == 0) output else "unknown"
            }.getOrDefault("unknown")
            val cargoVersion = runCatching {
                val process = ProcessBuilder(cargo.toString(), "--version")
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().use { it.readText().trim() }
                if (process.waitFor(2, TimeUnit.SECONDS) && process.exitValue() == 0) output else "unknown"
            }.getOrDefault("unknown")
            "$identityKey|$rustcVersion|$cargoVersion"
        }
    }

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

}
