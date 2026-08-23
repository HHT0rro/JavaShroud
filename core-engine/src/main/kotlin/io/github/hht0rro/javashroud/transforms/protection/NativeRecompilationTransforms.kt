package io.github.hht0rro.javashroud.transforms.protection

import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object NativeRecompilationTransforms {

    /*
     * AKEN-R1 has one production native path: copy the Rust workspace into a
     * build-private directory and invoke the locked Cargo command there.  The
     * lock is keyed by the complete specialization identity so two builds can
     * never share a mutable target directory or a partially-written cache entry.
     */
    private val rustCompileLocks = ConcurrentHashMap<String, Any>()
    private val rustToolchainIdentityCache = ConcurrentHashMap<String, String>()
    private const val DEFAULT_NATIVE_COMPILE_PARALLELISM = 2

    private const val NATIVE_CACHE_MAGIC = "JSR1-RUST-CACHE1"
    private const val NATIVE_CACHE_VERSION = 1
    private const val NATIVE_CACHE_HEADER_SIZE = 16 + 4 + 32 + 8 + 32
    private const val MAX_NATIVE_ARTIFACT_BYTES = 256L * 1024L * 1024L
    private const val MAX_RUST_DIAGNOSTIC_BYTES = 8_192
    private const val RUST_COMPILE_TIMEOUT_PROPERTY = "javashroud.rust.compile.timeout.ms"
    private const val RUST_COMPILE_TIMEOUT_ENV = "JS_VBC4_RUST_COMPILE_TIMEOUT_MS"
    private const val DEFAULT_RUST_COMPILE_TIMEOUT_MS = 15 * 60 * 1000L
    private const val PROCESS_OUTPUT_DRAIN_TIMEOUT_MS = 5_000L
    private const val PROCESS_CLEANUP_TIMEOUT_MS = 5_000L
    private const val RUST_WORKSPACE_PROPERTY = "javashroud.rust.workspace"
    private const val RUST_WORKSPACE_DIR = "src/main/rust"
    private const val RUST_FFI_PACKAGE = "jsrt-ffi"
    private const val RUST_FFI_LIBRARY = "jsrt_ffi"
    private const val RUST_SPECIALIZATION_DOMAIN = "JavaShroud/AKEN-R1/RustSpecialization/v1"

    /** Only the two locked AKEN-R1 Rust runtime targets are accepted. */
    internal val RUST_TARGETS: Map<String, String> = linkedMapOf(
        RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS to RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
        RustToolchainProvisioner.RUNTIME_TARGET_LINUX to RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
    )

    data class RecompiledNative(
        val platform: String,
        val libName: String,
        val bytes: ByteArray,
        val shellBindingCommitment: ByteArray? = null,
    )

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
        request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = nativeProtectionLevel,
            nativePackingLevel = NativeKernelShellPacker.Level.OFF,
            targetPlatforms = listOf(targetPlatform),
        ),
        cfgEvidenceExports = true,
        evidenceRandom = evidenceRandom,
    ).results.singleOrNull()

    /**
     * Compatibility adapter for raw callers. Production configuration should
     * construct NativeRecompilationRequest once at its boundary instead.
     */
    fun recompileWithDiagnostics(
        seed: Long,
        classLoader: ClassLoader,
        targetPlatforms: Collection<String> = RUST_TARGETS.keys,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
        onMessage: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
    ): RecompilationDiagnostics {
        val request = NativeRecompilationRequest.forTargets(
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
        request: NativeRecompilationRequest,
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
        request: NativeRecompilationRequest,
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
            requireR1Request(request)
        } catch (error: Exception) {
            report(rustMessage("error", error.message.orEmpty()))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        val resolution = try {
            RustToolchainProvisioner.resolve()
        } catch (error: Exception) {
            report(rustMessage("error", "AKEN-R1 Rust toolchain resolution failed: ${error.message.orEmpty()}"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        resolution.messages.forEach { message ->
            report(rustMessage(message.level, message.message))
        }
        val toolchain = resolution.toolchain ?: run {
            report(rustMessage("error", "AKEN-R1 Rust toolchain is unavailable; native recompilation is disabled"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        val workspace = try {
            resolveRustWorkspace(classLoader)
        } catch (error: Exception) {
            report(rustMessage("error", "AKEN-R1 Rust workspace resolution failed: ${error.message.orEmpty()}"))
            return RecompilationDiagnostics(emptyList(), messages)
        }
        val workDir = try {
            Files.createTempDirectory("javashroud-aken-r1-rust-")
        } catch (error: Exception) {
            report(rustMessage("error", "AKEN-R1 Rust build directory could not be created: ${error.message.orEmpty()}"))
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
            report(rustMessage("error", "AKEN-R1 Rust native recompilation failed: ${error.message.orEmpty()}"))
            RecompilationDiagnostics(emptyList(), messages)
        } finally {
            val deleted = runCatching { workDir.toFile().deleteRecursively() }.getOrDefault(false)
            if (!deleted && Files.exists(workDir)) {
                report(rustMessage("error", "AKEN-R1 Rust build directory cleanup failed; refusing to reuse it"))
            }
        }
    }

    private fun doRecompile(
        seed: Long,
        classLoader: ClassLoader,
        toolchain: RustToolchainProvisioner.RustToolchain,
        workspace: Path,
        workDir: Path,
        request: NativeRecompilationRequest,
        cfgEvidenceExports: Boolean,
        evidenceRandom: Random?,
        report: (NativeToolchainProvisioner.ResolutionMessage) -> Unit,
    ): List<RecompiledNative> {
        requireR1Request(request)
        val context = Vbc4BuildContexts.requireCurrent()
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
        try {
            copyRustWorkspace(workspace, rustWorkspace)
            sourceDigest = digestRustWorkspace(rustWorkspace)
            val toolchainIdentity = rustToolchainIdentity(toolchain)
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
                )
                val outputName = route.outputName
                val cacheKey = nativeArtifactCacheKey(
                    taskPlatform = route.platform,
                    rustTarget = target,
                    outputName = outputName,
                    sourceDigest = sourceDigest,
                    toolchainIdentity = toolchainIdentity,
                    seed = seed,
                    vbc4BuildContext = context,
                    protectedSectionKey = specializationNonce,
                    nativeProtectionLevel = request.nativeProtectionLevel,
                    nativePackingLevel = request.nativePackingLevel.configValue,
                    nativeShellPackerVersion = 1,
                    nativeShellPayloadProfile = "aken-r1-rust-ffi-v1",
                    nativeShellLoaderProfile = "rust-ffi-${route.platform}-v1",
                    specializationDigest = specializationDigest,
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
                )
            }
            val compiled = compileNativeTasksBounded(
                compileTasks = tasks,
                cargoPath = toolchain.cargoPath,
                rustWorkspace = rustWorkspace,
                cfgEvidenceExports = cfgEvidenceExports,
            )
            val results = ArrayList<RecompiledNative>(compiled.size)
            var failed = false
            for ((task, result) in compiled) {
                val bytes = result.bytes
                if (!result.success || bytes == null || bytes.isEmpty()) {
                    failed = true
                    report(rustMessage("error", "AKEN-R1 Rust target ${task.platform} failed: ${sanitizeDiagnostic(result.output)}"))
                    continue
                }
                try {
                    validateRustArtifact(task.platform, task.outputName, bytes)
                    if (!cfgEvidenceExports && !result.fromCache) {
                        writeRustArtifactCache(task.cachePath, bytes, task.cacheKey, task.platform, task.outputName)
                    }
                    results += RecompiledNative(task.platform, task.outputName, bytes)
                    report(rustMessage("info", "Built AKEN-R1 Rust JNI runtime for ${task.platform}"))
                } catch (error: Exception) {
                    failed = true
                    bytes.fill(0)
                    report(rustMessage("error", "AKEN-R1 Rust artifact for ${task.platform} was rejected: ${error.message.orEmpty()}"))
                }
            }
            if (failed || results.size != tasks.size) {
                results.forEach { it.bytes.fill(0) }
                return emptyList()
            }
            return results
        } finally {
            tasks.forEach { task -> task.specializationDigest.fill(0) }
            sourceDigest.fill(0)
            specializationNonce.fill(0)
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
    )

    private data class NativeArtifactBuildResult(
        val success: Boolean,
        val output: String,
        val bytes: ByteArray?,
        val fromCache: Boolean,
    )

    private fun compileNativeTasksBounded(
        compileTasks: List<NativeCompileTask>,
        cargoPath: Path,
        rustWorkspace: Path,
        cfgEvidenceExports: Boolean,
    ): List<Pair<NativeCompileTask, NativeArtifactBuildResult>> {
        if (compileTasks.isEmpty()) return emptyList()
        val parallelism = minOf(compileTasks.size, nativeCompileParallelism())
        fun compileOne(task: NativeCompileTask): Pair<NativeCompileTask, NativeArtifactBuildResult> {
            return try {
                Files.createDirectories(task.outputPath.parent)
                copyRustWorkspace(rustWorkspace, task.workspace)
                writeSpecializationModule(task)
                task to compileOrLoadRustArtifact(
                    cargoPath = cargoPath,
                    rustWorkspace = task.workspace,
                    task = task,
                    cfgEvidenceExports = cfgEvidenceExports,
                )
            } catch (error: Exception) {
                task to NativeArtifactBuildResult(false, error.message ?: error::class.java.simpleName, null, false)
            }
        }
        if (parallelism <= 1) return compileTasks.map(::compileOne)

        val executor = Executors.newFixedThreadPool(parallelism) { runnable ->
            Thread(runnable, "javashroud-aken-r1-rust-compile").apply { isDaemon = true }
        }
        return try {
            compileTasks.map { task -> executor.submit(Callable { compileOne(task) }) }.map { future ->
                try {
                    future.get()
                } catch (error: Exception) {
                    throw IllegalStateException("AKEN-R1 Rust compile worker failed", error)
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
            ?: System.getenv("JS_VBC4_NATIVE_COMPILE_PARALLELISM")
        return configured?.trim()?.toIntOrNull()?.takeIf { it > 0 }?.coerceAtMost(16)
            ?: minOf(DEFAULT_NATIVE_COMPILE_PARALLELISM, Runtime.getRuntime().availableProcessors().coerceAtLeast(1))
    }

    private fun compileOrLoadRustArtifact(
        cargoPath: Path,
        rustWorkspace: Path,
        task: NativeCompileTask,
        cfgEvidenceExports: Boolean,
    ): NativeArtifactBuildResult = withRustCompileLock(task.cachePath) {
        if (!cfgEvidenceExports) {
            readRustArtifactCache(task.cachePath, task.cacheKey, task.platform, task.outputName)?.let { cachedBytes ->
                return@withRustCompileLock NativeArtifactBuildResult(true, "cache-hit", cachedBytes, true)
            }
        }
        val specializationHex = HexEncodingSupport.toHexLower(task.specializationDigest)
        val compileResult = runRustCompile(
            cargoPath = cargoPath,
            workspace = rustWorkspace,
            targetDir = task.targetDir,
            target = task.rustTarget,
            specializationHex = specializationHex,
            cfgEvidenceExports = cfgEvidenceExports,
        )
        if (!compileResult.success) {
            return@withRustCompileLock NativeArtifactBuildResult(false, compileResult.output, null, false)
        }
        val builtArtifact = task.targetDir.resolve(task.rustTarget).resolve("release").resolve(rustLibraryFileName(task.platform))
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
            temporary = Files.createTempFile(cachePath.parent, ".aken-r1-cache-", ".tmp")
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
        Path.of(System.getProperty("user.home"), ".javashroud", "native", "aken-r1-rust").toAbsolutePath().normalize()

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

    private fun requireR1Request(request: NativeRecompilationRequest) {
        val unsupported = request.routes.filterNot { route -> route.platform in RUST_TARGETS }
        require(unsupported.isEmpty()) {
            "AKEN-R1 rejects macOS, Mach-O, .dylib, and legacy native routes: ${unsupported.joinToString { it.platform }}"
        }
        request.routes.forEach { route ->
            val expectedTarget = RUST_TARGETS.getValue(route.platform)
            require(expectedTarget == rustTargetForPlatform(route.platform)) {
                "AKEN-R1 Rust target mapping is inconsistent for ${route.platform}"
            }
        }
    }

    private fun rustTargetForPlatform(platform: String): String =
        RUST_TARGETS[platform]
            ?: throw IllegalArgumentException(
                "AKEN-R1 Rust target is unsupported: $platform; only Windows x64 and Linux x64 glibc 2.17 are accepted",
            )

    private fun rustLibraryFileName(platform: String): String = when (platform) {
        RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS -> "$RUST_FFI_LIBRARY.dll"
        RustToolchainProvisioner.RUNTIME_TARGET_LINUX -> "lib$RUST_FFI_LIBRARY.so"
        else -> throw IllegalArgumentException("AKEN-R1 Rust artifact platform is unsupported: $platform")
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
            val location = NativeRecompilationTransforms::class.java.protectionDomain.codeSource.location.toURI()
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
        classLoader.getResource("META-INF/rust-runtime/Cargo.toml")?.let { resource ->
            runCatching { Path.of(resource.toURI()).parent }.getOrNull()?.let(candidates::add)
        }
        return candidates.asSequence()
            .map { it.toAbsolutePath().normalize() }
            .firstOrNull { isRustWorkspaceTemplate(it) }
            ?: throw IllegalStateException(
                "AKEN-R1 Rust workspace is unavailable; expected core-engine/src/main/rust with Cargo.lock",
            )
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
        require(isRustWorkspaceTemplate(source)) { "AKEN-R1 Rust workspace template is invalid: $source" }
        Files.createDirectories(destination)
        val normalizedDestination = destination.toAbsolutePath().normalize()
        Files.walk(source).use { stream ->
            stream.sorted().forEach { entry ->
                if (Files.isSymbolicLink(entry)) {
                    throw IllegalStateException("AKEN-R1 rejects symlinked Rust workspace entries: $entry")
                }
                val relative = source.relativize(entry)
                if (relative.nameCount > 0 && relative.getName(0).toString() == "target") return@forEach
                val target = normalizedDestination.resolve(relative.toString()).normalize()
                require(target.startsWith(normalizedDestination)) {
                    "AKEN-R1 Rust workspace entry escapes its isolated build directory: $relative"
                }
                if (Files.isDirectory(entry)) {
                    Files.createDirectories(target)
                } else if (Files.isRegularFile(entry)) {
                    Files.createDirectories(target.parent)
                    Files.copy(entry, target, StandardCopyOption.REPLACE_EXISTING)
                } else {
                    throw IllegalStateException("AKEN-R1 rejects non-regular Rust workspace entry: $entry")
                }
            }
        }
        require(Files.isRegularFile(normalizedDestination.resolve("Cargo.lock"))) {
            "AKEN-R1 isolated Rust workspace is missing Cargo.lock"
        }
    }

    private fun writeSpecializationModule(task: NativeCompileTask) {
        val destination = task.workspace.resolve("crates").resolve("jsrt-ffi").resolve("src").resolve("specialization.rs")
        require(Files.isRegularFile(destination.parent.resolve("lib.rs"))) {
            "AKEN-R1 isolated Rust workspace is missing jsrt-ffi/src/lib.rs"
        }
        val digestLiteral = task.specializationDigest.joinToString(", ") { byte ->
            "0x" + ((byte.toInt() and 0xFF).toString(16).padStart(2, '0'))
        }
        val source = buildString {
            append("//! Generated AKEN-R1 nonsecret specialization. Contains no keys or plaintext.\n")
            append("pub const TARGET_TRIPLE: &str = \"")
            append(task.rustTarget)
            append("\";\n")
            append("pub const SPECIALIZATION_DIGEST: [u8; 32] = [")
            append(digestLiteral)
            append("];\n")
            append("pub const PAYLOAD_PROFILE: &str = \"aken-r1-rust-ffi-v1\";\n")
            append("pub const PROTECTION_LEVEL: &str = \"")
            append(task.protectionLevel)
            append("\";\n")
            append("pub const PACKING_LEVEL: &str = \"")
            append(task.packingLevel)
            append("\";\n")
        }
        require(!source.contains("masterKey", ignoreCase = true) && !source.contains("runtimeResourceKey", ignoreCase = true)) {
            "AKEN-R1 specialization module must not contain secret field names"
        }
        Files.writeString(destination, source, StandardCharsets.US_ASCII)
    }

    private fun rustSpecializationDigest(
        seed: Long,
        targetPlatform: String,
        targetTriple: String,
        sourceDigest: ByteArray,
        context: Vbc4BuildContext,
        request: NativeRecompilationRequest,
        specializationNonce: ByteArray,
    ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update(RUST_SPECIALIZATION_DOMAIN.toByteArray(StandardCharsets.US_ASCII))
        updateUtf8(targetPlatform)
        updateUtf8(targetTriple)
        updateLong(seed)
        updateLong(context.nativeSeed)
        update(context.jarLayoutDigest)
        updateUtf8(request.nativeProtectionLevel)
        updateUtf8(request.nativePackingLevel.configValue)
        updateUtf8("aken-r1-rust-ffi-v1")
        updateInt(context.nativeVmProfile.authenticatedId)
        update(sourceDigest)
        update(specializationNonce)
    }.digest()

    private fun runRustCompile(
        cargoPath: Path,
        workspace: Path,
        targetDir: Path,
        target: String,
        specializationHex: String,
        cfgEvidenceExports: Boolean,
    ): RustCompileResult {
        require(target in RUST_TARGETS.values) { "AKEN-R1 Rust target is not locked: $target" }
        require(specializationHex.length == 64 && specializationHex.all { it in "0123456789abcdefABCDEF" }) {
            "AKEN-R1 specialization digest is invalid"
        }
        Files.createDirectories(targetDir)
        val subcommand = if (target == RustToolchainProvisioner.LINUX_RUNTIME_TARGET) "zigbuild" else "build"
        val command = listOf(
            cargoPath.toString(),
            subcommand,
            "--locked",
            "--offline",
            "--workspace",
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
            put("CARGO_NET_OFFLINE", "true")
            put("CARGO_TERM_COLOR", "never")
            put("CARGO_TARGET_DIR", targetDir.toString())
            put("RUSTFLAGS", "-C metadata=jsr1_${specializationHex.take(16)}")
            if (cfgEvidenceExports) put("JSRT_R1_CFG_EVIDENCE", "1") else remove("JSRT_R1_CFG_EVIDENCE")
        }
        return runRustProcess(processBuilder, target)
    }

    internal fun rustCargoCommandForTest(cargoPath: Path, target: String, targetDir: Path): List<String> {
        require(target in RUST_TARGETS.values) { "AKEN-R1 Rust target is not locked: $target" }
        val subcommand = if (target == RustToolchainProvisioner.LINUX_RUNTIME_TARGET) "zigbuild" else "build"
        return listOf(
            cargoPath.toString(), subcommand, "--locked", "--offline", "--workspace", "--release",
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
            RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS -> validatePe64Artifact(bytes)
            RustToolchainProvisioner.RUNTIME_TARGET_LINUX -> validateElf64Artifact(bytes)
            else -> error("unsupported AKEN-R1 Rust artifact platform: $platform")
        }
        require(bytes.containsAscii("jsrt_r1_runtime_binding_digest")) {
            "Rust artifact is missing jsrt_r1_runtime_binding_digest"
        }
        require(bytes.containsAscii("jsrt_r1_open_frame")) {
            "Rust artifact is missing jsrt_r1_open_frame"
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

    private fun nativeBuildSecureRandom(seed: Long, context: Vbc4BuildContext): SecureRandom {
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
        vbc4BuildContext: Vbc4BuildContext,
        protectedSectionKey: ByteArray,
        nativeProtectionLevel: String = "standard",
        nativePackingLevel: String = "max",
        nativeShellPackerVersion: Int = 1,
        nativeShellPayloadProfile: String = "aken-r1-rust-ffi-v1",
        nativeShellLoaderProfile: String = "direct-rust-loader",
        specializationDigest: ByteArray = sourceDigest,
    ): String {
        require(taskPlatform in RUST_TARGETS) { "AKEN-R1 target platform is unsupported: $taskPlatform" }
        require(rustTarget == RUST_TARGETS.getValue(taskPlatform)) {
            "AKEN-R1 target triple does not match $taskPlatform: $rustTarget"
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
        digest.updateLong(vbc4BuildContext.nativeSeed)
        digest.update(vbc4BuildContext.jarLayoutDigest)
        digest.updateInt(vbc4BuildContext.nativeVmProfile.authenticatedId)
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
