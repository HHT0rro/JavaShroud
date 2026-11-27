package io.github.hht0rro.javashroud.transforms.protection

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/**
 * External packing handoff for unbound compiled Qp native images.
 * When the nativeshroud pass is enabled, JSIM measurement / seal runs after
 * this handoff on the returned disk image. Resolution order per platform:
 * a Xenolith CLI spawn (cliPath), then a pre-packed packedPath file, then the
 * desktop need-pack handoff on stdin. The only spawned process is the
 * external Xenolith CLI (`xenolith pack IN -o OUT --profile P --json`); no
 * packer code is linked in-process. Windows PE64 DLLs must come back packed
 * with the JS measurement sections and bridge exports preserved; Linux ELF
 * may reply SKIP to ship the unpacked .so.
 */
internal object NativeShroudPacker {
    internal const val PASS_ID = "nativeshroud"
    internal const val HANDOFF_ENV = "JAVASHROUD_PACK_HANDOFF"
    internal val XENOLITH_PROFILES = listOf("fast", "standard", "max")
    internal const val XENOLITH_PROFILE_DEFAULT = "standard"
    internal const val PACKER_SOURCE_XENOLITH_CLI = "xenolith-cli"
    internal const val PACKER_SOURCE_PACKED_PATH = "packed-path"
    internal const val PACKER_SOURCE_HANDOFF = "handoff"
    internal const val PACKER_SOURCE_SKIP = "skip"

    /** Function-level selection / virtualization and G5 flags forwarded to the Xenolith CLI. */
    internal data class XenolithSelectionFlags(
        val vmExports: List<String> = emptyList(),
        val selectRva: List<String> = emptyList(),
        val selectFunction: List<String> = emptyList(),
        val selectAll: Boolean = false,
        val strictCoverage: Boolean = false,
        val allowNativeFallback: Boolean = false,
        val lazyRegions: Boolean = false,
        val protectImports: Boolean = false,
        val strictConstants: Boolean = false,
        val traceDiverge: Boolean = false,
    )
    private const val WINDOWS_PLATFORM = "windows-x64"
    private const val LINUX_PLATFORM = "linux-x64"
    private const val HANDOFF_PROGRESS = 94
    private const val LINUX_SKIP = "SKIP"
    private const val CLI_TIMEOUT_MILLIS = 10L * 60L * 1000L
    private const val WINDOWS_IMAGE_NAME = "qp_ffi.dll"
    private const val LINUX_IMAGE_NAME = "libqp_ffi.so"
    private val jsonMapper = ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)

    /** One external Xenolith CLI invocation; injectable for tests. */
    internal data class XenolithCliResult(
        val exitCode: Int,
        val output: String,
        val timedOut: Boolean,
        val errorOutput: String = "",
    )

    internal fun interface XenolithCliRunner {
        fun run(cliPath: String, args: List<String>, timeoutMillis: Long): XenolithCliResult
    }

    internal val processXenolithCliRunner = XenolithCliRunner { cliPath, args, timeoutMillis ->
        val process = ProcessBuilder(listOf(cliPath) + args).start()
        val output = StringBuilder()
        val errorOutput = StringBuilder()
        fun readStream(stream: java.io.InputStream, destination: StringBuilder): Thread = Thread {
            stream.bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
                lines.forEach { line -> synchronized(destination) { destination.appendLine(line) } }
            }
        }.also { it.isDaemon = true; it.start() }
        val readerThread = readStream(process.inputStream, output)
        val errorThread = readStream(process.errorStream, errorOutput)
        val finished = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            process.waitFor(10, TimeUnit.SECONDS)
        }
        readerThread.join(5_000)
        errorThread.join(5_000)
        val outputText = synchronized(output) { output.toString() }
        XenolithCliResult(
            exitCode = runCatching { process.exitValue() }.getOrElse { -1 },
            output = outputText,
            timedOut = !finished,
            errorOutput = synchronized(errorOutput) { errorOutput.toString() },
        )
    }

    internal fun packIfRequested(
        config: ObfuscationConfig,
        compiled: List<QpNativeCompilerPass.RecompiledNative>,
        emit: (EngineEvent) -> Unit = {},
        workDir: Path? = null,
        handoffEnabled: Boolean = System.getenv(HANDOFF_ENV) == "1",
        readHandoffLine: () -> String? = ::readStdinLine,
        cliRunner: XenolithCliRunner = processXenolithCliRunner,
    ): List<QpNativeCompilerPass.RecompiledNative> {
        val pass = config.passes.firstOrNull { it.enabled && it.id == PASS_ID } ?: return compiled
        val packedPathWindows = pass.params["packedPath"]?.asText()?.trim().orEmpty()
        val packedPathLinux = pass.params["packedPathLinux"]?.asText()?.trim().orEmpty()
        val cliPath = pass.params["cliPath"]?.asText()?.trim().orEmpty()
        val profile = pass.params["profile"]?.asText()?.trim().orEmpty()
            .ifEmpty { XENOLITH_PROFILE_DEFAULT }
        if (cliPath.isNotEmpty()) {
            requireXenolithProfile(profile)
        }
        val selectionFlags = if (cliPath.isNotEmpty()) {
            parseXenolithSelectionFlags(pass.params).also { requireXenolithSelectionFlags(profile, it) }
        } else {
            XenolithSelectionFlags()
        }
        val cliVersion = if (cliPath.isNotEmpty()) probeXenolithVersion(cliPath, emit, cliRunner) else null
        val scratch = workDir ?: Files.createTempDirectory("javashroud-pack-handoff")
        val createdScratch = workDir == null
        try {
            return compiled.map { native ->
                when (native.platform) {
                    WINDOWS_PLATFORM -> handoffWindows(
                        native = native,
                        packedPathParam = packedPathWindows,
                        cliPath = cliPath,
                        profile = profile,
                        cliVersion = cliVersion,
                        selectionFlags = selectionFlags,
                        scratch = scratch,
                        handoffEnabled = handoffEnabled,
                        readHandoffLine = readHandoffLine,
                        emit = emit,
                        cliRunner = cliRunner,
                    )
                    LINUX_PLATFORM -> handoffLinux(
                        native = native,
                        packedPathParam = packedPathLinux,
                        cliPath = cliPath,
                        scratch = scratch,
                        handoffEnabled = handoffEnabled,
                        readHandoffLine = readHandoffLine,
                        emit = emit,
                    )
                    else -> {
                        emit(
                            EngineEvent(
                                level = "info",
                                type = "log",
                                message = "nativeshroud skipped ${native.platform}: unsupported platform",
                                progress = HANDOFF_PROGRESS,
                                outPath = null,
                            ),
                        )
                        native
                    }
                }
            }
        } finally {
            if (createdScratch) {
                scratch.toFile().deleteRecursively()
            }
        }
    }

    private fun handoffWindows(
        native: QpNativeCompilerPass.RecompiledNative,
        packedPathParam: String,
        cliPath: String,
        profile: String,
        cliVersion: String?,
        selectionFlags: XenolithSelectionFlags,
        scratch: Path,
        handoffEnabled: Boolean,
        readHandoffLine: () -> String?,
        emit: (EngineEvent) -> Unit,
        cliRunner: XenolithCliRunner,
    ): QpNativeCompilerPass.RecompiledNative {
        val outcome = runCatching {
            resolvePackedBytes(
                native = native,
                imageName = WINDOWS_IMAGE_NAME,
                packedPathParam = packedPathParam,
                cliPath = cliPath,
                profile = profile,
                cliVersion = cliVersion,
                selectionFlags = selectionFlags,
                scratch = scratch,
                handoffEnabled = handoffEnabled,
                readHandoffLine = readHandoffLine,
                emit = emit,
                allowSkip = false,
                cliRunner = cliRunner,
            )
        }
        return outcome.fold(
            onSuccess = { packed ->
                try {
                    PackedImageValidation.validateWindowsPackedDll(packed, native.bytes)
                } catch (error: Exception) {
                    packed.fill(0)
                    native.bytes.fill(0)
                    throw error
                }
                emit(
                    EngineEvent(
                        level = "info",
                        type = "log",
                        message = "Accepted packed Windows $WINDOWS_IMAGE_NAME (${packed.size} bytes)",
                        progress = HANDOFF_PROGRESS,
                        outPath = null,
                    ),
                )
                native.copy(bytes = packed)
            },
            onFailure = { error ->
                native.bytes.fill(0)
                throw IllegalStateException(
                    "nativeshroud pack failed for ${native.platform}: ${sanitize(error.message.orEmpty())}",
                    error,
                )
            },
        )
    }

    private fun handoffLinux(
        native: QpNativeCompilerPass.RecompiledNative,
        packedPathParam: String,
        cliPath: String,
        scratch: Path,
        handoffEnabled: Boolean,
        readHandoffLine: () -> String?,
        emit: (EngineEvent) -> Unit,
    ): QpNativeCompilerPass.RecompiledNative {
        if (cliPath.isNotEmpty()) {
            emit(
                EngineEvent(
                    level = "info",
                    type = "log",
                    message = "nativeshroud keeps linux-x64 on the unpacked/SKIP flow; xenolith cliPath applies to windows-x64 only",
                    progress = HANDOFF_PROGRESS,
                    outPath = null,
                ),
            )
        }
        val outcome = runCatching {
            resolvePackedBytes(
                native = native,
                imageName = LINUX_IMAGE_NAME,
                packedPathParam = packedPathParam,
                cliPath = "",
                profile = "",
                cliVersion = null,
                selectionFlags = XenolithSelectionFlags(),
                scratch = scratch,
                handoffEnabled = handoffEnabled,
                readHandoffLine = readHandoffLine,
                emit = emit,
                allowSkip = true,
                cliRunner = processXenolithCliRunner,
            )
        }
        return outcome.fold(
            onSuccess = { packed ->
                if (packed.contentEquals(native.bytes)) {
                    recordPackerObservation(native.platform, PACKER_SOURCE_SKIP, "", null, packed)
                    emit(
                        EngineEvent(
                            level = "info",
                            type = "log",
                            message = "nativeshroud skipped linux-x64 packing; shipping unpacked cdylib",
                            progress = HANDOFF_PROGRESS,
                            outPath = null,
                        ),
                    )
                    native
                } else {
                    emit(
                        EngineEvent(
                            level = "info",
                            type = "log",
                            message = "Accepted packed Linux $LINUX_IMAGE_NAME (${packed.size} bytes)",
                            progress = HANDOFF_PROGRESS,
                            outPath = null,
                        ),
                    )
                    native.copy(bytes = packed)
                }
            },
            onFailure = { error ->
                throw IllegalStateException(
                    "nativeshroud pack failed for ${native.platform}: ${sanitize(error.message.orEmpty())}",
                    error,
                )
            },
        )
    }

    private fun resolvePackedBytes(
        native: QpNativeCompilerPass.RecompiledNative,
        imageName: String,
        packedPathParam: String,
        cliPath: String,
        profile: String,
        cliVersion: String?,
        selectionFlags: XenolithSelectionFlags,
        scratch: Path,
        handoffEnabled: Boolean,
        readHandoffLine: () -> String?,
        emit: (EngineEvent) -> Unit,
        allowSkip: Boolean,
        cliRunner: XenolithCliRunner,
    ): ByteArray {
        Files.createDirectories(scratch)
        val unpackedPath = scratch.resolve(imageName).toAbsolutePath().normalize()
        Files.write(unpackedPath, native.bytes)

        fun validatePacked(bytes: ByteArray): ByteArray {
            if (native.platform != WINDOWS_PLATFORM) return bytes
            try {
                PackedImageValidation.validateWindowsPackedDll(bytes, native.bytes)
            } catch (error: Exception) {
                bytes.fill(0)
                native.bytes.fill(0)
                throw error
            }
            return bytes
        }

        if (cliPath.isNotEmpty()) {
            val packed = validatePacked(
                spawnXenolithPack(
                    cliPath = cliPath,
                    profile = profile,
                    cliVersion = cliVersion,
                    selectionFlags = selectionFlags,
                    unpackedPath = unpackedPath,
                    scratch = scratch,
                    emit = emit,
                    cliRunner = cliRunner,
                ),
            )
            recordPackerObservation(native.platform, PACKER_SOURCE_XENOLITH_CLI, profile, cliVersion, packed)
            return packed
        }

        if (packedPathParam.isNotEmpty()) {
            val packed = validatePacked(readPackedFile(Path.of(packedPathParam), platformLabel = native.platform))
            recordPackerObservation(native.platform, PACKER_SOURCE_PACKED_PATH, "", null, packed)
            return packed
        }

        if (handoffEnabled) {
            emit(
                EngineEvent(
                    level = "info",
                    type = "need-pack",
                    message = "Pack $imageName externally, then provide the absolute packed path (or SKIP on Linux)",
                    progress = HANDOFF_PROGRESS,
                    outPath = unpackedPath.toString(),
                ),
            )
            val line = readHandoffLine()?.trim()
            if (line.isNullOrEmpty()) {
                throw IllegalStateException(
                    "nativeshroud handoff canceled or stdin closed while waiting for packed $imageName",
                )
            }
            if (allowSkip && line.equals(LINUX_SKIP, ignoreCase = true)) {
                return native.bytes
            }
            val packed = validatePacked(readPackedFile(Path.of(line), platformLabel = native.platform))
            recordPackerObservation(native.platform, PACKER_SOURCE_HANDOFF, "", null, packed)
            return packed
        }

        throw IllegalStateException(
            "nativeshroud is enabled but no cliPath/packedPath was provided; set cliPath/packedPath/packedPathLinux " +
                "or enable desktop handoff via $HANDOFF_ENV=1",
        )
    }

    private fun spawnXenolithPack(
        cliPath: String,
        profile: String,
        cliVersion: String?,
        selectionFlags: XenolithSelectionFlags,
        unpackedPath: Path,
        scratch: Path,
        emit: (EngineEvent) -> Unit,
        cliRunner: XenolithCliRunner,
    ): ByteArray {
        val cliFile = Path.of(cliPath).toAbsolutePath().normalize()
        if (!Files.isRegularFile(cliFile)) {
            throw IllegalStateException("nativeshroud xenolith cliPath does not exist: $cliFile")
        }
        val outputPath = scratch.resolve("$WINDOWS_IMAGE_NAME.xenolith-packed").toAbsolutePath().normalize()
        Files.deleteIfExists(outputPath)
        emit(
            EngineEvent(
                level = "info",
                type = "log",
                message = buildString {
                    append("Running Xenolith pack profile=").append(profile)
                    cliVersion?.let { append(" (").append(it).append(")") }
                },
                progress = HANDOFF_PROGRESS,
                outPath = null,
            ),
        )
        val result = cliRunner.run(
            cliPath = cliFile.toString(),
            args = xenolithPackArgs(unpackedPath, outputPath, profile, selectionFlags),
            timeoutMillis = CLI_TIMEOUT_MILLIS,
        )
        val diagnostics = result.output + "\n" + result.errorOutput
        if (result.timedOut) {
            throw IllegalStateException(
                "xenolith pack timed out after ${CLI_TIMEOUT_MILLIS / 60000} minutes: ${sanitize(tail(diagnostics))}",
            )
        }
        if (result.exitCode != 0) {
            throw IllegalStateException(
                "xenolith pack exited with code ${result.exitCode}: ${sanitize(tail(diagnostics))}",
            )
        }
        val packed = readPackedFile(outputPath, platformLabel = WINDOWS_PLATFORM)
        try {
            val report = parsePackReport(result.output)
            validatePackReport(report, profile, selectionFlags, Files.size(unpackedPath), packed.size.toLong())
            emit(
                EngineEvent(
                    level = "info",
                    type = "log",
                    message = buildString {
                        append("Xenolith packed $WINDOWS_IMAGE_NAME (").append(packed.size).append(" bytes")
                        append(", iat=").append(report["iat_mode"].asText())
                        append(", format=").append(report["format"].asText())
                        append(", gate=").append(report["debug_gate"].asInt())
                        report["imports_kept_reason"]?.asText()?.takeIf(String::isNotEmpty)?.let {
                            append(", imports-kept=").append(it)
                        }
                        report["vm_functions"]?.let { append(", vm-functions=").append(it.asInt()) }
                        report["coverage"]?.takeIf { it.isArray }?.let { coverage ->
                            append(", mixed-native=").append(coverage.count { it["bucket"]?.asText() == "mixed_native" })
                        }
                        report["constants_encrypted"]?.let { append(", constants-encrypted=").append(it.asInt()) }
                        report["runtime_decryption_window"]?.let { append(", decrypt-window=").append(it.asBoolean()) }
                        append(')')
                    },
                    progress = HANDOFF_PROGRESS,
                    outPath = null,
                ),
            )
            return packed
        } catch (error: Exception) {
            packed.fill(0)
            throw error
        }
    }

    private fun probeXenolithVersion(
        cliPath: String,
        emit: (EngineEvent) -> Unit,
        cliRunner: XenolithCliRunner,
    ): String? {
        val cliFile = Path.of(cliPath).toAbsolutePath().normalize()
        if (!Files.isRegularFile(cliFile)) {
            throw IllegalStateException("nativeshroud xenolith cliPath does not exist: $cliFile")
        }
        val result = cliRunner.run(cliFile.toString(), listOf("--version"), 30_000)
        if (result.timedOut || result.exitCode != 0) {
            emit(
                EngineEvent(
                    level = "warn",
                    type = "log",
                    message = "Xenolith version probe failed (exit=${result.exitCode}); continuing with pack",
                    progress = HANDOFF_PROGRESS,
                    outPath = null,
                ),
            )
            return null
        }
        val version = result.output.lineSequence().firstOrNull { it.isNotBlank() }?.trim()
        if (version != null) {
            emit(
                EngineEvent(
                    level = "info",
                    type = "log",
                    message = "Xenolith packer CLI: $version",
                    progress = HANDOFF_PROGRESS,
                    outPath = null,
                ),
            )
        }
        return version
    }

    private fun parsePackReport(output: String): JsonNode {
        val report = runCatching { jsonMapper.readTree(output) }.getOrNull()
        if (report == null || !report.isObject) {
            throw IllegalStateException("xenolith pack returned no valid JSON object report")
        }
        return report
    }

    private fun validatePackReport(
        report: JsonNode,
        profile: String,
        flags: XenolithSelectionFlags,
        inputBytes: Long,
        outputBytes: Long,
    ) {
        fun requireText(field: String, expected: String) {
            val value = report[field]
            check(value?.isTextual == true && value.textValue() == expected) {
                "xenolith pack report $field ${value ?: "missing"} does not match $expected"
            }
        }
        fun optionalText(field: String): String {
            val value = report[field]
            check(value?.isTextual == true) {
                "xenolith pack report $field ${value ?: "missing"} is not text"
            }
            return value.textValue()
        }
        fun requireNumber(field: String, expected: Long) {
            val value = report[field]
            check(value?.isIntegralNumber == true && value.canConvertToLong() && value.longValue() == expected) {
                "xenolith pack report $field ${value ?: "missing"} does not match $expected"
            }
        }
        fun requireFlag(field: String, expected: Boolean) {
            val value = report[field]
            check(value?.isBoolean == true && value.booleanValue() == expected) {
                "xenolith pack report $field ${value ?: "missing"} does not match $expected"
            }
        }

        val reportedProfile = report["profile"]
        check(reportedProfile?.isTextual == true && reportedProfile.textValue() == profile) {
            "xenolith pack report profile ${reportedProfile ?: "missing"} does not match requested profile $profile"
        }
        requireNumber("report_version", 1)
        requireNumber("debug_gate", 3)
        requireText("format", "pe64-dll")
        requireText("machine", "x86_64")
        requireText("backend", "pic-stub+xl-core")
        check(optionalText("iat_mode") in setOf("disk-import-directory", "hashed-resolve-writeback-iat")) {
            "xenolith pack report iat_mode is unsupported"
        }
        val importsKept = report["imports_kept"]
        check(importsKept?.isIntegralNumber == true && importsKept.canConvertToLong() && importsKept.longValue() >= 0) {
            "xenolith pack report imports_kept ${importsKept ?: "missing"} is invalid"
        }
        val importsKeptReason = optionalText("imports_kept_reason")
        check(importsKeptReason.isEmpty() || importsKeptReason in setOf(
            "tls-bootstrap-needs-loader-iat",
            "jni-abi-needs-loader-iat",
        )) {
            "xenolith pack report imports_kept_reason is unsupported"
        }
        if (importsKeptReason.isNotEmpty()) {
            check(importsKept.longValue() > 0 && optionalText("iat_mode") == "disk-import-directory") {
                "xenolith pack report IAT keep reason conflicts with the import disposition"
            }
        }
        requireNumber("input_bytes", inputBytes)
        requireNumber("output_bytes", outputBytes)
        requireFlag("strict_coverage", flags.strictCoverage)
        requireFlag("allow_native_fallback", flags.allowNativeFallback)
    }

    /** Mirrors the xenolith pack CLI surface: `pack IN -o OUT --profile P --json` plus
     *  the function-selection and G5 flags, only when explicitly set. */
    internal fun xenolithPackArgs(
        unpackedPath: Path,
        outputPath: Path,
        profile: String,
        flags: XenolithSelectionFlags,
    ): List<String> {
        val args = mutableListOf(
            "pack",
            unpackedPath.toString(),
            "-o",
            outputPath.toString(),
            "--profile",
            profile,
            "--json",
        )
        if (flags.vmExports.isNotEmpty()) {
            args.add("--vm-export")
            args.add(flags.vmExports.joinToString(","))
        }
        flags.selectRva.forEach { token ->
            args.add("--select-rva")
            args.add(token)
        }
        if (flags.selectFunction.isNotEmpty()) {
            args.add("--select-function")
            args.add(flags.selectFunction.joinToString(","))
        }
        if (flags.selectAll) args.add("--select-all")
        if (flags.strictCoverage) args.add("--strict-coverage")
        if (flags.allowNativeFallback) args.add("--allow-native-fallback")
        if (flags.lazyRegions) args.add("--lazy-regions")
        if (flags.protectImports) args.add("--protect-imports")
        if (flags.strictConstants) args.add("--strict-constants")
        if (flags.traceDiverge) args.add("--trace-diverge")
        return args
    }

    private fun parseXenolithSelectionFlags(params: Map<String, JsonNode>): XenolithSelectionFlags =
        XenolithSelectionFlags(
            vmExports = commaSplit(params["vmExports"]?.asText()),
            selectRva = commaSplit(params["selectRva"]?.asText()),
            selectFunction = commaSplit(params["selectFunction"]?.asText()),
            selectAll = params["selectAll"]?.asBoolean() == true,
            strictCoverage = params["strictCoverage"]?.asBoolean() == true,
            allowNativeFallback = params["allowNativeFallback"]?.asBoolean() == true,
            lazyRegions = params["lazyRegions"]?.asBoolean() == true,
            protectImports = params["protectImports"]?.asBoolean() == true,
            strictConstants = params["strictConstants"]?.asBoolean() == true,
            traceDiverge = params["traceDiverge"]?.asBoolean() == true,
        )

    /** Fail-fast mirrors of xenolith's own pack-time rejections, so an invalid
     *  combination is a named config error instead of a wasted CLI spawn. */
    private fun requireXenolithSelectionFlags(profile: String, flags: XenolithSelectionFlags) {
        require(flags.vmExports.isEmpty() || profile != "fast") {
            "nativeshroud vmExports is rejected by the xenolith fast profile; use standard/max or clear vmExports"
        }
        require(!(flags.strictCoverage && flags.allowNativeFallback)) {
            "nativeshroud strictCoverage and allowNativeFallback are mutually exclusive"
        }
        require(!flags.lazyRegions) {
            "nativeshroud lazyRegions is incompatible with the qp_ffi JNI host boot: the VEH wake cannot run under " +
                "the loader lock, so the packed DLL fails its initialization routine"
        }
        flags.vmExports.forEach { name ->
            require(!isJvmOrCrtAbiExportName(name)) {
                "nativeshroud vmExports name \"$name\" is a JVM/CRT ABI export; xenolith refuses to virtualize it"
            }
        }
    }

    /** Xenolith refuses these for --vm-export: DllMain, *crt*, leading underscore,
     *  JNI_OnLoad/JNI_OnUnload, Java_*, qp_r1_*. */
    private fun isJvmOrCrtAbiExportName(name: String): Boolean {
        val trimmed = name.trim()
        val lower = trimmed.lowercase()
        return trimmed.isEmpty() ||
            lower == "jni_onload" ||
            lower == "jni_onunload" ||
            lower == "dllmain" ||
            lower.startsWith("java_") ||
            lower.startsWith("qp_r1_") ||
            trimmed.startsWith("_") ||
            lower.contains("crt")
    }

    private fun commaSplit(value: String?): List<String> =
        value.orEmpty().split(',', ';').map { it.trim() }.filter { it.isNotEmpty() }

    private fun requireXenolithProfile(profile: String) {
        require(profile in XENOLITH_PROFILES) {
            "nativeshroud profile must be one of ${XENOLITH_PROFILES.joinToString("/")} but was \"$profile\""
        }
    }

    private fun recordPackerObservation(
        platform: String,
        source: String,
        profile: String,
        cliVersion: String?,
        packedBytes: ByteArray,
    ) {
        val context = currentQpBuildContextOrNull() ?: return
        context.productionBuildEvidence.recordPacker(
            CandidateProductionBuildEvidence.PackerObservation(
                platform = platform,
                source = source,
                profile = profile,
                cliVersion = cliVersion.orEmpty(),
                packedSha256 = CandidateProductionBuildEvidence.sha256Hex(packedBytes),
            ),
        )
    }

    private fun readPackedFile(path: Path, platformLabel: String): ByteArray {
        val absolute = path.toAbsolutePath().normalize()
        if (!Files.isRegularFile(absolute)) {
            throw IllegalStateException("nativeshroud packed path does not exist for $platformLabel: $absolute")
        }
        val packed = Files.readAllBytes(absolute)
        if (packed.isEmpty()) {
            throw IllegalStateException("nativeshroud packed path is empty for $platformLabel: $absolute")
        }
        if (platformLabel == WINDOWS_PLATFORM) {
            PackedImageValidation.validateWindowsPackedDll(packed)
        } else {
            PackedImageValidation.validateLinuxPackedSo(packed)
        }
        return packed
    }

    private fun readStdinLine(): String? {
        val reader = BufferedReader(InputStreamReader(System.`in`, StandardCharsets.UTF_8))
        return reader.readLine()
    }

    private fun tail(output: String): String = output.lineSequence().toList().takeLast(12).joinToString(" | ")

    private fun sanitize(value: String): String =
        value.replace(Regex("[0-9a-fA-F]{32,}"), "<redacted>").take(512)
}
