package io.github.hht0rro.javashroud

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Comparator
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Bounded executable contract coverage for the full native runtime benchmark
 * catalogue.
 *
 * The production CLI intentionally exposes the costly 100/1000/10000/100000
 * matrix. This test verifies those exact profiles and percentile ranks in the
 * native probe, while executing a one-sample, non-measured-warmup report in
 * both capability-gated and forced-software builds. It does not represent a
 * throughput claim and cannot close the production coverage/security gate.
 */
class NativeRuntimeBenchmarkMatrixContractTest {
    @Test
    fun bounded_matrix_contract_preserves_profiles_report_fields_and_crypto_path_parity() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the native benchmark matrix contract probe")
        assumeTrue(isWindows() || isLinux(), "the native benchmark matrix contract probe supports Windows and Linux")

        val sourceNativeDir = resolveSource("src/main/native")
        val benchmarkSource = resolveSource("src/test/native/native_runtime_benchmark.c")
        val probeSource = resolveSource("src/test/native/runtime_benchmark_matrix_contract_probe.c")
        val root = Files.createTempDirectory("javashroud-native-benchmark-matrix-contract-")
        try {
            val nativeDir = root.resolve("native")
            copyTree(sourceNativeDir, nativeDir)
            /* Zig 0.16's MinGW sysroot may omit this optional AVX10 header.
             * The benchmark only relies on capability-gated AES/PCLMUL paths;
             * keep the shim isolated to this copied test fixture. */
            Files.writeString(
                nativeDir.resolve("avx10_2satcvtintrin.h"),
                "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#endif\n",
                StandardCharsets.US_ASCII,
            )
            val benchmark = nativeDir.resolve("native_runtime_benchmark.c")
            val probe = nativeDir.resolve("runtime_benchmark_matrix_contract_probe.c")
            Files.copy(benchmarkSource, benchmark, StandardCopyOption.REPLACE_EXISTING)
            Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)

            val hardwareExecutable = root.resolve(executableName("benchmark_matrix_hardware"))
            val softwareExecutable = root.resolve(executableName("benchmark_matrix_software"))
            val hardwareCompile = runWithTransientZigRetry(
                compileCommand(checkNotNull(zig), nativeDir, probe, hardwareExecutable, forceSoftware = false),
                root,
                "compile-hardware",
            )
            assertEquals(0, hardwareCompile.exitCode, "hardware benchmark matrix contract probe must compile:\n${hardwareCompile.output}")
            val softwareCompile = runWithTransientZigRetry(
                compileCommand(checkNotNull(zig), nativeDir, probe, softwareExecutable, forceSoftware = true),
                root,
                "compile-software",
            )
            assertEquals(0, softwareCompile.exitCode, "software benchmark matrix contract probe must compile:\n${softwareCompile.output}")

            val hardwareRun = run(
                listOf(hardwareExecutable.toString()),
                root,
                "run-hardware",
                timeoutSeconds = 300L,
            )
            val softwareRun = run(
                listOf(softwareExecutable.toString()),
                root,
                "run-software",
                timeoutSeconds = 300L,
            )
            assertTrue(hardwareRun.completed, "hardware benchmark matrix contract probe timed out:\n${hardwareRun.output}")
            assertTrue(softwareRun.completed, "software benchmark matrix contract probe timed out:\n${softwareRun.output}")
            assertEquals(0, hardwareRun.exitCode, "hardware benchmark matrix contract probe failed:\n${hardwareRun.output}")
            assertEquals(0, softwareRun.exitCode, "software benchmark matrix contract probe failed:\n${softwareRun.output}")

            val hardware = contractFields(hardwareRun.output)
            val software = contractFields(softwareRun.output)
            assertContract(hardware, "hardware", hardwareRun.output)
            assertContract(software, "software", softwareRun.output)
            assertEquals("0", software["hardware_aes"], "forced-software probe exposed AES hardware capability:\n${softwareRun.output}")
            assertEquals("0", software["hardware_ghash"], "forced-software probe exposed GHASH hardware capability:\n${softwareRun.output}")
            assertEquals("0", software["hardware_crypto_path"], "forced-software probe selected a hardware crypto path:\n${softwareRun.output}")
            assertTrue(
                (software["software_crypto_path"]?.toLongOrNull() ?: 0L) > 0L,
                "forced-software probe did not report its software crypto path:\n${softwareRun.output}",
            )

            val hardwareAes = hardware["hardware_aes"]?.toIntOrNull() ?: error("missing hardware AES capability")
            val hardwarePath = hardware["hardware_crypto_path"]?.toLongOrNull() ?: error("missing hardware path counter")
            if (hardwareAes != 0) {
                assertTrue(hardwarePath > 0L, "AES capability was reported without hardware crypto dispatch:\n${hardwareRun.output}")
            } else {
                assertEquals(0L, hardwarePath, "hardware crypto dispatch occurred without AES capability:\n${hardwareRun.output}")
            }
            assertEquals(
                hardware["output_digest"],
                software["output_digest"],
                "hardware/software benchmark matrix aggregate output digest mismatch",
            )
            for (phase in COMPARABLE_PHASES) {
                assertEquals(
                    phaseFields(hardwareRun.output, phase)["output_digest"],
                    phaseFields(softwareRun.output, phase)["output_digest"],
                    "$phase hardware/software output digest mismatch",
                )
            }

            println(
                "native-benchmark-matrix-contract profiles=${hardware["profiles"]} warmup=${hardware["warmup"]} " +
                    "hardware_aes=$hardwareAes hardware_path=$hardwarePath " +
                    "software_path=${software["software_crypto_path"]} output_digest=${hardware["output_digest"]}",
            )
        } finally {
            deleteTree(root)
        }
    }

    private fun assertContract(fields: Map<String, String>, mode: String, output: String) {
        assertEquals("pass", fields["status"], "$mode contract probe did not pass:\n$output")
        assertEquals("100,1000,10000,100000", fields["profiles"], "$mode profile catalogue drifted:\n$output")
        assertEquals("3", fields["warmup"], "$mode probe did not use the bounded non-measured warmup:\n$output")
        assertEquals("1", fields["measured_samples"], "$mode probe did not use the bounded measured profile:\n$output")
        assertEquals("17", fields["phase_count"], "$mode probe did not validate every available phase:\n$output")
        assertEquals("3", fields["unsupported_phase_count"], "$mode probe did not preserve explicit unsupported production adapters:\n$output")
        assertTrue(
            fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true,
            "$mode contract probe did not emit a de-identified aggregate output digest:\n$output",
        )
        listOf("hardware_aes", "hardware_ghash").forEach { field ->
            assertTrue(
                fields[field]?.toIntOrNull()?.let { it == 0 || it == 1 } == true,
                "$mode contract probe emitted an invalid $field value:\n$output",
            )
        }
        listOf("hardware_crypto_path", "software_crypto_path").forEach { field ->
            assertTrue(
                fields[field]?.toLongOrNull()?.let { it >= 0L } == true,
                "$mode contract probe omitted $field:\n$output",
            )
        }
    }

    private fun contractFields(output: String): Map<String, String> {
        val prefix = "matrix_contract "
        val lines = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, lines.size, "expected exactly one benchmark matrix contract line:\n$output")
        return tokenFields(lines.single())
    }

    private fun phaseFields(output: String, phase: String): Map<String, String> {
        val prefix = "phase=$phase "
        val lines = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, lines.size, "expected exactly one $phase phase report:\n$output")
        return tokenFields(lines.single())
    }

    private fun tokenFields(line: String): Map<String, String> = line
        .split(' ')
        .mapNotNull { token ->
            val separator = token.indexOf('=')
            if (separator <= 0 || separator == token.lastIndex) null else token.substring(0, separator) to token.substring(separator + 1)
        }
        .toMap()

    private fun compileCommand(
        zig: String,
        nativeDir: Path,
        probe: Path,
        executable: Path,
        forceSoftware: Boolean,
    ): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-std=c11",
                "-O2",
                "-fwrapv",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
            ),
        )
        if (forceSoftware) add("-DJS_CRYPTO_FORCE_SOFTWARE=1")
        addAll(
            listOf(
                "-I", nativeDir.toString(),
                "-I", nativeDir.resolve("cross-compile").toString(),
                "-I", nativeDir.resolve("zstd").toString(),
                "-I", nativeDir.resolve("zstd/common").toString(),
                "-I", nativeDir.resolve("zstd/decompress").toString(),
                nativeDir.resolve("js_crypto.c").toString(),
                nativeDir.resolve("js_shell_crypto.c").toString(),
                probe.toString(),
                "-o", executable.toString(),
            ),
        )
        when {
            isWindows() -> add("-ladvapi32")
            isLinux() -> {
                add("-pthread")
                add("-Wl,-T,${nativeDir.resolve("js_protected_section_linux.ld")}")
                add("-ldl")
            }
        }
    }

    private fun runWithTransientZigRetry(command: List<String>, directory: Path, label: String): ProcessResult {
        var result = run(command, directory, "$label-0", timeoutSeconds = 300L, zigCache = directory.resolve("zig-cache-0"))
        for (attempt in 1..5) {
            if (result.completed && result.exitCode == 0 || !isTransientZigFailure(result.output)) break
            result = run(
                command,
                directory,
                "$label-$attempt",
                timeoutSeconds = 300L,
                zigCache = directory.resolve("zig-cache-$attempt"),
            )
        }
        return result
    }

    private fun run(
        command: List<String>,
        directory: Path,
        label: String,
        timeoutSeconds: Long,
        zigCache: Path? = null,
    ): ProcessResult {
        val outputFile = directory.resolve("$label.log")
        val builder = ProcessBuilder(command)
            .directory(directory.toFile())
            .redirectErrorStream(true)
            .redirectOutput(outputFile.toFile())
        zigCache?.let { cache ->
            builder.environment()["ZIG_GLOBAL_CACHE_DIR"] = cache.resolve("global").toString()
            builder.environment()["ZIG_LOCAL_CACHE_DIR"] = cache.resolve("local").toString()
        }
        val process = builder.start()
        val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly().waitFor(10L, TimeUnit.SECONDS)
        val output = Files.readString(outputFile, StandardCharsets.UTF_8)
        return ProcessResult(if (completed) process.exitValue() else 124, output, completed)
    }

    private fun copyTree(source: Path, target: Path) {
        Files.walk(source).use { paths ->
            paths.forEach { path ->
                val destination = target.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path)) {
                    Files.createDirectories(destination)
                } else {
                    Files.createDirectories(destination.parent)
                    Files.copy(path, destination, StandardCopyOption.REPLACE_EXISTING)
                }
            }
        }
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { path -> Files.deleteIfExists(path) }
        }
    }

    private fun findZig(): String? = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig").firstOrNull { candidate ->
        runCatching {
            val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
            process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(10L, TimeUnit.SECONDS) && process.exitValue() == 0
        }.getOrDefault(false)
    }

    private fun resolveSource(relative: String): Path {
        var current = Path.of("").toAbsolutePath().normalize()
        while (true) {
            val direct = current.resolve(relative)
            if (Files.isRegularFile(direct) || Files.isDirectory(direct)) return direct
            current = current.parent ?: error("unable to resolve source path: $relative")
        }
    }

    private fun isWindows(): Boolean = System.getProperty("os.name", "").lowercase().contains("win")

    private fun isLinux(): Boolean = System.getProperty("os.name", "").lowercase().contains("linux")

    private fun executableName(stem: String): String = if (isWindows()) "$stem.exe" else stem

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains("sub-compilation of mingw-w64") ||
            output.contains("unable to update cache: Unexpected") ||
            output.contains("error: Unexpected") ||
            (output.contains("unable to load '") && output.contains("': Unexpected"))

    private data class ProcessResult(val exitCode: Int, val output: String, val completed: Boolean)

    private companion object {
        val COMPARABLE_PHASES = listOf(
            "aes-gcm-128-kat",
            "aes-gcm-256-kat",
            "ghash-aad-authenticated-page-4k",
            "ghash-aad-authenticated-page-64k",
            "ghash-aad-authenticated-page-1m",
            "aes-ctr-128-4k",
            "aes-ctr-256-4k",
            "aes-ctr-128-64k",
            "aes-ctr-256-64k",
            "aes-ctr-128-1m",
            "aes-ctr-256-1m",
            "shell-payload-decode-4k",
            "shell-payload-decode-64k",
            "shell-payload-decode-1m",
            "resource-alias-lookup",
            "resource-commitment-lookup",
            "jni-method-class-lookup",
        )
    }
}
