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
 * Differential authentication gate for the three synthetic page sizes used by
 * the native runtime benchmark.  The probe exercises successful opens plus
 * tag/AAD/nonce/truncation/key failures and verifies that failed opens wipe the
 * supplied output.  It is deliberately a fixture-only crypto gate: it does not
 * claim a live AKEN catalog or JNI session.
 */
class NativeRuntimeMultiPageAuthDifferentialTest {
    @Test
    fun authenticated_page_rejections_match_between_hardware_and_software_paths() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the authenticated-page probe")
        assumeTrue(isWindows() || isLinux(), "the authenticated-page probe supports Windows and Linux")

        val sourceNativeDir = resolveSource("src/main/native")
        val probeSource = resolveSource("src/test/native/aken_page_auth_differential_probe.c")
        val benchmarkSource = resolveSource("src/test/native/native_runtime_benchmark.c")
        val root = Files.createTempDirectory("javashroud-aken-page-auth-differential-")
        try {
            val nativeDir = root.resolve("native")
            copyTree(sourceNativeDir, nativeDir)
            Files.writeString(
                nativeDir.resolve("avx10_2satcvtintrin.h"),
                "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n" +
                    "#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n" +
                    "#endif\n",
                StandardCharsets.US_ASCII,
            )
            Files.copy(benchmarkSource, nativeDir.resolve("native_runtime_benchmark.c"), StandardCopyOption.REPLACE_EXISTING)
            Files.copy(probeSource, nativeDir.resolve("aken_page_auth_differential_probe.c"), StandardCopyOption.REPLACE_EXISTING)

            val hardwareExecutable = root.resolve(executableName("aken_page_auth_hardware"))
            val softwareExecutable = root.resolve(executableName("aken_page_auth_software"))
            val unsupportedCpuExecutable = root.resolve(executableName("aken_page_auth_unsupported_cpu"))
            val executables = listOf(
                "hardware" to Pair(hardwareExecutable, compileCommand(checkNotNull(zig), nativeDir, hardwareExecutable)),
                "software" to Pair(softwareExecutable, compileCommand(checkNotNull(zig), nativeDir, softwareExecutable, forceSoftware = true)),
                "unsupported-cpu" to Pair(unsupportedCpuExecutable, compileCommand(checkNotNull(zig), nativeDir, unsupportedCpuExecutable, forceUnsupportedCpu = true)),
            )

            val runs = executables.associate { (label, pair) ->
                val (executable, command) = pair
                val compile = runWithTransientZigRetry(command, root, "compile-$label")
                assertEquals(0, compile.exitCode, "$label authenticated-page probe must compile:\n${compile.output}")
                label to run(listOf(executable.toString()), root, "run-$label", timeoutSeconds = 300L).also {
                    assertTrue(it.completed, "$label authenticated-page probe timed out:\n${it.output}")
                    assertEquals(0, it.exitCode, "$label authenticated-page probe must pass:\n${it.output}")
                }
            }

            val hardware = parseLine(runs.getValue("hardware").output)
            val software = parseLine(runs.getValue("software").output)
            val unsupported = parseLine(runs.getValue("unsupported-cpu").output)
            assertEquals("pass", hardware["status"])
            assertEquals("pass", software["status"])
            assertEquals("pass", unsupported["status"])
            for (fields in listOf(hardware, software, unsupported)) {
                assertEquals("3", fields["page_count"])
                assertEquals("18", fields["tamper_cases"])
                assertEquals("3", fields["cross_page_replay_cases"])
                assertEquals("2", fields["scalar_lane_cases"])
                assertTrue((fields["auth_check_count"]?.toLongOrNull() ?: 0L) >= 23L)
                assertTrue((fields["auth_failure_count"]?.toLongOrNull() ?: 0L) >= 19L)
                assertTrue((fields["tag_check_count"]?.toLongOrNull() ?: 0L) >= 20L)
                assertTrue((fields["length_check_count"]?.toLongOrNull() ?: 0L) >= 23L)
                assertTrue((fields["structure_check_count"]?.toLongOrNull() ?: 0L) >= 23L)
                assertTrue((fields["aes_block_count"]?.toLongOrNull() ?: 0L) > 0L)
                assertTrue((fields["ghash_block_count"]?.toLongOrNull() ?: 0L) > 0L)
                assertTrue((fields["wipe_count"]?.toLongOrNull() ?: 0L) > 0L)
                listOf(
                    "wipe_failure_count",
                    "security_checks_skipped",
                    "fallback_count",
                    "legacy_path_hits",
                    "plaintext_persistence_bytes",
                    "exception_count",
                ).forEach { field -> assertEquals("0", fields[field], "$field must remain zero") }
                assertTrue(fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true)
            }
            assertEquals(hardware["output_digest"], software["output_digest"], "hardware/software tamper digest mismatch")
            assertEquals(software["output_digest"], unsupported["output_digest"], "software/unsupported tamper digest mismatch")
            assertEquals("0", software["hardware_aes"])
            assertEquals("0", software["hardware_ghash"])
            assertEquals("0", unsupported["hardware_aes"])
            assertEquals("0", unsupported["hardware_ghash"])
            assertTrue((software["software_crypto_path"]?.toLongOrNull() ?: 0L) > 0L)
            assertTrue((unsupported["software_crypto_path"]?.toLongOrNull() ?: 0L) > 0L)
            assertProtocolCounterParity(hardware, software)
            assertProtocolCounterParity(software, unsupported)
            println(
                "aken-page-auth-differential hardware_aes=${hardware["hardware_aes"]} " +
                    "hardware_ghash=${hardware["hardware_ghash"]} auth_failures=${hardware["auth_failure_count"]} " +
                    "output_digest=${hardware["output_digest"]}",
            )
        } finally {
            deleteTree(root)
        }
    }

    private fun assertProtocolCounterParity(left: Map<String, String>, right: Map<String, String>) {
        listOf(
            "auth_check_count",
            "auth_failure_count",
            "tag_check_count",
            "length_check_count",
            "structure_check_count",
            "wipe_failure_count",
            "security_checks_skipped",
            "fallback_count",
            "legacy_path_hits",
            "plaintext_persistence_bytes",
            "exception_count",
        ).forEach { field -> assertEquals(left[field], right[field], "counter mismatch for $field") }
    }

    private fun parseLine(output: String): Map<String, String> {
        val line = output.lineSequence().singleOrNull { it.startsWith("aken_page_auth_differential ") }
            ?: error("authenticated-page probe did not emit a sanitized result line:\n$output")
        return line.split(' ').drop(1).mapNotNull { token ->
            val separator = token.indexOf('=')
            if (separator <= 0 || separator == token.lastIndex) null
            else token.substring(0, separator) to token.substring(separator + 1)
        }.toMap()
    }

    private fun compileCommand(
        zig: String,
        nativeDir: Path,
        executable: Path,
        forceSoftware: Boolean = false,
        forceUnsupportedCpu: Boolean = false,
    ): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-std=c11",
                "-O2",
                "-fwrapv",
                "-fno-exceptions",
                "-fvisibility=hidden",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
            ),
        )
        if (forceSoftware) add("-DJS_CRYPTO_FORCE_SOFTWARE=1")
        if (forceUnsupportedCpu) add("-DJS_CRYPTO_FORCE_UNSUPPORTED_CPU=1")
        addAll(
            listOf(
                "-I", nativeDir.toString(),
                "-I", nativeDir.resolve("cross-compile").toString(),
                "-I", nativeDir.resolve("zstd").toString(),
                "-I", nativeDir.resolve("zstd/common").toString(),
                "-I", nativeDir.resolve("zstd/decompress").toString(),
                nativeDir.resolve("js_crypto.c").toString(),
                nativeDir.resolve("js_shell_crypto.c").toString(),
                nativeDir.resolve("aken_page_auth_differential_probe.c").toString(),
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
        var result = run(command, directory, "$label-0", timeoutSeconds = 300L)
        for (attempt in 1..10) {
            if (result.completed && result.exitCode == 0 || !isTransientZigFailure(result.output)) break
            result = run(command, directory, "$label-$attempt", timeoutSeconds = 300L)
        }
        return result
    }

    private fun run(command: List<String>, directory: Path, label: String, timeoutSeconds: Long): ProcessResult {
        val outputFile = directory.resolve("$label.log")
        val process = ProcessBuilder(command)
            .directory(directory.toFile())
            .redirectErrorStream(true)
            .redirectOutput(outputFile.toFile())
            .start()
        val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly().waitFor(10L, TimeUnit.SECONDS)
        val output = Files.readString(outputFile, StandardCharsets.UTF_8)
        return ProcessResult(if (completed) process.exitValue() else 124, output, completed)
    }

    private fun findZig(): String? = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig")
        .firstOrNull { candidate ->
            runCatching {
                val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
                process.inputStream.bufferedReader().use { it.readText() }
                process.waitFor(10L, TimeUnit.SECONDS) && process.exitValue() == 0
            }.getOrDefault(false)
        }

    private fun isWindows(): Boolean = System.getProperty("os.name", "").lowercase().contains("win")

    private fun isLinux(): Boolean = System.getProperty("os.name", "").lowercase().contains("linux")

    private fun executableName(stem: String): String = if (isWindows()) "$stem.exe" else stem

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains("unable to update cache: Unexpected") ||
            output.contains("error: Unexpected") ||
            (output.contains("unable to load '") && output.contains("': Unexpected"))

    private fun resolveSource(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val direct = current.resolve(relative)
            if (Files.exists(direct)) return direct
            val nested = current.resolve("core-engine").resolve(relative)
            if (Files.exists(nested)) return nested
            current = current.parent ?: error("Unable to locate $relative")
        }
    }

    private fun copyTree(source: Path, target: Path) {
        Files.walk(source).use { paths ->
            paths.forEach { path ->
                val destination = target.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path)) Files.createDirectories(destination)
                else {
                    Files.createDirectories(destination.parent)
                    Files.copy(path, destination, StandardCopyOption.REPLACE_EXISTING)
                }
            }
        }
    }

    private fun deleteTree(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private data class ProcessResult(val exitCode: Int, val output: String, val completed: Boolean = true)
}
