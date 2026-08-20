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
 * Differential smoke coverage for the current multi-page crypto benchmark.
 *
 * The benchmark owns the authenticated 4 KiB, 64 KiB, and 1 MiB page fixtures
 * and exercises the same GCM/CTR entry points used by the runtime.  Compile
 * the fixture once with capability-gated dispatch and once with the
 * authoritative software path, then compare only its de-identified output
 * digests and security counters.  This deliberately does not treat the
 * standalone VM/resource adapter phases as production coverage.
 */
class NativeRuntimeMultiPageDifferentialTest {
    @Test
    fun multi_page_gcm_and_ctr_outputs_match_between_hardware_and_software_paths() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the multi-page benchmark")
        assumeTrue(isWindows() || isLinux(), "the multi-page benchmark supports Windows and Linux")

        val sourceNativeDir = resolveSource("src/main/native")
        val benchmarkSource = resolveSource("src/test/native/native_runtime_benchmark.c")
        val root = Files.createTempDirectory("javashroud-multi-page-differential-")
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
            val benchmark = nativeDir.resolve("native_runtime_benchmark.c")
            Files.copy(benchmarkSource, benchmark, StandardCopyOption.REPLACE_EXISTING)
            val hardwareExecutable = root.resolve(executableName("multi_page_hardware"))
            val softwareExecutable = root.resolve(executableName("multi_page_software"))

            val hardwareCompile = runWithTransientZigRetry(
                compileCommand(
                    zig = checkNotNull(zig),
                    nativeDir = nativeDir,
                    benchmark = benchmark,
                    executable = hardwareExecutable,
                    forceSoftware = false,
                ),
                root,
                "compile-hardware",
            )
            assertEquals(0, hardwareCompile.exitCode, "hardware multi-page benchmark must compile:\n${hardwareCompile.output}")

            val softwareCompile = runWithTransientZigRetry(
                compileCommand(
                    zig = checkNotNull(zig),
                    nativeDir = nativeDir,
                    benchmark = benchmark,
                    executable = softwareExecutable,
                    forceSoftware = true,
                ),
                root,
                "compile-software",
            )
            assertEquals(0, softwareCompile.exitCode, "software multi-page benchmark must compile:\n${softwareCompile.output}")

            /* A single measured sample keeps this differential gate bounded
             * while still traversing every 4 KiB/64 KiB/1 MiB page.  The
             * benchmark itself remains available for the full 100..100000
             * sample matrix. */
            val hardwareRun = run(
                listOf(hardwareExecutable.toString(), "1", "0"),
                root,
                "run-hardware",
                timeoutSeconds = 300L,
            )
            val softwareRun = run(
                listOf(softwareExecutable.toString(), "1", "0"),
                root,
                "run-software",
                timeoutSeconds = 300L,
            )
            assertTrue(hardwareRun.completed, "hardware multi-page benchmark timed out:\n${hardwareRun.output}")
            assertTrue(softwareRun.completed, "software multi-page benchmark timed out:\n${softwareRun.output}")

            val hardwareCapability = capabilityFields(hardwareRun.output)
            val softwareCapability = capabilityFields(softwareRun.output)
            val gcmKatNames = listOf(
                "aes-gcm-128-kat",
                "aes-gcm-256-kat",
            )
            val ghashPageNames = listOf(
                "ghash-aad-authenticated-page-4k",
                "ghash-aad-authenticated-page-64k",
                "ghash-aad-authenticated-page-1m",
            )
            val ctrPageNames = listOf(
                "aes-ctr-128-4k",
                "aes-ctr-128-64k",
                "aes-ctr-128-1m",
                "aes-ctr-256-4k",
                "aes-ctr-256-64k",
                "aes-ctr-256-1m",
            )
            val shellPageNames = listOf(
                "shell-payload-decode-4k",
                "shell-payload-decode-64k",
                "shell-payload-decode-1m",
            )
            val differentialPhaseNames = gcmKatNames + ghashPageNames + ctrPageNames + shellPageNames
            for (phaseName in differentialPhaseNames) {
                val hardware = phaseFields(hardwareRun.output, phaseName)
                val software = phaseFields(softwareRun.output, phaseName)
                assertPhase(hardware, phaseName, hardwareRun.output)
                assertPhase(software, phaseName, softwareRun.output)
                assertEquals(
                    hardware["output_digest"],
                    software["output_digest"],
                    "$phaseName hardware/software output digest mismatch",
                )
                assertSecureCounters(hardware, phaseName, hardwareRun.output)
                assertSecureCounters(software, phaseName, softwareRun.output)
                assertProtocolCounterParity(hardware, software, phaseName)
            }

            val hardwareAes = hardwareCapability["hardware_aes"]?.toIntOrNull() ?: 0
            val hardwareGhash = hardwareCapability["hardware_ghash"]?.toIntOrNull() ?: 0
            assertEquals("0", softwareCapability["hardware_aes"], "forced-software benchmark reported AES hardware capability")
            assertEquals("0", softwareCapability["hardware_ghash"], "forced-software benchmark reported GHASH hardware capability")
            assertEquals(
                "capability-only",
                hardwareCapability["active_ghash_path"],
                "benchmark must not present the AES schedule counter as GHASH path evidence",
            )

            val hardwareCtrPath = ctrPageNames
                .map { phaseFields(hardwareRun.output, it)["hardware_crypto_path"]?.toLongOrNull() ?: 0L }
                .sum()
            val softwareCtrPath = ctrPageNames
                .map { phaseFields(softwareRun.output, it)["software_crypto_path"]?.toLongOrNull() ?: 0L }
                .sum()
            /* `hardware_crypto_path` counts AES schedule dispatch. GHASH's
             * backend is reported separately by the capability line, so use
             * GCM phase block parity to prove that both profiles processed the
             * same AAD/ciphertext/length GHASH inputs without claiming a
             * nonexistent per-multiplication hardware counter. */
            val hardwareGhashBlocks = (gcmKatNames + ghashPageNames)
                .map { phaseFields(hardwareRun.output, it)["ghash_block_count"]?.toLongOrNull() ?: 0L }
                .sum()
            val softwareGhashBlocks = (gcmKatNames + ghashPageNames)
                .map { phaseFields(softwareRun.output, it)["ghash_block_count"]?.toLongOrNull() ?: 0L }
                .sum()
            assertTrue(softwareCtrPath > 0L, "forced-software benchmark did not use software AES-CTR")
            assertTrue(hardwareGhashBlocks > 0L, "hardware profile did not process GCM GHASH blocks")
            assertTrue(softwareGhashBlocks > 0L, "software profile did not process GCM GHASH blocks")
            assertEquals(
                hardwareGhashBlocks,
                softwareGhashBlocks,
                "hardware/software GCM phases must process the same GHASH block count",
            )
            if (hardwareAes != 0) {
                assertTrue(hardwareCtrPath > 0L, "hardware AES capability was reported but no AES-CTR phase was used")
            } else {
                assertEquals(0L, hardwareCtrPath, "AES-CTR selected a hardware path without AES capability")
            }

            println(
                "multi-page-differential capability_hardware_aes=$hardwareAes capability_hardware_ghash=$hardwareGhash " +
                    "hardware_ctr_schedule_count=$hardwareCtrPath software_ctr_schedule_count=$softwareCtrPath " +
                    "gcm_ghash_blocks=$hardwareGhashBlocks phase_count=${differentialPhaseNames.size}",
            )
        } finally {
            deleteTree(root)
        }
    }

    private fun assertPhase(fields: Map<String, String>, name: String, output: String) {
        assertEquals("pass", fields["phase_status"], "$name did not pass:\n$output")
        assertEquals("1", fields["samples"], "$name did not use the bounded differential profile:\n$output")
        assertEquals("0", fields["warmup"], "$name unexpectedly included warmup samples:\n$output")
        assertTrue(fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true, "$name digest missing:\n$output")
    }

    private fun assertSecureCounters(fields: Map<String, String>, name: String, output: String) {
        assertTrue((fields["aes_block_count"]?.toLongOrNull() ?: 0L) > 0L, "$name did not process AES blocks:\n$output")
        listOf(
            "auth_failure_count",
            "exception_count",
            "native_exception_count",
            "wipe_failure_count",
            "plaintext_persistence_bytes",
            "fallback_count",
            "legacy_path_hits",
            "security_checks_skipped",
        ).forEach { field ->
            assertEquals("0", fields[field], "$name must keep $field at zero:\n$output")
        }
        assertTrue((fields["wipe_count"]?.toLongOrNull() ?: 0L) > 0L, "$name did not wipe transient state:\n$output")
        if (name.startsWith("aes-gcm-") || name.startsWith("ghash-aad-authenticated-page-")) {
            assertTrue((fields["ghash_block_count"]?.toLongOrNull() ?: 0L) > 0L, "$name did not process GHASH blocks:\n$output")
            assertTrue((fields["auth_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted auth check:\n$output")
            assertTrue((fields["tag_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted tag check:\n$output")
            assertTrue((fields["length_check_count"]?.toLongOrNull() ?: 0L) >= 2L, "$name omitted length checks:\n$output")
            assertTrue((fields["structure_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted structure check:\n$output")
        }
        if (name.startsWith("shell-payload-decode-")) {
            assertTrue((fields["auth_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted shell auth check:\n$output")
            assertTrue((fields["tag_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted shell tag check:\n$output")
            assertTrue((fields["length_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted shell length check:\n$output")
            assertTrue((fields["structure_check_count"]?.toLongOrNull() ?: 0L) >= 1L, "$name omitted shell structure check:\n$output")
        }
    }

    private fun assertProtocolCounterParity(
        hardware: Map<String, String>,
        software: Map<String, String>,
        phaseName: String,
    ) {
        /* Wipe work remains mandatory and is checked above, but its count is
         * intentionally excluded: AES/GHASH implementations may use different
         * internal scratch layouts. All listed fields describe externally
         * required protocol/security decisions and must be identical for one
         * operation on the same input. */
        listOf(
            "auth_check_count",
            "auth_failure_count",
            "digest_check_count",
            "tag_check_count",
            "length_check_count",
            "structure_check_count",
            "jni_abi_check_count",
            "wipe_failure_count",
            "plaintext_persistence_bytes",
            "fallback_count",
            "legacy_path_hits",
            "exception_count",
            "native_exception_count",
            "security_checks_skipped",
        ).forEach { field ->
            val hardwareValue = hardware[field] ?: error("$phaseName hardware profile did not emit $field")
            val softwareValue = software[field] ?: error("$phaseName software profile did not emit $field")
            assertEquals(
                hardwareValue,
                softwareValue,
                "$phaseName hardware/software security counter mismatch for $field",
            )
        }
    }

    private fun phaseFields(output: String, name: String): Map<String, String> {
        val prefix = "phase=$name "
        val matches = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, matches.size, "expected exactly one $name phase line:\n$output")
        return matches.single()
            .split(' ')
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0 || separator == token.lastIndex) null
                else token.substring(0, separator) to token.substring(separator + 1)
            }
            .toMap()
    }

    private fun capabilityFields(output: String): Map<String, String> {
        val line = output.lineSequence().singleOrNull { it.startsWith("capability ") }
            ?: error("multi-page benchmark did not emit a capability line:\n$output")
        return line.split(' ')
            .drop(1)
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0 || separator == token.lastIndex) null
                else token.substring(0, separator) to token.substring(separator + 1)
            }
            .toMap()
    }

    private fun compileCommand(
        zig: String,
        nativeDir: Path,
        benchmark: Path,
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
                "-DJS_RUNTIME_BENCH_MAIN=1",
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
                benchmark.toString(),
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

    private fun run(
        command: List<String>,
        directory: Path,
        label: String,
        timeoutSeconds: Long,
    ): ProcessResult {
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
