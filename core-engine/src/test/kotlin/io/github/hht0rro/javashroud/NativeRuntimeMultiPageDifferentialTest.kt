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
            val unsupportedCpuExecutable = root.resolve(executableName("multi_page_unsupported_cpu"))

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

            val unsupportedCpuCompile = runWithTransientZigRetry(
                compileCommand(
                    zig = checkNotNull(zig),
                    nativeDir = nativeDir,
                    benchmark = benchmark,
                    executable = unsupportedCpuExecutable,
                    forceSoftware = false,
                    forceUnsupportedCpu = true,
                ),
                root,
                "compile-unsupported-cpu",
            )
            assertEquals(0, unsupportedCpuCompile.exitCode, "unsupported-CPU multi-page benchmark must compile:\n${unsupportedCpuCompile.output}")

            /* A single measured sample keeps this differential gate bounded
             * while still traversing every 4 KiB/64 KiB/1 MiB page.  The
             * benchmark itself remains available for the full 100..100000
             * sample matrix. */
            /* First obtain a same-profile software reference without a baseline.
             * The expected security-blocked result is intentional: it proves
             * that an unbound differential run cannot be accepted.  The
             * aggregate digest is then bound into a fixed, non-derived
             * security floor for all three profiles below. */
            val softwareReferenceRun = run(
                listOf(softwareExecutable.toString(), "1", "0"),
                root,
                "run-software-reference",
                timeoutSeconds = 300L,
            )
            assertTrue(softwareReferenceRun.completed, "software reference benchmark timed out:\n${softwareReferenceRun.output}")
            assertEquals(1, softwareReferenceRun.exitCode, "software reference must remain unaccepted without a baseline:\n${softwareReferenceRun.output}")
            val referenceSecurity = reportFields(softwareReferenceRun.output, "security_gate ", "software reference")
            assertEquals("security-blocked", referenceSecurity["status"], "software reference without a baseline must be blocked")
            assertEquals("baseline-missing", referenceSecurity["reason"], "software reference must identify the missing baseline")
            val softwareReferenceMetrics = metricsFields(softwareReferenceRun.output, "software reference")
            val softwareReferenceDigest = softwareReferenceMetrics["output_digest"]
                ?: error("software reference benchmark did not emit aggregate output digest:\n${softwareReferenceRun.output}")
            assertTrue(softwareReferenceDigest.matches(Regex("[0-9a-f]{16}")), "software reference digest is malformed: $softwareReferenceDigest")
            val baselineFile = root.resolve("multi-page-security-baseline.txt")
            Files.writeString(
                baselineFile,
                """
                    # Fixed fixture floor; never derive security minima from the candidate run.
                    auth_check_count=8
                    digest_check_count=0
                    tag_check_count=8
                    length_check_count=13
                    structure_check_count=8
                    jni_abi_check_count=0
                    wipe_count=14
                    differential_output_digest=$softwareReferenceDigest
                """.trimIndent() + "\n",
                StandardCharsets.US_ASCII,
            )
            val hardwareRun = run(
                listOf(
                    hardwareExecutable.toString(), "1", "0",
                    "--baseline", baselineFile.toString(),
                    "--differential-output-digest", softwareReferenceDigest,
                ),
                root,
                "run-hardware",
                timeoutSeconds = 300L,
            )
            val softwareRun = run(
                listOf(
                    softwareExecutable.toString(), "1", "0",
                    "--baseline", baselineFile.toString(),
                    "--differential-output-digest", softwareReferenceDigest,
                ),
                root,
                "run-software",
                timeoutSeconds = 300L,
            )
            val unsupportedCpuRun = run(
                listOf(
                    unsupportedCpuExecutable.toString(), "1", "0",
                    "--baseline", baselineFile.toString(),
                    "--differential-output-digest", softwareReferenceDigest,
                ),
                root,
                "run-unsupported-cpu",
                timeoutSeconds = 300L,
            )
            assertRuntimeGate(hardwareRun, "hardware", softwareReferenceDigest)
            assertRuntimeGate(softwareRun, "software", softwareReferenceDigest)
            assertRuntimeGate(unsupportedCpuRun, "unsupported-CPU", softwareReferenceDigest)

            val hardwareCapability = capabilityFields(hardwareRun.output)
            val softwareCapability = capabilityFields(softwareRun.output)
            val unsupportedCpuCapability = capabilityFields(unsupportedCpuRun.output)
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
                val unsupportedCpu = phaseFields(unsupportedCpuRun.output, phaseName)
                assertPhase(hardware, phaseName, hardwareRun.output)
                assertPhase(software, phaseName, softwareRun.output)
                assertPhase(unsupportedCpu, phaseName, unsupportedCpuRun.output)
                assertEquals(
                    hardware["output_digest"],
                    software["output_digest"],
                    "$phaseName hardware/software output digest mismatch",
                )
                assertEquals(
                    software["output_digest"],
                    unsupportedCpu["output_digest"],
                    "$phaseName software/unsupported-CPU output digest mismatch",
                )
                assertSecureCounters(hardware, phaseName, hardwareRun.output)
                assertSecureCounters(software, phaseName, softwareRun.output)
                assertSecureCounters(unsupportedCpu, phaseName, unsupportedCpuRun.output)
                assertProtocolCounterParity(hardware, software, phaseName)
                assertProtocolCounterParity(software, unsupportedCpu, phaseName)
            }

            val hardwareAes = hardwareCapability["hardware_aes"]?.toIntOrNull() ?: 0
            val hardwareGhash = hardwareCapability["hardware_ghash"]?.toIntOrNull() ?: 0
            assertEquals("0", softwareCapability["hardware_aes"], "forced-software benchmark reported AES hardware capability")
            assertEquals("0", softwareCapability["hardware_ghash"], "forced-software benchmark reported GHASH hardware capability")
            assertEquals("0", unsupportedCpuCapability["hardware_aes"], "unsupported-CPU model reported AES hardware capability")
            assertEquals("0", unsupportedCpuCapability["hardware_ghash"], "unsupported-CPU model reported GHASH hardware capability")
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
            val unsupportedCpuCtrPath = ctrPageNames
                .map { phaseFields(unsupportedCpuRun.output, it)["software_crypto_path"]?.toLongOrNull() ?: 0L }
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
            assertTrue(unsupportedCpuCtrPath > 0L, "unsupported-CPU benchmark did not use software AES-CTR")
            assertTrue(hardwareGhashBlocks > 0L, "hardware profile did not process GCM GHASH blocks")
            assertTrue(softwareGhashBlocks > 0L, "software profile did not process GCM GHASH blocks")
            assertEquals(
                hardwareGhashBlocks,
                softwareGhashBlocks,
                "hardware/software GCM phases must process the same GHASH block count",
            )
            val unsupportedCpuGhashBlocks = (gcmKatNames + ghashPageNames)
                .map { phaseFields(unsupportedCpuRun.output, it)["ghash_block_count"]?.toLongOrNull() ?: 0L }
                .sum()
            assertEquals(
                softwareGhashBlocks,
                unsupportedCpuGhashBlocks,
                "software/unsupported-CPU GCM phases must process the same GHASH block count",
            )
            if (hardwareAes != 0) {
                assertTrue(hardwareCtrPath > 0L, "hardware AES capability was reported but no AES-CTR phase was used")
            } else {
                assertEquals(0L, hardwareCtrPath, "AES-CTR selected a hardware path without AES capability")
            }

            println(
                "multi-page-differential capability_hardware_aes=$hardwareAes capability_hardware_ghash=$hardwareGhash " +
                    "hardware_ctr_schedule_count=$hardwareCtrPath software_ctr_schedule_count=$softwareCtrPath " +
                    "unsupported_cpu_software_ctr_schedule_count=$unsupportedCpuCtrPath " +
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

    private fun assertRuntimeGate(result: ProcessResult, label: String, expectedDigest: String) {
        assertTrue(result.completed, "$label multi-page benchmark timed out:\n" + result.output)
        /* The standalone fixture intentionally reports coverage-incomplete for
         * the live-JNI VM phases, so its process status is non-zero even when
         * the security gate passes.  Check both signals instead of treating a
         * completed process as success. */
        assertEquals(1, result.exitCode, "$label benchmark must signal coverage-incomplete:\n" + result.output)
        val metrics = metricsFields(result.output, label)
        assertEquals(expectedDigest, metrics["output_digest"], "$label aggregate output digest mismatch")

        val baseline = reportFields(result.output, "baseline_security ", label)
        assertEquals("valid", baseline["status"], "$label baseline security record must be valid")
        assertEquals("1", baseline["supplied"], "$label baseline security record was not supplied")
        assertEquals("match", baseline["differential_status"], "$label differential baseline did not match")
        assertEquals("met", baseline["baseline_floor_status"], "$label security baseline floor was not met")

        val coverage = reportFields(result.output, "coverage_gate ", label)
        assertEquals("coverage-incomplete", coverage["status"], "$label standalone coverage must remain explicit")

        val security = reportFields(result.output, "security_gate ", label)
        assertEquals("pass", security["status"], "$label security gate must pass")
        assertEquals("pass", security["reason"], "$label security gate reason must be pass")
        listOf(
            "auth_failure_count",
            "exception_count",
            "fallback_count",
            "legacy_path_hits",
            "wipe_failure_count",
            "plaintext_persistence_bytes",
            "security_checks_skipped",
        ).forEach { field ->
            assertEquals("0", security[field], "$label security gate must keep $field at zero")
        }

        val candidate = reportFields(result.output, "benchmark_gate_candidate ", label)
        assertEquals("coverage-incomplete", candidate["status"], "$label benchmark candidate status must expose incomplete coverage")
        assertEquals("match", candidate["differential_status"], "$label benchmark candidate differential status must match")
        val benchmarkResult = reportFields(result.output, "benchmark_result ", label)
        assertEquals("coverage-incomplete", benchmarkResult["status"], "$label benchmark result must expose incomplete coverage")
    }

    private fun metricsFields(output: String, label: String): Map<String, String> =
        reportFields(output, "metrics ", label)

    private fun reportFields(output: String, prefix: String, label: String): Map<String, String> {
        val matches = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, matches.size, "$label did not emit exactly one $prefix line:\n$output")
        return matches.single()
            .removePrefix(prefix)
            .split(' ')
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0 || separator == token.lastIndex) null
                else token.substring(0, separator) to token.substring(separator + 1)
            }
            .toMap()
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
        forceUnsupportedCpu: Boolean = false,
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
