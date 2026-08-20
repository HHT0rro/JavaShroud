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
 * Binds the benchmark's resource phases to the real native runtime instead of
 * the standalone synthetic table.  The C probe installs a bounded current JSRP
 * commitment and resolves it through js_vm_resource.c's immutable indexes;
 * its output contains only de-identified counters and phase digests.
 */
class NativeRuntimeResourceProductionBenchmarkTest {
    @Test
    fun production_resource_benchmark_uses_native_immutable_indexes_and_current_jsrp_verifier() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the production resource benchmark probe")
        assumeTrue(isWindows() || isLinux(), "the production resource benchmark probe supports Windows and Linux")

        val jdkHome = findJdkHome()
        val platformInclude = jdkHome?.resolve("include")?.resolve(jniPlatformDirectory())
        assumeTrue(
            jdkHome != null && platformInclude != null && Files.isRegularFile(platformInclude.resolve("jni_md.h")),
            "JDK JNI headers are required to compile the full production runtime probe",
        )

        val sourceNativeDir = resolveSource("src/main/native/js_vm_resource.c").parent
        val benchmarkSource = resolveSource("src/test/native/native_runtime_benchmark.c")
        val probeSource = resolveSource("src/test/native/runtime_resource_production_benchmark_probe.c")
        val root = Files.createTempDirectory("javashroud-production-resource-benchmark-")
        try {
            val scenario = Files.createDirectories(root.resolve("resource-production"))
            val nativeDir = scenario.resolve("native")
            copyTree(sourceNativeDir, nativeDir)
            /* Zig 0.16's bundled immintrin.h references an optional AVX10
             * header that is absent from the MinGW sysroot.  The runtime only
             * needs AES-NI/PCLMUL here; keep this compatibility shim inside the
             * isolated fixture copy so the repository and ABI are untouched. */
            Files.writeString(
                nativeDir.resolve("avx10_2satcvtintrin.h"),
                "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#endif\n",
                StandardCharsets.US_ASCII,
            )
            Files.copy(benchmarkSource, nativeDir.resolve("native_runtime_benchmark.c"), StandardCopyOption.REPLACE_EXISTING)
            val probe = nativeDir.resolve("runtime_resource_production_benchmark_probe.c")
            Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
            val executable = scenario.resolve(
                if (isWindows()) "runtime_resource_production_benchmark_probe.exe" else "runtime_resource_production_benchmark_probe",
            )

            val compile = runWithTransientZigRetry(
                command = compileCommand(
                    zig = checkNotNull(zig),
                    nativeDir = nativeDir,
                    probe = probe,
                    executable = executable,
                    jdkHome = checkNotNull(jdkHome),
                ),
                directory = scenario,
                label = "compile",
            )
            assertEquals(0, compile.exitCode, "production resource benchmark probe must compile:\n${compile.output}")

            for (samples in REQUIRED_SAMPLE_PROFILES) {
                val execution = run(
                    command = listOf(executable.toString(), samples.toString(), WARMUP_SAMPLES.toString()),
                    directory = scenario,
                    label = "run-$samples",
                    timeoutSeconds = timeoutForSamples(samples),
                )
                assertEquals(0, execution.exitCode, "production resource benchmark probe must pass for samples=$samples:\n${execution.output}")

                val alias = phaseFields(execution.output, "resource-alias-lookup")
                val commitment = phaseFields(execution.output, "resource-commitment-lookup")
                val zstd = phaseFields(execution.output, "zstd-context-reuse")
                println("resource-production-benchmark profile_samples=$samples ${phaseLine(alias)}")
                println("resource-production-benchmark profile_samples=$samples ${phaseLine(commitment)}")
                println("resource-production-benchmark profile_samples=$samples ${phaseLine(zstd)}")
                assertProductionPhase(alias, "resource-alias-lookup", samples, execution.output)
                assertProductionPhase(commitment, "resource-commitment-lookup", samples, execution.output)
                assertProductionPhase(zstd, "zstd-context-reuse", samples, execution.output)
                assertSecureCounters(alias, "resource-alias-lookup", execution.output)
                assertSecureCounters(commitment, "resource-commitment-lookup", execution.output)
                assertSecureCounters(zstd, "zstd-context-reuse", execution.output)

                assertAtLeast(alias, "resource_index_hit_count", samples.toLong(), "alias lookup must hit the production immutable index")
                assertAtLeast(commitment, "resource_index_hit_count", samples.toLong(), "commitment lookup must hit the production immutable index")
                assertAtLeast(commitment, "structure_check_count", samples.toLong(), "current JSRP verifier must retain structure checks")
                assertAtLeast(commitment, "length_check_count", samples.toLong(), "current JSRP verifier must retain length checks")
                assertAtLeast(commitment, "digest_check_count", samples.toLong(), "current JSRP verifier must retain digest checks")
                assertAtLeast(commitment, "wipe_count", 1L, "current JSRP verifier must wipe transient digest material")

                assertEquals(samples.toString(), zstd["decompress_context_reuse_count"], "same-generation zstd decodes must reuse the production context")
                assertAtLeast(zstd, "structure_check_count", samples.toLong(), "production zstd path must retain structure checks")
                assertAtLeast(zstd, "length_check_count", samples.toLong(), "production zstd path must retain length checks")
                assertAtLeast(zstd, "wipe_count", samples.toLong(), "production zstd output must be wiped after each decode")

                val lifecycle = lifecycleFields(execution.output)
                println("resource-production-benchmark profile_samples=$samples ${phaseLine(lifecycle)}")
                assertEquals("production", lifecycle["phase_mode"], "zstd lifecycle check must be production-bound for samples=$samples:\n${execution.output}")
                assertEquals("pass", lifecycle["status"], "zstd lifecycle check must pass for samples=$samples:\n${execution.output}")
                assertEquals("0", lifecycle["post_reset_reuse_count"], "reset must not reuse the prior generation's zstd context")
                assertEquals("1", lifecycle["failure_reuse_count"], "failure must exercise the current-generation decoder context")
                assertAtLeast(lifecycle, "failure_wipe_delta", 1L, "failed production zstd decode must wipe its owned output")
                listOf(
                    "fallback_count",
                    "legacy_path_hits",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "security_checks_skipped",
                    "exception_count",
                ).forEach { field ->
                    assertEquals("0", lifecycle[field], "zstd lifecycle check must keep $field at zero:\n${execution.output}")
                }

                val cacheLifecycle = resourceCacheLifecycleFields(execution.output)
                println("resource-production-benchmark profile_samples=$samples ${phaseLine(cacheLifecycle)}")
                assertEquals("production", cacheLifecycle["phase_mode"], "resource cache lifecycle must be production-bound for samples=$samples:\n${execution.output}")
                assertEquals("pass", cacheLifecycle["status"], "resource cache lifecycle must pass for samples=$samples:\n${execution.output}")
                val generationInstalled = cacheLifecycle["generation_installed"]?.toLongOrNull()
                val generationAfterReset = cacheLifecycle["generation_after_reset"]?.toLongOrNull()
                val generationReinstalled = cacheLifecycle["generation_reinstalled"]?.toLongOrNull()
                assertTrue(
                    generationInstalled != null && generationAfterReset != null && generationReinstalled != null &&
                        generationInstalled != generationAfterReset && generationReinstalled != generationAfterReset,
                    "resource cache lifecycle must advance and reject the retired generation for samples=$samples:\n${execution.output}",
                )
                assertEquals("0", cacheLifecycle["stale_alias_reused"], "retired alias must not resolve to its old sealed route:\n${execution.output}")
                assertEquals("1", cacheLifecycle["stale_alias_identity_resolution"], "retired alias must resolve only as an unindexed identity path:\n${execution.output}")
                assertEquals("0", cacheLifecycle["stale_commitment_reused"], "retired commitment must not validate after session reset:\n${execution.output}")
                assertEquals("0", cacheLifecycle["stale_resource_index_hit_count"], "retired resource indexes must not record cache hits:\n${execution.output}")
                assertAtLeast(cacheLifecycle, "replacement_resource_index_hit_count", 2L, "replacement generation must hit both production indexes")
                assertAtLeast(cacheLifecycle, "replacement_structure_check_count", 1L, "replacement commitment must retain structure validation")
                assertAtLeast(cacheLifecycle, "replacement_length_check_count", 1L, "replacement commitment must retain length validation")
                assertAtLeast(cacheLifecycle, "replacement_digest_check_count", 1L, "replacement commitment must retain digest validation")
                assertEquals("1", cacheLifecycle["cross_artifact_a_match"], "artifact A commitment must validate only its own raw bytes:\n${execution.output}")
                assertEquals("1", cacheLifecycle["cross_artifact_b_match"], "artifact B commitment must validate only its own raw bytes:\n${execution.output}")
                assertEquals("1", cacheLifecycle["cross_artifact_swap_rejected"], "cross-artifact raw-byte replay must fail closed:\n${execution.output}")
                assertEquals("1", cacheLifecycle["cross_artifact_alias_collision_rejected"], "cross-artifact alias/route collision must fail closed:\n${execution.output}")
                assertEquals("1", cacheLifecycle["duplicate_commitment_path_rejected"], "duplicate commitment paths must fail closed:\n${execution.output}")
                listOf(
                    "fallback_count",
                    "legacy_path_hits",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "security_checks_skipped",
                    "exception_count",
                ).forEach { field ->
                    assertEquals("0", cacheLifecycle[field], "resource cache lifecycle must keep $field at zero:\n${execution.output}")
                }
            }
        } finally {
            deleteTree(root)
        }
    }

    private fun assertProductionPhase(fields: Map<String, String>, name: String, samples: Int, output: String) {
        assertEquals("production", fields["phase_mode"], "$name must call the production runtime:\n$output")
        assertEquals("pass", fields["phase_status"], "$name must pass:\n$output")
        assertEquals(samples.toString(), fields["samples"], "$name must use the requested profile:\n$output")
        assertEquals(WARMUP_SAMPLES.toString(), fields["warmup"], "$name must use a non-measured warmup:\n$output")
    }

    private fun timeoutForSamples(samples: Int): Long = when {
        samples <= 1_000 -> 180L
        samples <= 10_000 -> 300L
        else -> 900L
    }

    private fun assertSecureCounters(fields: Map<String, String>, name: String, output: String) {
        listOf(
            "allocation_count",
            "allocation_bytes",
            "exception_count",
            "native_exception_count",
            "auth_failure_count",
            "wipe_failure_count",
            "plaintext_persistence_bytes",
            "fallback_count",
            "legacy_path_hits",
            "security_checks_skipped",
        ).forEach { field ->
            assertEquals("0", fields[field], "$name must keep $field at zero:\n$output")
        }
    }

    private fun assertAtLeast(fields: Map<String, String>, field: String, minimum: Long, message: String) {
        val value = fields[field]?.toLongOrNull()
        assertTrue(value != null && value >= minimum, "$message; $field=${fields[field] ?: "missing"}")
    }

    private fun phaseFields(output: String, expectedName: String): Map<String, String> {
        val prefix = "phase=$expectedName "
        val matches = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, matches.size, "expected exactly one $expectedName phase line:\n$output")
        return matches.single()
            .split(' ')
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0 || separator == token.lastIndex) null else token.substring(0, separator) to token.substring(separator + 1)
            }
            .toMap()
    }

    private fun lifecycleFields(output: String): Map<String, String> {
        val prefix = "zstd_lifecycle phase_name=zstd-context-reuse "
        val matches = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, matches.size, "expected exactly one zstd lifecycle line:\n$output")
        return matches.single()
            .split(' ')
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0 || separator == token.lastIndex) null else token.substring(0, separator) to token.substring(separator + 1)
            }
            .toMap()
    }

    private fun resourceCacheLifecycleFields(output: String): Map<String, String> {
        val prefix = "resource_cache_lifecycle phase_name=resource-cache-generation "
        val matches = output.lineSequence().filter { it.startsWith(prefix) }.toList()
        assertEquals(1, matches.size, "expected exactly one resource cache lifecycle line:\n$output")
        return matches.single()
            .split(' ')
            .mapNotNull { token ->
                val separator = token.indexOf('=')
                if (separator <= 0 || separator == token.lastIndex) null else token.substring(0, separator) to token.substring(separator + 1)
            }
            .toMap()
    }

    private fun phaseLine(fields: Map<String, String>): String = fields.entries
        .joinToString(" ") { (name, value) -> "$name=$value" }

    private fun compileCommand(
        zig: String,
        nativeDir: Path,
        probe: Path,
        executable: Path,
        jdkHome: Path,
    ): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-std=c11",
                "-O0",
                "-fwrapv",
                "-fno-exceptions",
                "-fvisibility=hidden",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-DJS_RUNTIME_BENCH_RESOURCE_RUNTIME=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DZSTD_DISABLE_ASM=1",
                "-DZSTDLIB_VISIBLE=",
                "-DZSTDERRORLIB_VISIBLE=",
                "-DXXH_PUBLIC_API=",
                "-o",
                executable.toString(),
            ),
        )
        addAll(FULL_NATIVE_SOURCES.map { nativeDir.resolve(it).toString() })
        add(probe.toString())
        addAll(
            listOf(
                "-I",
                nativeDir.toString(),
                "-I",
                nativeDir.resolve("cross-compile").toString(),
                "-I",
                nativeDir.resolve("zstd").toString(),
                "-I",
                nativeDir.resolve("zstd/common").toString(),
                "-I",
                nativeDir.resolve("zstd/decompress").toString(),
                "-I",
                jdkHome.resolve("include").toString(),
                "-I",
                jdkHome.resolve("include").resolve(jniPlatformDirectory()).toString(),
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

    private fun runWithTransientZigRetry(
        command: List<String>,
        directory: Path,
        label: String,
    ): ProcessResult {
        var result = run(
            command = command,
            directory = directory,
            label = "$label-0",
            zigCache = directory.resolve("zig-cache-0"),
            timeoutSeconds = 300L,
        )
        for (attempt in 1..5) {
            if (result.exitCode == 0 || !isTransientZigFailure(result.output)) break
            result = run(
                command = command,
                directory = directory,
                label = "$label-$attempt",
                zigCache = directory.resolve("zig-cache-$attempt"),
                timeoutSeconds = 300L,
            )
        }
        return result
    }

    private fun run(
        command: List<String>,
        directory: Path,
        label: String,
        zigCache: Path? = null,
        timeoutSeconds: Long = 180L,
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
        assertTrue(completed, "process timed out after ${timeoutSeconds}s: $label\n$output")
        return ProcessResult(process.exitValue(), output)
    }

    private fun findZig(): String? = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig").firstOrNull { candidate ->
        runCatching {
            val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
            process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(10L, TimeUnit.SECONDS) && process.exitValue() == 0
        }.getOrDefault(false)
    }

    private fun findJdkHome(): Path? {
        val javaHome = System.getProperty("java.home")?.takeIf { it.isNotBlank() }?.let(Path::of)
        return listOfNotNull(javaHome, javaHome?.parent)
            .map { it.toAbsolutePath().normalize() }
            .firstOrNull { Files.isRegularFile(it.resolve("include").resolve("jni.h")) }
    }

    private fun jniPlatformDirectory(): String = when {
        isWindows() -> "win32"
        isLinux() -> "linux"
        else -> error("unsupported native benchmark test host")
    }

    private fun isWindows(): Boolean = System.getProperty("os.name", "").lowercase().contains("win")

    private fun isLinux(): Boolean = System.getProperty("os.name", "").lowercase().contains("linux")

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains("sub-compilation of mingw-w64") ||
            output.contains("sub-compilation of libubsan failed") ||
            output.contains("unable to update cache: Unexpected") ||
            (output.contains("zig-x86_64-windows") && output.contains("no such file or directory")) ||
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
                if (Files.isDirectory(path)) {
                    Files.createDirectories(destination)
                } else {
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

    private data class ProcessResult(val exitCode: Int, val output: String)

    private companion object {
        val REQUIRED_SAMPLE_PROFILES = listOf(100, 1_000, 10_000, 100_000)
        const val WARMUP_SAMPLES = 16

        val FULL_NATIVE_SOURCES = listOf(
            "js_kernel.c",
            "js_helpers.c",
            "js_native_common.c",
            "js_crypto.c",
            "js_shell_crypto.c",
            "js_antidebug.c",
            "js_protected_section.c",
            "js_vm_core.c",
            "js_vm_resource.c",
            "js_vm_symbol.c",
            "js_jni_runtime.c",
            "js_machine_id.c",
            "zstd/common/debug.c",
            "zstd/common/entropy_common.c",
            "zstd/common/error_private.c",
            "zstd/common/fse_decompress.c",
            "zstd/common/xxhash.c",
            "zstd/common/zstd_common.c",
            "zstd/decompress/huf_decompress.c",
            "zstd/decompress/zstd_ddict.c",
            "zstd/decompress/zstd_decompress.c",
            "zstd/decompress/zstd_decompress_block.c",
        )
    }
}
