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
 * Exercises the production JNI class/method cache through a real attached JVM.
 *
 * This is deliberately separate from the lightweight benchmark fixture: the
 * native probe starts a disposable VM, transitions from a bootstrap owner to
 * the system ClassLoader, rejects a non-loader receiver, invalidates the
 * resource/session generation, and then measures repeated cache validation.
 * It reports de-identified counters and a digest only.
 */
class NativeRuntimeJniCacheProductionBenchmarkTest {
    @Test
    fun production_jni_cache_benchmark_binds_cache_hits_to_real_jvm_loader_and_generation() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the production JNI benchmark probe")
        assumeTrue(isWindows() || isLinux(), "the production JNI benchmark probe supports Windows and Linux")

        val jdkHome = findJdkHome()
        val platformInclude = jdkHome?.resolve("include")?.resolve(jniPlatformDirectory())
        val jvm = jdkHome?.resolve(jvmLibraryRelativePath())
        assumeTrue(
            jdkHome != null &&
                platformInclude != null &&
                Files.isRegularFile(platformInclude.resolve("jni_md.h")) &&
                jvm != null &&
                Files.isRegularFile(jvm),
            "JDK JNI headers and JVM library are required to run the production JNI benchmark probe",
        )

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val probeSource = resolveSource("src/test/native/jni_cache_production_benchmark_probe.c")
        val root = Files.createTempDirectory("javashroud-production-jni-cache-benchmark-")
        try {
            val scenario = Files.createDirectories(root.resolve("jni-cache-production"))
            val nativeDir = scenario.resolve("native")
            copyTree(sourceNativeDir, nativeDir)
            writeWindowsZigAvx10Shim(nativeDir)
            val probe = nativeDir.resolve("jni_cache_production_benchmark_probe.c")
            Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
            val executable = scenario.resolve(
                if (isWindows()) "jni_cache_production_benchmark_probe.exe" else "jni_cache_production_benchmark_probe",
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
            assertEquals(0, compile.exitCode, "production JNI cache benchmark probe must compile:\n${compile.output}")

            for (samples in REQUIRED_SAMPLE_PROFILES) {
                val execution = run(
                    command = listOf(executable.toString(), checkNotNull(jvm).toString(), samples.toString(), WARMUP_SAMPLES.toString()),
                    directory = scenario,
                    label = "run-$samples",
                    environment = jvmLibraryEnvironment(checkNotNull(jdkHome)),
                    timeoutSeconds = timeoutForSamples(samples),
                )
                assertEquals(0, execution.exitCode, "production JNI cache benchmark probe must pass for samples=$samples:\n${execution.output}")

                val fields = phaseFields(execution.output, "jni-method-class-lookup")
                println("jni-production-benchmark profile_samples=$samples ${phaseLine(fields)}")
                assertEquals("production", fields["phase_mode"], "JNI benchmark must use the production runtime:\n${execution.output}")
                assertEquals("pass", fields["phase_status"], "JNI benchmark must pass:\n${execution.output}")
                assertEquals(samples.toString(), fields["samples"], "JNI benchmark must run the requested sample profile")
                assertEquals(WARMUP_SAMPLES.toString(), fields["warmup"], "JNI benchmark must have a non-measured warmup")
                assertAtLeast(fields, "jni_cache_hit_count", samples.toLong(), "repeated production lookup must hit the JNI cache")
                assertAtLeast(fields, "jni_abi_check_count", samples.toLong(), "each production lookup must retain JNI ABI validation")
                assertPresentLatency(fields, "p50")
                assertPresentLatency(fields, "p95")
                assertPresentLatency(fields, "p99")
                assertPresentLatency(fields, "max")
                listOf(
                    "allocation_count",
                    "exception_count",
                    "native_exception_count",
                    "fallback_count",
                    "legacy_path_hits",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "security_checks_skipped",
                ).forEach { field ->
                    assertEquals("0", fields[field], "production JNI cache benchmark must keep $field at zero:\n${execution.output}")
                }
                assertTrue(
                    fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true,
                    "production JNI cache benchmark must emit a de-identified output digest:\n${execution.output}",
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    private fun assertPresentLatency(fields: Map<String, String>, name: String) {
        assertTrue(
            fields[name]?.removeSuffix("ns")?.toLongOrNull()?.let { it >= 0L } == true,
            "missing or malformed latency field $name: ${fields[name]}",
        )
    }

    private fun timeoutForSamples(samples: Int): Long = when {
        samples <= 1_000 -> 180L
        samples <= 10_000 -> 300L
        else -> 900L
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

    private fun writeWindowsZigAvx10Shim(nativeDir: Path) {
        /* Zig 0.16's MinGW sysroot has an immintrin include that references an
         * optional AVX10 header which is not shipped with that sysroot.  This
         * fixture-local shim leaves the production source and ABI untouched. */
        Files.writeString(
            nativeDir.resolve("avx10_2satcvtintrin.h"),
            "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#endif\n",
            StandardCharsets.US_ASCII,
        )
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
        environment: Map<String, String> = emptyMap(),
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
        environment.forEach { (name, value) -> builder.environment()[name] = value }
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

    private fun jvmLibraryRelativePath(): String = when {
        isWindows() -> "bin/server/jvm.dll"
        isLinux() -> "lib/server/libjvm.so"
        else -> error("unsupported native benchmark test host")
    }

    private fun jvmLibraryEnvironment(jdkHome: Path): Map<String, String> {
        val separator = System.getProperty("path.separator", ";")
        return when {
            isWindows() -> {
                val name = "PATH"
                mapOf(name to "${jdkHome.resolve("bin")}$separator${System.getenv(name).orEmpty()}")
            }
            isLinux() -> {
                val name = "LD_LIBRARY_PATH"
                mapOf(name to "${jdkHome.resolve("lib")}$separator${System.getenv(name).orEmpty()}")
            }
            else -> emptyMap()
        }
    }

    private fun isWindows(): Boolean = System.getProperty("os.name", "").lowercase().contains("win")

    private fun isLinux(): Boolean = System.getProperty("os.name", "").lowercase().contains("linux")

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains("sub-compilation of mingw-w64") ||
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
