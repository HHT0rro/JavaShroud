package io.github.hht0rro.javashroud

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Comparator
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Binds prepared VM execution and nested frame lifecycle to a real attached
 * JNI invocation JVM.  The native fixture calls the production prepared
 * entrypoint with session-bound resident state; it does not claim a full
 * artifact/catalog parse, so that scope remains explicit in phase_scope.
 */
class NativeRuntimeVmPreparedExecutionBenchmarkTest {
    @Test
    fun production_attached_jvm_prepared_execution_reuses_frames_and_bounds_nested_depth() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the prepared VM benchmark probe")
        assumeTrue(isWindows() || isLinux(), "the prepared VM benchmark probe supports Windows and Linux")

        val jdkHome = findJdkHome()
        val platformInclude = jdkHome?.resolve("include")?.resolve(jniPlatformDirectory())
        val jvm = jdkHome?.resolve(jvmLibraryRelativePath())
        assumeTrue(
            jdkHome != null &&
                platformInclude != null &&
                Files.isRegularFile(platformInclude.resolve("jni_md.h")) &&
                jvm != null &&
                Files.isRegularFile(jvm),
            "JDK JNI headers and JVM library are required for the prepared VM benchmark probe",
        )

        val sourceNativeDir = resolveSource("src/main/native/js_vm_core.c").parent
        val probeSource = resolveSource("src/test/native/vm_prepared_execution_production_benchmark_probe.c")
        val root = Files.createTempDirectory("javashroud-production-vm-prepared-benchmark-")
        try {
            val scenario = Files.createDirectories(root.resolve("vm-prepared-production"))
            val probe = scenario.resolve("vm_prepared_execution_production_benchmark_probe.c")
            Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
            val executable = scenario.resolve(
                if (isWindows()) {
                    "vm_prepared_execution_production_benchmark_probe.exe"
                } else {
                    "vm_prepared_execution_production_benchmark_probe"
                },
            )
            val compile = runWithTransientZigRetry(
                command = compileCommand(
                    zig = checkNotNull(zig),
                    nativeDir = sourceNativeDir,
                    probe = probe,
                    executable = executable,
                    jdkHome = checkNotNull(jdkHome),
                ),
                directory = scenario,
                label = "compile",
            )
            assertEquals(0, compile.exitCode, "prepared VM benchmark probe must compile:\n${compile.output}")

            for (samples in sampleProfiles()) {
                val execution = run(
                    command = listOf(executable.toString(), checkNotNull(jvm).toString(), samples.toString(), "16"),
                    directory = scenario,
                    label = "run-$samples",
                    environment = jvmLibraryEnvironment(checkNotNull(jdkHome)),
                    timeoutSeconds = if (samples >= 100_000) 240L else 120L,
                )
                assertEquals(0, execution.exitCode, "prepared VM benchmark probe must pass for $samples samples:\n${execution.output}")
                val fields = phaseFields(execution.output, "vm-prepared-execution")
                println("vm-prepared-benchmark ${phaseLine(fields)}")
                assertEquals("attached-jvm-production-entrypoint", fields["phase_mode"], execution.output)
                assertEquals("session-bound-resident-program", fields["fixture_scope"], execution.output)
                assertEquals("pass", fields["phase_status"], execution.output)
                assertEquals("pass", fields["invoke_static_cp0"], execution.output)
                assertEquals("0", fields["invoke_static_cp0_index"], execution.output)
        assertEquals("sealed", fields["invoke_static_cp0_type"], execution.output)
                assertEquals("7", fields["invoke_static_cp0_result"], execution.output)
                assertEquals("9", fields["invoke_static_cp0_decode_stage"], execution.output)
                assertEquals("1", fields["invoke_static_cp0_decode_auth"], execution.output)
                assertEquals("1", fields["invoke_static_cp0_session_layout_bound"], execution.output)
        listOf(
            "invoke_static_cp0_tamper_cipher",
            "invoke_static_cp0_tamper_tag",
            "invoke_static_cp0_tamper_nonce",
            "invoke_static_cp0_tamper_length",
            "invoke_static_cp0_tamper_type",
        ).forEach { field ->
            assertEquals("fail-closed", fields[field], execution.output)
        }
                assertEquals("8", fields["nested_frame_depth"], execution.output)
                assertEquals("pass", fields["nested_execution"], execution.output)
                assertEquals("pass", fields["recursive_execution"], execution.output)
                assertEquals("pass", fields["exception_execution"], execution.output)
                assertEquals("typed", fields["exception_catch"], execution.output)
                assertEquals("42", fields["exception_result"], execution.output)
                assertEquals("pass", fields["threaded_execution"], execution.output)
                assertEquals("4", fields["thread_count"], execution.output)
                assertEquals("32", fields["thread_iterations"], execution.output)
                assertTrue(
                    fields["thread_output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true,
                    "prepared VM benchmark must emit a de-identified threaded output digest:\n${execution.output}",
                )
                assertAtLeast(fields, "thread_frame_reuse_count", 4L * 31L, execution.output)
                assertEquals("0", fields["thread_heap_fallback_count"], execution.output)
                assertAtLeast(fields, "vm_frame_reuse_count", max(0, samples - 1).toLong(), execution.output)
                listOf(
                    "vm_heap_fallback_count",
                    "allocation_count",
                    "exception_count",
                    "native_exception_count",
                    "fallback_count",
                    "legacy_path_hits",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "security_checks_skipped",
                ).forEach { field ->
                    assertEquals("0", fields[field], "prepared VM benchmark must keep $field at zero:\n${execution.output}")
                }
                listOf("p50", "p95", "p99", "max").forEach { field -> assertPresentLatency(fields, field, execution.output) }
                assertTrue(
                    fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true,
                    "prepared VM benchmark must emit a de-identified output digest:\n${execution.output}",
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    private fun sampleProfiles(): List<Int> {
        val matrix = System.getenv("JS_VM_PREPARED_EXEC_BENCH_MATRIX")
            ?.trim()
            ?.lowercase()
            ?.let { it == "1" || it == "true" || it == "yes" }
            ?: false
        if (matrix) return listOf(100, 1_000, 10_000, 100_000)
        return listOf(
            System.getenv("JS_VM_PREPARED_EXEC_BENCH_SAMPLES")
                ?.toIntOrNull()
                ?.takeIf { it in 100..100_000 }
                ?: 100,
        )
    }

    private fun assertPresentLatency(fields: Map<String, String>, name: String, output: String) {
        assertTrue(fields[name]?.removeSuffix("ns")?.toLongOrNull()?.let { it >= 0L } == true, "missing $name: $output")
    }

    private fun phaseLine(fields: Map<String, String>): String = fields.entries
        .joinToString(" ") { (name, value) -> "$name=$value" }

    private fun assertAtLeast(fields: Map<String, String>, field: String, minimum: Long, output: String) {
        val value = fields[field]?.toLongOrNull()
        assertTrue(value != null && value >= minimum, "expected $field >= $minimum, got ${fields[field]}:\n$output")
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

    private fun compileCommand(zig: String, nativeDir: Path, probe: Path, executable: Path, jdkHome: Path): List<String> = buildList {
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
                "-DZSTD_DISABLE_ASM=1",
                "-DZSTDLIB_VISIBLE=",
                "-DZSTDERRORLIB_VISIBLE=",
                "-DXXH_PUBLIC_API=",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_VM_EXECUTION_FRAME_TEST=1",
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

    private fun runWithTransientZigRetry(command: List<String>, directory: Path, label: String): ProcessResult {
        var result = run(command, directory, "$label-0", directory.resolve("zig-cache-0"), timeoutSeconds = 300L)
        for (attempt in 1..5) {
            if (result.exitCode == 0 || !isTransientZigFailure(result.output)) break
            result = run(command, directory, "$label-$attempt", directory.resolve("zig-cache-$attempt"), timeoutSeconds = 300L)
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
        assertTrue(completed, "process timed out after ${timeoutSeconds}s: ${command.joinToString(" ")}\n$output")
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
            isWindows() -> mapOf("PATH" to "${jdkHome.resolve("bin")}$separator${System.getenv("PATH").orEmpty()}")
            isLinux() -> mapOf("LD_LIBRARY_PATH" to "${jdkHome.resolve("lib")}$separator${System.getenv("LD_LIBRARY_PATH").orEmpty()}")
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

    private fun deleteTree(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
    }

    private data class ProcessResult(val exitCode: Int, val output: String)

    private companion object {
        val FULL_NATIVE_SOURCES = listOf(
            "js_kernel.c",
            "js_helpers.c",
            "js_native_common.c",
            "js_crypto.c",
            "js_antidebug.c",
            "js_protected_section.c",
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
