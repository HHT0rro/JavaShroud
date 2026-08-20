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

class NativeRuntimeZstdContextTest {
    @Test
    fun production_zstd_context_reuses_only_current_session_and_wipes_failed_output() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the native Zstd context probe")
        assumeTrue(isWindows() || isLinux(), "the native Zstd context probe supports Windows and Linux")

        val sourceNativeDir = resolveSource("src/main/native/js_vm_resource.c").parent
        val probeSource = resolveSource("src/test/native/zstd_context_reuse_probe.c")
        val root = Files.createTempDirectory("javashroud-zstd-context-")
        try {
            val nativeDir = root.resolve("native")
            copyTree(sourceNativeDir, nativeDir)
            Files.writeString(
                nativeDir.resolve("avx10_2satcvtintrin.h"),
                "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#endif\n",
                StandardCharsets.US_ASCII,
            )
            val probe = nativeDir.resolve("zstd_context_reuse_probe.c")
            Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
            val executable = root.resolve(if (isWindows()) "zstd_context_reuse_probe.exe" else "zstd_context_reuse_probe")

            val compile = runWithTransientZigRetry(
                command = compileCommand(checkNotNull(zig), nativeDir, probe, executable),
                directory = root,
                label = "compile",
            )
            assertEquals(0, compile.exitCode, "production Zstd context probe must compile:\n${compile.output}")

            val execution = run(
                command = listOf(executable.toString()),
                directory = root,
                label = "run",
                timeoutSeconds = 120L,
            )
            assertEquals(0, execution.exitCode, "production Zstd context probe must pass:\n${execution.output}")
            assertTrue(
                execution.output.contains("Zstd production context probe: PASS"),
                "native probe did not report success:\n${execution.output}",
            )
            assertTrue(
                execution.output.contains("partial_output_wipe=1"),
                "malformed frame must wipe output written before the truncated tail:\n${execution.output}",
            )
        } finally {
            deleteTree(root)
        }
    }

    private fun compileCommand(zig: String, nativeDir: Path, probe: Path, executable: Path): List<String> = buildList {
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
                "-DZSTD_DISABLE_ASM=1",
                "-DZSTDLIB_VISIBLE=",
                "-DZSTDERRORLIB_VISIBLE=",
                "-DXXH_PUBLIC_API=",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
                "-DJS_ZSTD_CONTEXT_TEST_HOOKS=1",
                "-o",
                executable.toString(),
            ),
        )
        addAll(FULL_NATIVE_SOURCES.map { nativeDir.resolve(it).toString() })
        add(probe.toString())
        addAll(
            listOf(
                "-I", nativeDir.toString(),
                "-I", nativeDir.resolve("cross-compile").toString(),
                "-I", nativeDir.resolve("zstd").toString(),
                "-I", nativeDir.resolve("zstd/common").toString(),
                "-I", nativeDir.resolve("zstd/decompress").toString(),
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
        var result = run(command, directory, "$label-0", directory.resolve("zig-cache-0"), 300L)
        for (attempt in 1..5) {
            if (result.exitCode == 0 || !isTransientZigFailure(result.output)) break
            result = run(command, directory, "$label-$attempt", directory.resolve("zig-cache-$attempt"), 300L)
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
        val FULL_NATIVE_SOURCES = listOf(
            "js_kernel.c",
            "js_helpers.c",
            "js_native_common.c",
            "js_crypto.c",
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
