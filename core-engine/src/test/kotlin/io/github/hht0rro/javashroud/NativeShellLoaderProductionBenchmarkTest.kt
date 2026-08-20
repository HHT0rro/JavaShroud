package io.github.hht0rro.javashroud

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Production-bound shell loader fixture.
 *
 * The probe receives a compiled current native image through the same
 * platform loader entrypoint used by the shell.  The shell stub is responsible
 * for authenticating the decoded payload before calling this API; this fixture
 * therefore focuses on the validated loader/mapping lifecycle and explicitly
 * checks that a tampered image is rejected by the loader itself.
 */
class NativeShellLoaderProductionBenchmarkTest {
    @Test
    fun native_shell_loader_maps_authenticated_inner_image_and_rejects_tampering() {
        val zig = findZig()
        val platform = platform()
        assumeTrue(zig != null, "Zig is required to compile the shell loader fixture")
        assumeTrue(platform != null, "The shell loader fixture supports Windows and Linux")
        val hostPlatform = platform ?: error("shell loader platform assumption did not hold")

        val root = Files.createTempDirectory("javashroud-shell-loader-production-")
        try {
            val nativeDir = resolveSource("src/main/native").toAbsolutePath().normalize()
            val fixtureSource = resolveSource("src/test/native/shell_loader_fixture_image.c")
            val probeSource = resolveSource("src/test/native/shell_loader_production_benchmark_probe.c")
            val image = root.resolve("inner-fixture${platform.fileSuffix}")
            val probe = root.resolve("shell-loader-probe${platform.executableSuffix}")

            val imageCompile = runWithTransientZigRetry(
                command = compileImageCommand(
                    zig = checkNotNull(zig),
                    nativeDir = nativeDir,
                    fixtureSource = fixtureSource,
                    image = image,
                    platform = hostPlatform,
                ),
                directory = root,
                label = "compile-inner-image",
            )
            assertEquals(0, imageCompile.exitCode, "inner loader image must compile:\n${imageCompile.output}")
            assertTrue(Files.isRegularFile(image) && Files.size(image) > 0L, "inner loader image is missing")

            val probeCompile = runWithTransientZigRetry(
                command = compileProbeCommand(
                    zig = checkNotNull(zig),
                    nativeDir = nativeDir,
                    probeSource = probeSource,
                    probe = probe,
                    platform = hostPlatform,
                ),
                directory = root,
                label = "compile-loader-probe",
            )
            assertEquals(0, probeCompile.exitCode, "shell loader probe must compile:\n${probeCompile.output}")
            assertTrue(Files.isRegularFile(probe) && Files.size(probe) > 0L, "shell loader probe is missing")

            val samples = System.getenv("JS_SHELL_LOADER_BENCH_SAMPLES")
                ?.toIntOrNull()
                ?.takeIf { it in 100..100_000 }
                ?: 100
            val warmup = System.getenv("JS_SHELL_LOADER_BENCH_WARMUP")
                ?.toIntOrNull()
                ?.takeIf { it in 0..100_000 }
                ?: 16
            val timeoutSeconds = System.getenv("JS_SHELL_LOADER_BENCH_TIMEOUT_SECONDS")
                ?.toLongOrNull()
                ?.takeIf { it in 120L..86_400L }
                ?: 300L
            val run = run(
                command = listOf(probe.toString(), image.toString(), samples.toString(), warmup.toString()),
                directory = root,
                label = "run-loader-probe",
                timeoutSeconds = timeoutSeconds,
            )
            assertEquals(0, run.exitCode, "shell loader production probe must pass:\n${run.output}")
            val line = run.output.lineSequence()
                .singleOrNull { it.startsWith("phase=shell-loader ") }
                ?: error("shell loader probe did not emit a sanitized phase line:\n${run.output}")
            val fields = line.split(' ')
                .mapNotNull { token ->
                    val separator = token.indexOf('=')
                    if (separator <= 0 || separator == token.lastIndex) null
                    else token.substring(0, separator) to token.substring(separator + 1)
                }
                .toMap()
            assertEquals("production", fields["phase_mode"], line)
            assertEquals("pass", fields["phase_status"], line)
            assertEquals("preverified", fields["auth_boundary"], line)
            assertEquals(samples.toString(), fields["samples"], line)
            assertEquals(warmup.toString(), fields["warmup"], line)
            listOf("p50", "p95", "p99", "max").forEach { field ->
                assertTrue(fields[field]?.toLongOrNull()?.let { it >= 0L } == true, line)
            }
            assertEquals(samples.toString(), fields["load_count"], line)
            assertEquals(samples.toString(), fields["unload_count"], line)
            assertTrue(fields["mapping_unit_count"]?.toLongOrNull()?.let { it > 0L } == true, line)
            assertEquals("1", fields["tamper_rejection_count"], line)
            assertEquals("0", fields["failure_count"], line)
            assertEquals("1", fields["length_check_count"], line)
            assertEquals("1", fields["structure_check_count"], line)
            assertEquals("1", fields["jni_abi_check_count"], line)
            assertEquals("0", fields["wipe_failure_count"], line)
            assertEquals("0", fields["plaintext_persistence_bytes"], line)
            assertEquals("0", fields["fallback_count"], line)
            assertEquals("0", fields["legacy_path_hits"], line)
            assertEquals("0", fields["security_checks_skipped"], line)
            assertTrue(fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true, line)
            println(line)
        } finally {
            deleteTree(root)
        }
    }

    private fun compileImageCommand(
        zig: String,
        nativeDir: Path,
        fixtureSource: Path,
        image: Path,
        platform: LoaderPlatform,
    ): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-target",
                platform.zigTarget,
                "-std=c11",
                "-O2",
                "-shared",
                "-fvisibility=hidden",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
                "-I", nativeDir.toString(),
                "-I", nativeDir.resolve("cross-compile").toString(),
                "-I", javaInclude().toString(),
                "-I", javaPlatformInclude().toString(),
                "-o", image.toString(),
                fixtureSource.toString(),
            ),
        )
        if (platform == LoaderPlatform.LINUX_X64) add("-fPIC")
    }

    private fun compileProbeCommand(
        zig: String,
        nativeDir: Path,
        probeSource: Path,
        probe: Path,
        platform: LoaderPlatform,
    ): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-target",
                platform.zigTarget,
                "-std=c11",
                "-O2",
                "-fwrapv",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
                "-I", nativeDir.toString(),
                "-I", nativeDir.resolve("cross-compile").toString(),
                "-I", javaInclude().toString(),
                "-I", javaPlatformInclude().toString(),
                "-o", probe.toString(),
                probeSource.toString(),
                nativeDir.resolve(platform.loaderSource).toString(),
            ),
        )
        if (platform == LoaderPlatform.WINDOWS_X64) add("-ladvapi32")
        else addAll(listOf("-ldl", "-pthread"))
    }

    private fun runWithTransientZigRetry(command: List<String>, directory: Path, label: String): ProcessResult {
        var result = run(command, directory, "$label-0", directory.resolve("zig-cache-0"), 300L)
        for (attempt in 1..10) {
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
        timeoutSeconds: Long,
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
        return if (completed) {
            ProcessResult(process.exitValue(), output)
        } else {
            ProcessResult(124, "process timed out after ${timeoutSeconds}s: ${command.joinToString(" ")}\n$output")
        }
    }

    private fun findZig(): String? = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig")
        .firstOrNull { candidate ->
            runCatching {
                val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
                process.inputStream.bufferedReader().use { it.readText() }
                process.waitFor(10L, TimeUnit.SECONDS) && process.exitValue() == 0
            }.getOrDefault(false)
        }

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains("sub-compilation of mingw-w64") ||
            output.contains("unable to update cache: Unexpected") ||
            output.contains("error: Unexpected")

    private fun platform(): LoaderPlatform? = when {
        System.getProperty("os.name", "").lowercase().contains("win") -> LoaderPlatform.WINDOWS_X64
        System.getProperty("os.name", "").lowercase().contains("linux") -> LoaderPlatform.LINUX_X64
        else -> null
    }

    private fun javaInclude(): Path {
        val configured = System.getenv("JAVA_HOME")?.takeIf { it.isNotBlank() }
        val javaHome = Path.of(configured ?: System.getProperty("java.home"))
        val direct = javaHome.resolve("include")
        return if (Files.isDirectory(direct)) direct else javaHome.parent.resolve("include")
    }

    private fun javaPlatformInclude(): Path = javaInclude().resolve(
        if (platform() == LoaderPlatform.WINDOWS_X64) "win32" else "linux",
    )

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

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { path ->
                runCatching { Files.deleteIfExists(path) }
            }
        }
    }

    private enum class LoaderPlatform(
        val zigTarget: String,
        val fileSuffix: String,
        val executableSuffix: String,
        val loaderSource: String,
    ) {
        WINDOWS_X64("x86_64-windows-gnu", ".dll", ".exe", "js_shell_loader_pe.c"),
        LINUX_X64("x86_64-linux-gnu", ".so", "", "js_shell_loader_elf.c"),
    }

    private data class ProcessResult(val exitCode: Int, val output: String)
}
