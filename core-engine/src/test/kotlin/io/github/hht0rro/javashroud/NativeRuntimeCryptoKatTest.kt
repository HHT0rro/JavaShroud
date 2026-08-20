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

class NativeRuntimeCryptoKatTest {
    @Test
    fun native_crypto_kat_rejection_and_hardware_software_differential() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the native crypto KAT probe")
        assumeTrue(isWindows() || isLinux(), "the native crypto KAT probe supports Windows and Linux")

        val sourceNativeDir = resolveSource("src/main/native/js_crypto.c").parent
        val probeSource = resolveSource("src/test/native/crypto_kat_security_probe.c")
        val root = Files.createTempDirectory("javashroud-crypto-kat-")
        try {
            val nativeDir = root.resolve("native")
            copyTree(sourceNativeDir, nativeDir)
            Files.writeString(
                nativeDir.resolve("avx10_2satcvtintrin.h"),
                "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#endif\n",
                StandardCharsets.US_ASCII,
            )
            val probe = nativeDir.resolve("crypto_kat_security_probe.c")
            Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
            val hardwareExecutable = root.resolve(if (isWindows()) "crypto_kat_hardware.exe" else "crypto_kat_hardware")
            val softwareExecutable = root.resolve(if (isWindows()) "crypto_kat_software.exe" else "crypto_kat_software")
            val disabledExecutable = root.resolve(if (isWindows()) "crypto_kat_capability_disabled.exe" else "crypto_kat_capability_disabled")

            val hardwareCompile = runWithTransientZigRetry(
                command = compileCommand(checkNotNull(zig), nativeDir, probe, hardwareExecutable, forceSoftware = false),
                directory = root,
                label = "compile-hardware",
            )
            assertEquals(0, hardwareCompile.exitCode, "hardware-capability crypto probe must compile:\n${hardwareCompile.output}")
            val hardwareRun = run(
                command = listOf(hardwareExecutable.toString()),
                directory = root,
                label = "run-hardware",
                timeoutSeconds = 180L,
            )
            assertEquals(0, hardwareRun.exitCode, "hardware-capability crypto probe must pass:\n${hardwareRun.output}")

            val softwareCompile = runWithTransientZigRetry(
                command = compileCommand(checkNotNull(zig), nativeDir, probe, softwareExecutable, forceSoftware = true),
                directory = root,
                label = "compile-software",
            )
            assertEquals(0, softwareCompile.exitCode, "forced-software crypto probe must compile:\n${softwareCompile.output}")
            val softwareRun = run(
                command = listOf(softwareExecutable.toString()),
                directory = root,
                label = "run-software",
                timeoutSeconds = 180L,
            )
            assertEquals(0, softwareRun.exitCode, "forced-software crypto probe must pass:\n${softwareRun.output}")

            val disabledCompile = runWithTransientZigRetry(
                command = compileCommand(
                    checkNotNull(zig),
                    nativeDir,
                    probe,
                    disabledExecutable,
                    forceSoftware = false,
                    disableHardware = true,
                ),
                directory = root,
                label = "compile-capability-disabled",
            )
            assertEquals(0, disabledCompile.exitCode, "capability-disabled crypto probe must compile:\n${disabledCompile.output}")
            val disabledRun = run(
                command = listOf(disabledExecutable.toString()),
                directory = root,
                label = "run-capability-disabled",
                timeoutSeconds = 180L,
            )
            assertEquals(0, disabledRun.exitCode, "capability-disabled crypto probe must pass:\n${disabledRun.output}")

            val hardwareLine = phaseLine(hardwareRun.output)
            val softwareLine = phaseLine(softwareRun.output)
            val disabledLine = phaseLine(disabledRun.output)
            assertTrue(hardwareLine.contains("status=pass"), "hardware probe did not report pass:\n$hardwareLine")
            assertTrue(softwareLine.contains("status=pass"), "software probe did not report pass:\n$softwareLine")
            assertTrue(softwareLine.contains("software_crypto_path="), "software path counter missing:\n$softwareLine")
            assertEquals("0", field(disabledLine, "hardware_available"), "capability-disabled build selected hardware AES")
            assertEquals("0", field(disabledLine, "ghash_hardware_available"), "capability-disabled build selected hardware GHASH")
            assertTrue(field(disabledLine, "software_crypto_path").toLong() > 0L, "capability-disabled build did not use software crypto")
            assertEquals(
                field(hardwareLine, "output_digest"),
                field(softwareLine, "output_digest"),
                "hardware and software crypto paths must produce the same digest",
            )
            assertEquals(
                field(softwareLine, "output_digest"),
                field(disabledLine, "output_digest"),
                "capability-disabled and software crypto paths must produce the same digest",
            )
            for (line in listOf(hardwareLine, softwareLine, disabledLine)) {
                assertTrue(field(line, "auth_failure_count").toLong() >= 4L, "rejection cases were not exercised:\n$line")
                assertTrue(field(line, "aes_block_count").toLong() > 0L, "AES blocks were not counted:\n$line")
                assertTrue(field(line, "ghash_block_count").toLong() > 0L, "GHASH blocks were not counted:\n$line")
                assertTrue(field(line, "wipe_count").toLong() > 0L, "wipe count was not recorded:\n$line")
                assertEquals("0", field(line, "security_checks_skipped"), "security checks were skipped:\n$line")
                assertEquals("0", field(line, "fallback_count"), "fallback path was used:\n$line")
                assertEquals("0", field(line, "legacy_path_hits"), "legacy path was used:\n$line")
                assertEquals("0", field(line, "plaintext_persistence_bytes"), "plaintext persisted:\n$line")
            }
            println("crypto-kat differential hardware $hardwareLine")
            println("crypto-kat differential software $softwareLine")
            println("crypto-kat differential capability-disabled $disabledLine")
        } finally {
            deleteTree(root)
        }
    }

    private fun phaseLine(output: String): String = output.lineSequence()
        .firstOrNull { it.startsWith("crypto_kat_security_probe ") }
        ?: error("crypto KAT probe did not emit a sanitized phase line:\n$output")

    private fun field(line: String, name: String): String = line.split(' ')
        .firstOrNull { it.startsWith("$name=") }
        ?.substringAfter('=')
        ?: error("missing $name in phase line: $line")

    private fun compileCommand(
        zig: String,
        nativeDir: Path,
        probe: Path,
        executable: Path,
        forceSoftware: Boolean,
        disableHardware: Boolean = false,
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
        if (disableHardware) add("-DJS_CRYPTO_DISABLE_HARDWARE=1")
        /* The crypto KAT only exercises js_crypto.c.  Keep this lane's source
         * set minimal so a transient Zig cache/parser failure in unrelated VM,
         * loader, or anti-debug translation units cannot invalidate the crypto
         * differential evidence.  Production integration lanes continue to
         * compile their full native dependency set separately. */
        addAll(CRYPTO_NATIVE_SOURCES.map { nativeDir.resolve(it).toString() })
        add(probe.toString())
        addAll(
            listOf(
                "-I", nativeDir.toString(),
                "-I", nativeDir.resolve("cross-compile").toString(),
                "-I", nativeDir.resolve("zstd").toString(),
                "-I", nativeDir.resolve("zstd/common").toString(),
                "-I", nativeDir.resolve("zstd/decompress").toString(),
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
        var result = run(command, directory, "$label-0", directory.resolve("zig-cache-0"), 300L)
        /* Zig can transiently report a compiler-cache/file-open `Unexpected`
         * while another native fixture or the background watcher is closing a
         * cache entry.  Keep each retry isolated and allow enough attempts for
         * that external cache contention to clear; non-transient compiler
         * errors still return immediately. */
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
            output.contains("sub-compilation of libubsan failed") ||
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

    private data class ProcessResult(val exitCode: Int, val output: String)

    private companion object {
        val CRYPTO_NATIVE_SOURCES = listOf(
            "js_crypto.c",
        )
    }
}
