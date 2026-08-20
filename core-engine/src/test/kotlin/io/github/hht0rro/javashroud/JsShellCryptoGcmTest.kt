package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class JsShellCryptoGcmTest {
    @Test
    fun native_chunk_decoder_authenticates_and_wipes_rejected_payload() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the focused native chunk decoder test")

        val nativeDir = resolveSource("src/main/native/js_shell_crypto.c").parent
        val jniIncludeDir = Path.of(System.getProperty("java.home")).resolve("include")
        val jniPlatformIncludeDir = jniIncludeDir.resolve(
            if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "win32"
            else if (System.getProperty("os.name").startsWith("Mac", ignoreCase = true)) "darwin"
            else "linux",
        )
        assertTrue(Files.isDirectory(jniIncludeDir) && Files.isDirectory(jniPlatformIncludeDir),
            "focused native chunk decoder test requires the active JDK JNI headers")
        val tempDir = Files.createTempDirectory("javashroud-shell-chunks-")
        // The production shell profile selects a chunk size from 1024/1536/2048/3072.
        // Keep at least two complete chunks so the reorder/duplication vectors exercise
        // position-bound authentication regardless of the selected profile.
        val plaintext = pseudoRandomBytes(8193)
        var bundle: NativeKernelShellPacker.MaxPayloadBundle? = null
        try {
            val payloadBundle = NativeKernelShellPacker.buildMaxPayloadBundle(
                bytes = plaintext,
                platform = "linux-x64",
                outputName = "js_kernel_linux-x64.so",
                seed = 0xA4E1_5EEDL,
                bootstrapNativeIndexDigest = ByteArray(32) { index -> (index * 13 + 7).toByte() },
            )
            bundle = payloadBundle
            assertEquals(
                plaintext.size,
                payloadBundle.storedPayloadSize,
                "the native chunk vector must stay uncompressed so C output can be compared directly",
            )
            val harness = tempDir.resolve("chunk_decoder_test.c")
            val executable = tempDir.resolve(
                if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
                    "chunk_decoder_test.exe"
                } else {
                    "chunk_decoder_test"
                },
            )
            Files.writeString(harness, vectorHarness(payloadBundle, plaintext))

            val compile = runWithRetry(
                listOf(
                    zig!!,
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DJS_NATIVE_PROTECTION_NONE=1",
                    nativeDir.resolve("js_crypto.c").toString(),
                    nativeDir.resolve("js_shell_crypto.c").toString(),
                    harness.toString(),
                    "-I",
                    nativeDir.toString(),
                    "-I",
                    jniIncludeDir.toString(),
                    "-I",
                    jniPlatformIncludeDir.toString(),
                    "-o",
                    executable.toString(),
                ),
                tempDir,
            )
            assertEquals(0, compile.exitCode, "native AKEN chunk decoder harness must compile:\n${compile.output}")

            val execution = run(listOf(executable.toString()), tempDir)
            assertEquals(0, execution.exitCode, "native AKEN chunk decoder harness failed:\n${execution.output}")
        } finally {
            bundle?.wipeSensitive()
            plaintext.fill(0)
            Files.walk(tempDir).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun native_shell_payload_decode_production_profile_reports_sanitized_phase() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the native shell payload decode benchmark")

        val sampleProfiles = shellPayloadBenchmarkProfiles()
        val warmup = System.getenv("JS_SHELL_PAYLOAD_BENCH_WARMUP")
            ?.toIntOrNull()
            ?.takeIf { it in 0..100_000 }
            ?: 16
        val nativeDir = resolveSource("src/main/native/js_shell_crypto.c").parent
        val jniIncludeDir = Path.of(System.getProperty("java.home")).resolve("include")
        val jniPlatformIncludeDir = jniIncludeDir.resolve(
            if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "win32"
            else if (System.getProperty("os.name").startsWith("Mac", ignoreCase = true)) "darwin"
            else "linux",
        )
        assertTrue(
            Files.isDirectory(jniIncludeDir) && Files.isDirectory(jniPlatformIncludeDir),
            "shell payload benchmark requires the active JDK JNI headers",
        )
        val tempDir = Files.createTempDirectory("javashroud-shell-payload-bench-")
        val plaintext = pseudoRandomBytes(4097)
        var bundle: NativeKernelShellPacker.MaxPayloadBundle? = null
        try {
            val payloadBundle = NativeKernelShellPacker.buildMaxPayloadBundle(
                bytes = plaintext,
                platform = "linux-x64",
                outputName = "js_kernel_linux-x64.so",
                seed = 0xA4E1_5EEDL,
                bootstrapNativeIndexDigest = ByteArray(32) { index -> (index * 13 + 7).toByte() },
            )
            bundle = payloadBundle
            sampleProfiles.forEach { samples ->
                val harness = tempDir.resolve("shell_payload_decode_benchmark_$samples.c")
                val executable = tempDir.resolve(
                    if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
                        "shell_payload_decode_benchmark_$samples.exe"
                    } else {
                        "shell_payload_decode_benchmark_$samples"
                    },
                )
                Files.writeString(harness, benchmarkHarness(payloadBundle, plaintext, samples, warmup), StandardCharsets.UTF_8)

                val compile = runWithRetry(
                    listOf(
                        zig!!,
                        "cc",
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-DJS_NATIVE_PROTECTION_NONE=1",
                        nativeDir.resolve("js_crypto.c").toString(),
                        nativeDir.resolve("js_shell_crypto.c").toString(),
                        harness.toString(),
                        "-I",
                        nativeDir.toString(),
                        "-I",
                        jniIncludeDir.toString(),
                        "-I",
                        jniPlatformIncludeDir.toString(),
                        "-o",
                        executable.toString(),
                    ),
                    tempDir,
                )
                assertEquals(0, compile.exitCode, "native shell payload benchmark must compile for samples=$samples:\n${compile.output}")

                val execution = run(listOf(executable.toString()), tempDir)
                assertEquals(0, execution.exitCode, "native shell payload benchmark failed for samples=$samples:\n${execution.output}")
                val phaseLine = execution.output.lineSequence()
                    .singleOrNull { it.startsWith("phase=shell-payload-decode ") }
                requireNotNull(phaseLine) { "shell payload benchmark phase is missing for samples=$samples:\n${execution.output}" }
                println(phaseLine)
                val fields = phaseLine.split(' ')
                    .mapNotNull { token ->
                        val separator = token.indexOf('=')
                        if (separator <= 0 || separator == token.lastIndex) null
                        else token.substring(0, separator) to token.substring(separator + 1)
                    }
                    .toMap()
                assertEquals("production", fields["phase_mode"], execution.output)
                assertEquals("pass", fields["phase_status"], execution.output)
                assertEquals(samples.toString(), fields["samples"], execution.output)
                assertEquals(warmup.toString(), fields["warmup"], execution.output)
                listOf("p50", "p95", "p99", "max").forEach { field ->
                    assertTrue(fields[field]?.toLongOrNull()?.let { it >= 0L } == true, execution.output)
                }
                listOf("auth_check_count", "tag_check_count", "length_check_count", "structure_check_count", "wipe_count")
                    .forEach { field ->
                        assertTrue(fields[field]?.toLongOrNull()?.let { it > 0L } == true, execution.output)
                    }
                listOf(
                    "auth_failure_count",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "fallback_count",
                    "legacy_path_hits",
                    "exception_count",
                    "security_checks_skipped",
                ).forEach { field -> assertEquals("0", fields[field], execution.output) }
                assertEquals("not-measured", fields["loader_path"], execution.output)
                assertTrue(fields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true, execution.output)
            }
        } finally {
            bundle?.wipeSensitive()
            plaintext.fill(0)
            Files.walk(tempDir).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun native_shell_metadata_parser_records_real_framing_checks_and_wipes_tampered_state() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the focused native shell metadata parser test")

        val nativeDir = resolveSource("src/main/native/js_shell_stub.c").parent
        val jniIncludeDir = Path.of(System.getProperty("java.home")).resolve("include")
        val jniPlatformIncludeDir = jniIncludeDir.resolve(
            if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "win32"
            else if (System.getProperty("os.name").startsWith("Mac", ignoreCase = true)) "darwin"
            else "linux",
        )
        assertTrue(Files.isDirectory(jniIncludeDir) && Files.isDirectory(jniPlatformIncludeDir),
            "focused native shell metadata parser test requires the active JDK JNI headers")

        val tempDir = Files.createTempDirectory("javashroud-shell-metadata-")
        try {
            val sourcePath = nativeDir.resolve("js_shell_stub.c").toAbsolutePath().toString().replace('\\', '/')
            val harness = tempDir.resolve("shell_metadata_metrics_test.c")
            val executable = tempDir.resolve(
                if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
                    "shell_metadata_metrics_test.exe"
                } else {
                    "shell_metadata_metrics_test"
                },
            )
            Files.writeString(tempDir.resolve("js_shell_payload.inc"), metadataFixtureHeader(), StandardCharsets.UTF_8)
            Files.writeString(harness, metadataParserHarness(sourcePath), StandardCharsets.UTF_8)

            val compile = runWithRetry(
                listOf(
                    zig!!,
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wno-unused-function",
                    "-DJS_NATIVE_PROTECTION_NONE=1",
                    nativeDir.resolve("js_crypto.c").toString(),
                    nativeDir.resolve("js_shell_crypto.c").toString(),
                    harness.toString(),
                    "-I",
                    tempDir.toString(),
                    "-I",
                    nativeDir.toString(),
                    "-I",
                    nativeDir.resolve("zstd").toString(),
                    "-I",
                    nativeDir.resolve("zstd/common").toString(),
                    "-I",
                    nativeDir.resolve("zstd/decompress").toString(),
                    "-I",
                    jniIncludeDir.toString(),
                    "-I",
                    jniPlatformIncludeDir.toString(),
                    "-o",
                    executable.toString(),
                ),
                tempDir,
            )
            assertEquals(0, compile.exitCode, "native shell metadata parser harness must compile:\n${compile.output}")

            val execution = run(listOf(executable.toString()), tempDir)
            assertEquals(0, execution.exitCode, "native shell metadata parser harness failed:\n${execution.output}")
        } finally {
            Files.walk(tempDir).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun findZig(): String? {
        val candidates = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig")
        return candidates.firstOrNull { candidate ->
            runCatching {
                val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
                process.inputStream.bufferedReader().use { it.readText() }
                process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0
            }.getOrDefault(false)
        }
    }

    private fun shellPayloadBenchmarkProfiles(): List<Int> {
        val matrix = System.getenv("JS_SHELL_PAYLOAD_BENCH_MATRIX")
            ?.trim()
            ?.lowercase()
            ?.let { it == "1" || it == "true" || it == "yes" }
            ?: false
        if (matrix) return listOf(100, 1_000, 10_000, 100_000)
        return listOf(
            System.getenv("JS_SHELL_PAYLOAD_BENCH_SAMPLES")
                ?.toIntOrNull()
                ?.takeIf { it in 100..100_000 }
                ?: 100,
        )
    }

    private fun runWithRetry(command: List<String>, directory: Path): ProcessResult {
        var result = run(command, directory)
        repeat(2) { attempt ->
            if (result.exitCode == 0) return result
            Thread.sleep((attempt + 1L) * 250L)
            result = run(command, directory)
        }
        return result
    }

    private fun run(command: List<String>, directory: Path): ProcessResult {
        val process = ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).start()
        val completed = process.waitFor(60, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
        val output = process.inputStream.bufferedReader().use { it.readText() }
        assertTrue(completed, "process timed out: ${command.joinToString(" ")}")
        return ProcessResult(process.exitValue(), output)
    }

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

    private data class ProcessResult(val exitCode: Int, val output: String)

    private companion object {
        fun metadataFixtureHeader(): String {
            fun ByteArrayOutputStream.writeIntLe(value: Int) {
                write(value and 0xFF)
                write((value ushr 8) and 0xFF)
                write((value ushr 16) and 0xFF)
                write((value ushr 24) and 0xFF)
            }

            fun ByteArrayOutputStream.writeAscii(value: String) {
                val bytes = value.toByteArray(StandardCharsets.US_ASCII)
                try {
                    writeIntLe(bytes.size)
                    write(bytes)
                } finally {
                    bytes.fill(0)
                }
            }

            val nonce = ByteArray(16) { index -> (index + 1).toByte() }
            val sectionDigest = ByteArray(32) { index -> index.toByte() }
            val bindingTag = ByteArray(32).also { it[0] = 0xA5.toByte() }
            val chunkTags = ByteArray(32) { 0x11.toByte() }
            val metadata = ByteArrayOutputStream().apply {
                writeAscii("windows-x64")
                writeAscii("js_kernel_windows-x64.dll")
                writeAscii("pe64-dll")
                writeIntLe(1)
                writeIntLe(1)
                writeIntLe(1)
                writeIntLe(0)
                writeIntLe(1)
                writeIntLe(1)
                writeIntLe(7)
                writeIntLe(9)
                write(sectionDigest)
                write(bindingTag)
                writeIntLe(chunkTags.size)
                write(chunkTags)
            }.toByteArray()
            val header = ByteArrayOutputStream().apply {
                write(NativeKernelShellPacker.MAX_PAYLOAD_MARKER.toByteArray(StandardCharsets.US_ASCII))
                write(0)
                writeIntLe(2)
                writeIntLe(nonce.size)
                write(nonce)
                writeIntLe(metadata.size)
                write(metadata)
            }.toByteArray()
            return try {
                buildString {
                    appendLine("#ifndef JS_SHELL_PAYLOAD_INC")
                    appendLine("#define JS_SHELL_PAYLOAD_INC")
                    appendLine("#define JS_NATIVE_MAX_STUB_MARKER \"${NativeKernelShellPacker.MAX_STUB_MARKER}\"")
                    appendLine("#define JS_NATIVE_MAX_PAYLOAD_MARKER \"${NativeKernelShellPacker.MAX_PAYLOAD_MARKER}\"")
                    appendLine("#define JS_SHELL_PROTOCOL_LEVEL 2u")
                    appendLine("#define JS_SHELL_AKEN_BINDING_LANE_COUNT 4u")
                    appendLine("#define JS_SHELL_AKEN_BINDING_LANE_SIZE 8u")
                    appendLine("static unsigned char js_shell_payload_header[] = { ${header.toCBytes()} };")
                    appendLine("static const unsigned char js_shell_payload_bytes[] = { 0u };")
                    appendLine("static const unsigned char js_shell_aken_binding_lane_0[8] = { 0u };")
                    appendLine("static const unsigned char js_shell_aken_binding_lane_1[8] = { 0u };")
                    appendLine("static const unsigned char js_shell_aken_binding_lane_2[8] = { 0u };")
                    appendLine("static const unsigned char js_shell_aken_binding_lane_3[8] = { 0u };")
                    appendLine("static const unsigned char js_shell_aken_binding_lane_order[4] = { 0u, 1u, 2u, 3u };")
                    appendLine("static const unsigned char js_shell_aken_payload_commitment[32] = { 0u };")
                    appendLine("#define JS_SHELL_PAYLOAD_HEADER_SIZE ${header.size}u")
                    appendLine("#define JS_SHELL_PAYLOAD_SIZE 1u")
                    appendLine("#endif")
                }
            } finally {
                nonce.fill(0)
                sectionDigest.fill(0)
                bindingTag.fill(0)
                chunkTags.fill(0)
                metadata.fill(0)
                header.fill(0)
            }
        }

        fun metadataParserHarness(shellStubSource: String) = """
            #include "js_shell_stub.h"
            #include "js_shell_loader.h"
            #include "zstd.h"
            #include "js_crypto.h"
            #include <string.h>

            const char *js_shell_loader_failure_reason(void) { return "fixture"; }
            int js_shell_load_inner_image(const js_shell_payload_view *view, js_shell_loaded_image *out) {
                (void)view;
                (void)out;
                return 0;
            }
            size_t ZSTD_decompress(void *dst, size_t dstCapacity, const void *src, size_t compressedSize) {
                (void)dst;
                (void)dstCapacity;
                (void)src;
                (void)compressedSize;
                return (size_t)-1;
            }
            unsigned ZSTD_isError(size_t code) {
                (void)code;
                return 1u;
            }

            #include "$shellStubSource"

            int main(void) {
                js_shell_payload_meta meta;
                unsigned char stream_key[32];
                unsigned char binding_salt[32];
                js_crypto_runtime_metrics metrics;
                uint64_t valid_wipe_count;
                memset(binding_salt, 0x3c, sizeof(binding_salt));
                js_crypto_runtime_metrics_reset();
                if (!js_shell_extract_aken_meta(&meta, stream_key, binding_salt)) return 10;
                if (meta.original_size != 1u || meta.stored_size != 1u || meta.encoded_size != 1u ||
                    meta.chunk_size != 1u || meta.chunk_count != 1u || meta.chunk_tags_size != 32u ||
                    meta.compression_codec != 0u || meta.layout_profile != 7u || meta.dispatcher_profile != 9u ||
                    meta.binding_tag[0] != 0xa5u || meta.nonce[15] != 16u) return 11;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (metrics.structure_check_count != 1u || metrics.length_check_count != 1u ||
                    metrics.auth_check_count != 0u || metrics.auth_failure_count != 0u ||
                    metrics.wipe_count == 0u || metrics.wipe_failure_count != 0u ||
                    metrics.fallback_count != 0u || metrics.legacy_path_hits != 0u ||
                    metrics.plaintext_persistence_bytes != 0u || metrics.security_checks_skipped != 0u) return 12;
                valid_wipe_count = metrics.wipe_count;

                js_shell_payload_header[0] ^= 0x01u;
                memset(&meta, 0xa5, sizeof(meta));
                memset(stream_key, 0xa5, sizeof(stream_key));
                if (js_shell_extract_aken_meta(&meta, stream_key, binding_salt)) return 13;
                for (size_t index = 0u; index < sizeof(stream_key); index++) if (stream_key[index] != 0u) return 14;
                for (size_t index = 0u; index < sizeof(meta); index++) if (((unsigned char *)&meta)[index] != 0u) return 15;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (metrics.structure_check_count != 2u || metrics.length_check_count != 2u ||
                    metrics.auth_check_count != 0u || metrics.auth_failure_count != 0u ||
                    metrics.wipe_count <= valid_wipe_count || metrics.wipe_failure_count != 0u ||
                    metrics.fallback_count != 0u || metrics.legacy_path_hits != 0u ||
                    metrics.plaintext_persistence_bytes != 0u || metrics.security_checks_skipped != 0u) return 16;
                return 0;
            }
        """.trimIndent()

        fun vectorHarness(bundle: NativeKernelShellPacker.MaxPayloadBundle, expected: ByteArray) = """
            #include "js_crypto.h"
            #include "js_shell_crypto.h"
            #include <stddef.h>
            #include <stdio.h>
            #include <string.h>

            static int buffer_is_zero(const unsigned char *bytes, size_t size) {
                unsigned int diff = 0u;
                if (!bytes) return 0;
                for (size_t index = 0u; index < size; index++) diff |= bytes[index];
                return diff == 0u;
            }

            static int rejected_metrics_are_clean(const js_crypto_runtime_metrics *metrics, uint64_t expected_auth_checks) {
                return metrics &&
                    metrics->structure_check_count == 1u &&
                    metrics->length_check_count == 1u &&
                    metrics->auth_check_count == expected_auth_checks &&
                    metrics->tag_check_count == expected_auth_checks &&
                    metrics->auth_failure_count == 1u &&
                    metrics->wipe_count > 0u &&
                    metrics->wipe_failure_count == 0u &&
                    metrics->plaintext_persistence_bytes == 0u &&
                    metrics->fallback_count == 0u &&
                    metrics->legacy_path_hits == 0u &&
                    metrics->exception_count == 0u &&
                    metrics->security_checks_skipped == 0u;
            }

            int main(void) {
                unsigned char payload[] = { ${bundle.encodedPayload.toCBytes()} };
                const unsigned char expected[] = { ${expected.toCBytes()} };
                const unsigned char stream_key[32] = { ${bundle.streamKey.toCBytes()} };
                unsigned char nonce[16] = { ${bundle.nonce.toCBytes()} };
                unsigned char binding_tag[32] = { ${bundle.bindingTag.toCBytes()} };
                const unsigned char original_tags[] = { ${bundle.chunkTags.toCBytes()} };
                unsigned char work[sizeof(payload)];
                unsigned char tags[sizeof(original_tags)];
                unsigned char too_many_tags[sizeof(original_tags) + 32u];
                unsigned char chunk_scratch[${bundle.chunkSize}u];
                js_crypto_runtime_metrics metrics;
                size_t chunk_count = sizeof(original_tags) / 32u;

                if (chunk_count < 2u || sizeof(payload) < ${bundle.chunkSize}u * 2u) {
                    fprintf(stderr, "fixture_shape chunk_count=%zu payload_size=%zu chunk_size=%uu tags_size=%zu\n",
                        chunk_count, sizeof(payload), ${bundle.chunkSize}u, sizeof(original_tags));
                    return 10;
                }

                /* Valid decode establishes the expected output and that every
                 * chunk is authenticated before plaintext is used. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(tags, original_tags, sizeof(tags));
                if (!js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 11;
                if (sizeof(work) != sizeof(expected) || memcmp(work, expected, sizeof(expected)) != 0) return 12;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (metrics.structure_check_count != 1u ||
                    metrics.length_check_count != 1u ||
                    metrics.auth_check_count != chunk_count ||
                    metrics.tag_check_count != chunk_count ||
                    metrics.auth_failure_count != 0u ||
                    metrics.wipe_count == 0u ||
                    metrics.wipe_failure_count != 0u ||
                    metrics.plaintext_persistence_bytes != 0u ||
                    metrics.fallback_count != 0u ||
                    metrics.legacy_path_hits != 0u ||
                    metrics.exception_count != 0u ||
                    metrics.security_checks_skipped != 0u) return 13;
                js_vbc4_wipe_volatile(work, sizeof(work));

                /* A wrong final tag must reject and wipe after checking every
                 * preceding chunk. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(tags, original_tags, sizeof(tags));
                tags[sizeof(tags) - 1u] ^= 0x01u;
                if (js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 14;
                if (!buffer_is_zero(work, sizeof(work))) return 15;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (!rejected_metrics_are_clean(&metrics, (uint64_t)chunk_count)) return 16;

                /* Reordering complete ciphertext chunks and their tags together
                 * must still fail because each tag is bound to its position. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(tags, original_tags, sizeof(tags));
                memcpy(chunk_scratch, work, ${bundle.chunkSize}u);
                memcpy(work, work + ${bundle.chunkSize}u, ${bundle.chunkSize}u);
                memcpy(work + ${bundle.chunkSize}u, chunk_scratch, ${bundle.chunkSize}u);
                memcpy(chunk_scratch, tags, 32u);
                memcpy(tags, tags + 32u, 32u);
                memcpy(tags + 32u, chunk_scratch, 32u);
                if (js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 17;
                if (!buffer_is_zero(work, sizeof(work))) return 18;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (!rejected_metrics_are_clean(&metrics, 1u)) return 19;

                /* Duplicating one authenticated chunk into another position must
                 * fail rather than silently accepting replayed payload bytes. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(tags, original_tags, sizeof(tags));
                memcpy(work + ${bundle.chunkSize}u, work, ${bundle.chunkSize}u);
                memcpy(tags + 32u, tags, 32u);
                if (js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 20;
                if (!buffer_is_zero(work, sizeof(work))) return 21;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (!rejected_metrics_are_clean(&metrics, 2u)) return 22;

                /* Reusing ciphertext and tags under a different artifact binding
                 * must fail closed before any chunk can be decrypted. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(tags, original_tags, sizeof(tags));
                binding_tag[0] ^= 0x01u;
                if (js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 23;
                binding_tag[0] ^= 0x01u;
                if (!buffer_is_zero(work, sizeof(work))) return 24;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (!rejected_metrics_are_clean(&metrics, 1u)) return 25;

                /* Reusing the same payload under a different nonce is another
                 * cross-session replay and must be rejected with a full wipe. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(tags, original_tags, sizeof(tags));
                nonce[0] ^= 0x01u;
                if (js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 26;
                nonce[0] ^= 0x01u;
                if (!buffer_is_zero(work, sizeof(work))) return 27;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (!rejected_metrics_are_clean(&metrics, 1u)) return 28;

                /* A tag-length mismatch is a structural/length rejection.  The
                 * native decoder must wipe the ciphertext even though no tag was
                 * reached, preventing malformed metadata from leaving bytes
                 * resident for a later loader path. */
                js_crypto_runtime_metrics_reset();
                memcpy(work, payload, sizeof(work));
                memcpy(too_many_tags, original_tags, sizeof(original_tags));
                memcpy(too_many_tags + sizeof(original_tags), original_tags, 32u);
                if (js_shell_decode_payload_chunks(
                        work,
                        sizeof(work),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        too_many_tags,
                        sizeof(too_many_tags))) return 29;
                if (!buffer_is_zero(work, sizeof(work))) return 30;
                js_crypto_runtime_metrics_snapshot(&metrics);
                if (metrics.structure_check_count != 1u ||
                    metrics.length_check_count != 1u ||
                    metrics.auth_check_count != 0u ||
                    metrics.tag_check_count != 0u ||
                    metrics.auth_failure_count != 0u ||
                    metrics.wipe_count == 0u ||
                    metrics.wipe_failure_count != 0u ||
                    metrics.plaintext_persistence_bytes != 0u ||
                    metrics.fallback_count != 0u ||
                    metrics.legacy_path_hits != 0u ||
                    metrics.exception_count != 0u ||
                    metrics.security_checks_skipped != 0u) return 31;
                return 0;
            }
        """.trimIndent()

        fun benchmarkHarness(
            bundle: NativeKernelShellPacker.MaxPayloadBundle,
            expected: ByteArray,
            samples: Int,
            warmup: Int,
        ) = """
            #include "js_crypto.h"
            #include "js_shell_crypto.h"
            #include <stddef.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #if defined(_WIN32)
            #include <windows.h>
            static uint64_t bench_ticks_ns(void) {
                LARGE_INTEGER counter;
                LARGE_INTEGER frequency;
                if (!QueryPerformanceCounter(&counter) || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return 0u;
                return ((uint64_t)counter.QuadPart / (uint64_t)frequency.QuadPart) * UINT64_C(1000000000) +
                    (((uint64_t)counter.QuadPart % (uint64_t)frequency.QuadPart) * UINT64_C(1000000000)) / (uint64_t)frequency.QuadPart;
            }
            #else
            #include <time.h>
            static uint64_t bench_ticks_ns(void) {
                struct timespec value;
                if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0u;
                return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
            }
            #endif

            static int compare_u64(const void *left, const void *right) {
                const uint64_t a = *(const uint64_t *)left;
                const uint64_t b = *(const uint64_t *)right;
                return a < b ? -1 : a > b ? 1 : 0;
            }

            static uint64_t percentile(const uint64_t *sorted, size_t count, unsigned int percent) {
                size_t index = (count * (size_t)percent + 99u) / 100u;
                if (index == 0u) index = 1u;
                if (index > count) index = count;
                return sorted[index - 1u];
            }

            static uint64_t mix_digest(uint64_t value, uint64_t input) {
                value ^= input + UINT64_C(0x9e3779b97f4a7c15) + (value << 6u) + (value >> 2u);
                value ^= value >> 30u;
                value *= UINT64_C(0xbf58476d1ce4e5b9);
                value ^= value >> 27u;
                value *= UINT64_C(0x94d049bb133111eb);
                return value ^ (value >> 31u);
            }

            static uint64_t digest_bytes(const unsigned char *bytes, size_t size) {
                uint64_t value = UINT64_C(0xcbf29ce484222325);
                for (size_t index = 0u; index < size; index++) {
                    value ^= (uint64_t)bytes[index];
                    value *= UINT64_C(0x100000001b3);
                }
                return value;
            }

            int main(void) {
                unsigned char payload[] = { ${bundle.encodedPayload.toCBytes()} };
                const unsigned char expected[] = { ${expected.toCBytes()} };
                const unsigned char stream_key[32] = { ${bundle.streamKey.toCBytes()} };
                const unsigned char nonce[16] = { ${bundle.nonce.toCBytes()} };
                const unsigned char binding_tag[32] = { ${bundle.bindingTag.toCBytes()} };
                const unsigned char chunk_tags[] = { ${bundle.chunkTags.toCBytes()} };
                unsigned char work[sizeof(payload)];
                uint64_t timings[$samples];
                js_crypto_runtime_metrics before;
                js_crypto_runtime_metrics after;
                uint64_t digest = UINT64_C(0x243f6a8885a308d3);
                if (sizeof(payload) != sizeof(expected)) return 9;

                for (unsigned int iteration = 0u; iteration < ${warmup}u; iteration++) {
                    memcpy(work, payload, sizeof(work));
                    if (!js_shell_decode_payload_chunks(work, sizeof(work), stream_key, nonce, binding_tag,
                            ${bundle.chunkSize}u, chunk_tags, sizeof(chunk_tags)) ||
                        memcmp(work, expected, sizeof(expected)) != 0) return 10;
                    js_vbc4_wipe_volatile(work, sizeof(work));
                }

                js_crypto_runtime_metrics_reset();
                js_crypto_runtime_metrics_snapshot(&before);
                for (unsigned int iteration = 0u; iteration < ${samples}u; iteration++) {
                    uint64_t started;
                    uint64_t elapsed;
                    uint64_t output;
                    memcpy(work, payload, sizeof(work));
                    started = bench_ticks_ns();
                    if (!js_shell_decode_payload_chunks(work, sizeof(work), stream_key, nonce, binding_tag,
                            ${bundle.chunkSize}u, chunk_tags, sizeof(chunk_tags)) ||
                        memcmp(work, expected, sizeof(expected)) != 0) return 11;
                    elapsed = bench_ticks_ns() - started;
                    output = digest_bytes(work, sizeof(work));
                    digest = mix_digest(digest, output ^ (uint64_t)iteration);
                    timings[iteration] = elapsed;
                    js_vbc4_wipe_volatile(work, sizeof(work));
                }
                js_crypto_runtime_metrics_snapshot(&after);
                qsort(timings, ${samples}u, sizeof(timings[0]), compare_u64);

                #define DELTA(field) (after.field - before.field)
                if (DELTA(auth_check_count) == 0u || DELTA(tag_check_count) == 0u ||
                    DELTA(length_check_count) == 0u || DELTA(structure_check_count) == 0u ||
                    DELTA(wipe_count) == 0u || DELTA(auth_failure_count) != 0u ||
                    DELTA(wipe_failure_count) != 0u || DELTA(plaintext_persistence_bytes) != 0u ||
                    DELTA(fallback_count) != 0u || DELTA(legacy_path_hits) != 0u ||
                    DELTA(exception_count) != 0u || DELTA(security_checks_skipped) != 0u ||
                    DELTA(hardware_crypto_path) + DELTA(software_crypto_path) == 0u) return 12;
                printf(
                    "phase=shell-payload-decode phase_mode=production phase_status=pass "
                    "fixture_scope=current-format-native-shell-payload timing_unit=ns samples=%u warmup=%u "
                    "p50=%llu p95=%llu p99=%llu max=%llu "
                    "hardware_crypto_path=%llu software_crypto_path=%llu aes_block_count=%llu ghash_block_count=%llu "
                    "auth_check_count=%llu auth_failure_count=%llu tag_check_count=%llu "
                    "length_check_count=%llu structure_check_count=%llu wipe_count=%llu wipe_failure_count=%llu "
                    "plaintext_persistence_bytes=%llu fallback_count=%llu legacy_path_hits=%llu "
                    "exception_count=%llu security_checks_skipped=%llu loader_path=not-measured output_digest=%016llx\n",
                    ${samples}u,
                    ${warmup}u,
                    (unsigned long long)percentile(timings, ${samples}u, 50u),
                    (unsigned long long)percentile(timings, ${samples}u, 95u),
                    (unsigned long long)percentile(timings, ${samples}u, 99u),
                    (unsigned long long)timings[${samples}u - 1u],
                    (unsigned long long)DELTA(hardware_crypto_path),
                    (unsigned long long)DELTA(software_crypto_path),
                    (unsigned long long)DELTA(aes_block_count),
                    (unsigned long long)DELTA(ghash_block_count),
                    (unsigned long long)DELTA(auth_check_count),
                    (unsigned long long)DELTA(auth_failure_count),
                    (unsigned long long)DELTA(tag_check_count),
                    (unsigned long long)DELTA(length_check_count),
                    (unsigned long long)DELTA(structure_check_count),
                    (unsigned long long)DELTA(wipe_count),
                    (unsigned long long)DELTA(wipe_failure_count),
                    (unsigned long long)DELTA(plaintext_persistence_bytes),
                    (unsigned long long)DELTA(fallback_count),
                    (unsigned long long)DELTA(legacy_path_hits),
                    (unsigned long long)DELTA(exception_count),
                    (unsigned long long)DELTA(security_checks_skipped),
                    (unsigned long long)digest
                );
                js_vbc4_wipe_volatile(work, sizeof(work));
                return 0;
            }
        """.trimIndent()

        fun pseudoRandomBytes(size: Int): ByteArray {
            var state = 0x1357_9BDF
            return ByteArray(size) {
                state = state * 1_664_525 + 1_013_904_223
                (state ushr 16).toByte()
            }
        }

        fun ByteArray.toCBytes(): String = joinToString(", ") { "0x%02xu".format(it.toInt() and 0xFF) }
    }
}
