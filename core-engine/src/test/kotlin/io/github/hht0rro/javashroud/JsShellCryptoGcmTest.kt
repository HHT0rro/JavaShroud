package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
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
        val tempDir = Files.createTempDirectory("javashroud-shell-chunks-")
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
                    nativeDir.resolve("js_shell_crypto.c").toString(),
                    harness.toString(),
                    "-I",
                    nativeDir.toString(),
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
        fun vectorHarness(bundle: NativeKernelShellPacker.MaxPayloadBundle, expected: ByteArray) = """
            #include "js_shell_crypto.h"
            #include <stddef.h>
            #include <string.h>

            int main(void) {
                unsigned char payload[] = { ${bundle.encodedPayload.toCBytes()} };
                unsigned char expected[] = { ${expected.toCBytes()} };
                unsigned char stream_key[32] = { ${bundle.streamKey.toCBytes()} };
                unsigned char nonce[16] = { ${bundle.nonce.toCBytes()} };
                unsigned char binding_tag[32] = { ${bundle.bindingTag.toCBytes()} };
                unsigned char tags[] = { ${bundle.chunkTags.toCBytes()} };
                unsigned char tampered[sizeof(payload)];

                memcpy(tampered, payload, sizeof(payload));
                if (!js_shell_decode_payload_chunks(
                        payload,
                        sizeof(payload),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 11;
                if (sizeof(payload) != sizeof(expected) || memcmp(payload, expected, sizeof(expected)) != 0) return 12;

                tags[sizeof(tags) - 1u] ^= 0x01u;
                if (js_shell_decode_payload_chunks(
                        tampered,
                        sizeof(tampered),
                        stream_key,
                        nonce,
                        binding_tag,
                        ${bundle.chunkSize}u,
                        tags,
                        sizeof(tags))) return 13;
                for (size_t i = 0; i < sizeof(tampered); i++) if (tampered[i] != 0u) return 14;
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
