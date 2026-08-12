package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
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
    fun native_aes256_gcm_decrypts_nist_vector_and_wipes_rejected_output() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the focused native crypto vector test")

        val nativeDir = resolveSource("src/main/native/js_shell_crypto.c").parent
        val tempDir = Files.createTempDirectory("javashroud-shell-gcm-")
        try {
            val sidecarBinding = ByteArray(32) { index -> (index * 7 + 3).toByte() }
            val sidecarKek = ByteArray(32) { index -> (index * 11 + 5).toByte() }
            val sidecar = BootKekSidecar.encode(sidecarKek, sidecarBinding)
            val harness = tempDir.resolve("gcm_vector_test.c")
            val executable = tempDir.resolve(if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "gcm_vector_test.exe" else "gcm_vector_test")
            Files.writeString(harness, vectorHarness(sidecar, sidecarBinding, sidecarKek))

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
            assertEquals(0, compile.exitCode, "native AES-256-GCM vector harness must compile:\n${compile.output}")

            val execution = run(listOf(executable.toString()), tempDir)
            assertEquals(0, execution.exitCode, "native AES-256-GCM vector harness failed:\n${execution.output}")
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
        fun vectorHarness(sidecar: ByteArray, binding: ByteArray, kek: ByteArray) = """
            #include "js_shell_crypto.h"
            #include <stddef.h>
            #include <string.h>

            /* NIST AES-256-GCM vector with a 96-bit nonce and 20-byte AAD. */

            static int hex_decode(const char *hex, unsigned char *out, size_t size) {
                for (size_t i = 0; i < size; i++) {
                    unsigned char high = (unsigned char)hex[i * 2u];
                    unsigned char low = (unsigned char)hex[i * 2u + 1u];
                    int high_value = high >= '0' && high <= '9' ? high - '0' : high >= 'a' && high <= 'f' ? high - 'a' + 10 : -1;
                    int low_value = low >= '0' && low <= '9' ? low - '0' : low >= 'a' && low <= 'f' ? low - 'a' + 10 : -1;
                    if (high_value < 0 || low_value < 0) return 0;
                    out[i] = (unsigned char)((high_value << 4) | low_value);
                }
                return hex[size * 2u] == '\0';
            }

            int main(void) {
                unsigned char key[32], nonce[12], aad[20], sealed[80], expected[64], output[64];
                unsigned char sidecar[] = { ${sidecar.toCBytes()} };
                unsigned char sidecar_binding[32] = { ${binding.toCBytes()} };
                unsigned char sidecar_kek[32] = { ${kek.toCBytes()} };
                if (!hex_decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key, sizeof(key)) ||
                    !hex_decode("cafebabefacedbaddecaf888", nonce, sizeof(nonce)) ||
                    !hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof(aad)) ||
                    !hex_decode("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad2df7cd675b4f09163b41ebf980a7f638", sealed, sizeof(sealed)) ||
                    !hex_decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", expected, sizeof(expected))) return 10;

                memset(output, 0xa5, sizeof(output));
                if (!js_shell_aes256_gcm_decrypt(key, nonce, aad, sizeof(aad), sealed, sizeof(sealed), output)) return 11;
                if (memcmp(output, expected, sizeof(output)) != 0) return 12;

                sealed[sizeof(sealed) - 1u] ^= 0x01u;
                memset(output, 0xa5, sizeof(output));
                if (js_shell_aes256_gcm_decrypt(key, nonce, aad, sizeof(aad), sealed, sizeof(sealed), output)) return 13;
                for (size_t i = 0; i < sizeof(output); i++) if (output[i] != 0u) return 14;

                memset(output, 0xa5, sizeof(output));
                if (!js_shell_open_boot_kek_sidecar(sidecar, sizeof(sidecar), sidecar_binding, output)) return 15;
                if (memcmp(output, sidecar_kek, sizeof(sidecar_kek)) != 0) return 16;
                sidecar[sizeof(sidecar) - 1u] ^= 0x01u;
                memset(output, 0xa5, sizeof(output));
                if (js_shell_open_boot_kek_sidecar(sidecar, sizeof(sidecar), sidecar_binding, output)) return 17;
                for (size_t i = 0; i < sizeof(sidecar_kek); i++) if (output[i] != 0u) return 18;
                return 0;
            }
        """.trimIndent()

        fun ByteArray.toCBytes(): String = joinToString(", ") { "0x%02xu".format(it.toInt() and 0xFF) }
    }
}
