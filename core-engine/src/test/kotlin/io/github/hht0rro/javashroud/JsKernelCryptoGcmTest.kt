package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class JsKernelCryptoGcmTest {
    @Test
    fun kernel_aes128_and_aes256_gcm_vectors_authenticate_and_wipe_rejected_output() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the focused kernel GCM test")
        val nativeDir = resolveSource("src/main/native/js_crypto.c").parent
        val tempDir = Files.createTempDirectory("javashroud-kernel-gcm-")
        try {
            val harness = tempDir.resolve("kernel_gcm_test.c")
            val executable = tempDir.resolve(if (System.getProperty("os.name").startsWith("Windows", true)) "kernel_gcm_test.exe" else "kernel_gcm_test")
            Files.writeString(harness, harnessSource())
            val compile = run(
                listOf(
                    zig!!, "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    nativeDir.resolve("js_crypto.c").toString(), harness.toString(),
                    "-I", nativeDir.toString(), "-I", nativeDir.resolve("cross-compile").toString(),
                    "-o", executable.toString(),
                ),
                tempDir,
            )
            assertEquals(0, compile.exitCode, "kernel AES-GCM harness must compile:\n${compile.output}")
            val execution = run(listOf(executable.toString()), tempDir)
            assertEquals(0, execution.exitCode, "kernel AES-GCM vectors failed:\n${execution.output}")
        } finally {
            Files.walk(tempDir).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }

    private fun findZig(): String? = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig").firstOrNull { candidate ->
        runCatching {
            val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
            process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0
        }.getOrDefault(false)
    }

    private fun run(command: List<String>, directory: Path): ProcessResult {
        val process = ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).start()
        val completed = process.waitFor(90, TimeUnit.SECONDS)
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

    private fun harnessSource(): String = """
        #include "js_crypto.h"
        #include <stddef.h>
        #include <string.h>

        static int hex_decode(const char *hex, unsigned char *out, size_t size) {
            for (size_t i = 0; i < size; i++) {
                unsigned char hi = (unsigned char)hex[i * 2u], lo = (unsigned char)hex[i * 2u + 1u];
                int hv = hi >= '0' && hi <= '9' ? hi - '0' : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : -1;
                int lv = lo >= '0' && lo <= '9' ? lo - '0' : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : -1;
                if (hv < 0 || lv < 0) return 0;
                out[i] = (unsigned char)((hv << 4) | lv);
            }
            return hex[size * 2u] == '\0';
        }

        int main(void) {
            unsigned char key128[16] = {0}, nonce128[12] = {0}, sealed128[32], expected128[16] = {0}, out128[16];
            if (!hex_decode("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf", sealed128, sizeof(sealed128))) return 10;
            memset(out128, 0xa5, sizeof(out128));
            if (!js_aes_gcm_decrypt(key128, sizeof(key128), nonce128, NULL, 0u, sealed128, sizeof(sealed128), out128)) return 11;
            if (memcmp(out128, expected128, sizeof(out128)) != 0) return 12;
            sealed128[31] ^= 1u;
            memset(out128, 0xa5, sizeof(out128));
            if (js_aes_gcm_decrypt(key128, sizeof(key128), nonce128, NULL, 0u, sealed128, sizeof(sealed128), out128)) return 13;
            for (size_t i = 0; i < sizeof(out128); i++) if (out128[i] != 0u) return 14;

            unsigned char key256[32], nonce256[12], aad256[20], sealed256[80], expected256[64], out256[64];
            if (!hex_decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key256, sizeof(key256)) ||
                !hex_decode("cafebabefacedbaddecaf888", nonce256, sizeof(nonce256)) ||
                !hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad256, sizeof(aad256)) ||
                !hex_decode("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad2df7cd675b4f09163b41ebf980a7f638", sealed256, sizeof(sealed256)) ||
                !hex_decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", expected256, sizeof(expected256))) return 20;
            memset(out256, 0xa5, sizeof(out256));
            if (!js_aes_gcm_decrypt(key256, sizeof(key256), nonce256, aad256, sizeof(aad256), sealed256, sizeof(sealed256), out256)) return 21;
            if (memcmp(out256, expected256, sizeof(out256)) != 0) return 22;
            sealed256[79] ^= 1u;
            memset(out256, 0xa5, sizeof(out256));
            if (js_aes_gcm_decrypt(key256, sizeof(key256), nonce256, aad256, sizeof(aad256), sealed256, sizeof(sealed256), out256)) return 23;
            for (size_t i = 0; i < sizeof(out256); i++) if (out256[i] != 0u) return 24;
            return 0;
        }
    """.trimIndent()
}
