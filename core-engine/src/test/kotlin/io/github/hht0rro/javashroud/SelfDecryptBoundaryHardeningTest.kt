package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SelfDecryptBoundaryHardeningTest {
    @Test
    fun class_decrypt_boundary_is_native_and_sensitive_entries_are_forced_guarded() {
        val classHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper.java")
        val kernelHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java")
        val vmCore = source("src/main/native/js_vm_core.c")
        val jniRuntime = source("src/main/native/js_jni_runtime.c")
        val shellStub = source("src/main/native/js_shell_stub.c")
        val antiDebug = source("src/main/native/js_antidebug.c")

        assertFalse("javax.crypto.Cipher" in classHelper, "Class loader decryption must not expose a Java JCA hook")
        assertFalse("deriveClassEncryptionKey(" in classHelper, "Class loader decryption must not receive a native-derived AES key")
        assertTrue("nativeDecryptClassBytes" in kernelHelper, "The sealed helper must declare the native class decrypt bridge")
        assertTrue("nativeSealedBindingKey" in kernelHelper, "Post-load keyed binding lookup must remain native after Java boot material is wiped")
        assertTrue("public static byte[] decryptClassBytes" in kernelHelper, "The sealed helper bridge must remain accessible after helper relocation")
        assertTrue("jsn_k14" in vmCore && "js_aes_gcm_decrypt" in functionBody(vmCore, "jsn_k14"), "Native class decryption must authenticate and decrypt in the kernel")
        assertTrue("js_sealed_binding_key" in functionBody(vmCore, "jsn_k15"), "Native binding lookup must use the resident keyed identity implementation")
        assertTrue(
            "{js_native_name(\"De\", \"cryptClass\", \"Bytes\"), \"([B[B[B[B[BI)[B\", (void*)jsw_k14}" in jniRuntime,
            "The nativeDecryptClassBytes method name, descriptor, and wrapper must share one RegisterNatives row",
        )
        assertTrue(
            "{js_native_name(\"Sealed\", \"Binding\", \"Key\"), \"([B)Ljava/lang/String;\", (void*)jsw_k15}" in jniRuntime,
            "The nativeSealedBindingKey method must be registered through the guarded native wrapper",
        )
        assertTrue(
            "native_decrypt_class_bytes" in shellStub &&
                "js_shell_native_decrypt_class_bytes" in shellStub &&
                "([B[B[B[B[BI)[B" in shellStub,
            "The packed shell must forward the native class-decrypt bridge through its versioned ABI and RegisterNatives table",
        )
        assertTrue(
            "native_sealed_binding_key" in shellStub &&
                "js_shell_native_sealed_binding_key" in shellStub &&
                "([B)Ljava/lang/String;" in shellStub,
            "The packed shell must forward native keyed binding lookups after Java boot material cleanup",
        )
        assertTrue("js_vm_strong_debugger_present_now" in antiDebug, "Sensitive paths need a fresh debugger probe")

        listOf("jsn_k7", "jsn_k10", "jsn_k14", "jsn_k15", "jsn_r21").forEach { entry ->
            assertTrue(
                "js_vm_sensitive_path_guard(env, (const void*)$entry, 1)" in functionBody(vmCore, entry),
                "$entry must reject debugger, instrumentation, and trampoline entry before material handling",
            )
        }
        listOf("jsw_k7", "jsw_k10", "jsw_k14", "jsw_k15", "jsw_r21").forEach { wrapper ->
            assertTrue(
                "js_vm_sensitive_path_guard(env, (const void*)$wrapper, 1)" in functionBody(jniRuntime, wrapper),
                "$wrapper must authenticate its RegisterNatives dispatch entry before forwarding sensitive JNI arguments",
            )
        }
        assertTrue(
            "id_len > 4096 - salt_len" in functionBody(vmCore, "jsn_k10"),
            "legacy class-key derivation must bound the pair without signed jsize addition",
        )
        assertTrue(
            "key_id_len > 4096 - salt_len" in functionBody(vmCore, "jsn_k14"),
            "native class decryption must bound key metadata without signed jsize addition",
        )
    }

    private fun functionBody(source: String, name: String): String {
        val start = source.indexOf("$name(")
        check(start >= 0) { "Missing native entry $name" }
        val openingBrace = source.indexOf('{', start)
        check(openingBrace >= 0) { "Missing function body for $name" }
        var depth = 0
        for (index in openingBrace until source.length) {
            when (source[index]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return source.substring(start, index + 1)
            }
        }
        error("Unterminated function body for $name")
    }

    private fun source(relative: String): String = Files.readString(resolveSource(relative))

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
}
