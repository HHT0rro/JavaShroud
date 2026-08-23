package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SelfDecryptBoundaryHardeningTest {
    @Test
    fun class_decrypt_boundary_is_the_typed_r1_native_route() {
        val classHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper.java")
        val kernelHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java")
        val ffi = source("src/main/rust/crates/jsrt-ffi/src/lib.rs")
        assertFalse("javax.crypto.Cipher" in classHelper, "Class loader decryption must not expose a Java JCA hook")
        assertFalse("deriveClassEncryptionKey(" in classHelper, "Class loader decryption must not receive a native-derived AES key")
        assertTrue("nativeReadAkenClassPage" in kernelHelper, "The sealed helper must declare the typed class-page bridge")
        assertTrue("nativeOpenAkenString" in kernelHelper)
        assertTrue("RegisterNatives" in ffi)
        assertTrue("nativeReadAkenClassPage" in ffi)
        assertFalse("jsn_k14" in ffi)
        assertFalse(Files.exists(resolveSource("src/main/native/js_vm_core.c")))
    }

    private fun source(relative: String): String = Files.readString(resolveSource(relative))

    private fun resolveSource(relative: String): Path {
        val direct = Path.of(relative)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relative)
    }
}
