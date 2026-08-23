package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeHelperHardeningTest {
    @Test
    fun c_native_runtime_is_retired_and_rust_owns_the_r1_surface() {
        assertFalse(Files.exists(sourcePath("src/main/native")), "C native product tree must be deleted")
        assertFalse(Files.exists(sourcePath("src/test/native")), "C native probe tree must be deleted")
        val ffi = Files.readString(sourcePath("src/main/rust/crates/jsrt-ffi/src/lib.rs"))
        val helper = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val stringHelper = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.java"))
        assertTrue(ffi.contains("RegisterNatives"))
        assertTrue(ffi.contains("nativeOpenAkenString"))
        assertTrue(ffi.contains("nativeReadAkenClassPage"))
        assertTrue(ffi.contains("nativeConsumeAkenNativeChunk"))
        assertFalse(ffi.contains("jsn_k13"))
        assertTrue(helper.contains("nativeOpenAkenString"))
        assertTrue(stringHelper.contains("JniMicrokernelHelper.openAkenString"))
        assertFalse(stringHelper.contains("nativeDecodeString(payload"))
    }

    @Test
    fun rust_shell_and_crypto_replace_the_retired_c_hardening_surface() {
        val pe = Files.readString(sourcePath("src/main/rust/crates/jsrt-shell/src/pe.rs"))
        val elf = Files.readString(sourcePath("src/main/rust/crates/jsrt-shell/src/elf.rs"))
        val crypto = Files.readString(sourcePath("src/main/rust/crates/jsrt-crypto/src/lib.rs"))
        val vm = Files.readString(sourcePath("src/main/rust/crates/jsrt-vm/src/lib.rs"))
        assertTrue(pe.contains("pub fn parse(bytes: &[u8])"))
        assertTrue(elf.contains("pub fn parse(bytes: &[u8])"))
        assertTrue(crypto.contains("aes256_gcm_decrypt"))
        assertTrue(vm.contains("VBC4_MAGIC"))
        assertFalse(crypto.contains("js_aes256_expand_lanes"))
    }

    private fun sourcePath(relative: String): Path {
        val direct = Path.of(relative)
        if (Files.exists(direct)) return direct
        return Path.of("core-engine").resolve(relative)
    }
}
