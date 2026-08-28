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
        val ffi = Files.readString(sourcePath("src/main/rust/crates/qp-ffi/src/lib.rs"))
        val helper = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"))
        val stringHelper = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpTextBridge.java"))
        assertTrue(ffi.contains("RegisterNatives"))
        assertTrue(ffi.contains("nativeOpenStringPage"))
        assertTrue(ffi.contains("nativeReadClassPage"))
        assertTrue(ffi.contains("nativeConsumeNativeSegment"))
        assertFalse(ffi.contains("jsn_k13"))
        assertTrue(helper.contains("nativeOpenStringPage"))
        assertTrue(stringHelper.contains("QpBridge.openQpString"))
        assertFalse(stringHelper.contains("nativeDecodeString(payload"))
    }

    @Test
    fun rust_shell_and_crypto_replace_the_retired_c_hardening_surface() {
        val pe = Files.readString(sourcePath("src/main/rust/crates/qp-shell/src/pe.rs"))
        val elf = Files.readString(sourcePath("src/main/rust/crates/qp-shell/src/elf.rs"))
        val crypto = Files.readString(sourcePath("src/main/rust/crates/qp-crypto/src/lib.rs"))
        val vm = Files.readString(sourcePath("src/main/rust/crates/qp-vm/src/lib.rs"))
        assertTrue(pe.contains("pub fn parse(bytes: &[u8])"))
        assertTrue(elf.contains("pub fn parse(bytes: &[u8])"))
        assertTrue(crypto.contains("aes256_gcm_decrypt"))
        assertTrue(vm.contains("qp_magic") || vm.contains("derived_vm_magic"))
        assertFalse(crypto.contains("js_aes256_expand_lanes"))
    }

    private fun sourcePath(relative: String): Path {
        val direct = Path.of(relative)
        if (Files.exists(direct)) return direct
        return Path.of("core-engine").resolve(relative)
    }
}
