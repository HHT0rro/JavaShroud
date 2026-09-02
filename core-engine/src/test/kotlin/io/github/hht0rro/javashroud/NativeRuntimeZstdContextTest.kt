package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class NativeRuntimeZstdContextTest {
    @Test
    fun rust_native_crypto_contracts_are_bounded_authenticated_and_wipe_only() {
        val rustRoot = resolveRustRoot()
        val workspaceManifest = Files.readString(rustRoot.resolve("Cargo.toml"))
        val manifest = Files.readString(rustRoot.resolve("crates/qp-crypto/Cargo.toml"))
        val source = Files.readString(rustRoot.resolve("crates/qp-crypto/src/lib.rs"))

        assertContains(workspaceManifest, "crates/qp-crypto", "Rust workspace")
        assertContains(workspaceManifest, "unsafe_code = \"deny\"", "Rust workspace")
        assertContains(manifest, "name = \"qp-crypto\"", "qp-crypto manifest")
        assertContains(source, "#![forbid(unsafe_code)]", "qp-crypto")
        for (testName in listOf(
            "authentication_tag_is_framed_and_constant_time",
            "aes256_gcm_matches_nist_vector_and_round_trips",
            "aes256_gcm_empty_vector_and_authentication_failures",
            "ghash_and_capability_gate_match_known_answers",
            "public_helpers_enforce_the_current_bounds",
        )) {
            assertRustTest(source, testName)
        }

        for (marker in listOf(
            "pub fn aes256_gcm_encrypt(",
            "pub fn aes256_gcm_decrypt(",
            "pub fn ghash(",
            "fn ghash_multiply_software(",
            "fn constant_time_tag_eq(",
            "difference |= expected[index] ^ actual[index]",
            "const GCM_NONCE_SIZE: usize = 12;",
            "fn validate_gcm_inputs(",
            "if nonce.len() != GCM_NONCE_SIZE",
            "fn validate_gcm_lengths(",
            "aad_len > MAX_PAYLOAD_SIZE",
            "payload_len > MAX_PAYLOAD_SIZE",
            "MAX_GCM_BLOCKS",
            "fn bit_length(",
            "checked_mul(8)",
            "impl Drop for GhashWorkspace",
            "impl Drop for GcmWorkspace",
            "impl Drop for WipedVec",
            "self.nonce.fill(0);",
            "self.aad.fill(0);",
            "hardware_aes: false",
            "hardware_ghash: false",
        )) {
            assertContains(source, marker, "qp-crypto contract")
        }

        val decrypt = source.substringAfter("pub fn aes256_gcm_decrypt(").substringBefore("fn ensure_software_backend(")
        val tagCheck = decrypt.indexOf("constant_time_tag_eq")
        val plaintextDecrypt = decrypt.indexOf("workspace.crypt_payload")
        assertTrue(
            tagCheck >= 0 && plaintextDecrypt > tagCheck,
            "AES-256-GCM must authenticate the tag before decrypting plaintext",
        )
        assertContains(decrypt, "Err(CryptoError::AuthenticationFailed)", "AES-256-GCM authentication")
    }

    @Test
    fun rust_native_zstd_contracts_are_bounded_and_wipe_only() {
        val rustRoot = resolveRustRoot()
        val resourceManifest = Files.readString(rustRoot.resolve("crates/qp-resource/Cargo.toml"))
        val resourceSource = Files.readString(rustRoot.resolve("crates/qp-resource/src/lib.rs"))
        val vmManifest = Files.readString(rustRoot.resolve("crates/qp-vm/Cargo.toml"))
        val vmSource = Files.readString(rustRoot.resolve("crates/qp-vm/src/zstd.rs"))
        val vmCrateSource = Files.readString(rustRoot.resolve("crates/qp-vm/src/lib.rs"))
        val runtimeManifest = Files.readString(rustRoot.resolve("crates/qp-runtime/Cargo.toml"))
        val lifecycleSource = Files.readString(rustRoot.resolve("crates/qp-runtime/src/lifecycle.rs"))

        assertContains(resourceManifest, "name = \"qp-resource\"", "qp-resource manifest")
        assertContains(resourceManifest, "ruzstd", "qp-resource manifest")
        assertContains(resourceManifest, "unsafe_code = \"forbid\"", "qp-resource manifest")
        assertContains(resourceSource, "#![forbid(unsafe_code)]", "qp-resource")
        assertContains(resourceSource, "FrameDecoder", "qp-resource Zstd adapter")
        for (testName in listOf(
            "raw_and_rle_zstd_frames_are_bounded_and_wiped",
            "compressed_zstd_block_decodes_without_c_or_sys_dependencies",
            "malformed_trailing_and_window_frames_fail_closed",
            "authenticated_frame_checks_generation_before_decompression_and_wipes_context",
        )) {
            assertRustTest(resourceSource, testName)
        }
        for (marker in listOf(
            "pub const MAX_ZSTD_WINDOW_SIZE",
            "pub const MAX_ZSTD_FRAME_SIZE",
            "pub struct DecoderContext",
            "pub fn decode_zstd(",
            "if expected_length > self.max_plaintext_size",
            "if encoded.len() > self.max_frame_size",
            "pub fn reset_and_wipe(",
            "impl Drop for DecoderContext",
            "pub fn encode_raw_or_rle_zstd(",
            "write_zstd_block_header(&mut output, last, 1, length)",
            "write_zstd_block_header(&mut output, last, 0, length)",
            "ResourceError::Truncated",
            "ResourceError::ZstdTrailingBytes",
            "ResourceError::ZstdLengthMismatch",
            "decoded.len() != expected_length",
            "decoded.fill(0);",
            "self.window.fill(0);",
        )) {
            assertContains(resourceSource, marker, "qp-resource Zstd contract")
        }

        assertContains(vmManifest, "name = \"qp-vm\"", "qp-vm manifest")
        assertContains(vmManifest, "unsafe_code = \"forbid\"", "qp-vm manifest")
        assertContains(vmCrateSource, "#![forbid(unsafe_code)]", "qp-vm")
        for (marker in listOf(
            "const BLOCK_RAW: u32 = 0;",
            "const BLOCK_RLE: u32 = 1;",
            "pub(crate) fn decompress(",
            "expected_length > maximum_length",
            "if output.len() > expected_length",
            "ZstdError::Truncated",
            "ZstdError::TrailingBytes",
            "ZstdError::OutputTooLarge",
            "impl Drop for WipedVec",
            "self.0.fill(0);",
        )) {
            assertContains(vmSource, marker, "qp-vm Zstd contract")
        }
        assertRustTest(vmSource, "raw_and_rle_frames_are_bounded")
        assertRustTest(vmSource, "malformed_or_trailing_frames_fail")

        assertContains(runtimeManifest, "name = \"qp-runtime\"", "qp-runtime manifest")
        assertContains(lifecycleSource, "pub fn reset_and_wipe(", "Rust runtime wipe contract")
        assertContains(lifecycleSource, "impl Drop for SensitiveArena", "Rust runtime RAII wipe contract")
        assertContains(lifecycleSource, "impl Drop for DecoderContext", "Rust runtime RAII wipe contract")
        assertRustTest(lifecycleSource, "arenas_wipe_after_success_and_failure_paths")
    }

    private fun assertContains(source: String, marker: String, contract: String) {
        assertTrue(source.contains(marker), "$contract must contain `$marker`")
    }

    private fun assertRustTest(source: String, testName: String) {
        assertTrue(
            Regex("""#\[test]\s+fn\s+$testName\s*\(""").containsMatchIn(source),
            "Rust source must retain #[test] fn $testName",
        )
    }

    private fun resolveRustRoot(): Path {
        var current = Path.of("").toAbsolutePath().normalize()
        while (true) {
            for (relative in listOf(
                Path.of("src", "main", "rust"),
                Path.of("core-engine", "src", "main", "rust"),
            )) {
                val candidate = current.resolve(relative)
                if (Files.isDirectory(candidate)) return candidate
            }
            current = current.parent ?: error("Unable to locate core-engine/src/main/rust")
        }
    }
}
