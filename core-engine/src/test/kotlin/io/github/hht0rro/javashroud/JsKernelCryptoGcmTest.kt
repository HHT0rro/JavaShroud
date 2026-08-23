package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class JsKernelCryptoGcmTest {
    @Test
    fun r1_rust_gcm_contract_preserves_vectors_authentication_bounds_and_wipes() {
        val rustRoot = rustRoot()
        val manifest = Files.readString(rustRoot.resolve("crates/jsrt-crypto/Cargo.toml"))
        val source = Files.readString(rustRoot.resolve("crates/jsrt-crypto/src/lib.rs"))

        assertTrue(manifest.contains("name = \"jsrt-crypto\""), "GCM contract must use jsrt-crypto")
        for (contract in listOf(
            "pub fn aes256_gcm_encrypt(",
            "pub fn aes256_gcm_decrypt(",
            "fn ghash(",
            "fn constant_time_tag_eq(",
            "expected_tag.fill(0);",
            "nonce.len() != GCM_NONCE_SIZE",
            "aad_len > MAX_PAYLOAD_SIZE",
            "payload_len > MAX_PAYLOAD_SIZE",
            "AuthenticationFailed",
            "InvalidCiphertextLength",
            "impl Drop for GcmWorkspace",
            "hardware_aes: false",
            "hardware_ghash: false",
        )) {
            assertTrue(source.contains(contract), "R1 GCM contract is missing: $contract")
        }

        assertRustTests(
            source,
            listOf(
                "aes256_gcm_matches_nist_vector_and_round_trips",
                "aes256_gcm_empty_vector_and_authentication_failures",
                "ghash_and_capability_gate_match_known_answers",
            ),
        )
    }

    @Test
    fun r1_resource_and_vm_zstd_contracts_are_bounded_raw_rle_trailing_and_wiped() {
        val rustRoot = rustRoot()
        val vmManifest = Files.readString(rustRoot.resolve("crates/jsrt-vm/Cargo.toml"))
        val vmZstd = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/zstd.rs"))
        val resourceManifest = Files.readString(rustRoot.resolve("crates/jsrt-resource/Cargo.toml"))
        val resourceSource = Files.readString(rustRoot.resolve("crates/jsrt-resource/src/lib.rs"))

        assertTrue(vmManifest.contains("name = \"jsrt-vm\""), "VM manifest must be current")
        assertTrue(vmManifest.contains("jsrt-crypto.workspace = true"), "VM crate must use the workspace crypto crate")
        assertTrue(vmManifest.contains("unsafe_code = \"forbid\""), "VM must forbid unsafe code")
        for (contract in listOf(
            "const BLOCK_RAW: u32 = 0;",
            "const BLOCK_RLE: u32 = 1;",
            "Truncated",
            "TrailingBytes",
            "OutputTooLarge",
            "expected_length > maximum_length",
            "output.len() > expected_length",
            "offset != bytes.len()",
            "struct WipedVec(Vec<u8>);",
            "impl Drop for WipedVec",
            "self.0.fill(0);",
        )) {
            assertTrue(vmZstd.contains(contract), "R1 VM zstd contract is missing: $contract")
        }
        assertRustTests(vmZstd, listOf("raw_and_rle_frames_are_bounded", "malformed_or_trailing_frames_fail"))

        assertTrue(resourceManifest.contains("name = \"jsrt-resource\""), "resource manifest must be current")
        assertTrue(resourceManifest.contains("ruzstd"), "resource crate must use the Rust zstd decoder")
        assertTrue(resourceManifest.contains("unsafe_code = \"forbid\""), "resource must forbid unsafe code")
        for (contract in listOf(
            "#![forbid(unsafe_code)]",
            "use ruzstd::{BlockDecodingStrategy, FrameDecoder};",
            "pub fn decode_zstd_frame(",
            "pub fn encode_raw_or_rle_zstd(",
            "pub fn reset_and_wipe(",
            "MAX_ZSTD_WINDOW_SIZE",
            "MAX_ZSTD_FRAME_SIZE",
            "MAX_RESOURCE_SIZE",
            "Truncated",
            "ZstdMalformed",
            "ZstdTrailingBytes",
            "ZstdLengthMismatch",
            "ZstdWindowTooLarge",
            "ResourceTooLarge",
            "encoded.len() > self.max_frame_size",
            "expected_length > self.max_plaintext_size",
            "decoded.len() != expected_length",
            "constant_time_equals",
            "decoded.fill(0);",
            "WipedVec",
            "self.reset_and_wipe();",
        )) {
            assertTrue(resourceSource.contains(contract), "R1 resource zstd contract is missing: $contract")
        }
        assertRustTests(
            resourceSource,
            listOf(
                "raw_and_rle_zstd_frames_are_bounded_and_wiped",
                "malformed_trailing_and_window_frames_fail_closed",
                "authenticated_frame_checks_generation_before_decompression_and_wipes_context",
            ),
        )
    }

    private fun assertRustTests(source: String, names: List<String>) {
        for (name in names) {
            val test = Regex("""(?m)^\s*#\[test\]\s*fn\s+${Regex.escape(name)}\s*\(""")
            assertTrue(test.containsMatchIn(source), "Rust #[test] contract is missing: $name")
        }
    }

    private fun rustRoot(): Path {
        var current = Path.of("").toAbsolutePath().normalize()
        while (true) {
            for (candidate in listOf(
                current.resolve("core-engine").resolve("src").resolve("main").resolve("rust"),
                current.resolve("src").resolve("main").resolve("rust"),
            )) {
                if (Files.isRegularFile(candidate.resolve("Cargo.toml"))) return candidate
            }
            current = current.parent ?: break
        }
        error("Unable to locate core-engine/src/main/rust")
    }
}
