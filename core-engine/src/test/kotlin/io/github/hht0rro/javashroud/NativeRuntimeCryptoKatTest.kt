package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class NativeRuntimeCryptoKatTest {
    @Test
    fun r1_rust_crypto_contract_is_bounded_authenticated_wipe_only_and_software_only() {
        val rustRoot = rustRoot()
        val workspace = Files.readString(rustRoot.resolve("Cargo.toml"))
        val manifest = Files.readString(rustRoot.resolve("crates/jsrt-crypto/Cargo.toml"))
        val source = Files.readString(rustRoot.resolve("crates/jsrt-crypto/src/lib.rs"))

        assertTrue(workspace.contains("\"crates/jsrt-crypto\""), "R1 workspace must include jsrt-crypto")
        assertTrue(manifest.contains("name = \"jsrt-crypto\""), "jsrt-crypto manifest must be current")
        assertTrue(Files.isRegularFile(rustRoot.resolve("crates/jsrt-crypto/src/types.rs")), "jsrt-crypto must own Digest/Binding types")

        for (contract in listOf(
            "#![forbid(unsafe_code)]",
            "pub fn ghash(",
            "pub fn aes256_gcm_encrypt(",
            "pub fn aes256_gcm_decrypt(",
            "fn constant_time_tag_eq(",
            "difference |= expected[index] ^ actual[index];",
            "fn validate_gcm_inputs(",
            "fn validate_gcm_lengths(",
            "nonce.len() != GCM_NONCE_SIZE",
            "aad_len > MAX_PAYLOAD_SIZE",
            "payload_len > MAX_PAYLOAD_SIZE",
            "payload_blocks > MAX_GCM_BLOCKS",
            "checked_add(AES_BLOCK_SIZE - 1)",
            "bit_length(aad_len)?",
            "bit_length(payload_len)?",
            "AuthenticationFailed",
            "if !authenticated",
            "struct WipedVec(Vec<u8>);",
            "impl Drop for WipedVec",
            "impl Drop for GhashWorkspace",
            "impl Drop for GcmWorkspace",
            "self.0.fill(0);",
            "expected_tag.fill(0);",
            "tag.fill(0);",
            "fn ensure_software_backend(",
            "software_available()",
            "hardware_aes: false",
            "hardware_ghash: false",
        )) {
            assertTrue(source.contains(contract), "R1 crypto contract is missing: $contract")
        }

        assertRustTests(
            source,
            listOf(
                "authentication_tag_is_framed_and_constant_time",
                "aes256_gcm_matches_nist_vector_and_round_trips",
                "aes256_gcm_empty_vector_and_authentication_failures",
                "ghash_and_capability_gate_match_known_answers",
                "public_helpers_enforce_the_kotlin_r1_bounds",
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
