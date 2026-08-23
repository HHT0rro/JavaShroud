package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeRuntimeBenchmarkMatrixContractTest {
    @Test
    fun rust_r1_benchmark_contract_is_bounded_authenticated_software_only_and_workspace_locked() {
        val rustRoot = rustRoot()
        val workspace = Files.readString(rustRoot.resolve("Cargo.toml"))
        val cryptoManifest = Files.readString(rustRoot.resolve("crates/jsrt-crypto/Cargo.toml"))
        val crypto = Files.readString(rustRoot.resolve("crates/jsrt-crypto/src/lib.rs")) +
            Files.readString(rustRoot.resolve("crates/jsrt-crypto/src/types.rs"))
        val protocol = Files.readString(rustRoot.resolve("crates/jsrt-page/src/frame.rs"))
        val vmManifest = Files.readString(rustRoot.resolve("crates/jsrt-vm/Cargo.toml"))
        val vm = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/lib.rs"))
        val zstd = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/zstd.rs"))
        val executor = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/executor.rs"))

        assertEquals(
            listOf(
                "crates/jsrt-ffi",
                "crates/jsrt-runtime",
                "crates/jsrt-crypto",
                "crates/jsrt-page",
                "crates/jsrt-resource",
                "crates/jsrt-vm",
                "crates/jsrt-shell",
            ),
            workspaceMembers(workspace),
            "current R1 workspace members",
        )
        for (marker in listOf(
            "[workspace.metadata.aken-r1]",
            "runtime_abi = \"jsrt_ffi\"",
            "runtime_resource_root = \"META-INF/jsrt\"",
            "rust_toolchain = \"1.78.0\"",
            "windows_target = \"x86_64-pc-windows-gnu\"",
            "linux_glibc_floor = \"2.17\"",
            "unsafe_code = \"deny\"",
        )) {
            assertContains(workspace, marker, "R1 workspace")
        }

        assertContains(cryptoManifest, "name = \"jsrt-crypto\"", "jsrt-crypto manifest")
        assertContains(vmManifest, "name = \"jsrt-vm\"", "jsrt-vm manifest")
        assertContains(vmManifest, "unsafe_code = \"forbid\"", "jsrt-vm manifest")
        assertNoUnsafe(crypto, "jsrt-crypto")
        assertNoUnsafe(vm, "jsrt-vm")

        for (testName in listOf(
            "authentication_tag_is_framed_and_constant_time",
            "ghash_and_capability_gate_match_known_answers",
            "public_helpers_enforce_the_kotlin_r1_bounds",
        )) {
            assertRustTest(crypto, testName)
        }
        for (testName in listOf(
            "cursor_and_writer_are_explicit_and_bounds_checked",
            "authenticated_round_trip_happens_after_digest_check",
            "malformed_payload_is_not_returned_before_authentication",
        )) {
            assertRustTest(protocol, testName)
        }
        for (testName in listOf(
            "raw_and_rle_frames_are_bounded",
            "malformed_or_trailing_frames_fail",
            "frame_state_is_wiped_after_failure",
        )) {
            val source = if (testName.startsWith("frame_state")) executor else zstd
            assertRustTest(source, testName)
        }

        for (marker in listOf(
            "pub const MAX_PAYLOAD_SIZE",
            "pub fn aes256_gcm_encrypt(",
            "pub fn aes256_gcm_decrypt(",
            "fn validate_gcm_lengths(",
            "MAX_GCM_BLOCKS",
            "fn ensure_software_backend(",
            "software_available()",
            "hardware_aes: false",
            "hardware_ghash: false",
        )) {
            assertContains(crypto, marker, "software-only R1 crypto policy")
        }
        val decrypt = crypto.substringAfter("pub fn aes256_gcm_decrypt(")
        assertOrder(decrypt, "let authenticated =", "let mut plaintext", "GCM authentication before decryption")

        for (marker in listOf(
            "pub const VBC4_MAX_FRAME_SIZE",
            "pub const VBC4_MAX_SECTION_SIZE",
            "pub struct ParserLimits",
            "parser limit exceeds the R1 bound",
            "if frame.len() > self.limits.max_frame_size",
            "let expected_mac =",
            "vbc4_hmac_fields(",
            "if !ct_eq(&expected_mac",
            "let result = self.parse_sections(",
            "zstd::decompress(",
            "WipedBytes",
        )) {
            assertContains(vm, marker, "R1 VM benchmark contract")
        }
        assertOrder(
            vm.substringAfter("fn parse_authenticated("),
            "if !ct_eq(&expected_mac",
            "let result = self.parse_sections(",
            "VM authentication before section parse/decompression",
        )
        assertContains(executor, "frame.wipe();", "R1 VM execution wipe contract")
    }

    private fun workspaceMembers(manifest: String): List<String> {
        val block = Regex("(?s)members\\s*=\\s*\\[(.*?)\\]")
            .find(manifest)
            ?.groupValues
            ?.get(1)
            ?: error("current R1 workspace members are missing")
        return Regex("(?m)^\\s*\"([^\"]+)\"\\s*,?\\s*$")
            .findAll(block)
            .map { it.groupValues[1] }
            .toList()
    }

    private fun assertContains(source: String, marker: String, contract: String) {
        assertTrue(source.contains(marker), "$contract must contain `$marker`")
    }

    private fun assertNoUnsafe(source: String, contract: String) {
        assertContains(source, "#![forbid(unsafe_code)]", contract)
        assertTrue(!Regex("\\bunsafe\\s*\\{").containsMatchIn(source), "$contract must not contain unsafe blocks")
    }

    private fun assertRustTest(source: String, testName: String) {
        assertTrue(
            Regex("(?m)^\\s*#\\[test\\]\\s*fn\\s+${Regex.escape(testName)}\\s*\\(").containsMatchIn(source),
            "Rust #[test] contract is missing: $testName",
        )
    }

    private fun assertOrder(source: String, first: String, second: String, contract: String) {
        val firstIndex = source.indexOf(first)
        val secondIndex = source.indexOf(second)
        assertTrue(firstIndex >= 0 && secondIndex > firstIndex, "$contract must keep `$first` before `$second`")
    }

    private fun rustRoot(): Path {
        var current = Path.of("").toAbsolutePath().normalize()
        while (true) {
            for (candidate in listOf(
                current.resolve("core-engine/src/main/rust"),
                current.resolve("src/main/rust"),
            )) {
                if (Files.isRegularFile(candidate.resolve("Cargo.toml"))) return candidate
            }
            current = current.parent ?: break
        }
        error("Unable to locate core-engine/src/main/rust")
    }
}
