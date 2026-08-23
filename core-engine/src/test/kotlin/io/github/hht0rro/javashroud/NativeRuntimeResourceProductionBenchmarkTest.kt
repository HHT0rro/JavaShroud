package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class NativeRuntimeResourceProductionBenchmarkTest {
    @Test
    fun rust_r1_resource_cache_page_and_lifecycle_contracts_are_bounded_authenticated_and_wiped() {
        val rustRoot = rustRoot()
        val resourceManifest = Files.readString(rustRoot.resolve("crates/jsrt-resource/Cargo.toml"))
        val resource = Files.readString(rustRoot.resolve("crates/jsrt-resource/src/lib.rs"))
        val pageManifest = Files.readString(rustRoot.resolve("crates/jsrt-page/Cargo.toml"))
        val page = Files.readString(rustRoot.resolve("crates/jsrt-page/src/lib.rs"))
        val runtimeManifest = Files.readString(rustRoot.resolve("crates/jsrt-runtime/Cargo.toml"))
        val runtime = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/lib.rs"))
        val lifecycle = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/lifecycle.rs"))

        assertContains(resourceManifest, "name = \"jsrt-resource\"", "jsrt-resource manifest")
        assertContains(resourceManifest, "ruzstd.workspace = true", "jsrt-resource manifest")
        assertContains(resourceManifest, "unsafe_code = \"forbid\"", "jsrt-resource manifest")
        assertContains(pageManifest, "name = \"jsrt-page\"", "jsrt-page manifest")
        assertContains(pageManifest, "unsafe_code = \"forbid\"", "jsrt-page manifest")
        assertContains(runtimeManifest, "name = \"jsrt-runtime\"", "jsrt-runtime manifest")
        assertNoUnsafe(resource, "jsrt-resource")
        assertNoUnsafe(page, "jsrt-page")
        assertNoUnsafe(runtime, "jsrt-runtime")

        for (testName in listOf(
            "directory_is_r1_only_sorted_and_binary_searchable",
            "directory_authentication_rejects_reordering_and_tampering",
            "raw_and_rle_zstd_frames_are_bounded_and_wiped",
            "malformed_trailing_and_window_frames_fail_closed",
            "authenticated_frame_checks_generation_before_decompression_and_wipes_context",
            "generation_leases_retire_and_unload_with_bounded_wait",
            "generation_lease_can_be_released_from_another_thread",
        )) {
            assertRustTest(resource, testName)
        }
        for (testName in listOf(
            "page_round_trip_has_exact_header_offsets_and_strict_bounds",
            "page_header_and_locator_tamper_fail_before_plaintext",
            "lease_only_exposes_authenticated_payload_and_transitions_once",
        )) {
            assertRustTest(page, testName)
        }
        for (testName in listOf(
            "artifact_index_is_sorted_and_uses_binary_search",
            "arenas_wipe_after_success_and_failure_paths",
            "retirement_wait_is_bounded_and_final_release_wipes_generation",
            "replayed_generation_ids_are_rejected_after_retirement",
            "multiple_threads_hold_retiring_leases_until_their_work_finishes",
            "invalid_generation_limits_fail_before_runtime_activation",
        )) {
            assertRustTest(lifecycle, testName)
        }

        for (marker in listOf(
            "pub const MAX_DIRECTORY_ENTRIES",
            "pub const MAX_DIRECTORY_SIZE",
            "pub const MAX_RESOURCE_SIZE",
            "pub const MAX_STORED_SIZE",
            "pub const MAX_ZSTD_WINDOW_SIZE",
            "pub const MAX_ZSTD_FRAME_SIZE",
            "pub fn decode_resource(",
            "fn decode_resource_inner(",
            "let view = parse_frame(encoded)?;",
            "let expected_tag = authenticate(",
            "context.decode_zstd(",
            "pub struct DecoderContext",
            "pub fn reset_and_wipe(",
            "impl Drop for DecoderContext",
            "pub struct ResourceGeneration",
            "pub struct ResourceLease<'a>",
            "GenerationState::Retiring",
            "GenerationState::Unloaded",
            "pub fn wait_for_unload(",
        )) {
            assertContains(resource, marker, "R1 resource generation/decompression contract")
        }
        val resourceDecode = resource.substringAfter("fn decode_resource_inner(")
        assertOrder(resourceDecode, "require_auth_key(auth_key)?;", "let view = parse_frame(encoded)?;", "resource key validation before parse")
        assertOrder(resourceDecode, "let expected_tag = authenticate(", "context.decode_zstd(", "resource authentication before decompression")

        for (marker in listOf(
            "pub const MAX_CACHE_ENTRIES",
            "pub const MAX_CACHE_VALUE_SIZE",
            "pub struct FixedCache",
            "pub fn insert(",
            "pub fn clear_and_wipe(",
            "self.clear_and_wipe();",
            "pub struct RuntimeGeneration",
            "pub struct RuntimeLease",
            "pub fn begin_retirement(",
            "active_leases",
            "resources.wipe_and_clear();",
            "pub fn is_wiped(",
        )) {
            assertContains(lifecycle, marker, "R1 cache/lifecycle contract")
        }

        for (marker in listOf(
            "pub const MAX_PAGE_FRAME_SIZE",
            "pub const MAX_PAGE_PLAINTEXT_SIZE",
            "pub fn encode_page(",
            "pub fn decode_page(",
            "pub fn open_r1_frame(",
            "fn gcm_decrypt(",
            "let authenticated = constant_time_eq(",
            "if !authenticated",
            "pub fn wipe(&mut self)",
        )) {
            assertContains(page, marker, "R1 page authentication/bounds/wipe contract")
        }
        val pageDecrypt = page.substringAfter("fn gcm_decrypt(")
        assertOrder(pageDecrypt, "let authenticated = constant_time_eq(", "let plain = ctr_crypt(", "page authentication before plaintext")
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
