package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeShellLoaderProductionBenchmarkTest {
    @Test
    fun r1_rust_runtime_contracts_are_bounded_authenticated_and_wiped() {
        val rustRoot = rustRoot()
        val workspace = Files.readString(rustRoot.resolve("Cargo.toml"))
        val crypto = Files.readString(rustRoot.resolve("crates/jsrt-crypto/src/lib.rs"))
        val cryptoManifest = Files.readString(rustRoot.resolve("crates/jsrt-crypto/Cargo.toml"))
        val resource = Files.readString(rustRoot.resolve("crates/jsrt-resource/src/lib.rs"))
        val resourceManifest = Files.readString(rustRoot.resolve("crates/jsrt-resource/Cargo.toml"))
        val vm = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/lib.rs"))
        val vmExecutor = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/executor.rs"))
        val vmZstd = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/zstd.rs"))
        val vmManifest = Files.readString(rustRoot.resolve("crates/jsrt-vm/Cargo.toml"))
        val page = Files.readString(rustRoot.resolve("crates/jsrt-page/src/lib.rs"))
        val pageManifest = Files.readString(rustRoot.resolve("crates/jsrt-page/Cargo.toml"))
        val runtime = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/lib.rs"))
        val lifecycle = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/lifecycle.rs"))
        val runtimeManifest = Files.readString(rustRoot.resolve("crates/jsrt-runtime/Cargo.toml"))

        val expectedMembers = listOf(
            "crates/jsrt-ffi",
            "crates/jsrt-runtime",
            "crates/jsrt-crypto",
            "crates/jsrt-page",
            "crates/jsrt-resource",
            "crates/jsrt-vm",
            "crates/jsrt-shell",
        )
        val members = workspace.substringAfter("members = [").substringBefore("]")
            .lineSequence()
            .map(String::trim)
            .filter { it.startsWith("\"") }
            .map { it.removeSuffix(",").removeSurrounding("\"") }
            .toList()
        assertEquals(expectedMembers, members, "Cargo workspace members must be the current R1 set")
        assertContains(workspace, "runtime_abi = \"jsrt_ffi\"", "R1 workspace metadata")
        assertContains(workspace, "unsafe_code = \"deny\"", "R1 workspace lint policy")

        assertContains(cryptoManifest, "name = \"jsrt-crypto\"", "jsrt-crypto manifest")
        assertContains(crypto, "#![forbid(unsafe_code)]", "jsrt-crypto")
        for (marker in listOf(
            "pub fn aes256_gcm_encrypt(",
            "pub fn aes256_gcm_decrypt(",
            "fn validate_gcm_inputs(",
            "aad_len > MAX_PAYLOAD_SIZE",
            "payload_len > MAX_PAYLOAD_SIZE",
            "fn ensure_software_backend(",
            "software_available()",
            "hardware_aes: false",
            "hardware_ghash: false",
            "impl Drop for WipedVec",
            "expected_tag.fill(0);",
        )) {
            assertContains(crypto, marker, "software-only crypto R1 contract")
        }
        assertRustTests(
            crypto,
            "authentication_tag_is_framed_and_constant_time",
            "aes256_gcm_matches_nist_vector_and_round_trips",
            "aes256_gcm_empty_vector_and_authentication_failures",
            "ghash_and_capability_gate_match_known_answers",
            "public_helpers_enforce_the_kotlin_r1_bounds",
        )

        assertContains(resourceManifest, "name = \"jsrt-resource\"", "jsrt-resource manifest")
        assertContains(resourceManifest, "unsafe_code = \"forbid\"", "jsrt-resource lint policy")
        assertContains(resource, "#![forbid(unsafe_code)]", "jsrt-resource")
        for (marker in listOf(
            "pub const MAX_DIRECTORY_ENTRIES",
            "pub const MAX_DIRECTORY_SIZE",
            "pub const MAX_RESOURCE_SIZE",
            "pub const MAX_FRAME_SIZE",
            "pub const MAX_ZSTD_WINDOW_SIZE",
            "pub fn decode_resource(",
            "pub fn decode_zstd_frame(",
            "if encoded.len() > MAX_FRAME_SIZE",
            "expected_length > self.max_plaintext_size",
            "constant_time_equals",
            "pub fn reset_and_wipe(",
            "self.window.fill(0);",
            "generation",
            "lease_count",
        )) {
            assertContains(resource, marker, "resource bounds/authentication/lifecycle contract")
        }
        val resourceDecode = resource.substringAfter("fn decode_resource_inner(")
        assertOrdered(
            resourceDecode,
            "let view = parse_frame(encoded)?;",
            "let expected_tag = authenticate(",
            "resource authentication must precede body handling",
        )
        assertOrdered(
            resourceDecode,
            "let expected_tag = authenticate(",
            "context.decode_zstd(",
            "resource authentication must precede decompression",
        )
        assertRustTests(
            resource,
            "directory_is_r1_only_sorted_and_binary_searchable",
            "directory_authentication_rejects_reordering_and_tampering",
            "raw_and_rle_zstd_frames_are_bounded_and_wiped",
            "compressed_zstd_block_decodes_without_c_or_sys_dependencies",
            "malformed_trailing_and_window_frames_fail_closed",
            "authenticated_frame_checks_generation_before_decompression_and_wipes_context",
            "generation_leases_retire_and_unload_with_bounded_wait",
            "generation_lease_can_be_released_from_another_thread",
        )

        assertContains(vmManifest, "name = \"jsrt-vm\"", "jsrt-vm manifest")
        assertContains(vmManifest, "unsafe_code = \"forbid\"", "jsrt-vm lint policy")
        assertContains(vm, "#![forbid(unsafe_code)]", "jsrt-vm")
        for (marker in listOf(
            "pub const VBC4_MAX_FRAME_SIZE",
            "pub const VBC4_MAX_SECTION_SIZE",
            "pub const VBC4_MAX_INSTRUCTIONS",
            "pub struct ParserLimits",
            "parser limit exceeds the R1 bound",
            "if frame.len() > self.limits.max_frame_size",
            "fn parse_authenticated(",
            "AuthenticationFailed",
            "impl Drop for VmKeyMaterial",
            "session_wipe.fill(0);",
        )) {
            assertContains(vm, marker, "VM parser bounds/authentication contract")
        }
        val vmAuthenticated = vm.substringAfter("fn parse_authenticated(")
        assertOrdered(
            vmAuthenticated,
            "let expected_mac =",
            "if !ct_eq",
            "VM parsing must verify its MAC before accepting sections",
        )
        assertOrdered(
            vmAuthenticated,
            "if !ct_eq",
            "self.parse_sections(",
            "VM parsing must authenticate before parsing sections",
        )
        for (marker in listOf(
            "const BLOCK_RAW: u32 = 0;",
            "const BLOCK_RLE: u32 = 1;",
            "expected_length > maximum_length",
            "if output.len() > expected_length",
            "ZstdError::TrailingBytes",
            "ZstdError::OutputTooLarge",
            "impl Drop for WipedVec",
            "self.0.fill(0);",
        )) {
            assertContains(vmZstd, marker, "VM decompressor bounds/wipe contract")
        }
        assertRustTests(vmZstd, "raw_and_rle_frames_are_bounded", "malformed_or_trailing_frames_fail")
        assertRustTests(
            vmExecutor,
            "wrapping_integer_arithmetic_and_branches_execute",
            "call_uses_safe_host_trait_and_exception_handler",
            "divide_by_zero_is_caught_by_bounded_handler",
            "frame_state_is_wiped_after_failure",
        )

        assertContains(pageManifest, "name = \"jsrt-page\"", "jsrt-page manifest")
        assertContains(pageManifest, "unsafe_code = \"forbid\"", "jsrt-page lint policy")
        assertContains(page, "#![forbid(unsafe_code)]", "jsrt-page")
        for (marker in listOf(
            "pub const MAX_PAYLOAD_SIZE",
            "pub const MAX_PAGE_FRAME_SIZE",
            "pub const MAX_PAGE_KEY_SIZE",
            "pub fn encode_r1_frame(",
            "pub fn open_r1_frame(",
            "pub fn authenticate(&mut self",
            "self.encoded.fill(0);",
            "self.dek.fill(0);",
            "fn wipe_buffers(",
            "pub fn wipe(&mut self)",
        )) {
            assertContains(page, marker, "page bounds/lease/wipe contract")
        }
        assertRustTests(
            page,
            "page_round_trip_has_exact_header_offsets_and_strict_bounds",
            "page_header_and_locator_tamper_fail_before_plaintext",
            "descriptor_route_proof_and_evaluator_are_exact_and_bounded",
            "envelope_authenticates_inline_and_compact_forms",
            "locator_binding_is_route_and_descriptor_bound",
            "page_keys_sort_and_reject_duplicates",
            "lease_only_exposes_authenticated_payload_and_transitions_once",
        )

        assertContains(runtimeManifest, "name = \"jsrt-runtime\"", "jsrt-runtime manifest")
        assertContains(runtime, "#![forbid(unsafe_code)]", "jsrt-runtime")
        assertContains(runtime, "authenticate-before-parse", "runtime authentication boundary")
        assertContains(runtime, "pub fn authenticate_frame(", "runtime authentication entrypoint")
        assertContains(runtime, "RuntimeEnvelope::open(&self.binding, frame)", "runtime authenticated envelope")
        assertRustTests(runtime, "runtime_requires_supported_target_and_authenticates_before_opening")

        for (marker in listOf(
            "pub const MAX_CACHE_ENTRIES",
            "pub const MAX_CACHE_VALUE_SIZE",
            "pub const MAX_SENSITIVE_ARENA_SIZE",
            "pub const MAX_VM_FRAMES",
            "pub const MAX_DECODER_WORKSPACE_SIZE",
            "pub struct FixedCache",
            "CacheFull",
            "CacheValueTooLarge",
            "pub fn clear_and_wipe(",
            "pub fn reset_and_wipe(",
            "pub fn acquire(self: &Arc<Self>)",
            "pub fn begin_retirement(",
            "pub fn wait_for_unload(",
            "pub fn is_wiped(",
            "resources.wipe_and_clear();",
            "impl Drop for SensitiveArena",
            "impl Drop for VmFrameArena",
            "impl Drop for DecoderContext",
        )) {
            assertContains(lifecycle, marker, "cache/generation/lease/wipe lifecycle contract")
        }
        assertRustTests(
            lifecycle,
            "artifact_index_is_sorted_and_uses_binary_search",
            "arenas_wipe_after_success_and_failure_paths",
            "retirement_wait_is_bounded_and_final_release_wipes_generation",
            "replayed_generation_ids_are_rejected_after_retirement",
            "multiple_threads_hold_retiring_leases_until_their_work_finishes",
            "invalid_generation_limits_fail_before_runtime_activation",
        )
    }

    @Test
    fun native_shell_loader_r1_contract_rejects_unsafe_pe_elf_and_legacy_formats() {
        val rustRoot = rustRoot()
        val shellManifest = Files.readString(rustRoot.resolve("crates/jsrt-shell/Cargo.toml"))
        val shell = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/lib.rs"))
        val payload = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/payload.rs"))
        val pe = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/pe.rs"))
        val elf = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/elf.rs"))
        val loaderManifest = Files.readString(rustRoot.resolve("crates/jsrt-shell/Cargo.toml"))
        val loader = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/loader.rs"))
        val runtimeShell = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/shell.rs"))
        val platform = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/platform.rs"))

        assertContains(shellManifest, "name = \"jsrt-shell\"", "jsrt-shell manifest")
        assertContains(shellManifest, "unsafe_code = \"deny\"", "jsrt-shell lint policy")
        assertContains(shell, "#![forbid(unsafe_code)]", "jsrt-shell")
        for (marker in listOf(
            "pub const MAX_ARTIFACT_SIZE",
            "pub const MAX_SECTIONS",
            "pub const MAX_SEGMENTS",
            "pub const R1_REQUIRED_EXPORTS",
            "Pe64Image::parse(bytes)?",
            "Elf64Image::parse(bytes)?",
            "plan.require_r1_exports()?",
            "EmptyArtifact",
            "TargetFormatMismatch",
            "MissingRequiredExport",
        )) {
            assertContains(shell, marker, "safe shell format contract")
        }
        assertRustTests(shell, "target_names_are_strict_and_empty_images_fail")

        for (marker in listOf(
            "const PE_MACHINE_AMD64",
            "const PE32_PLUS_MAGIC",
            "const MAX_DIRECTORY_SIZE",
            "if section_count == 0 || section_count > MAX_SECTIONS",
            "checked_range(",
            "ParseError::WriteExecute",
            "PE has no executable section",
            "fn parse(bytes: &[u8]) -> Result<Self, ParseError>",
        )) {
            assertContains(pe, marker, "PE parser bounds/rejection contract")
        }
        for (marker in listOf(
            "const ELF_CLASS64",
            "const EM_X86_64",
            "const MAX_DYNAMIC_STRING_BYTES",
            "const MAX_NEEDED_LIBRARIES",
            "program_count > MAX_SEGMENTS",
            "checked_file_range(",
            "ParseError::WriteExecute",
            "ELF PT_DYNAMIC missing",
            "ELF load or executable segment missing",
            "fn parse(bytes: &[u8]) -> Result<Self, ParseError>",
        )) {
            assertContains(elf, marker, "ELF parser bounds/rejection contract")
        }

        assertContains(loaderManifest, "name = \"jsrt-shell\"", "jsrt-shell manifest")
        assertContains(loader, "pub fn validate_artifact(", "jsrt-shell loader")
        for (marker in listOf(
            "pub fn detect_format(",
            "fn is_x64_elf_shared(",
            "fn is_x64_pe(",
            "if !format.is_supported()",
            "UnsupportedFormat",
            "TargetFormatMismatch",
            "reject_legacy_or_macos_name(name)?",
            "impl Drop for LoadedArtifact",
            "self.bytes.fill(0);",
            "MachO",
        )) {
            assertContains(loader, marker, "jsrt-shell loader format rejection contract")
        }
        assertRustTests(
            loader,
            "only_current_target_images_are_retained",
            "macho_dylib_and_legacy_paths_are_rejected",
        )

        assertContains(runtimeShell, "ShellArtifact::validate", "jsrt-runtime shell validation")
        assertContains(runtimeShell, "jsrt_shell::validate_artifact", "jsrt-runtime shell loader boundary")
        assertContains(runtimeShell, "ShellBinding::from_artifact", "jsrt-runtime shell binding")
        assertRustTests(
            runtimeShell,
            "shell_binding_is_derived_only_after_image_validation",
            "shell_rejects_retired_platform_and_legacy_names",
        )
        assertRustTests(
            platform,
            "only_the_two_r1_targets_are_accepted",
            "retired_artifact_names_fail_closed",
        )

        val payloadOpen = payload.substringAfter("pub fn open_with<")
        assertOrdered(
            payloadOpen,
            "let authenticated = RuntimeEnvelope::open",
            "PayloadManifest::decode",
            "shell payload authentication must precede manifest parsing",
        )
        assertOrdered(
            payloadOpen,
            "PayloadManifest::decode",
            "decompressor.decompress",
            "shell payload parsing must precede decompression only after authentication",
        )
        for (marker in listOf(
            "pub const R1_PAYLOAD_MAGIC",
            "pub const MAX_PAYLOAD_BYTES",
            "pub fn open_with<D: PayloadDecompressor>(",
            "PayloadDigestMismatch",
            "pub fn wipe(&mut self)",
            "self.plaintext.wipe();",
        )) {
            assertContains(payload, marker, "shell payload bounds/authentication/wipe contract")
        }
    }

    private fun assertContains(source: String, marker: String, contract: String) {
        assertTrue(source.contains(marker), "$contract must contain `$marker`")
    }

    private fun assertOrdered(source: String, first: String, second: String, contract: String) {
        val firstIndex = source.indexOf(first)
        val secondIndex = source.indexOf(second)
        assertTrue(
            firstIndex >= 0 && secondIndex > firstIndex,
            "$contract: expected `$first` before `$second`",
        )
    }

    private fun assertRustTests(source: String, vararg names: String) {
        for (name in names) {
            val test = Regex("""(?m)^\s*#\[test\]\s*fn\s+${Regex.escape(name)}\s*\(""")
            assertTrue(test.containsMatchIn(source), "Rust #[test] contract is missing: $name")
        }
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
