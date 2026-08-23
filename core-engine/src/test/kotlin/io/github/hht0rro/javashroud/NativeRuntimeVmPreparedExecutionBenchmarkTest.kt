package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class NativeRuntimeVmPreparedExecutionBenchmarkTest {
    @Test
    fun rust_r1_vm_and_shell_loader_contracts_are_bounded_authenticated_safe_and_format_strict() {
        val rustRoot = rustRoot()
        val vmManifest = Files.readString(rustRoot.resolve("crates/jsrt-vm/Cargo.toml"))
        val vm = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/lib.rs"))
        val zstd = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/zstd.rs"))
        val executor = Files.readString(rustRoot.resolve("crates/jsrt-vm/src/executor.rs"))
        val loaderManifest = Files.readString(rustRoot.resolve("crates/jsrt-shell/Cargo.toml"))
        val loader = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/lib.rs")) +
            Files.readString(rustRoot.resolve("crates/jsrt-shell/src/loader.rs"))
        val pe = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/pe.rs"))
        val elf = Files.readString(rustRoot.resolve("crates/jsrt-shell/src/elf.rs"))
        val runtimeManifest = Files.readString(rustRoot.resolve("crates/jsrt-runtime/Cargo.toml"))
        val runtime = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/lib.rs"))
        val runtimeShell = Files.readString(rustRoot.resolve("crates/jsrt-runtime/src/shell.rs"))

        assertContains(vmManifest, "name = \"jsrt-vm\"", "jsrt-vm manifest")
        assertContains(vmManifest, "unsafe_code = \"forbid\"", "jsrt-vm manifest")
        assertContains(loaderManifest, "name = \"jsrt-shell\"", "jsrt-shell manifest")
        assertContains(runtimeManifest, "name = \"jsrt-runtime\"", "jsrt-runtime manifest")
        assertNoUnsafe(vm, "jsrt-vm")
        assertNoUnsafe(loader, "jsrt-shell loader")
        assertNoUnsafe(runtime, "jsrt-runtime")

        for (testName in listOf(
            "raw_and_rle_frames_are_bounded",
            "malformed_or_trailing_frames_fail",
        )) {
            assertRustTest(zstd, testName)
        }
        for (testName in listOf(
            "wrapping_integer_arithmetic_and_branches_execute",
            "call_uses_safe_host_trait_and_exception_handler",
            "divide_by_zero_is_caught_by_bounded_handler",
            "frame_state_is_wiped_after_failure",
        )) {
            assertRustTest(executor, testName)
        }
        for (testName in listOf(
            "only_current_target_images_are_retained",
            "macho_dylib_and_legacy_paths_are_rejected",
        )) {
            assertRustTest(loader, testName)
        }
        for (testName in listOf(
            "shell_binding_is_derived_only_after_image_validation",
            "shell_rejects_retired_platform_and_legacy_names",
        )) {
            assertRustTest(runtimeShell, testName)
        }

        for (marker in listOf(
            "pub const VBC4_MAX_FRAME_SIZE",
            "pub const VBC4_MAX_SECTION_SIZE",
            "pub const VBC4_MAX_BLOCKS",
            "pub const VBC4_MAX_INSTRUCTIONS",
            "pub struct ParserLimits",
            "parser limit exceeds the R1 bound",
            "if frame.len() > self.limits.max_frame_size",
            "if block_count == 0 || block_count > self.limits.max_blocks",
            "let expected_mac =",
            "vbc4_hmac_fields(",
            "if !ct_eq(&expected_mac",
            "let result = self.parse_sections(",
            "zstd::decompress(",
            "WipedBytes",
        )) {
            assertContains(vm, marker, "R1 VM bounds/authentication/decompression contract")
        }
        val authenticatedVm = vm.substringAfter("fn parse_authenticated(")
        assertOrder(
            authenticatedVm,
            "if !ct_eq(&expected_mac",
            "let result = self.parse_sections(",
            "VM authentication before section parse/decompression",
        )
        assertContains(executor, "if depth >= self.limits.max_recursion", "R1 VM execution depth bound")
        assertContains(executor, "frame.wipe();", "R1 VM execution wipe contract")
        assertContains(vm, "operand_count >", "R1 VM operand bound")
        for (marker in listOf(
            "const BLOCK_RAW: u32 = 0;",
            "const BLOCK_RLE: u32 = 1;",
            "pub(crate) fn decompress(",
            "expected_length > maximum_length",
            "ZstdError::Truncated",
            "ZstdError::TrailingBytes",
            "impl Drop for WipedVec",
            "self.0.fill(0);",
        )) {
            assertContains(zstd, marker, "R1 VM zstd contract")
        }

        for (marker in listOf(
            "pub const MAX_ARTIFACT_SIZE",
            "pub const MAX_IMAGE_SIZE",
            "pub const MAX_SECTIONS",
            "pub const MAX_SEGMENTS",
            "pub enum ArtifactFormat",
            "pub fn detect_format(",
            "fn is_x64_pe(",
            "fn is_x64_elf_shared(",
            "pub fn validate_artifact(",
            "reject_legacy_or_macos_name(name)?",
            "TargetFormatMismatch",
            "UnsupportedFormat",
            "impl Drop for LoadedArtifact",
        )) {
            assertContains(loader, marker, "jsrt-shell loader safe R1 format contract")
        }
        for (marker in listOf(
            "PE_MACHINE_AMD64",
            "MAX_DIRECTORY_SIZE",
            "if section_count == 0 || section_count > MAX_SECTIONS",
            "WriteExecute",
            "checked_file_range(",
            "ParseError::OutOfBounds",
            "ELF_CLASS64",
            "MAX_DYNAMIC_ENTRIES",
            "program_count > MAX_SEGMENTS",
            "if flags & PF_W != 0 && flags & PF_X != 0",
            "PT_DYNAMIC missing",
        )) {
            val source = if (marker.startsWith("ELF") || marker.startsWith("MAX_DYNAMIC") || marker.startsWith("program_count") || marker.startsWith("if flags") || marker.startsWith("PT_DYNAMIC")) elf else pe
            assertContains(source, marker, "jsrt-shell PE/ELF parser contract")
        }
        assertContains(runtime, "validate_artifact", "jsrt-runtime shell loader boundary")
        assertContains(runtime, "use jsrt_shell::", "jsrt-runtime shell loader boundary")
        assertContains(runtimeShell, "ShellArtifact::validate", "jsrt-runtime shell validation")
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
