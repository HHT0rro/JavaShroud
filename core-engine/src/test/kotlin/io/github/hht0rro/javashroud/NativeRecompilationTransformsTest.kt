package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationRequest
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import java.nio.file.Path

class NativeRecompilationTransformsTest {
    @Test
    fun r1_exposes_exactly_the_locked_runtime_targets() {
        assertEquals(
            mapOf(
                "windows-x64" to "x86_64-pc-windows-gnu",
                "linux-x64" to "x86_64-unknown-linux-gnu.2.17",
            ),
            NativeRecompilationTransforms.RUST_TARGETS,
        )
        assertFalse(NativeRecompilationTransforms.RUST_TARGETS.keys.any { it.startsWith("macos") })
    }

    @Test
    fun r1_cargo_command_is_locked_and_target_directory_is_explicit() {
        val windows = NativeRecompilationTransforms.rustCargoCommandForTest(
            Path.of("cargo"),
            RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            Path.of("build", "windows"),
        )
        assertEquals(
            listOf("cargo", "zigbuild", "--locked", "--package", "jsrt-ffi", "--lib", "--release", "--target", "x86_64-pc-windows-gnu", "--target-dir", "build/windows"),
            windows.map { it.replace('\\', '/') },
        )

        val linux = NativeRecompilationTransforms.rustCargoCommandForTest(
            Path.of("cargo"),
            RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            Path.of("build", "linux"),
        )
        assertEquals("zigbuild", linux[1])
        assertTrue(linux.contains("--locked"))
        assertTrue(linux.contains("--target-dir"))
        assertFalse(linux.contains("--offline"))
    }

    @Test
    fun windows_rust_flags_keep_the_current_native_exports() {
        val flags = NativeRecompilationTransforms.rustFlagsForTest(
            RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        assertTrue(flags.contains("-C metadata=jsr1_0123456789abcdef"))
        for (export in listOf("JNI_OnLoad", "JNI_OnUnload", "jsrt_r1_open_frame", "jsrt_r1_runtime_binding_digest")) {
            assertTrue(flags.contains("-C link-arg=/EXPORT:$export"))
        }
        assertFalse(
            NativeRecompilationTransforms.rustFlagsForTest(
                RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ).contains("/EXPORT:"),
        )
    }

    @Test
    fun retired_targets_are_rejected_before_toolchain_resolution() {
        val diagnostics = NativeRecompilationTransforms.recompileWithDiagnostics(
            seed = 1L,
            classLoader = javaClass.classLoader,
            targetPlatforms = listOf("macos-arm64"),
            nativeProtectionLevel = "standard",
            nativePackingLevel = "off",
        )
        assertTrue(diagnostics.results.isEmpty())
        assertTrue(diagnostics.messages.any { it.level == "error" })
        assertTrue(diagnostics.messages.any { it.message.contains("macOS") || it.message.contains("unsupported") })
    }

    @Test
    fun specialization_changes_the_artifact_identity() {
        val context = fixedContext()
        val source = ByteArray(32) { it.toByte() }
        val first = NativeRecompilationTransforms.nativeArtifactCacheKey(
            taskPlatform = "windows-x64",
            rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            outputName = "jsrt_ffi.dll",
            sourceDigest = source,
            toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
            seed = 7L,
            vbc4BuildContext = context,
            protectedSectionKey = ByteArray(32) { 1 },
            specializationDigest = ByteArray(32) { 2 },
        )
        val second = NativeRecompilationTransforms.nativeArtifactCacheKey(
            taskPlatform = "windows-x64",
            rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            outputName = "jsrt_ffi.dll",
            sourceDigest = source,
            toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
            seed = 7L,
            vbc4BuildContext = context,
            protectedSectionKey = ByteArray(32) { 1 },
            specializationDigest = ByteArray(32) { 3 },
        )
        assertNotEquals(first, second)
    }

    @Test
    fun cache_key_does_not_bind_master_or_resource_keys() {
        val first = fixedContext(masterFill = 1)
        val second = fixedContext(masterFill = 99)
        val source = ByteArray(32) { it.toByte() }
        val specialization = ByteArray(32) { 4 }
        val nonce = ByteArray(32) { 5 }
        try {
            val left = NativeRecompilationTransforms.nativeArtifactCacheKey(
                taskPlatform = "windows-x64",
                rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                outputName = "jsrt_ffi.dll",
                sourceDigest = source,
                toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
                seed = 7L,
                vbc4BuildContext = first,
                protectedSectionKey = nonce,
                specializationDigest = specialization,
            )
            val right = NativeRecompilationTransforms.nativeArtifactCacheKey(
                taskPlatform = "windows-x64",
                rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                outputName = "jsrt_ffi.dll",
                sourceDigest = source,
                toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
                seed = 7L,
                vbc4BuildContext = second,
                protectedSectionKey = nonce,
                specializationDigest = specialization,
            )
            assertEquals(left, right)
        } finally {
            first.wipe()
            second.wipe()
        }
    }

    @Test
    fun rust_orchestrator_source_does_not_carry_c_generation_or_secret_specialization() {
        val source = java.nio.file.Files.readString(
            java.nio.file.Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"),
        )
        for (forbidden in listOf(
            "META-INF/native-src",
            "js_aken_page_locator.inc",
            "generateC",
            "copyNativeSource",
            "zig cc",
            "update(context.masterKey)",
            "update(context.runtimeResourceKey)",
            "update(vbc4BuildContext.masterKey)",
            "update(vbc4BuildContext.runtimeResourceKey)",
        )) {
            assertFalse(source.contains(forbidden), "Rust orchestrator retains retired C/secret path: $forbidden")
        }
        assertTrue(source.contains("writeSpecializationModule"), "isolated builds must emit specialization.rs")
        assertTrue(source.contains("specialization.rs"), "isolated builds must emit specialization.rs")
    }

    @Test
    fun artifact_validation_is_bounds_checked_and_rejects_macos_names() {
        val error = assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.validateRustArtifactForTest(
                "windows-x64",
                "runtime.dylib",
                byteArrayOf('M'.code.toByte(), 'Z'.code.toByte()),
            )
        }
        assertTrue(error.message.orEmpty().contains("Mach-O") || error.message.orEmpty().contains("dylib"))

        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.validateRustArtifactForTest(
                "linux-x64",
                "libjsrt_ffi.so",
                ByteArray(64) { 0 },
            )
        }
    }

    @Test
    fun recompiled_native_rejects_invalid_specialization_digest() {
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.RecompiledNative("windows-x64", "jsrt_ffi.dll", byteArrayOf(1), ByteArray(0))
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.RecompiledNative("windows-x64", "jsrt_ffi.dll", byteArrayOf(1), ByteArray(32))
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.RecompiledNative("windows-x64", "jsrt_ffi.dll", byteArrayOf(1), ByteArray(16) { 1 })
        }
    }

    @Test
    fun recompiled_native_retains_specialization_digest() {
        val digest = ByteArray(32) { it.toByte() }
        val native = NativeRecompilationTransforms.RecompiledNative(
            "windows-x64",
            "jsrt_ffi.dll",
            byteArrayOf(1),
            digest.copyOf(),
        )
        assertContentEquals(digest, native.specializationDigest)
    }

    @Test
    fun native_specialization_digests_are_published_copied_and_wiped() {
        val context = fixedContext()
        val digest = ByteArray(32) { (it + 3).toByte() }
        try {
            context.publishNativeSpecializationDigests(mapOf("windows-x64" to digest))
            digest.fill(0)
            assertContentEquals(ByteArray(32) { (it + 3).toByte() }, context.copyNativeSpecializationDigest("windows-x64"))
            assertFailsWith<IllegalStateException> {
                context.copyNativeSpecializationDigest("linux-x64")
            }
            context.wipe()
            assertFailsWith<IllegalStateException> {
                context.copyNativeSpecializationDigest("windows-x64")
            }
        } finally {
            context.wipe()
        }
    }

    private fun fixedContext(masterFill: Int = 1): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it + masterFill).toByte() },
        nativeSeed = 0x10203040L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it + 2).toByte() },
    )
}
