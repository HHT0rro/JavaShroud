package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class NativeHardeningProfileBindingTest {
    @Test
    fun rust_artifact_identity_binds_the_specialization_profile() {
        val firstContext = context(NativeVmBuildProfile(0, 0))
        val secondContext = context(NativeVmBuildProfile(2, 1))
        val sourceDigest = ByteArray(32) { index -> (index + 1).toByte() }
        val specializationDigest = ByteArray(32) { index -> (index * 3 + 7).toByte() }
        val protectedSectionKey = ByteArray(32) { index -> (index * 5 + 11).toByte() }
        try {
            val first = cacheKey(firstContext, sourceDigest, specializationDigest, protectedSectionKey)
            val repeated = cacheKey(firstContext, sourceDigest, specializationDigest, protectedSectionKey)
            val changed = cacheKey(secondContext, sourceDigest, specializationDigest, protectedSectionKey)

            assertEquals(first, repeated)
            assertNotEquals(first, changed)
        } finally {
            firstContext.wipe()
            secondContext.wipe()
            sourceDigest.fill(0)
            specializationDigest.fill(0)
            protectedSectionKey.fill(0)
        }
    }

    @Test
    fun rust_artifact_identity_uses_the_locked_target_triple() {
        val context = context(NativeVmBuildProfile(1, 2))
        val sourceDigest = ByteArray(32) { it.toByte() }
        val specializationDigest = ByteArray(32) { (it * 7).toByte() }
        val protectedSectionKey = ByteArray(32) { (it * 11).toByte() }
        try {
            val windows = NativeRecompilationTransforms.nativeArtifactCacheKey(
                taskPlatform = RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                outputName = "jsrt_ffi.dll",
                sourceDigest = sourceDigest,
                toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
                seed = 7L,
                vbc4BuildContext = context,
                protectedSectionKey = protectedSectionKey,
                specializationDigest = specializationDigest,
            )
            val linux = NativeRecompilationTransforms.nativeArtifactCacheKey(
                taskPlatform = RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
                rustTarget = RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
                outputName = "libjsrt_ffi.so",
                sourceDigest = sourceDigest,
                toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
                seed = 7L,
                vbc4BuildContext = context,
                protectedSectionKey = protectedSectionKey,
                specializationDigest = specializationDigest,
            )
            assertNotEquals(windows, linux)
        } finally {
            context.wipe()
            sourceDigest.fill(0)
            specializationDigest.fill(0)
            protectedSectionKey.fill(0)
        }
    }

    private fun cacheKey(
        context: Vbc4BuildContext,
        sourceDigest: ByteArray,
        specializationDigest: ByteArray,
        protectedSectionKey: ByteArray,
    ): String = NativeRecompilationTransforms.nativeArtifactCacheKey(
        taskPlatform = RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
        rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
        outputName = "jsrt_ffi.dll",
        sourceDigest = sourceDigest,
        toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
        seed = 7L,
        vbc4BuildContext = context,
        protectedSectionKey = protectedSectionKey,
        specializationDigest = specializationDigest,
    )

    private fun context(profile: NativeVmBuildProfile): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it + 1).toByte() },
        nativeSeed = 0x1020304050607080L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it + 2).toByte() },
        nativeVmProfile = profile,
    )
}
