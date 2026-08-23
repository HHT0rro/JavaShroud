package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertNotEquals

class NativeCompiledStructureDivergenceTest {

    @Test
    fun rust_specialization_identity_diverges_across_vm_profiles() {
        val sourceDigest = ByteArray(32) { (it * 7 + 1).toByte() }
        val specializationDigest = ByteArray(32) { (it * 11 + 3).toByte() }
        val protectedSectionKey = ByteArray(32) { (it * 13 + 5).toByte() }
        val contexts = listOf(
            context(NativeVmBuildProfile(0, 0)),
            context(NativeVmBuildProfile(1, 1)),
            context(NativeVmBuildProfile(2, 2)),
        )
        try {
            val identities = contexts.map { context ->
                NativeRecompilationTransforms.nativeArtifactCacheKey(
                    taskPlatform = RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                    rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                    outputName = "jsrt_ffi.dll",
                    sourceDigest = sourceDigest,
                    toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
                    seed = 0x4455_6600L,
                    vbc4BuildContext = context,
                    protectedSectionKey = protectedSectionKey,
                    specializationDigest = specializationDigest,
                )
            }
            assertNotEquals(identities[0], identities[1])
            assertNotEquals(identities[1], identities[2])
            assertNotEquals(identities[0], identities[2])
        } finally {
            contexts.forEach(Vbc4BuildContext::wipe)
            sourceDigest.fill(0)
            specializationDigest.fill(0)
            protectedSectionKey.fill(0)
        }
    }

    @Test
    fun rust_specialization_identity_changes_when_the_source_digest_changes() {
        val context = context(NativeVmBuildProfile(1, 2))
        val firstSource = ByteArray(32) { it.toByte() }
        val secondSource = firstSource.copyOf().also { it[17] = (it[17].toInt() xor 0x55).toByte() }
        val specializationDigest = ByteArray(32) { (it * 3).toByte() }
        val protectedSectionKey = ByteArray(32) { (it * 5).toByte() }
        try {
            fun key(source: ByteArray) = NativeRecompilationTransforms.nativeArtifactCacheKey(
                taskPlatform = RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                outputName = "jsrt_ffi.dll",
                sourceDigest = source,
                toolchainIdentity = "rustc=1.78.0|cargo=1.78.0",
                seed = 0x4455_6600L,
                vbc4BuildContext = context,
                protectedSectionKey = protectedSectionKey,
                specializationDigest = specializationDigest,
            )
            assertNotEquals(key(firstSource), key(secondSource))
        } finally {
            context.wipe()
            firstSource.fill(0)
            secondSource.fill(0)
            specializationDigest.fill(0)
            protectedSectionKey.fill(0)
        }
    }

    private fun context(profile: NativeVmBuildProfile): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 11 + 5).toByte() },
        nativeSeed = 0x1122_3344_5566_7788L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 13 + 7).toByte() },
        nativeVmProfile = profile,
    )
}
