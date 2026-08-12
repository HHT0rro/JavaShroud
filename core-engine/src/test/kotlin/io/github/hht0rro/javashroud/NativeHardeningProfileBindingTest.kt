package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse

class NativeHardeningProfileBindingTest {
    @Test
    fun max_hardening_bootstrap_binding_includes_generated_native_profile() {
        val context = context(maxHardening = true)
        val firstSource = ByteArray(32) { index -> (index + 1).toByte() }
        val secondSource = firstSource.copyOf().also { it[17] = (it[17].toInt() xor 0x55).toByte() }

        val first = NativeRecompilationTransforms.nativeBootstrapIndexDigest("windows-x64", "kernel.dll", context, firstSource)
        val repeated = NativeRecompilationTransforms.nativeBootstrapIndexDigest("windows-x64", "kernel.dll", context, firstSource)
        val changed = NativeRecompilationTransforms.nativeBootstrapIndexDigest("windows-x64", "kernel.dll", context, secondSource)

        assertContentEquals(first, repeated)
        assertFalse(first.contentEquals(changed), "generated parser/dispatcher source must participate in max-hardening binding")
    }

    @Test
    fun ordinary_profile_keeps_legacy_bootstrap_digest_contract() {
        val context = context(maxHardening = false)
        val first = NativeRecompilationTransforms.nativeBootstrapIndexDigest("windows-x64", "kernel.dll", context, ByteArray(32) { 1 })
        val second = NativeRecompilationTransforms.nativeBootstrapIndexDigest("windows-x64", "kernel.dll", context, ByteArray(32) { 2 })

        assertContentEquals(first, second)
    }

    private fun context(maxHardening: Boolean) = Vbc4BuildContext(
        masterKey = ByteArray(32) { index -> (index * 3 + 1).toByte() },
        nativeSeed = 0x1020304050607080L,
        jarLayoutDigest = ByteArray(32) { index -> (index * 5 + 7).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (index * 11 + 9).toByte() },
        maxHardening = maxHardening,
    )
}
