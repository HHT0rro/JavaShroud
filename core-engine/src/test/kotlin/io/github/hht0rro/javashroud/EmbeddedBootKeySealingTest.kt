package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.QpResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.defaultQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.qp.qpResourceDir
import io.github.hht0rro.javashroud.transforms.protection.withQpBuildContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EmbeddedBootKeySealingTest {
    @Test
    fun sealing_emits_one_current_native_image_without_boot_sidecars() = withBuildContext {
        val nativeImage = byteArrayOf(0x4D, 0x5A, 1, 2, 3)
        val input = nativeInput(wrapNativeImage(nativeImage))
        val deployed = EmbeddedHelperDeployment.injectRequiredHelpers(input, listOf("jni-microkernel-loader"))
        val sealed = RuntimeArtifactSealing.seal(deployed, seed = SEALING_SEED)

        val nativeEntry = sealed.jarEntries.single { it.name.endsWith(".dll") }
        assertContentEquals(nativeImage, nativeEntry.bytes)
        assertFalse(sealed.jarEntries.any { it.name == nativeResourcePath() })
        assertFalse(sealed.jarEntries.any { it.name.substringAfterLast('/') in setOf("boot.dat", "kek.dat") })
        assertTrue(sealed.classArtifacts.any { it.summary.internalName.startsWith("jsh/") })
    }

    @Test
    fun sealing_rejects_invalid_current_native_input_envelopes() = withBuildContext {
        val current = wrapNativeImage(byteArrayOf(0x4D, 0x5A, 1, 2, 3))
        val invalidEnvelopes = mapOf(
            "magic" to current.copyOf().also { it[0] = 0 },
            "length" to current.copyOf(current.size - 1),
            "authentication" to current.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
        )
        for ((check, bytes) in invalidEnvelopes) {
            val failure = assertFailsWith<IllegalArgumentException>("invalid envelope $check must fail sealing") {
                RuntimeArtifactSealing.seal(nativeInput(bytes), seed = SEALING_SEED)
            }
            assertTrue(failure.message.orEmpty().startsWith("Qp native resource wrapper failed authentication:"))
        }
    }

    private fun nativeInput(bytes: ByteArray) = testAttachedArtifact(
        classArtifacts = emptyList(),
        jarEntries = listOf(JarEntryData(nativeResourcePath(), bytes)),
    )

    private fun nativeResourcePath() = "${qpResourceDir()}/windows-x64/qp_ffi.dll"

    private fun wrapNativeImage(bytes: ByteArray) = QpResourceCodec.encode(
        bytes = bytes,
        kind = RuntimeResourceKind.NativeLibrary,
        seed = 0x454D,
        variantId = 0,
        layerCount = 1,
        compress = false,
    )

    private fun withBuildContext(block: () -> Unit) {
        val context = defaultQpBuildContext()
        try {
            context.publishNativeSpecializationDigests(mapOf("windows-x64" to ByteArray(32) { 1 }))
            withQpBuildContext(context) { block() }
        } finally {
            context.wipe()
        }
    }

    private companion object {
        const val SEALING_SEED = 0x454D4245444CL
    }
}
