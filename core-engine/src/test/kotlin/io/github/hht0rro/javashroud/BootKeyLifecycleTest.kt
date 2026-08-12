package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
import io.github.hht0rro.javashroud.transforms.protection.BootMaterialEnvelope
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import java.lang.reflect.InvocationTargetException
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BootKeyLifecycleTest {
    @Test
    fun java_boot_key_copies_are_wiped_on_clear_failure_and_repeated_installation() {
        val secret = ByteArray(32) { index -> (index * 17 + 5).toByte() }
        val binding = ByteArray(32) { index -> (index * 19 + 7).toByte() }
        val shellCommitment = ByteArray(32) { index -> (index * 31 + 9).toByte() }
        val context = context()
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        var envelope: ByteArray? = null
        var material: ByteArray? = null
        try {
            BootKekSidecar.buildArtifactBindingProvider = { binding.copyOf() }
            envelope = BootMaterialEnvelope.encode(context, secret, mapOf("windows-x64" to shellCommitment))
            material = decryptBootMaterial(envelope, secret)

            val helper = helperClass()
            val validate = helper.getDeclaredMethod(
                "validateAndPublishJavaBootMaterial",
                ByteArray::class.java,
                String::class.java,
            ).apply { isAccessible = true }
            val clear = helper.getDeclaredMethod("clearJavaBootMaterial").apply { isAccessible = true }
            val keysField = helper.getDeclaredField("runtimeResourceKeys").apply { isAccessible = true }
            clear.invoke(null)

            validate.invoke(null, material, "windows-x64")
            @Suppress("UNCHECKED_CAST")
            val firstKeys = keysField.get(null) as Array<ByteArray>
            assertTrue(firstKeys.any { key -> key.any { it != 0.toByte() } })
            clear.invoke(null)
            assertNull(keysField.get(null))
            assertTrue(firstKeys.all { key -> key.all { it == 0.toByte() } })

            validate.invoke(null, material, "windows-x64")
            @Suppress("UNCHECKED_CAST")
            val secondKeys = keysField.get(null) as Array<ByteArray>
            clear.invoke(null)
            assertTrue(secondKeys.all { key -> key.all { it == 0.toByte() } })

            val invalid = material.copyOf().also { bytes ->
                val bindingOffset = 4 + 64 + (bytes[2].toInt() and 0xFF) * 32
                bytes.fill(0, bindingOffset + 1, bindingOffset + 33)
            }
            try {
                val failure = assertFailsWith<InvocationTargetException> {
                    validate.invoke(null, invalid, "windows-x64")
                }
                assertTrue(failure.targetException is SecurityException)
                assertNull(keysField.get(null))
            } finally {
                invalid.fill(0)
            }
        } finally {
            runCatching {
                helperClass().getDeclaredMethod("clearJavaBootMaterial").apply { isAccessible = true }.invoke(null)
            }
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            envelope?.fill(0)
            material?.fill(0)
            secret.fill(0)
            binding.fill(0)
            shellCommitment.fill(0)
            context.wipe()
        }
    }

    @Test
    fun build_context_wipes_cached_boot_material_on_close() {
        val providerSecret = ByteArray(32) { index -> (index * 23 + 11).toByte() }
        val providerBinding = ByteArray(32) { index -> (index * 29 + 13).toByte() }
        val previousSecretProvider = NativeKernelShellPacker.buildBootSecretProvider
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        val context = context()
        var secretCopy: ByteArray? = null
        var bindingCopy: ByteArray? = null
        try {
            NativeKernelShellPacker.buildBootSecretProvider = { providerSecret.copyOf() }
            BootKekSidecar.buildArtifactBindingProvider = { providerBinding.copyOf() }
            secretCopy = context.copyBootSecretForBuild()
            bindingCopy = context.copyBootSidecarBindingForBuild()

            val secretSnapshotField = Vbc4BuildContext::class.java
                .getDeclaredField("bootSecretSnapshot").apply { isAccessible = true }
            val bindingSnapshotField = Vbc4BuildContext::class.java
                .getDeclaredField("bootSidecarBindingSnapshot").apply { isAccessible = true }
            val secretSnapshot = secretSnapshotField.get(context) as ByteArray
            val bindingSnapshot = bindingSnapshotField.get(context) as ByteArray

            context.wipe()

            assertTrue(secretSnapshot.all { it == 0.toByte() })
            assertTrue(bindingSnapshot.all { it == 0.toByte() })
            assertNull(secretSnapshotField.get(context))
            assertNull(bindingSnapshotField.get(context))
        } finally {
            NativeKernelShellPacker.buildBootSecretProvider = previousSecretProvider
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            secretCopy?.fill(0)
            bindingCopy?.fill(0)
            providerSecret.fill(0)
            providerBinding.fill(0)
            context.wipe()
        }
    }

    private fun context(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(32) { index -> (index * 3 + 17).toByte() },
        nativeSeed = 0x1020_3040_5060_7080L,
        jarLayoutDigest = ByteArray(32) { index -> (index * 5 + 19).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (index * 7 + 23).toByte() },
        runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
        maxHardening = true,
    )

    private fun decryptBootMaterial(envelope: ByteArray, secret: ByteArray): ByteArray =
        try {
            helperClass().getDeclaredMethod(
                "decryptBootMaterial",
                ByteArray::class.java,
                ByteArray::class.java,
            ).apply { isAccessible = true }.invoke(null, envelope, secret) as ByteArray
        } catch (error: InvocationTargetException) {
            throw (error.targetException ?: error)
        }

    private fun helperClass(): Class<*> =
        Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
}
