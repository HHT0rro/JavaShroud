package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
import io.github.hht0rro.javashroud.transforms.protection.BootMaterialEnvelope
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class MaxHardeningBootEnvelopeTest {
    @Test
    fun jsbm_v3_and_jsbk_round_trip_through_the_java_runtime_decoder() {
        val bootSecret = ByteArray(32) { index -> (index * 29 + 3).toByte() }
        val binding = ByteArray(32) { index -> (index * 31 + 5).toByte() }
        val context = context(maxHardening = true)
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        var envelope: ByteArray? = null
        var recoveredSecret: ByteArray? = null
        var material: ByteArray? = null
        try {
            BootKekSidecar.buildArtifactBindingProvider = { binding.copyOf() }
            val sidecar = BootKekSidecar.encodeText(bootSecret, binding)
            val sidecarBinding = BootKekSidecar.embeddedBindingText(sidecar)
            try {
                assertContentEquals(binding, sidecarBinding)
            } finally {
                sidecarBinding?.fill(0)
            }
            envelope = BootMaterialEnvelope.encode(context, bootSecret)

            assertEquals(3, envelope[4].toInt() and 0xFF)
            assertEquals(32, envelope[5].toInt() and 0xFF)
            assertContentEquals(binding, envelope.copyOfRange(6, 38))

            val embeddedBinding = bootSidecarBinding(envelope)
            try {
                assertContentEquals(binding, embeddedBinding)
            } finally {
                embeddedBinding?.fill(0)
            }

            val sidecarBytes = sidecar.toByteArray(Charsets.US_ASCII)
            recoveredSecret = try {
                decodeSidecar(sidecarBytes, binding)
            } finally {
                sidecarBytes.fill(0)
            }
            assertContentEquals(bootSecret, recoveredSecret)

            material = decryptEnvelope(envelope, recoveredSecret)
            assertEquals(3, material[0].toInt() and 0xFF)
            assertContentEquals(context.masterKey, material.copyOfRange(4, 36))
            assertContentEquals(context.jarLayoutDigest, material.copyOfRange(36, 68))
        } finally {
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            envelope?.fill(0)
            recoveredSecret?.fill(0)
            material?.fill(0)
            bootSecret.fill(0)
            binding.fill(0)
            context.wipe()
        }
    }

    @Test
    fun hardened_binding_mismatch_and_binding_field_tampering_fail_closed() {
        val bootSecret = ByteArray(32) { index -> (index * 17 + 9).toByte() }
        val binding = ByteArray(32) { index -> (index * 11 + 7).toByte() }
        val wrongBinding = binding.copyOf().also { it[0] = (it[0].toInt() xor 0x5A).toByte() }
        val context = context(maxHardening = true)
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        val sidecar = BootKekSidecar.encode(bootSecret, binding)
        var envelope: ByteArray? = null
        try {
            BootKekSidecar.buildArtifactBindingProvider = { binding.copyOf() }
            envelope = BootMaterialEnvelope.encode(context, bootSecret)

            assertFailsWith<SecurityException> {
                decodeSidecar(sidecar, wrongBinding)
            }

            val sidecarWithTamperedBinding = sidecar.copyOf().also { bytes ->
                bytes[10] = (bytes[10].toInt() xor 0x5A).toByte()
            }
            try {
                assertFailsWith<SecurityException> {
                    decodeSidecar(sidecarWithTamperedBinding, binding)
                }
            } finally {
                sidecarWithTamperedBinding.fill(0)
            }

            val envelopeWithTamperedBinding = envelope.copyOf().also { bytes ->
                bytes[6] = (bytes[6].toInt() xor 0x5A).toByte()
            }
            try {
                assertFailsWith<SecurityException> {
                    decryptEnvelope(envelopeWithTamperedBinding, bootSecret)
                }
            } finally {
                envelopeWithTamperedBinding.fill(0)
            }
        } finally {
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            envelope?.fill(0)
            sidecar.fill(0)
            bootSecret.fill(0)
            binding.fill(0)
            wrongBinding.fill(0)
            context.wipe()
        }
    }

    @Test
    fun jsbm_v2_remains_compatible_with_a_raw_boot_kek() {
        val bootSecret = ByteArray(32) { index -> (index * 7 + 19).toByte() }
        val context = context(maxHardening = false)
        var envelope: ByteArray? = null
        var material: ByteArray? = null
        try {
            envelope = BootMaterialEnvelope.encode(context, bootSecret)

            assertEquals(2, envelope[4].toInt() and 0xFF)
            assertNull(bootSidecarBinding(envelope))

            material = decryptEnvelope(envelope, bootSecret)
            assertEquals(2, material[0].toInt() and 0xFF)
            assertContentEquals(context.masterKey, material.copyOfRange(4, 36))
            assertContentEquals(context.jarLayoutDigest, material.copyOfRange(36, 68))
        } finally {
            envelope?.fill(0)
            material?.fill(0)
            bootSecret.fill(0)
            context.wipe()
        }
    }

    private fun context(maxHardening: Boolean): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 5 + 13).toByte() },
        nativeSeed = 0x0102_0304_0506_0708L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 3 + 23).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (index * 9 + 29).toByte() },
        runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
        maxHardening = maxHardening,
    )

    private fun bootSidecarBinding(envelope: ByteArray): ByteArray? =
        helperMethod("bootSidecarBinding", ByteArray::class.java).invoke(null, envelope) as ByteArray?

    private fun decodeSidecar(sidecar: ByteArray, binding: ByteArray): ByteArray =
        invokeBytes(helperMethod("decodeBootKekSidecar", ByteArray::class.java, ByteArray::class.java), sidecar, binding)

    private fun decryptEnvelope(envelope: ByteArray, bootSecret: ByteArray): ByteArray =
        invokeBytes(helperMethod("decryptBootMaterial", ByteArray::class.java, ByteArray::class.java), envelope, bootSecret)

    private fun invokeBytes(method: Method, vararg arguments: Any): ByteArray =
        try {
            method.invoke(null, *arguments) as ByteArray
        } catch (error: InvocationTargetException) {
            throw (error.targetException ?: error)
        }

    private fun helperMethod(name: String, vararg parameterTypes: Class<*>): Method =
        Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
            .getDeclaredMethod(name, *parameterTypes)
            .apply { isAccessible = true }
}
