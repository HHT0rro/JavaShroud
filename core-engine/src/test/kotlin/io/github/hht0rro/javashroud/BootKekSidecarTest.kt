package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BootKekSidecarTest {
    private val kek = ByteArray(BootKekSidecar.KEK_SIZE) { index -> (index * 17 + 11).toByte() }
    private val binding = ByteArray(BootKekSidecar.KEK_SIZE) { index -> (index * 23 + 7).toByte() }

    @Test
    fun binary_and_text_sidecars_are_randomized_artifact_bound_and_round_trip() {
        val first = BootKekSidecar.encode(kek, binding)
        val second = BootKekSidecar.encode(kek, binding)
        val text = BootKekSidecar.encodeText(kek, binding)

        assertFalse(first.contentEquals(second), "a max-hardening build must not reuse a sidecar ciphertext")
        assertEquals(BootKekSidecar.Format.BinaryV1, BootKekSidecar.identify(first))
        assertEquals(BootKekSidecar.Format.TextV1, BootKekSidecar.identifyText(text))
        assertTrue(text.startsWith(BootKekSidecar.TEXT_PREFIX))
        assertTrue(text.drop(BootKekSidecar.TEXT_PREFIX.length).all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertContentEquals(kek, BootKekSidecar.decode(first, binding))
        assertContentEquals(kek, BootKekSidecar.decodeText(text, binding))
        assertFalse(containsSlice(first, kek), "the binary sidecar must not contain a plaintext Boot KEK")
    }

    @Test
    fun tampering_and_cross_artifact_replay_fail_closed() {
        val sidecar = BootKekSidecar.encode(kek, binding)
        val replacementBinding = binding.copyOf().also { it[0] = (it[0].toInt() xor 0x7F).toByte() }

        assertFailsWith<IllegalArgumentException> { BootKekSidecar.decode(sidecar, replacementBinding) }
        for (offset in listOf(0, 4, 8, 10, 26, sidecar.lastIndex)) {
            val tampered = sidecar.copyOf().also { it[offset] = (it[offset].toInt() xor 0x5A).toByte() }
            assertFailsWith<IllegalArgumentException>("tampering offset $offset must fail") {
                BootKekSidecar.decode(tampered, binding)
            }
        }
    }

    @Test
    fun malformed_sidecars_and_invalid_key_material_are_rejected() {
        val sidecar = BootKekSidecar.encode(kek, binding)

        assertNull(BootKekSidecar.identify(sidecar.copyOf(sidecar.size - 1)))
        assertNull(BootKekSidecar.identifyText("JSBK1.!not-base64!"))
        assertFailsWith<IllegalArgumentException> { BootKekSidecar.decode(sidecar.copyOf(sidecar.size - 1), binding) }
        assertFailsWith<IllegalArgumentException> { BootKekSidecar.decodeText("JSBK1.!not-base64!", binding) }
        assertFailsWith<IllegalArgumentException> { BootKekSidecar.encode(ByteArray(BootKekSidecar.KEK_SIZE - 1), binding) }
        assertFailsWith<IllegalArgumentException> { BootKekSidecar.encode(kek, ByteArray(BootKekSidecar.KEK_SIZE - 1)) }
    }

    private fun containsSlice(haystack: ByteArray, needle: ByteArray): Boolean =
        needle.isNotEmpty() && haystack.indices.any { start ->
            start + needle.size <= haystack.size && needle.indices.all { offset -> haystack[start + offset] == needle[offset] }
        }
}
