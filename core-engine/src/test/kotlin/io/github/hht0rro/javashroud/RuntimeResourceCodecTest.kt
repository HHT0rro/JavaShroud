package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4ZstdCodec
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RuntimeResourceCodecTest {
    @Test
    fun vbc4_zstd_codec_emits_real_zstd_frame_and_roundtrips() {
        val plain = ByteArray(512) { 0x2A.toByte() }

        val encoded = Vbc4ZstdCodec.compress(plain)

        assertTrue(encoded.size < plain.size, "VBC4 Zstd codec must emit a smaller real Zstd frame for compressible input")
        assertContentEquals(byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte()), encoded.copyOfRange(0, 4), "encoded payload must start with the standard Zstd frame magic")
        assertContentEquals(plain, Vbc4ZstdCodec.decompress(encoded, plain.size), "encoded Zstd frame must decode to the original payload")
        assertEquals(null, Vbc4ZstdCodec.decompress(encoded, plain.size + 1), "decoded length mismatch must fail closed")
    }
    @Test
    fun runtime_resource_codec_roundtrips_and_rejects_tampering() = withVbc4BuildContext(fixedRuntimeCodecContext()) {
        val plain = "native-or-vbc-payload".toByteArray(Charsets.UTF_8)
        val encoded = RuntimeResourceCodec.encode(
            bytes = plain,
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x12345678,
            variantId = 7,
            layerCount = 3,
        )

        assertTrue(!encoded.startsWithAscii("VBC5"), "encoded resource must not expose raw VBC5 magic before sealing")
        assertEquals(8, encoded[4].toInt() and 0xFF, "runtime resources must use only the partitioned JSRP v8 envelope")
        assertEquals(96, readLe16ForTest(encoded, 21), "public v3 header must expose only encrypted metadata length")
        assertEquals(32, readLe16ForTest(encoded, 23), "public v3 header must expose only MAC length")
        assertContentEquals(plain, RuntimeResourceCodec.decode(encoded), "encoded payload must round-trip")

        encoded[encoded.lastIndex] = (encoded.last().toInt() xor 0x55).toByte()
        assertEquals(null, RuntimeResourceCodec.decode(encoded), "tampered payload must fail MAC/hash validation")
    }

    @Test
    fun runtime_resource_codec_v8_ends_at_authenticated_mac_without_length_marker() =
        withVbc4BuildContext(fixedRuntimeCodecContext()) {
            val plain = ByteArray(73) { index -> (index * 17 + 5).toByte() }
            val encoded = RuntimeResourceCodec.encode(
                bytes = plain,
                kind = RuntimeResourceKind.VmBytecode,
                seed = 0x1357_2468,
                variantId = 3,
                layerCount = 2,
                compress = false,
            )

            assertEquals(8, encoded[4].toInt() and 0xFF)
            assertEquals(27 + 96 + plain.size + 32, encoded.size)

            val retiredMarker = encoded.copyOf(encoded.size + 1).also {
                it[it.lastIndex] = 32
            }
            assertEquals(
                null,
                RuntimeResourceCodec.decode(retiredMarker),
                "JSRP v8 must reject the retired trailing MAC-length marker",
            )

            val retiredV7 = retiredMarker.copyOf().also { it[4] = 7 }
            assertEquals(
                null,
                RuntimeResourceCodec.decode(retiredV7),
                "JSRP v7 must not be accepted through a compatibility branch",
            )
        }

    @Test
    fun runtime_resource_codec_same_inputs_emit_different_authenticated_envelopes() = withVbc4BuildContext(fixedRuntimeCodecContext()) {
        val plain = "same-runtime-resource-plaintext".toByteArray(Charsets.UTF_8)
        val first = RuntimeResourceCodec.encode(
            bytes = plain,
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x12345678,
            variantId = 7,
            layerCount = 3,
        )
        val second = RuntimeResourceCodec.encode(
            bytes = plain,
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x12345678,
            variantId = 7,
            layerCount = 3,
        )

        assertTrue(!first.contentEquals(second), "same runtime resource inputs must receive fresh envelope nonce/material")
        assertContentEquals(plain, RuntimeResourceCodec.decode(first), "first randomized envelope must round-trip")
        assertContentEquals(plain, RuntimeResourceCodec.decode(second), "second randomized envelope must round-trip")
    }

    @Test
    fun runtime_resource_codec_is_bound_to_build_local_resource_key() {
        val plain = "build-bound-runtime-resource".toByteArray(Charsets.UTF_8)
        val firstContext = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 11 + 7).toByte() },
            nativeSeed = 0x1357_2468L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 3 + 1).toByte() },
        )
        val secondContext = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 13 + 5).toByte() },
            nativeSeed = 0x2468_1357L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 7 + 9).toByte() },
        )

        val encoded = withVbc4BuildContext(firstContext) {
            RuntimeResourceCodec.encode(
                bytes = plain,
                kind = RuntimeResourceKind.VmBytecode,
                seed = 0x12345678,
                variantId = 7,
                layerCount = 3,
            )
        }

        assertContentEquals(plain, withVbc4BuildContext(firstContext) { RuntimeResourceCodec.decode(encoded) }, "matching build context must decode its own runtime resources")
        assertEquals(null, withVbc4BuildContext(secondContext) { RuntimeResourceCodec.decode(encoded) }, "a different build context must fail closed instead of decoding copied runtime resources")
    }

    @Test
    fun runtime_resource_codec_authenticates_header_body_and_tag() = withVbc4BuildContext(fixedRuntimeCodecContext()) {
        val encoded = RuntimeResourceCodec.encode(
            bytes = "authenticated-runtime-resource".toByteArray(Charsets.UTF_8),
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x13572468,
            variantId = 5,
            layerCount = 4,
        )

        for (offset in listOf(5, 21, 25, 121, encoded.size - 32)) {
            val tampered = encoded.copyOf()
            tampered[offset] = (tampered[offset].toInt() xor 0x21).toByte()
            assertEquals(null, RuntimeResourceCodec.decode(tampered), "tampering offset $offset must fail closed")
        }
    }

    @Test
    fun runtime_resource_codec_rejects_non_current_headers() = withVbc4BuildContext(fixedRuntimeCodecContext()) {
        val encoded = RuntimeResourceCodec.encode(
            bytes = "current-only".toByteArray(Charsets.UTF_8),
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x10203040,
            variantId = 3,
            layerCount = 1,
        )
        encoded[4] = (encoded[4].toInt() - 1).toByte()

        assertEquals(null, RuntimeResourceCodec.decode(encoded), "Runtime resource codec must decode only current authenticated envelopes")
    }

    @Test
    fun runtime_resource_codec_rejects_legacy_user_reachable_xor_stream_envelopes() {
        val legacy = ByteArray(64) { index -> (index * 29 + 7).toByte() }
        "JSRP".toByteArray(Charsets.US_ASCII).copyInto(legacy, 0)
        legacy[4] = 2
        legacy[5] = RuntimeResourceKind.NativeLibrary.id.toByte()
        legacy[6] = 1
        legacy[7] = 0

        assertEquals(null, RuntimeResourceCodec.decode(legacy), "Legacy stream/XOR runtime resource envelopes must fail closed")
    }

    @Test
    fun runtime_resource_codec_does_not_require_java_zstd_jni_for_runtime_resources() = withVbc4BuildContext(fixedRuntimeCodecContext()) {
        val highEntropy = ByteArray(512) { index -> (index * 131 + (index ushr 1) * 17).toByte() }
        val seed = 0x2468ACE0
        val requested = RuntimeResourceCodec.encode(
            bytes = highEntropy,
            kind = RuntimeResourceKind.NativeLibrary,
            seed = seed,
            variantId = 11,
            layerCount = 2,
            compress = true,
        )
        val forced = RuntimeResourceCodec.encode(
            bytes = highEntropy,
            kind = RuntimeResourceKind.NativeLibrary,
            seed = seed,
            variantId = 11,
            layerCount = 2,
            compress = false,
        )

        assertEquals(96, readLe16ForTest(requested, 21), "requested compression must not add a public compression flag")
        assertEquals(96, readLe16ForTest(forced, 21), "disabled compression must not add a public compression flag")
        assertContentEquals(highEntropy, RuntimeResourceCodec.decode(requested), "runtime payload must round-trip")
        assertContentEquals(highEntropy, RuntimeResourceCodec.decode(forced), "forced uncompressed payload must round-trip")
    }

    @Test
    fun retired_native_kernel_packer_has_no_production_api() {
        val relative = "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelPacker.kt"
        var current = java.nio.file.Path.of("").toAbsolutePath()
        while (!Files.isDirectory(current.resolve("core-engine")) && current.parent != null) {
            current = current.parent
        }
        assertFalse(
            Files.exists(current.resolve(relative)),
            "the retired Kotlin native packer must not remain as a production source",
        )
    }

    private fun fixedRuntimeCodecContext(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 17 + 3).toByte() },
        nativeSeed = 0x1122_3344L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 5 + 9).toByte() },
    )

    private fun ByteArray.startsWithAscii(value: String): Boolean {
        val prefix = value.toByteArray(Charsets.US_ASCII)
        if (size < prefix.size) return false
        return prefix.indices.all { index -> this[index] == prefix[index] }
    }

    private fun readLe16ForTest(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
}
