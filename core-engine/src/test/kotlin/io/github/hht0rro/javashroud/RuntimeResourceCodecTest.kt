package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeKernelPacker
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

        assertTrue(!encoded.startsWithAscii("VBC4"), "encoded resource must not expose raw VBC4 magic before sealing")
        assertEquals(6, encoded[4].toInt() and 0xFF, "runtime resource envelope must use the opaque VBC4-only authenticated version")
        assertEquals(96, readLe16ForTest(encoded, 21), "public v2 header must expose only encrypted metadata length")
        assertEquals(32, readLe16ForTest(encoded, 23), "public v2 header must expose only MAC length")
        assertContentEquals(plain, RuntimeResourceCodec.decode(encoded), "encoded payload must round-trip")

        encoded[encoded.lastIndex] = (encoded.last().toInt() xor 0x55).toByte()
        assertEquals(null, RuntimeResourceCodec.decode(encoded), "tampered payload must fail MAC/hash validation")
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

        for (offset in listOf(5, 21, 25, 121, encoded.size - 33)) {
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
    fun native_kernel_packer_outputs_stable_neutral_resources_without_plain_kernel_name() {
        val inputDir = Files.createTempDirectory("javashroud-native-pack-in")
        val outputDir = Files.createTempDirectory("javashroud-native-pack-out")
        val secondOutputDir = Files.createTempDirectory("javashroud-native-pack-out-second")
        val thirdOutputDir = Files.createTempDirectory("javashroud-native-pack-out-third")
        try {
            Files.write(inputDir.resolve("js_kernel_linux-x64.so"), "fake-native-JNI_OnLoad-j.l-j.b-j.m".toByteArray(Charsets.UTF_8))

            val first = withVbc4BuildContext(fixedRuntimeCodecContext()) { NativeKernelPacker.pack(inputDir, outputDir, seed = 42) }
            val second = withVbc4BuildContext(fixedRuntimeCodecContext()) { NativeKernelPacker.pack(inputDir, secondOutputDir, seed = 42) }
            val third = withVbc4BuildContext(fixedRuntimeCodecContext()) { NativeKernelPacker.pack(inputDir, thirdOutputDir, seed = 99) }

            assertEquals(1, first.resources.size, "one native resource should be packed")
            assertEquals(first.indexBytes.toList(), second.indexBytes.toList(), "bootstrap native packer index remains deterministic for Java-readable loading metadata")
            assertEquals(first.resources.single().bytes.toList(), second.resources.single().bytes.toList(), "same seed should produce stable resource bytes")
            assertNotEquals(first.indexBytes.toList(), third.indexBytes.toList(), "different seed should diversify bootstrap index bytes")
            assertNotEquals(first.resources.single().path, third.resources.single().path, "different seed should diversify neutral resource paths")

            val resource = first.resources.single()
            assertTrue(resource.path.startsWith("META-INF/"), "packed resource must live under META-INF")
            assertTrue(resource.path.endsWith(".bin"), "packed native resource must use neutral .bin suffix")
            assertTrue(!resource.path.contains("js_kernel"), "packed resource path must not expose js_kernel")
            assertTrue(resource.path.contains('\u00A0'), "packed native resource path should include NBSP camouflage")
            assertTrue(!String(first.indexBytes, Charsets.ISO_8859_1).contains("js_kernel"), "packed index must not expose js_kernel")
            assertEquals(null, withVbc4BuildContext(fixedRuntimeCodecContext()) { RuntimeResourceCodec.decode(resource.bytes) }, "bootstrap native library must remain directly loadable, not zstd-JSRP wrapped")
            assertContentEquals("fake-native-JNI_OnLoad-j.l-j.b-j.m".toByteArray(Charsets.UTF_8), resource.bytes, "bootstrap native library bytes must be written raw under a neutral resource path")
            assertTrue(first.indexBytes.startsWithAscii("JSBI"), "bootstrap native index must use the Java-readable JSBI envelope")
        } finally {
            inputDir.toFile().deleteRecursively()
            outputDir.toFile().deleteRecursively()
            secondOutputDir.toFile().deleteRecursively()
            thirdOutputDir.toFile().deleteRecursively()
        }
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
