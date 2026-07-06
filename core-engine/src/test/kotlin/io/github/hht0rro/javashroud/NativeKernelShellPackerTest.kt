package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class NativeKernelShellPackerTest {
    private val nativeBytes = "MZfake-loadable-native-JNI_OnLoad-j.l-j.b-j.m-(J[Ljava/lang/Object;)Ljava/lang/Object;".toByteArray()
    private val keyMaterial = ByteArray(32) { index -> (index * 3 + 1).toByte() }
    private val bootstrapDigest = ByteArray(32) { index -> (0xA0 + index).toByte() }

    @Test
    fun off_level_returns_original_bytes() {
        val packed = NativeKernelShellPacker.pack(
            bytes = nativeBytes,
            platform = "windows-x64",
            outputName = "js_kernel_windows-x64.dll",
            seed = 7L,
            nativePackingLevel = "off",
            keyMaterial = keyMaterial,
        )

        assertTrue(nativeBytes.contentEquals(packed), "off level must not modify native bytes")
        assertFalse(NativeKernelShellPacker.isShellPacked(packed), "off level must not append a shell block")
    }

    @Test
    fun standard_level_appends_authenticated_overlay_without_replacing_loader() {
        val packed = NativeKernelShellPacker.pack(
            bytes = nativeBytes,
            platform = "windows-x64",
            outputName = "js_kernel_windows-x64.dll",
            seed = 11L,
            nativePackingLevel = "standard",
            keyMaterial = keyMaterial,
        )
        val inspection = NativeKernelShellPacker.inspect(packed, 11L, keyMaterial)

        assertTrue(packed.size > nativeBytes.size, "standard overlay must increase native artifact size")
        assertTrue(packed.copyOf(nativeBytes.size).contentEquals(nativeBytes), "standard overlay must preserve the loadable dynamic library prefix")
        assertTrue(packed.containsAscii(NativeKernelShellPacker.LOADER_MARKER), "overlay should expose a loader marker")
        assertTrue(inspection.present, "inspection should detect shell overlay")
        assertTrue(inspection.macValid, "fresh shell overlay must authenticate")
        assertEquals(NativeKernelShellPacker.Level.STANDARD, inspection.level)
        assertEquals("windows-x64", inspection.platform)
        assertEquals("js_kernel_windows-x64.dll", inspection.outputName)
        assertEquals(nativeBytes.size, inspection.originalSize)
        assertTrue(inspection.encodedPayloadSize > 0, "standard overlay should carry encoded evidence")
        assertTrue(inspection.bogusSize >= 32, "standard overlay should carry a bounded bogus decode surface")
    }

    @Test
    fun max_level_is_not_allowed_to_emit_overlay() {
        assertFailsWith<IllegalArgumentException> {
            NativeKernelShellPacker.pack(
                bytes = nativeBytes,
                platform = "windows-x64",
                outputName = "js_kernel_windows-x64.dll",
                seed = 11L,
                nativePackingLevel = "max",
                keyMaterial = keyMaterial,
            )
        }
    }

    @Test
    fun max_payload_bundle_carries_authenticated_stub_bound_metadata() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 23L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val inspection = NativeKernelShellPacker.inspectMaxPayloadBundle(
            headerBytes = bundle.headerBytes,
            encodedPayload = bundle.encodedPayload,
            payloadMac = bundle.payloadMac,
            seed = 23L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )

        assertTrue(inspection.present, "max payload header must parse")
        assertTrue(inspection.macValid, "max payload must authenticate with VBC4/runtime/protected-section key material")
        assertTrue(inspection.bindingTagValid, "max payload binding tag must cover stub and bootstrap index material")
        assertEquals("linux-x64", inspection.platform)
        assertEquals("js_kernel_linux-x64.so", inspection.outputName)
        assertEquals("elf64-so", inspection.innerFileType)
        assertEquals(nativeBytes.size, inspection.originalSize)
        assertEquals(bundle.storedPayloadSize, inspection.storedPayloadSize)
        assertEquals(bundle.encodedPayload.size, inspection.encodedPayloadSize)
        assertEquals(bundle.compressionCodec, inspection.compressionCodec)
        assertEquals(NativeKernelShellPacker.MAX_PAYLOAD_CHUNK_SIZE, inspection.chunkSize)
        assertEquals(bundle.chunkCount, inspection.chunkCount)
        assertEquals(16, inspection.nonceSize)
        assertTrue(bundle.chunkCount >= 1, "max payload must be split into authenticated chunk metadata")
        assertEquals(bundle.chunkCount * 4, bundle.chunkTags.size, "each max payload chunk must carry a 32-bit native tag")
        assertTrue(NativeKernelShellPacker.decodeMaxPayloadForTest(bundle)!!.contentEquals(nativeBytes), "test decoder should recover the original inner kernel bytes")
        assertFalse(bundle.encodedPayload.contentEquals(nativeBytes), "inner kernel must not be stored as plaintext payload")
        assertTrue(bundle.headerBytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER), "payload header must carry max payload marker")
        val renderedHeader = NativeKernelShellPacker.renderMaxPayloadHeader(bundle)
        assertTrue(renderedHeader.contains(NativeKernelShellPacker.MAX_STUB_MARKER), "generated C header must bind to the max stub marker")
        assertTrue(renderedHeader.contains("js_shell_stream_key"), "generated C header must expose the stub decode stream key")
        assertTrue(renderedHeader.contains("js_shell_build_hmac"), "generated C header must retain build-side HMAC separately from the native MAC")
        assertTrue(renderedHeader.contains(cBytesForTest(bundle.nativeMac)), "stub payload MAC must use the native-side MAC algorithm")
        assertTrue(renderedHeader.contains(cBytesForTest(bundle.streamKey)), "stub decode key must match the payload stream key")
    }

    @Test
    fun max_payload_defaults_to_zstd_then_chunk_authenticated_encoding_when_smaller() {
        val compressibleNative = ByteArray(20000) { 0x5A.toByte() }
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = compressibleNative,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 41L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )

        assertEquals(1, bundle.compressionCodec, "compressible max payload should use the bundled zstd frame codec")
        assertTrue(bundle.storedPayloadSize < compressibleNative.size, "stored zstd frame should be smaller than the original inner kernel")
        assertTrue(bundle.chunkCount >= 1, "encoded payload must still carry per-chunk tags after compression")
        assertTrue(NativeKernelShellPacker.decodeMaxPayloadForTest(bundle)!!.contentEquals(compressibleNative), "zstd + chunk decode should recover the original inner kernel")

        val tamperedTags = bundle.copy(chunkTags = bundle.chunkTags.copyOf().also { it[0] = (it[0].toInt() xor 0x7F).toByte() })
        assertEquals(null, NativeKernelShellPacker.decodeMaxPayloadForTest(tamperedTags), "tampered chunk tag must fail closed before loader mapping")
    }

    @Test
    fun native_max_decoder_carries_profile_bound_bogus_decode_surface() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_crypto.c"))

        assertTrue(source.contains("js_shell_profile_bound_mask"), "native max decoder must route chunk bytes through a profile-bound decoder lane")
        assertTrue(source.contains("layout_profile * 3u") && source.contains("dispatcher_profile * 5u"), "decoder lane selection must be bound to layout and dispatcher profiles")
        assertTrue(source.contains("bogus_accumulator") && source.contains("bogus_row"), "decoder must carry bogus decode rows in the runtime code path")
        assertTrue(source.contains("bytes[0] ^= 0u"), "bogus accumulator must remain anchored so optimizer-visible decoder surface survives native compilation")
    }

    @Test
    fun tampering_standard_overlay_fails_mac_validation() {
        val packed = NativeKernelShellPacker.pack(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 13L,
            nativePackingLevel = "standard",
            keyMaterial = keyMaterial,
        )
        val tampered = packed.copyOf()
        tampered[tampered.size - 20] = (tampered[tampered.size - 20].toInt() xor 0x41).toByte()

        assertTrue(NativeKernelShellPacker.inspect(packed, 13L, keyMaterial).macValid, "control artifact should authenticate")
        assertFalse(NativeKernelShellPacker.inspect(tampered, 13L, keyMaterial).macValid, "tampered shell overlay must fail closed at validation boundary")
    }

    @Test
    fun tampering_max_payload_or_bootstrap_binding_fails_mac_validation() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 29L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val tamperedPayload = bundle.encodedPayload.copyOf()
        tamperedPayload[tamperedPayload.lastIndex] = (tamperedPayload.last().toInt() xor 0x23).toByte()
        val wrongBootstrapDigest = bootstrapDigest.copyOf().also { it[0] = (it[0].toInt() xor 0x55).toByte() }

        assertTrue(
            NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, bundle.encodedPayload, bundle.payloadMac, 29L, keyMaterial, bootstrapDigest).macValid,
            "control max payload should authenticate",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, tamperedPayload, bundle.payloadMac, 29L, keyMaterial, bootstrapDigest).macValid,
            "tampered max payload must fail MAC validation",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, bundle.encodedPayload, bundle.payloadMac, 29L, keyMaterial, wrongBootstrapDigest).macValid,
            "bootstrap native index digest must be bound into the max payload MAC",
        )
    }

    @Test
    fun tampering_max_payload_profiles_fails_header_mac_and_chunk_decode() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 31L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val tamperedLayoutHeader = bundle.headerBytes.copyOf().also { header ->
            val offset = maxPayloadProfileOffsets(header).first
            writeIntLeForTest(header, offset, bundle.layoutProfile xor 0x01)
        }
        val tamperedDispatcherHeader = bundle.headerBytes.copyOf().also { header ->
            val offset = maxPayloadProfileOffsets(header).second
            writeIntLeForTest(header, offset, bundle.dispatcherProfile xor 0x01)
        }

        assertTrue(
            NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, bundle.encodedPayload, bundle.payloadMac, 31L, keyMaterial, bootstrapDigest).macValid,
            "control max payload should authenticate before profile tampering",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(tamperedLayoutHeader, bundle.encodedPayload, bundle.payloadMac, 31L, keyMaterial, bootstrapDigest).macValid,
            "layout profile must be bound into the max payload MAC",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(tamperedDispatcherHeader, bundle.encodedPayload, bundle.payloadMac, 31L, keyMaterial, bootstrapDigest).macValid,
            "dispatcher profile must be bound into the max payload MAC",
        )
        assertEquals(
            null,
            NativeKernelShellPacker.decodeMaxPayloadForTest(bundle.copy(layoutProfile = bundle.layoutProfile xor 0x01)),
            "layout profile mismatch must fail closed at per-chunk tag validation",
        )
        assertEquals(
            null,
            NativeKernelShellPacker.decodeMaxPayloadForTest(bundle.copy(dispatcherProfile = bundle.dispatcherProfile xor 0x01)),
            "dispatcher profile mismatch must fail closed at per-chunk tag validation",
        )
    }

    @Test
    fun repeated_max_payloads_diverge_while_same_seed_remains_verifiable() {
        val first = NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "linux-x64", "js_kernel_linux-x64.so", 17L, keyMaterial, bootstrapDigest)
        val second = NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "linux-x64", "js_kernel_linux-x64.so", 17L, keyMaterial, bootstrapDigest)

        assertFalse(first.encodedPayload.contentEquals(second.encodedPayload), "per-build nonce must make max payloads diverge")
        assertTrue(NativeKernelShellPacker.inspectMaxPayloadBundle(first.headerBytes, first.encodedPayload, first.payloadMac, 17L, keyMaterial, bootstrapDigest).macValid)
        assertTrue(NativeKernelShellPacker.inspectMaxPayloadBundle(second.headerBytes, second.encodedPayload, second.payloadMac, 17L, keyMaterial, bootstrapDigest).macValid)
        assertNotEquals(first.layoutProfile to first.dispatcherProfile, -1 to -1, "payload profiles must be populated")
    }

    private fun ByteArray.toCArrayFragmentForTest(): String = take(4).joinToString(", ") { byte -> "0x%02Xu".format(byte.toInt() and 0xFF) }

    private fun cBytesForTest(bytes: ByteArray): String = bytes.joinToString(", ") { byte -> "0x%02Xu".format(byte.toInt() and 0xFF) }

    private fun maxPayloadProfileOffsets(header: ByteArray): Pair<Int, Int> {
        var offset = NativeKernelShellPacker.MAX_PAYLOAD_MARKER.length + 1
        repeat(2) { offset += 4 }
        repeat(3) {
            val length = readIntLeForTest(header, offset)
            offset += 4 + length
        }
        repeat(7) { offset += 4 }
        return offset to offset + 4
    }

    private fun readIntLeForTest(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private fun writeIntLeForTest(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private fun resolveSource(relativePath: String): java.nio.file.Path =
        java.nio.file.Path.of(System.getProperty("user.dir")).resolve(relativePath).normalize()

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        return indices.any { start -> start + needle.size <= size && needle.indices.all { offset -> this[start + offset] == needle[offset] } }
    }
}
