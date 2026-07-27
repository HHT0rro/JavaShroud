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
        assertTrue(inspection.bogusMetadataDigestValid, "max payload must carry authenticated bogus section metadata")
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
        assertFalse(renderedHeader.contains("js_shell_stream_key[32]"), "generated C header must not expose a complete contiguous stream key")
        assertTrue(renderedHeader.contains("JS_SHELL_STREAM_KEY_LANE_COUNT") && renderedHeader.contains("JS_SHELL_COPY_SCOPED_STREAM_KEY"), "generated C header must emit a build-specific scoped reconstruction program")
        assertTrue(renderedHeader.contains("js_shell_bogus_metadata_digest"), "generated C header must carry bogus section metadata evidence")
        assertTrue(renderedHeader.contains("js_shell_build_hmac"), "generated C header must retain build-side HMAC separately from the native MAC")
        assertTrue(renderedHeader.contains(cBytesForTest(bundle.nativeMac)), "stub payload MAC must use the native-side MAC algorithm")
        assertFalse(renderedHeader.contains(cBytesForTest(bundle.streamKey)), "generated C header must not contain the complete payload stream key literal")
    }

    @Test
    fun max_native_authenticator_changes_when_header_version_changes() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "windows-x64",
            outputName = "js_kernel_windows-x64.dll",
            seed = 24L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val tamperedHeader = bundle.headerBytes.copyOf().also { header ->
            writeIntLeForTest(header, NativeKernelShellPacker.MAX_PAYLOAD_MARKER.length + 1, NativeKernelShellPacker.PACKER_VERSION - 1)
        }
        val controlNativeMac = nativeMac32ForTest(bundle.streamKey, bundle.headerBytes, bundle.encodedPayload, bundle.bindingTag)

        assertTrue(
            bundle.nativeMac.contentEquals(controlNativeMac),
            "test-side native authenticator must match the production bundle before evaluating tamper sensitivity",
        )
        assertFalse(
            bundle.nativeMac.contentEquals(nativeMac32ForTest(bundle.streamKey, tamperedHeader, bundle.encodedPayload, bundle.bindingTag)),
            "changing the max header version must invalidate the native authenticator",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(tamperedHeader, bundle.encodedPayload, bundle.payloadMac, 24L, keyMaterial, bootstrapDigest).macValid,
            "changing the max header version must invalidate build-side inspection",
        )
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
    fun native_max_stub_reconstructs_stream_key_only_in_scoped_buffers_and_wipes_it() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_stub.c"))
        val crypto = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_crypto.c"))

        assertFalse(source.contains("js_shell_stream_key[32]"), "native stub source must not depend on a complete static stream key")
        assertTrue(source.contains("unsigned char stream_key[32]") && source.contains("JS_SHELL_COPY_SCOPED_STREAM_KEY(stream_key"), "native stub must reconstruct the key into a scoped stack buffer")
        assertTrue(source.contains("js_shell_secure_wipe(stream_key, sizeof(stream_key))"), "every native stream-key scope must be wiped immediately after MAC/decode use")
        assertFalse(source.contains("js_shell_reconstruct_stream_key") || crypto.contains("js_shell_reconstruct_stream_key"), "outer shell must not retain a stable generic key reconstruction API")
        assertTrue(crypto.contains("volatile unsigned char"), "scoped wipe primitive must resist dead-store removal")
    }

    @Test
    fun independent_max_headers_diverge_in_lane_count_layout_and_reconstruction_program() {
        fun header(): String = NativeKernelShellPacker.renderMaxPayloadHeader(
            NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "linux-x64", "js_kernel_linux-x64.so", 37L, keyMaterial, bootstrapDigest),
        )
        val first = header()
        val second = header()
        val firstProgram = first.substringAfter("#define JS_SHELL_STREAM_KEY_LANE_COUNT").substringBefore("static const unsigned char js_shell_section_digest")
        val secondProgram = second.substringAfter("#define JS_SHELL_STREAM_KEY_LANE_COUNT").substringBefore("static const unsigned char js_shell_section_digest")

        assertNotEquals(firstProgram, secondProgram, "independent max builds must emit structurally divergent lane layouts and scoped reconstruction programs")
        assertFalse(first.contains(cBytesForTest(keyMaterial)) || second.contains(cBytesForTest(keyMaterial)), "generated shell source must not expose caller key material as a complete literal")
    }

    @Test
    fun native_max_stub_revalidates_header_bound_bogus_metadata() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_stub.c"))

        assertTrue(source.contains("meta->section_digest") && source.contains("js_shell_section_digest"), "native stub must retain parsed section digest metadata from the max payload header")
        assertTrue(source.contains("meta->bogus_metadata_digest") && source.contains("js_shell_bogus_metadata_digest"), "native stub must retain parsed bogus metadata digest from the max payload header")
        assertTrue(source.contains("meta->binding_tag") && source.contains("js_shell_binding_tag"), "native stub must retain parsed binding tag metadata from the max payload header")
        assertTrue(source.contains("js_shell_consttime_equal(meta->bogus_metadata_digest, js_shell_bogus_metadata_digest"), "native stub must fail closed when header bogus metadata diverges from generated stub metadata")
        assertTrue(source.contains("js_shell_consttime_equal(meta->binding_tag, js_shell_binding_tag"), "native stub must fail closed when header binding tag diverges from generated stub metadata")
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
    fun max_payload_binding_tag_changes_with_platform_output_and_bootstrap_index() {
        val linux = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 37L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val windows = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "windows-x64",
            outputName = "js_kernel_windows-x64.dll",
            seed = 37L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val renamed = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64-renamed.so",
            seed = 37L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
        )
        val wrongBootstrapDigest = bootstrapDigest.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x33).toByte() }

        assertFalse(linux.bindingTag.contentEquals(windows.bindingTag), "binding tag must be platform-bound")
        assertFalse(linux.bindingTag.contentEquals(renamed.bindingTag), "binding tag must be output-name-bound")
        assertTrue(
            NativeKernelShellPacker.inspectMaxPayloadBundle(linux.headerBytes, linux.encodedPayload, linux.payloadMac, 37L, keyMaterial, bootstrapDigest).bindingTagValid,
            "control max payload binding tag should validate",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(linux.headerBytes, linux.encodedPayload, linux.payloadMac, 37L, keyMaterial, wrongBootstrapDigest).bindingTagValid,
            "binding tag must reject a bootstrap native index digest mismatch",
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
        val tamperedBogusMetadataHeader = bundle.headerBytes.copyOf().also { header ->
            val offset = maxPayloadBogusMetadataDigestOffset(header)
            header[offset] = (header[offset].toInt() xor 0x5A).toByte()
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
        val bogusTamperInspection = NativeKernelShellPacker.inspectMaxPayloadBundle(tamperedBogusMetadataHeader, bundle.encodedPayload, bundle.payloadMac, 31L, keyMaterial, bootstrapDigest)
        assertFalse(bogusTamperInspection.macValid, "bogus section metadata must be bound into the max payload MAC")
        assertFalse(bogusTamperInspection.bogusMetadataDigestValid, "bogus section metadata digest mismatch must be independently inspectable")
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

    private fun nativeMac32ForTest(key: ByteArray, header: ByteArray, payload: ByteArray, bindingTag: ByteArray): ByteArray {
        val state = intArrayOf(
            0x4A534D32, 0x9E3779B9u.toInt(), 0x243F6A88, 0xB7E15162u.toInt(),
            0xDEADBEEFu.toInt(), 0x8BADF00Du.toInt(), 0xC001D00Du.toInt(), 0x13579BDF,
        )
        for ((partIndex, part) in listOf(key, header, payload, bindingTag).withIndex()) {
            for (index in part.indices) {
                val value = (part[index].toInt() and 0xFF) + index * 17 + partIndex * 131
                val slot = (index + partIndex) and 7
                state[slot] = mix32ForTest(state[slot] xor value xor state[(slot + 3) and 7])
            }
        }
        val total = key.size + header.size + payload.size + bindingTag.size
        return ByteArray(32).also { out ->
            for (round in 0 until 8) {
                state[round] = mix32ForTest(state[round] xor state[(round + 1) and 7] xor total)
                writeIntLeForTest(out, round * 4, state[round])
            }
        }
    }

    private fun mix32ForTest(input: Int): Int {
        var value = input
        value = value xor (value ushr 16)
        value *= 0x7FEB352D
        value = value xor (value ushr 15)
        value *= 0x846CA68Bu.toInt()
        return value xor (value ushr 16)
    }

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

    private fun maxPayloadBogusMetadataDigestOffset(header: ByteArray): Int {
        val profiles = maxPayloadProfileOffsets(header)
        var offset = profiles.second + 4
        val nonceSize = readIntLeForTest(header, profiles.first - 4)
        offset += nonceSize
        offset += 32
        return offset
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
