package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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
    fun aken_v4_payload_bundle_carries_chunk_local_authenticated_metadata() {
        val bundle = maxBundle(seed = 23L)
        val inspection = inspect(bundle)

        assertTrue(inspection.present, "AKEN v4 payload header must parse")
        assertTrue(inspection.macValid, "AKEN v4 payload commitment must authenticate header and payload")
        assertTrue(inspection.bindingTagValid, "AKEN v4 payload must authenticate its decoded inner image")
        assertEquals("linux-x64", inspection.platform)
        assertEquals("js_kernel_linux-x64.so", inspection.outputName)
        assertEquals("elf64-so", inspection.innerFileType)
        assertEquals(nativeBytes.size, inspection.originalSize)
        assertEquals(bundle.storedPayloadSize, inspection.storedPayloadSize)
        assertEquals(bundle.encodedPayload.size, inspection.encodedPayloadSize)
        assertEquals(bundle.compressionCodec, inspection.compressionCodec)
        assertTrue(bundle.chunkSize in setOf(1024, 1536, 2048, 3072), "native chunks must use an AKEN v4 randomized page size")
        assertEquals(bundle.chunkSize, inspection.chunkSize)
        assertEquals(bundle.chunkCount, inspection.chunkCount)
        assertEquals(16, inspection.nonceSize)
        assertTrue(bundle.chunkCount >= 1, "AKEN v4 payload must be split into authenticated chunk metadata")
        assertEquals(bundle.chunkCount * 32, bundle.chunkTags.size, "each native chunk must carry a 256-bit HMAC tag")
        assertTrue(NativeKernelShellPacker.decodeMaxPayloadForTest(bundle)!!.contentEquals(nativeBytes), "test decoder should recover the original inner kernel bytes")
        assertFalse(bundle.encodedPayload.contentEquals(nativeBytes), "inner kernel must not be stored as a plaintext payload")
        assertTrue(bundle.headerBytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER), "payload prefix must carry the AKEN v4 marker")
        assertTrue(bundle.headerBytes.containsAscii("linux-x64"), "artifact routing metadata is public framing, not a key source")

        val renderedHeader = NativeKernelShellPacker.renderMaxPayloadHeader(bundle)
        assertTrue(renderedHeader.contains(NativeKernelShellPacker.MAX_STUB_MARKER), "generated C header must bind to the AKEN native stub marker")
        assertTrue(renderedHeader.contains("js_shell_payload_header"), "generated C header must carry the authenticated payload header")
        assertTrue(renderedHeader.contains("js_shell_aken_payload_commitment"), "generated C header must carry the public payload commitment")
        assertTrue(renderedHeader.contains("js_shell_aken_binding_lane_0"), "binding salt must be emitted only as shuffled C lanes")
        assertTrue(renderedHeader.contains("js_shell_aken_binding_lane_order"), "header must carry the lane reconstruction order")
        assertFalse(renderedHeader.contains("js_shell_stream_key[32]"), "generated C header must not expose a complete contiguous stream key")
        assertFalse(renderedHeader.contains("js_shell_build_hmac") || renderedHeader.contains("js_shell_expected_binding_commitment"))
        assertFalse(renderedHeader.contains("JAVASHROUD_BOOT_SECRET_") || renderedHeader.contains("JSBK1") || renderedHeader.contains("kek.dat"))
        assertFalse(renderedHeader.contains(cBytesForTest(bundle.bindingSalt)), "the binding salt must not appear as one contiguous C literal")
        assertFalse(renderedHeader.contains(cBytesForTest(bundle.streamKey)), "generated C header must not contain the complete payload stream key literal")
    }

    @Test
    fun aken_v4_payload_commitment_fails_closed_for_header_payload_or_binding_salt_tamper() {
        val bundle = maxBundle(seed = 24L, platform = "windows-x64", outputName = "js_kernel_windows-x64.dll")
        val tamperedHeader = bundle.headerBytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val tamperedPayload = bundle.encodedPayload.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val tamperedBindingSalt = bundle.bindingSalt.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertTrue(inspect(bundle).macValid, "control payload must authenticate")
        assertFalse(inspect(bundle, headerBytes = tamperedHeader).macValid, "header tampering must fail the payload commitment")
        assertFalse(inspect(bundle, encodedPayload = tamperedPayload).macValid, "payload tampering must fail the payload commitment")
        assertFalse(inspect(bundle, bindingSalt = tamperedBindingSalt).macValid, "binding-lane tampering must fail the payload commitment")
    }

    @Test
    fun aken_v4_payload_uses_zstd_then_chunk_authenticated_encoding_when_smaller() {
        val compressibleNative = ByteArray(20_000) { 0x5A.toByte() }
        val bundle = maxBundle(bytes = compressibleNative, seed = 41L)

        assertEquals(1, bundle.compressionCodec, "compressible AKEN payload should use the bundled zstd frame codec")
        assertTrue(bundle.storedPayloadSize < compressibleNative.size, "stored zstd frame should be smaller than the original inner kernel")
        assertTrue(bundle.chunkCount >= 1, "encoded payload must still carry per-chunk tags after compression")
        assertTrue(NativeKernelShellPacker.decodeMaxPayloadForTest(bundle)!!.contentEquals(compressibleNative), "zstd + chunk decode should recover the original inner kernel")

        val tamperedTags = bundle.copy(chunkTags = bundle.chunkTags.copyOf().also { it[0] = (it[0].toInt() xor 0x7F).toByte() })
        assertEquals(null, NativeKernelShellPacker.decodeMaxPayloadForTest(tamperedTags), "tampered chunk tag must fail closed before loader mapping")
    }

    @Test
    fun native_aken_v4_decoder_uses_hmac_derived_aes_ctr_chunk_subkeys() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_crypto.c"))
        assertTrue(source.contains("javashroud-aken-v4-native-shell-chunk-aes-v1"))
        assertTrue(source.contains("javashroud-aken-v4-native-shell-chunk-hmac-v1"))
        assertTrue(source.contains("javashroud-aken-v4-native-shell-chunk-iv-v1"))
        assertTrue(source.contains("js_shell_aes128_ctr_xor") && source.contains("js_shell_hmac_sha256"))
        assertFalse(source.contains("javashroud-native-shell-chunk-aes-v3") || source.contains("javashroud-native-shell-chunk-hmac-v3"))
        assertFalse(source.contains("js_shell_mix32") || source.contains("xorshift"))
    }

    @Test
    fun native_aken_v4_stub_validates_binding_lanes_and_commitment_before_inner_image_load() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_stub.c"))
        val reconstruct = source.indexOf("js_shell_reconstruct_aken_binding_salt")
        val commitment = source.indexOf("js_shell_verify_aken_payload_commitment", reconstruct)
        val extract = source.indexOf("js_shell_extract_aken_meta", commitment)
        val decode = source.indexOf("js_shell_decode_payload_chunks", extract)
        val load = source.indexOf("js_shell_load_inner_image", decode)

        assertTrue(reconstruct >= 0 && commitment > reconstruct && extract > commitment && decode > extract && load > decode)
        assertTrue(source.contains("js_shell_fail_onload"), "all native metadata failures must be fail-closed")
        assertFalse(source.contains("JAVASHROUD_BOOT_SECRET_") || source.contains("JSBK1"))
        assertFalse(source.contains("js_shell_load_boot_secret") || source.contains("js_shell_open_seed_envelope"))
        assertFalse(source.contains("js_shell_take_expected_binding_commitment") || source.contains("takeExpectedShellBindingCommitment"))
        assertFalse(source.contains("js_shell_build_hmac") || source.contains("js_shell_expected_binding_commitment"))
    }

    @Test
    fun aken_v4_max_build_does_not_invoke_legacy_provider_seam() {
        val previous = NativeKernelShellPacker.buildBootSecretProvider
        NativeKernelShellPacker.buildBootSecretProvider = { error("AKEN v4 native payload must not invoke a boot-secret provider") }
        try {
            val bundle = maxBundle(seed = 45L)
            assertTrue(inspect(bundle).macValid)
        } finally {
            NativeKernelShellPacker.buildBootSecretProvider = previous
        }
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
    fun aken_v4_payload_components_are_not_cross_bundle_interchangeable() {
        val first = maxBundle(seed = 47L)
        val second = maxBundle(bytes = nativeBytes + 0x41.toByte(), seed = 47L)

        assertTrue(inspect(first).bindingTagValid)
        assertTrue(inspect(second).bindingTagValid)
        assertFalse(
            inspect(second, payloadCommitment = first.payloadCommitment, bindingSalt = first.bindingSalt).macValid,
            "a second bundle cannot use the first bundle's commitment and binding lanes",
        )
        assertFalse(
            inspect(first, headerBytes = second.headerBytes, encodedPayload = first.encodedPayload).macValid,
            "header and payload components cannot be mixed across bundles",
        )
    }

    @Test
    fun aken_v4_binding_tag_is_artifact_specific_and_build_randomized() {
        val linux = maxBundle(seed = 37L)
        val windows = maxBundle(seed = 37L, platform = "windows-x64", outputName = "js_kernel_windows-x64.dll")
        val renamed = maxBundle(seed = 37L, outputName = "js_kernel_linux-x64-renamed.so")
        val changedBootstrap = maxBundle(seed = 37L, bootstrapNativeIndexDigest = bootstrapDigest.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x33).toByte() })

        assertFalse(linux.bindingTag.contentEquals(windows.bindingTag), "binding tag must vary with platform")
        assertFalse(linux.bindingTag.contentEquals(renamed.bindingTag), "binding tag must vary with output name")
        assertFalse(linux.bindingTag.contentEquals(changedBootstrap.bindingTag), "binding tag must vary with the bootstrap index digest")
        assertTrue(inspect(linux).bindingTagValid, "control payload must authenticate and decode")
    }

    @Test
    fun tampering_chunk_hmac_fails_before_inner_decode() {
        val bundle = maxBundle(seed = 31L)
        val tamperedTags = bundle.copy(chunkTags = bundle.chunkTags.copyOf().also { it[0] = (it[0].toInt() xor 0x5A).toByte() })
        assertEquals(null, NativeKernelShellPacker.decodeMaxPayloadForTest(tamperedTags))
    }

    @Test
    fun repeated_aken_v4_payloads_diverge_while_each_build_remains_verifiable() {
        val first = maxBundle(seed = 17L)
        val second = maxBundle(seed = 17L)

        assertTrue(
            !first.encodedPayload.contentEquals(second.encodedPayload) ||
                !first.bindingSalt.contentEquals(second.bindingSalt) ||
                !first.bindingLaneOrder.contentEquals(second.bindingLaneOrder),
            "per-build AKEN v4 nonce, binding lanes, or layout must diverge",
        )
        assertTrue(inspect(first).macValid)
        assertTrue(inspect(second).macValid)
        assertTrue(first.layoutProfile >= 0 && first.dispatcherProfile >= 0, "payload profiles must be populated")
    }

    private fun maxBundle(
        bytes: ByteArray = nativeBytes,
        seed: Long,
        platform: String = "linux-x64",
        outputName: String = "js_kernel_linux-x64.so",
        bootstrapNativeIndexDigest: ByteArray = bootstrapDigest,
    ): NativeKernelShellPacker.MaxPayloadBundle = NativeKernelShellPacker.buildMaxPayloadBundle(
        bytes = bytes,
        platform = platform,
        outputName = outputName,
        seed = seed,
        bootstrapNativeIndexDigest = bootstrapNativeIndexDigest,
    )

    private fun inspect(
        bundle: NativeKernelShellPacker.MaxPayloadBundle,
        headerBytes: ByteArray = bundle.headerBytes,
        encodedPayload: ByteArray = bundle.encodedPayload,
        payloadCommitment: ByteArray = bundle.payloadCommitment,
        bindingSalt: ByteArray = bundle.bindingSalt,
    ): NativeKernelShellPacker.MaxPayloadInspection = NativeKernelShellPacker.inspectMaxPayloadBundle(
        headerBytes = headerBytes,
        encodedPayload = encodedPayload,
        payloadCommitment = payloadCommitment,
        bindingSalt = bindingSalt,
    )

    private fun cBytesForTest(bytes: ByteArray): String = bytes.joinToString(", ") { byte -> "0x%02Xu".format(byte.toInt() and 0xFF) }

    private fun resolveSource(relativePath: String): java.nio.file.Path =
        java.nio.file.Path.of(System.getProperty("user.dir")).resolve(relativePath).normalize()

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        return indices.any { start -> start + needle.size <= size && needle.indices.all { offset -> this[start + offset] == needle[offset] } }
    }
}
