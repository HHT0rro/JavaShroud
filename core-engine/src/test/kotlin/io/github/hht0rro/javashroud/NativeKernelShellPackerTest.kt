package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
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
    private val bootSecret = ByteArray(32) { index -> (0xD3 xor index).toByte() }

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
            bootSecret = bootSecret,
        )
        val inspection = NativeKernelShellPacker.inspectMaxPayloadBundle(
            headerBytes = bundle.headerBytes,
            encodedPayload = bundle.encodedPayload,
            payloadMac = bundle.payloadMac,
            seed = 23L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
            bootSecret = bootSecret,
            artifactBindingCommitment = bundle.artifactBindingCommitment,
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
        assertEquals(bundle.chunkCount * 32, bundle.chunkTags.size, "each max payload chunk must carry a 256-bit HMAC tag")
        assertTrue(NativeKernelShellPacker.decodeMaxPayloadForTest(bundle)!!.contentEquals(nativeBytes), "test decoder should recover the original inner kernel bytes")
        assertFalse(bundle.encodedPayload.contentEquals(nativeBytes), "inner kernel must not be stored as plaintext payload")
        assertTrue(bundle.headerBytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER), "payload prefix must carry max payload marker")
        assertFalse(bundle.headerBytes.containsAscii("linux-x64") || bundle.headerBytes.containsAscii("js_kernel_linux-x64.so"), "sensitive payload header fields must be encrypted")
        val renderedHeader = NativeKernelShellPacker.renderMaxPayloadHeader(bundle)
        assertTrue(renderedHeader.contains(NativeKernelShellPacker.MAX_STUB_MARKER), "generated C header must bind to the max stub marker")
        assertFalse(renderedHeader.contains("js_shell_stream_key[32]"), "generated C header must not expose a complete contiguous stream key")
        assertFalse(renderedHeader.contains("JS_SHELL_STREAM_KEY_LANE_COUNT") || renderedHeader.contains("JS_SHELL_COPY_SCOPED_STREAM_KEY") || renderedHeader.contains("js_shell_key_material_"), "generated C header must not emit a statically evaluable lane program")
        assertFalse(
            listOf(
                "JS_SHELL_ORIGINAL_PAYLOAD_SIZE",
                "JS_SHELL_STORED_PAYLOAD_SIZE",
                "JS_SHELL_COMPRESSION_CODEC",
                "JS_SHELL_CHUNK_SIZE",
                "JS_SHELL_CHUNK_COUNT",
            ).any(renderedHeader::contains),
            "generated C header must not duplicate encrypted payload metadata as plaintext macros",
        )
        assertTrue(renderedHeader.contains("js_shell_payload_header"), "generated C header must carry the authenticated encrypted shell seed envelope")
        assertTrue(renderedHeader.contains("js_shell_build_hmac"), "generated C header must carry the boot-keyed payload commitment")
        assertFalse(renderedHeader.contains("js_shell_expected_binding_commitment"), "payload header must not carry the independent artifact commitment")
        assertFalse(renderedHeader.contains(cBytesForTest(bundle.artifactBindingCommitment)), "artifact commitment must be delivered through boot.dat instead of compiled into the shell")
        assertFalse(renderedHeader.contains(cBytesForTest(bundle.streamKey)), "generated C header must not contain the complete payload stream key literal")
    }

    @Test
    fun max_header_seed_envelope_and_ciphertext_fail_closed_when_tampered() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "windows-x64", "js_kernel_windows-x64.dll", 24L, keyMaterial, bootstrapDigest, bootSecret)
        val tampered = bundle.headerBytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val wrongBootSecret = bootSecret.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(NativeKernelShellPacker.inspectMaxPayloadBundle(tampered, bundle.encodedPayload, bundle.payloadMac, 24L, keyMaterial, bootstrapDigest, bootSecret, bundle.artifactBindingCommitment).present)
        assertFalse(NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, bundle.encodedPayload, bundle.payloadMac, 24L, keyMaterial, bootstrapDigest, wrongBootSecret, bundle.artifactBindingCommitment).present)
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
            bootSecret = bootSecret,
        )

        assertEquals(1, bundle.compressionCodec, "compressible max payload should use the bundled zstd frame codec")
        assertTrue(bundle.storedPayloadSize < compressibleNative.size, "stored zstd frame should be smaller than the original inner kernel")
        assertTrue(bundle.chunkCount >= 1, "encoded payload must still carry per-chunk tags after compression")
        assertTrue(NativeKernelShellPacker.decodeMaxPayloadForTest(bundle)!!.contentEquals(compressibleNative), "zstd + chunk decode should recover the original inner kernel")

        val tamperedTags = bundle.copy(chunkTags = bundle.chunkTags.copyOf().also { it[0] = (it[0].toInt() xor 0x7F).toByte() })
        assertEquals(null, NativeKernelShellPacker.decodeMaxPayloadForTest(tamperedTags), "tampered chunk tag must fail closed before loader mapping")
    }

    @Test
    fun native_max_decoder_uses_hmac_derived_aes_ctr_chunk_subkeys() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_crypto.c"))
        assertTrue(source.contains("javashroud-native-shell-chunk-aes-v3") && source.contains("javashroud-native-shell-chunk-hmac-v3"))
        assertTrue(source.contains("js_shell_aes128_ctr_xor") && source.contains("js_shell_hmac_sha256"))
        assertFalse(source.contains("js_shell_mix32") || source.contains("xorshift"))
    }

    @Test
    fun native_max_stub_opens_boot_envelope_before_inner_image_load() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_stub.c"))
        val open = source.indexOf("js_shell_open_seed_envelope")
        val decode = source.indexOf("js_shell_decode_payload_chunks", open)
        val load = source.indexOf("js_shell_load_inner_image", decode)
        assertTrue(open >= 0 && decode > open && load > decode)
        assertTrue(source.contains("JAVASHROUD_BOOT_SECRET_V1") && source.contains("JAVASHROUD_BOOT_SECRET_FILE_V1"))
        assertFalse(source.contains("JavaShroudBootSecretProviderV1"))
        assertTrue(source.contains("js_shell_verify_build_hmac") && source.contains("js_shell_build_hmac"))
        assertTrue(source.contains("js_shell_take_expected_binding_commitment") && source.contains("takeExpectedShellBindingCommitment"))
        assertFalse(source.contains("js_shell_binding.inc") || source.contains("js_shell_expected_binding_commitment"))
        assertFalse(source.contains("JS_SHELL_COPY_SCOPED_STREAM_KEY") || source.contains("JS_SHELL_STREAM_KEY_LANE_COUNT"))
        assertTrue(source.contains("native_install_boot_material") && source.contains("native_is_boot_material_ready") && source.contains("native_abort_boot_material"))
        assertTrue(source.contains("native_abort_boot_name") && source.contains("mapped_abort_boot") && source.contains("methods[7].signature = \"()V\""))
        assertFalse(source.contains("native_install_runtime_resource_key"))
    }

    @Test
    fun boot_secret_parser_is_strict_and_supports_hex() {
        val encoded = bootSecret.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertTrue(NativeKernelShellPacker.parseBootSecret(encoded, null)!!.contentEquals(bootSecret))
        val secretFile = java.nio.file.Files.createTempFile("javashroud-shell-secret", ".txt")
        try {
            java.nio.file.Files.writeString(secretFile, encoded, Charsets.US_ASCII)
            assertTrue(NativeKernelShellPacker.parseBootSecret(null, secretFile.toString())!!.contentEquals(bootSecret))
            java.nio.file.Files.writeString(secretFile, "$encoded\r\n", Charsets.US_ASCII)
            assertEquals(null, NativeKernelShellPacker.parseBootSecret(null, secretFile.toString()))
        } finally {
            java.nio.file.Files.deleteIfExists(secretFile)
        }
        assertEquals(null, NativeKernelShellPacker.parseBootSecret("abcd", null))
        assertEquals(null, NativeKernelShellPacker.parseBootSecret(" $encoded", null))
    }

    @Test
    fun boot_secret_provider_result_is_copied_and_wiped() {
        val provided = bootSecret.copyOf()
        val previous = NativeKernelShellPacker.buildBootSecretProvider
        NativeKernelShellPacker.buildBootSecretProvider = { provided }
        try {
            val loaded = NativeKernelShellPacker.requireBootSecretForBuild()
            try {
                assertTrue(loaded.contentEquals(bootSecret), "build must receive an independent copy of the provider KEK")
                assertTrue(provided.all { it == 0.toByte() }, "provider-owned KEK buffer must be wiped immediately after copying")
                assertFalse(loaded === provided, "build code must not retain the provider-owned KEK buffer")
            } finally {
                loaded.fill(0)
            }
        } finally {
            NativeKernelShellPacker.buildBootSecretProvider = previous
        }
    }

    @Test
    fun build_context_snapshots_boot_secret_once_per_run() {
        var providerCalls = 0
        val previous = NativeKernelShellPacker.buildBootSecretProvider
        val context = defaultVbc4BuildContext()
        NativeKernelShellPacker.buildBootSecretProvider = {
            providerCalls++
            ByteArray(32) { providerCalls.toByte() }
        }
        try {
            val first = context.copyBootSecretForBuild()
            val second = context.copyBootSecretForBuild()
            try {
                assertEquals(1, providerCalls)
                assertTrue(first.contentEquals(second))
                assertFalse(first === second)
            } finally {
                first.fill(0)
                second.fill(0)
            }
        } finally {
            context.wipe()
            NativeKernelShellPacker.buildBootSecretProvider = previous
        }
    }

    @Test
    fun max_build_fails_closed_without_boot_secret_contract() {
        val previousProvider = NativeKernelShellPacker.buildBootSecretProvider
        try {
            NativeKernelShellPacker.buildBootSecretProvider = null
            if (System.getenv(NativeKernelShellPacker.BOOT_SECRET_ENV).isNullOrBlank() && System.getenv(NativeKernelShellPacker.BOOT_SECRET_FILE_ENV).isNullOrBlank()) {
                assertFailsWith<IllegalStateException> { NativeKernelShellPacker.requireBootSecretForBuild() }
            }
        } finally {
            NativeKernelShellPacker.buildBootSecretProvider = previousProvider
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
    fun tampering_max_payload_or_bootstrap_binding_fails_mac_validation() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64.so",
            seed = 29L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
            bootSecret = bootSecret,
        )
        val tamperedPayload = bundle.encodedPayload.copyOf()
        tamperedPayload[tamperedPayload.lastIndex] = (tamperedPayload.last().toInt() xor 0x23).toByte()
        val wrongBootstrapDigest = bootstrapDigest.copyOf().also { it[0] = (it[0].toInt() xor 0x55).toByte() }

        assertTrue(
            NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, bundle.encodedPayload, bundle.payloadMac, 29L, keyMaterial, bootstrapDigest, bootSecret, bundle.artifactBindingCommitment).macValid,
            "control max payload should authenticate",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(bundle.headerBytes, tamperedPayload, bundle.payloadMac, 29L, keyMaterial, bootstrapDigest, bootSecret, bundle.artifactBindingCommitment).macValid,
            "tampered max payload must fail MAC validation",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(
                bundle.headerBytes,
                bundle.encodedPayload,
                bundle.payloadMac,
                29L,
                keyMaterial,
                wrongBootstrapDigest,
                bootSecret,
                bundle.artifactBindingCommitment,
            ).bindingTagValid,
            "bootstrap native index digest must be bound into the independent artifact commitment",
        )
    }


    @Test
    fun max_artifact_binding_commitment_rejects_cross_artifact_replay() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            nativeBytes,
            "linux-x64",
            "js_kernel_linux-x64.so",
            47L,
            keyMaterial,
            bootstrapDigest,
            bootSecret,
        )
        val replayedBundle = NativeKernelShellPacker.buildMaxPayloadBundle(
            nativeBytes + 0x41.toByte(),
            "linux-x64",
            "js_kernel_linux-x64.so",
            47L,
            keyMaterial,
            bootstrapDigest,
            bootSecret,
        )
        assertTrue(
            NativeKernelShellPacker.inspectMaxPayloadBundle(
                bundle.headerBytes,
                bundle.encodedPayload,
                bundle.payloadMac,
                47L,
                keyMaterial,
                bootstrapDigest,
                bootSecret,
                bundle.artifactBindingCommitment,
            ).bindingTagValid,
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(
                replayedBundle.headerBytes,
                replayedBundle.encodedPayload,
                replayedBundle.payloadMac,
                47L,
                keyMaterial,
                bootstrapDigest,
                bootSecret,
                bundle.artifactBindingCommitment,
            ).bindingTagValid,
            "a complete header/payload/MAC replay must fail against the original boot.dat commitment",
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
            bootSecret = bootSecret,
        )
        val windows = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "windows-x64",
            outputName = "js_kernel_windows-x64.dll",
            seed = 37L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
            bootSecret = bootSecret,
        )
        val renamed = NativeKernelShellPacker.buildMaxPayloadBundle(
            bytes = nativeBytes,
            platform = "linux-x64",
            outputName = "js_kernel_linux-x64-renamed.so",
            seed = 37L,
            keyMaterial = keyMaterial,
            bootstrapNativeIndexDigest = bootstrapDigest,
            bootSecret = bootSecret,
        )
        val wrongBootstrapDigest = bootstrapDigest.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x33).toByte() }

        assertFalse(linux.bindingTag.contentEquals(windows.bindingTag), "binding tag must be platform-bound")
        assertFalse(linux.bindingTag.contentEquals(renamed.bindingTag), "binding tag must be output-name-bound")
        assertTrue(
            NativeKernelShellPacker.inspectMaxPayloadBundle(linux.headerBytes, linux.encodedPayload, linux.payloadMac, 37L, keyMaterial, bootstrapDigest, bootSecret, linux.artifactBindingCommitment).bindingTagValid,
            "control max payload binding tag should validate",
        )
        assertFalse(
            NativeKernelShellPacker.inspectMaxPayloadBundle(linux.headerBytes, linux.encodedPayload, linux.payloadMac, 37L, keyMaterial, wrongBootstrapDigest, bootSecret, linux.artifactBindingCommitment).bindingTagValid,
            "binding tag must reject a bootstrap native index digest mismatch",
        )
    }

    @Test
    fun tampering_chunk_hmac_fails_before_inner_decode() {
        val bundle = NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "linux-x64", "js_kernel_linux-x64.so", 31L, keyMaterial, bootstrapDigest, bootSecret)
        val tamperedTags = bundle.copy(chunkTags = bundle.chunkTags.copyOf().also { it[0] = (it[0].toInt() xor 0x5A).toByte() })
        assertEquals(null, NativeKernelShellPacker.decodeMaxPayloadForTest(tamperedTags))
    }

    @Test
    fun repeated_max_payloads_diverge_while_same_seed_remains_verifiable() {
        val first = NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "linux-x64", "js_kernel_linux-x64.so", 17L, keyMaterial, bootstrapDigest, bootSecret)
        val second = NativeKernelShellPacker.buildMaxPayloadBundle(nativeBytes, "linux-x64", "js_kernel_linux-x64.so", 17L, keyMaterial, bootstrapDigest, bootSecret)

        assertFalse(first.encodedPayload.contentEquals(second.encodedPayload), "per-build nonce must make max payloads diverge")
        assertTrue(NativeKernelShellPacker.inspectMaxPayloadBundle(first.headerBytes, first.encodedPayload, first.payloadMac, 17L, keyMaterial, bootstrapDigest, bootSecret, first.artifactBindingCommitment).macValid)
        assertTrue(NativeKernelShellPacker.inspectMaxPayloadBundle(second.headerBytes, second.encodedPayload, second.payloadMac, 17L, keyMaterial, bootstrapDigest, bootSecret, second.artifactBindingCommitment).macValid)
        assertNotEquals(first.layoutProfile to first.dispatcherProfile, -1 to -1, "payload profiles must be populated")
    }

    private fun cBytesForTest(bytes: ByteArray): String = bytes.joinToString(", ") { byte -> "0x%02Xu".format(byte.toInt() and 0xFF) }

    private fun resolveSource(relativePath: String): java.nio.file.Path =
        java.nio.file.Path.of(System.getProperty("user.dir")).resolve(relativePath).normalize()

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        return indices.any { start -> start + needle.size <= size && needle.indices.all { offset -> this[start + offset] == needle[offset] } }
    }
}
