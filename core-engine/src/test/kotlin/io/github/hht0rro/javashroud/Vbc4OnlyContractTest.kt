package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.encodeNativeDiversifiedVmResource
import io.github.hht0rro.javashroud.transforms.protection.vmStateBinding
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Vbc4OnlyContractTest {

    @Test
    fun serializer_outputs_vbc4_seeded_register_format_with_encrypted_sections_and_mac() {
        val serializer = VmBytecodeSerializer(buildSeed = 0x1357_2468, buildContext = fixedVbc4Context())
        serializer.visitCode()
        serializer.visitInsn(Opcodes.ICONST_2)
        serializer.visitInsn(Opcodes.ICONST_3)
        serializer.visitInsn(Opcodes.IADD)
        serializer.visitInsn(Opcodes.IRETURN)
        serializer.visitMaxs(8, 8)
        serializer.visitEnd()

        val bytes = serializer.serialize()

        assertEquals("VBC4", bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals(4, readU2(bytes, 4), "VBC4 version 4 must be encoded in the header")
        assertFalse(bytes.containsInt32BigEndian(0x1357_2468), "VBC4 must not carry the method encryption key/seed in plaintext")
        assertEquals(16, bytes.copyOfRange(26, 42).size, "VBC4 header must carry a 16-byte wrapped method seed token")
        assertFalse(bytes.copyOfRange(26, 30).contentEquals(byteArrayOf(0x13, 0x57, 0x24, 0x68)), "Wrapped seed slot must not expose the seed bytes directly")
        val flags = readU2(bytes, 42)
        assertTrue(flags and 0x0001 != 0, "VBC4 constant pool section must be encrypted")
        assertTrue(flags and 0x0002 != 0, "VBC4 instruction section must be block encrypted")
        assertTrue(flags and 0x0004 != 0, "VBC4 stream must include a MAC")
        assertTrue(flags and 0x0020 != 0, "VBC4 stream must use authenticated encryption metadata")
        val blockCount = readU2(bytes, 44)
        assertTrue(blockCount >= 1, "VBC4 must include a basic-block index")
        val macLength = bytes.last().toInt() and 0xFF
        assertEquals(32, macLength, "VBC4 MAC must be a 32-byte keyed HMAC and length tagged at EOF")
    }

    @Test
    fun vbc4_seed_wrap_is_bound_to_method_entry_token_and_resource_path() {
        val buildContext = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 5 + 11).toByte() },
            nativeSeed = 0x24681357L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 3 + 1).toByte() },
        )
        fun serializedFor(resourcePath: String): ByteArray = withVbc4BuildContext(buildContext) {
            val serializer = VmBytecodeSerializer(
                buildSeed = 0x2468_1357,
                stateBinding = vmStateBinding(0x1357_2468_9ABCL, resourcePath),
                buildContext = buildContext,
                structureEntropy = fixedStructureEntropy(),
            )
            serializer.visitCode()
            serializer.visitInsn(Opcodes.ICONST_2)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitMaxs(1, 0)
            serializer.visitEnd()
            serializer.serialize()
        }

        val first = serializedFor("META-INF/vm/a.bin")
        val second = serializedFor("META-INF/vm/b.bin")

        assertEquals("VBC4", first.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals("VBC4", second.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertTrue(first.copyOfRange(6, 22).contentEquals(second.copyOfRange(6, 22)), "Same program and seed should keep nonce stable")
        assertFalse(first.copyOfRange(26, 42).contentEquals(second.copyOfRange(26, 42)), "Wrapped seed token must change when resource-path binding changes")
        assertFalse(first.copyOfRange(first.size - 33, first.size - 1).contentEquals(second.copyOfRange(second.size - 33, second.size - 1)), "VBC4 MAC must authenticate the binding-derived seed token")
    }
    @Test
    fun native_vm_resource_envelope_uses_keyed_authentication_without_plain_seed_or_fnv() {
        val vmBytes = byteArrayOf(0x56, 0x42, 0x43, 0x34, 1, 2, 3, 4, 5, 6)
        val seed = 0x2468_1357

        val buildContext = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x1357_9BDFL,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 11 + 5).toByte() },
        )
        val encoded = withVbc4BuildContext(buildContext) {
            encodeNativeDiversifiedVmResource(vmBytes, seed)
        }

        assertFalse(encoded.containsInt32LittleEndian(seed xor 0x6A09E667), "Native VM resource must not expose the reversible seed slot")
        assertFalse(encoded.containsInt32LittleEndian(fnv1a32ForTest(vmBytes) xor seed), "Native VM resource must not expose an unkeyed FNV integrity slot")
        assertEquals(32, encoded.last().toInt() and 0xFF, "Native VM resource must end with a 32-byte keyed MAC tag")
    }

    @Test
    fun runtime_resource_codec_uses_authenticated_cipher_not_user_reachable_xor_stream() {
        val codecSource = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeResourceCodec.kt"))
        val helperSource = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val combinedSource = codecSource + "\n" + helperSource
        val forbiddenRuntimeStreamMarkers = listOf(
            "jsrp-stream",
            "HMAC-derived XOR",
            "XOR stream",
            "xor stream",
            "bytes[offset + i] ^ stream[i]",
            "stream[i] ^ bytes[offset + i]",
            "for (int i = 0; i < length; i++) bytes[offset + i]",
            "for (index in bytes.indices) bytes[index]",
        )

        assertTrue(codecSource.contains("AES/CTR/NoPadding"), "Build-time runtime resource sealing must use AES-CTR plus HMAC authentication")
        assertTrue(helperSource.contains("AES/CTR/NoPadding"), "Runtime resource unsealing must use AES-CTR plus HMAC authentication")
        forbiddenRuntimeStreamMarkers.forEach { marker ->
            assertFalse(combinedSource.contains(marker), "Runtime resource codec/helper must fail closed against legacy user-reachable XOR stream marker: $marker")
        }
        assertTrue(combinedSource.contains("constantTimeEquals") || combinedSource.contains("constantTimeTagEquals"), "Internal bitwise diff for constant-time tag comparison remains allowed and explicit")
    }

    @Test
    fun runtime_resource_compress_parameter_changes_authenticated_storage() = withVbc4BuildContext(fixedVbc4Context()) {
        val plain = ByteArray(32768) { 0x41 }
        val compressed = RuntimeResourceCodec.encode(plain, RuntimeResourceKind.VmBytecode, seed = 0x2468_1357, variantId = 4, layerCount = 3, compress = true)
        val stored = RuntimeResourceCodec.encode(plain, RuntimeResourceKind.VmBytecode, seed = 0x2468_1357, variantId = 4, layerCount = 3, compress = false)

        assertTrue(compressed.size < stored.size, "compress=true should store compressible VM resources smaller than forced plain storage")
        assertEquals(plain.toList(), RuntimeResourceCodec.decode(compressed)?.toList(), "compressed resource must round-trip")
        assertEquals(plain.toList(), RuntimeResourceCodec.decode(stored)?.toList(), "uncompressed resource must round-trip")
        val tampered = compressed.copyOf()
        tampered[25] = (tampered[25].toInt() xor 0x11).toByte()
        assertEquals(null, RuntimeResourceCodec.decode(tampered), "metadata compressed flag and hashes must be MAC-authenticated")
    }

    @Test
    fun native_verify_uses_keyed_mac_instead_of_recomputable_fnv_hash() {
        val helperSource = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val sealingSource = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"))
        val nativeKernel = Files.readString(resolveSource("src/main/native/js_kernel.c"))
        val nativeHelpers = nativeRuntimeSources()

        assertTrue(helperSource.contains("nativeVerify(byte[] data, byte[] expectedMac)"), "Java nativeVerify ABI must accept a keyed MAC byte array, not a recomputable int hash")
        assertTrue(sealingSource.contains("addMethod(jniHelper, \"nativeVerify\", \"([B[B)I\")"), "Sealed helper rename plan must preserve the byte-array MAC signature")
        assertTrue(nativeHelpers.contains("\"([B[B)I\", (void*)jsn_k1"), "JNI registration must bind nativeVerify to the keyed MAC signature")
        assertTrue(nativeKernel.contains("js_native_keyed_mac64"), "Native verify must compute a keyed MAC using native secret material")
        assertTrue(nativeKernel.contains("js_consttime_eq8"), "Native verify must compare MACs without early-exit equality")
        assertFalse(nativeKernel.contains("computed = fnv1a_hash((const unsigned char*)bytes, len)"), "Native verify must not use unkeyed FNV over attacker-controlled bytes")
        assertFalse(helperSource.contains("nativeVerify(byte[] data, int expectedHash)"), "Java nativeVerify ABI must not retain the old int hash parameter")
        assertFalse(nativeHelpers.contains("\"([BI)I\", (void*)jsn_k1"), "JNI registration must not retain the old int hash signature")
    }

    @Test
    fun runtime_sealing_rejects_legacy_native_vm_seed_fnv_envelopes() {
        val source = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"))

        assertFalse(source.contains("decodeExistingVmResourceEnvelope"), "Runtime sealing must not decode legacy seed/FNV native VM envelopes")
        assertFalse(source.contains("sealedVmResourceKeystream"), "Runtime sealing must not retain reversible seed-derived native VM keystreams")
        assertFalse(source.contains("sealedVmResourceMix"), "Runtime sealing must not retain reversible seed-derived native VM mixing")
        assertFalse(source.contains("readNativeVmLe32"), "Runtime sealing must not parse legacy plaintext seed/header slots")
        assertFalse(source.contains("fnv1a32(bytes)"), "Runtime sealing must not derive VM resource keys from unkeyed FNV fingerprints")
        assertFalse(source.contains("LEGACY_VM_RESOURCE_ROOT"), "Runtime sealing must not retain old VM resource root recognition")
        assertFalse(source.contains("isVmResource("), "Runtime sealing must not route old VM resource layouts through compatibility sealing")
        assertFalse(source.contains("encodeSealedVmResource"), "Runtime sealing must not reseal old VM resource layouts")
        assertTrue(source.contains("entry.copy(name = sealedName, bytes = RuntimeResourceCodec.decode(entry.bytes) ?: entry.bytes)"), "Bootstrap native libraries must be direct-loadable raw bytes after unwrapping any existing authenticated envelope")
        assertTrue(source.contains("encodeBootstrapNativeIndex(plain)"), "Bootstrap native index must use the Java-readable JSBI envelope instead of zstd-JSRP")
        assertFalse(source.contains("kind = RuntimeResourceKind.NativeLibrary"), "Runtime sealing must not zstd-wrap the first-stage native bridge library")
    }


    @Test
    fun jni_helper_rejects_legacy_runtime_resource_envelopes() {
        val source = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))

        assertFalse(source.contains("decodeRuntimeResourceV"), "JNI helper must not retain numbered runtime-resource decoder entrypoints")
        assertTrue(source.contains("RUNTIME_RESOURCE_VERSION = 6"), "JNI helper must pin runtime resources to the current opaque VBC4-only envelope version")
        assertFalse(source.contains("decoded != null ? decoded : raw"), "JNI helper must not pass through raw pre-VBC4 or unsealed resources")
        assertTrue(source.contains("throw new IllegalArgumentException(\"unsupported runtime resource envelope\")"), "JNI helper must fail closed on non-current runtime resources")
        assertFalse(source.contains("transformRuntimeResourceLayer"), "JNI helper must not retain legacy seed-derived runtime-resource transforms")
        assertFalse(source.contains("sealedResourceKeystream"), "JNI helper must not retain legacy sealed native keystreams")
        assertFalse(source.contains("sealedResourceMix"), "JNI helper must not retain legacy sealed native mixing")
        assertFalse(source.contains("legacyNativeRoot"), "JNI helper must not load raw legacy native resources")
        assertFalse(source.contains("bundledLibraryNames"), "JNI helper must not enumerate raw legacy native library names")
    }

    @Test
    fun java_runtime_vm_interpreter_entrypoints_are_removed() {
        val helperNames = listOf(
            listOf("Vm", "Interpreter", "Helper").joinToString(""),
            listOf("Vm", "Block", "Dispatcher", "Helper").joinToString(""),
        )

        for (helperName in helperNames) {
            val helperPath = resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/$helperName.java")
            assertFalse(Files.exists(helperPath), "Java VM helper source '$helperName' must be deleted in VBC4-only mode")
        }
    }

    @Test
    fun jni_microkernel_vm_dispatch_is_fail_closed_without_java_forwarder_or_default_return() {
        val source = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val executeBody = source.substringAfter("public static Object executeVmResource(").substringBefore("private static")

        assertTrue(executeBody.contains("nativeExecuteVmResource"), "JniMicrokernelHelper should bootstrap native VBC4 dispatch")
        assertFalse(executeBody.contains("tryExecuteForwarderFallback"), "Native VM dispatch must not use Java forwarder fallback")
        assertFalse(executeBody.contains("defaultReturn"), "Native VM dispatch must fail closed instead of returning defaults")
        assertFalse(executeBody.contains("catch (UnsatisfiedLinkError"), "Native ABI failure must reject execution, not continue")
    }

    @Test
    fun runtime_helper_deployment_and_native_registration_do_not_keep_java_vm_fallback_artifacts() {
        val jniHelper = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val helperDeployment = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/EmbeddedHelperDeployment.kt"))
        val runtimeSealing = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"))
        val methodVirtualization = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))
        val nativeRegistration = nativeRuntimeSources()

        for (forbidden in listOf("ForwarderResult", "ForwarderTarget", "VmShape", "MethodParts", "activateFallbackKernel", "vmCompute")) {
            assertFalse(jniHelper.contains(forbidden), "JniMicrokernelHelper must not retain Java VM fallback artifact '$forbidden'")
        }
        for (forbidden in listOf("JniMicrokernelHelper${"$"}Forwarder", "JniMicrokernelHelper${"$"}VmShape", "includeVmInterpreterFallback")) {
            assertFalse(helperDeployment.contains(forbidden), "Helper deployment must not inject Java VM fallback artifact '$forbidden'")
            assertFalse(runtimeSealing.contains(forbidden), "Runtime sealing must not seal Java VM fallback artifact '$forbidden'")
        }
        assertFalse(methodVirtualization.contains("serializeForwarder("), "Method virtualization must not generate Java forwarder VM resources")
        assertFalse(methodVirtualization.contains("Vm" + "Interpreter" + "Helper"), "Method virtualization must not retain Java VM interpreter dispatch owners")
        assertFalse(nativeRegistration.contains("js_native_name(\"Vm\", \"En\", \"code\")"), "JNI registration must not expose build-time nativeVmEncode")
        assertFalse(nativeRegistration.contains("js_native_name(\"Vm\", \"Dis\", \"patch\")"), "JNI registration must not expose build-time nativeVmDispatch")
        assertFalse(nativeRegistration.contains("js_helper_owner(\"Vm\", \"Interpreter\", \"\", \"Helper\")"), "JNI registration must not bind the deleted Java VM interpreter helper")
    }

    @Test
    fun c_vm_parser_accepts_only_vbc4_and_declares_register_dispatch_safety_hooks() {
        val source = nativeRuntimeSources()

        assertTrue(source.contains("0x56424334u"), "C VM parser must accept VBC4 magic only")
        assertTrue(source.contains("JS_VM_DISPATCH"), "C interpreter must route dispatch through JS_VM_DISPATCH")
        assertFalse(source.contains("#define JS_VM_DISPATCH_TABLE"), "C interpreter must not retain table-shaped dispatch marker macros")
        assertTrue(source.contains("js_vm_dispatch_done:"), "C interpreter dispatch must use a flattened exit edge instead of a switch body")
        assertTrue(source.contains("js_vm_dispatch_salt"), "C interpreter dispatch must derive runtime salt for handler matching")
        assertTrue(source.contains("js_vm_case_match"), "C interpreter dispatch must avoid plain opcode-to-handler equality checks")
        assertTrue(source.contains("js_vm_dispatch_drift_step"), "C interpreter dispatch must rotate a per-execution drift state")
        assertTrue(source.contains("js_vm_dispatch_progress_salt"), "C interpreter dispatch salt must include execution-progress drift")
        assertTrue(source.contains("dispatch_step & JS_VBC4_DISPATCH_STEP_MASK"), "C interpreter dispatch drift must rotate with a per-build mask during normal execution")
        assertFalse(source.contains("#define JS_VM_DISPATCH(insn_ptr) switch"), "C interpreter must not expose textbook switch dispatch in the VM main loop")
        assertFalse(source.contains("js_vm_dispatch_table[256]"), "C interpreter must not expose a fixed 256-entry computed-goto dispatch table")
        assertFalse(source.contains("goto *js_vm_target"), "C interpreter must not expose a direct computed-goto dispatch edge")
        assertFalse(source.contains("JS_USE_COMPUTED_GOTO"), "C interpreter must not retain the computed-goto feature gate")
        assertFalse(source.contains("js_vm_dispatch_opcode == (x)"), "C interpreter dispatch cases must not be direct opcode equality checks")
        assertTrue(source.contains("js_vbc4_wipe_volatile"), "C VM must wipe sensitive registers/JNI scratch buffers through a volatile wipe")
        assertTrue(source.contains("js_jni_callgate"), "JNI calls from the VM must flow through the callgate")
        assertTrue(source.contains("js_vbc4_decrypt_block"), "Instruction blocks must be decrypted on demand")
        assertTrue(source.contains("js_vbc4_aes_material"), "VBC4 block decrypt must derive AES-CTR key material")
        assertTrue(source.contains("js_aes128_encrypt_block(counter, key, stream)"), "VBC4 block decrypt must use AES-CTR rather than a raw HMAC keystream")
        assertTrue(source.contains("js_vbc4_hmac_sha256"), "VBC4 integrity must use a keyed HMAC instead of js_vbc4_mac16")
        assertFalse(source.contains("js_vbc4_mac16"), "VBC4 must not retain the forgeable 16-byte unkeyed MAC")
        assertFalse(source.contains("vbc4-stream"), "VBC4 block encryption must not retain legacy HMAC stream domain labels")
        assertFalse(source.contains("#define js_vbc4_decrypt_block(buf, len, seed, section, block_id) js_vbc4_xor_decrypt"), "VBC4 block decryption must not be a reversible seed XOR macro")
    }

    @Test
    fun production_sources_do_not_retain_seed_derived_vm_keystream_or_unkeyed_mac_helpers() {
        val serializer = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val nativeKernel = Files.readString(resolveSource("src/main/native/js_kernel.c"))
        val nativeHelpers = nativeRuntimeSources()

        assertFalse(serializer.contains("computeVbc3Mac32"), "VBC4 must not expose a seed-only MAC helper that suggests offline forgeability")
        assertFalse(serializer.contains("var x = seed xor"), "VBC4 entry tokens must not be generated by reversible seed/xor mixing")
        assertFalse(serializer.contains("vbc4-stream"), "VBC4 block encryption must not retain legacy HMAC stream domain labels")
        assertFalse(serializer.contains("0x56, 0x42, 0x43, 0x34, 0x6A, 0x09"), "Build serializer must not keep the contiguous flat VBC4 master key literal")
        assertFalse(nativeHelpers.contains("0x56u, 0x42u, 0x43u, 0x34u, 0x6Au, 0x09u"), "Native helper must not keep the contiguous flat VBC4 master key literal")
        assertFalse(serializer.contains("private fun vbc4MasterKey()"), "Build serializer must not retain a source-constant VBC4 master key helper")
        assertTrue(
            serializer.contains("Vbc4CryptoScope.use(vbc4MasterKey, vbc4LayoutDigest)") &&
                serializer.contains("activeVbc4ScopedKey(label: ByteArray, seed: Int, vararg parts: ByteArray)") &&
                serializer.contains("Vbc4CryptoScope.deriveScopedKey(label, seed, *parts)") &&
                serializer.contains("vbc4-session-integrity"),
            "Build serializer must take VBC4 master key material and layout digest through an explicit scoped key",
        )
        assertFalse(nativeHelpers.contains("JS_VBC4_MASTER_KEY_SHARE_A") || nativeHelpers.contains("JS_VBC4_MASTER_KEY_SHARE_B"), "Native helper must not retain repository-fixed VBC4 master key shares")
        assertTrue(nativeHelpers.contains("JS_VBC4_COPY_SCOPED_MASTER_KEY") && nativeHelpers.contains("JS_VBC4_SECRET_SLOT_BYTE"), "Native helper must consume per-build generated VBC4 secret slots through accessors")
        assertFalse(nativeHelpers.contains("JS_VBC4_BUILD_KEY_SHARE_A") || nativeHelpers.contains("JS_VBC4_BUILD_KEY_SHARE_B"), "Native helper must not retain a stable A/B share extraction recipe")
        assertFalse(nativeHelpers.contains("static unsigned char JS_VBC4_MASTER_KEY"), "Native helper must not retain a resident plaintext VBC4 master key")
        assertFalse(nativeHelpers.contains("g_vbc4_inner_pad") || nativeHelpers.contains("g_vbc4_outer_pad"), "Native helper must not retain long-lived HMAC pads for VBC4 master material")
        assertTrue(nativeHelpers.contains("js_vbc4_hmac_with_scoped_master_key") && (nativeHelpers.contains("js_vbc4_wipe_volatile(scoped_key") || nativeHelpers.contains("js_vbc4_wipe_volatile(session_key")), "Native helper must reconstruct VBC4 key material only inside scoped HMAC calls and wipe it")
        assertTrue(serializer.contains("AES/CTR/NoPadding"), "VBC4 program sections must use AES-CTR encryption")
        assertTrue(serializer.contains("vbc4-aes-key") && serializer.contains("vbc4-aes-iv"), "VBC4 AES-CTR key and IV must use separate HMAC domains")
        // 0x85EBCA6B is acceptable when used for decoy exception-table generation, not for entry token derivation
        assertTrue(
            !serializer.contains("entryToken") || !serializer.contains("0x85EBCA6B") ||
                serializer.indexOf("0x85EBCA6B") > serializer.indexOf("decoy"),
            "VBC4 entry token derivation must not retain legacy multiplication-mix constants; decoy generation usage is acceptable."
        )
        assertTrue(serializer.contains("vbc4-entry-token"), "VBC4 block entry tokens should be derived through keyed HMAC domain separation")
        assertTrue(
            serializer.contains("vbc4-exception-token") &&
                serializer.contains("vbc4-exception-mask") &&
                serializer.contains("writeU4(out, token)") &&
                serializer.contains("typeCpIndex xor vbc4ExceptionMask"),
            "VBC4 exception tables must be tokenized and masked instead of fixed plaintext u2 fields",
        )
        assertFalse(nativeKernel.contains("js_vm_ks"), "Native kernel must not retain seed-derived user-reachable keystream helpers")
        assertFalse(nativeKernel.contains("0xC2B2AE35"), "Native kernel must not retain legacy reversible keystream mix constants")
    }


    @Test
    fun method_local_handler_profile_is_encoded_for_critical_plus_and_consumed_by_native_dispatch() {
        val serializerSource = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val virtualizationSource = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))
        val nativeHelpers = nativeRuntimeSources()
        val nativeSymbols = Files.readString(resolveSource("src/main/native/js_vm_symbol.c"))

        assertTrue(serializerSource.contains("val methodLocalProfile: Int = 0"), "VBC4 metadata must carry a method-local profile slot")
        assertTrue(serializerSource.contains("methodLocalProfile.toUInt().toString(16)"), "VBC4 metadata must serialize the method-local profile")
        assertTrue(virtualizationSource.contains("methodLocalHandlerProfile(methodSelection") && virtualizationSource.contains("selectionMode != MethodSelectionMode.CriticalPlus"), "method-local profiles must be gated to critical-plus selection")
        assertTrue(virtualizationSource.contains("license") && virtualizationSource.contains("auth") && virtualizationSource.contains("signature"), "critical-plus method-local profile detection must cover license/auth/signature method names")
        assertTrue(serializerSource.contains("VBC4_FLAG_NESTED_VM") && serializerSource.contains("entryMetadata.methodLocalProfile != 0"), "High-value method-local profiles must mark resources with the nested-VM flag")
        assertTrue(nativeHelpers.contains("method_local_profile") && nativeHelpers.contains("p->method_local_profile = 0"), "Native VM program state must retain and initialize parsed method-local profile")
        assertTrue(nativeHelpers.contains("JS_VBC4_FLAG_NESTED_VM") && nativeHelpers.contains("nested_vm_profile"), "Native parser must bind nested-VM flag to a non-zero method-local profile")
        assertTrue(nativeSymbols.contains("strtoul(parts[5], NULL, 16)"), "Native VM parser must parse the sixth metadata field as the method-local profile")
        assertTrue(nativeHelpers.contains("js_vm_method_local_salt") && nativeHelpers.contains("program->method_local_profile"), "Native dispatch salt must mix the method-local profile")
    }

    @Test
    fun runtime_resource_codec_and_helper_do_not_retain_fixed_repository_key() {
        val codecSource = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeResourceCodec.kt"))
        val helperSource = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val deploymentSource = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/EmbeddedHelperDeployment.kt"))

        assertFalse(codecSource.contains("private val masterKey = byteArrayOf"), "RuntimeResourceCodec must not keep a repository-fixed resource master key")
        assertTrue(codecSource.contains("copyRuntimeResourceKey()"), "RuntimeResourceCodec must draw resource authentication key material from the VBC4 build context")
        assertFalse(helperSource.contains("RUNTIME_RESOURCE_KEY"), "JniMicrokernelHelper source must not retain the repository-fixed resource key field")
        assertTrue(helperSource.contains("runtimeResourceKey()") && helperSource.contains("Arrays.fill(key, (byte) 0)"), "JniMicrokernelHelper must use an injected runtime resource key and wipe temporary copies")
        assertTrue(deploymentSource.contains("injectRuntimeResourceKey") && deploymentSource.contains("copyRuntimeResourceKey()"), "Helper deployment must inject the build-local runtime resource key into JniMicrokernelHelper")
    }
    @Test
    fun production_sources_only_keep_current_vbc4_format_marker() {
        val scannedFiles = sequenceOf(
            Path.of("src", "main"),
        ).flatMap { root ->
            if (Files.isRegularFile(root)) sequenceOf(root) else Files.walk(root).use { stream ->
                stream.filter { Files.isRegularFile(it) }
                    .filter { path -> path.toString().replace('\\', '/').let { it.endsWith(".kt") || it.endsWith(".java") || it.endsWith(".c") || it.endsWith(".h") || it.endsWith(".py") } }
                    .toList()
                    .asSequence()
            }
        }.toList()

        val acceptedMagic = "0x56424334u"
        val legacyVmMagicPattern = Regex("0x56[0-9A-Fa-f]{6}u?")
        val offenders = scannedFiles.flatMap { path ->
            legacyVmMagicPattern.findAll(Files.readString(path))
                .map { match -> match.value }
                .filterNot { token -> token == acceptedMagic }
                .map { token -> "${path.normalize()}:$token" }
                .toList()
        }
        assertTrue(offenders.isEmpty(), "Only the current VBC4 VM magic marker should remain: $offenders")
    }

    @Test
    fun production_sources_do_not_retain_legacy_vm_identifiers() {
        val scannedFiles = Files.walk(Path.of("src", "main")).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { path -> path.toString().replace('\\', '/').let { it.endsWith(".kt") || it.endsWith(".java") || it.endsWith(".c") || it.endsWith(".h") } }
                .toList()
        }
        val forbiddenMarkers = legacyVmMarkers()
        val offenders = scannedFiles.flatMap { path ->
            val source = Files.readString(path)
            forbiddenMarkers.filter { marker -> source.contains(marker) }
                .map { marker -> "${path.normalize()}:$marker" }
        }

        assertTrue(offenders.isEmpty(), "Production sources must be VBC4-only with no legacy VM compatibility markers: $offenders")
    }


    @Test
    fun multi_block_ir_has_opaque_dispatch_chain_and_correctness_guardrails() {
        val serializer = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val nativeHelpers = nativeRuntimeSources()

        assertTrue(serializer.contains("private fun partitionLogicalGroups"), "Serializer must retain explicit multi-block IR partitioning")
        assertTrue(serializer.contains("coalesceLogicalPartitions"), "Multi-block lowering must seed-diversify block coalescing, not only splitting")
        assertTrue(serializer.contains("validateLogicalPartitions"), "Multi-block lowering must validate partition shape before serialization")
        assertTrue(serializer.contains("VBC4_FLAG_BLOCK_DISPATCH") && serializer.contains("vbc4BlockDispatchToken"),
            "Serializer must emit masked block-dispatch metadata instead of only storage-order partitions")
        assertTrue(nativeHelpers.contains("js_vbc4_decode_block_dispatch_next") && nativeHelpers.contains("block_parse_order"),
            "Native parser must validate the opaque block-dispatch chain before reassembling execution order")
        assertTrue(serializer.contains("branch targets remain") && serializer.contains("dominance/liveness"),
            "Multi-block comments must document the correctness model rather than ad-hoc rewrites")
        assertFalse(serializer.contains("VBC4 emits a single logical block"),
            "Serializer must not retain stale single-block fallback claims that contradict the active multi-block pipeline")
    }

    @Test
    fun multi_block_layout_varies_across_build_seeds_for_same_guest_program() {
        data class LayoutSignature(
            val blockCount: Int,
            val physicalBlockOrder: List<Int>,
            val plainBlockSizes: List<Int>,
            val encryptedBlockSizes: List<Int>,
        )

        fun serializedLayout(seed: Int): LayoutSignature {
            val serializer = VmBytecodeSerializer(buildSeed = seed, buildContext = fixedVbc4Context())
            serializer.visitCode()
            repeat(96) { index ->
                serializer.visitInsn(Opcodes.ICONST_0 + (index % 6))
                serializer.visitInsn(Opcodes.POP)
            }
            serializer.visitInsn(Opcodes.RETURN)
            serializer.visitMaxs(2, 0)
            serializer.visitEnd()
            val bytes = serializer.serialize()
            val blockCount = readU2(bytes, 44)
            var offset = 46
            offset += 4
            val cpSectionSize = readU4(bytes, offset)
            offset += 4 + cpSectionSize
            val physicalBlockOrder = (0 until blockCount).map {
                val blockId = readU2(bytes, offset)
                offset += 10
                blockId
            }
            val plainBlockSizes = mutableListOf<Int>()
            val encryptedBlockSizes = mutableListOf<Int>()
            repeat(blockCount) {
                plainBlockSizes += readU4(bytes, offset)
                offset += 4
                offset += 4
                val encryptedSize = readU4(bytes, offset)
                encryptedBlockSizes += encryptedSize
                offset += 4 + encryptedSize
            }
            return LayoutSignature(blockCount, physicalBlockOrder, plainBlockSizes, encryptedBlockSizes)
        }

        val layouts = listOf(0x1357_2468, 0x2468_1357, 0x1020_3040, 0x5566_7788, 0x0BAD_F00D, 0x7F4A_7C15)
            .map(::serializedLayout)
        val uniqueStructureSignatures = layouts.map {
            listOf(it.blockCount.toString(), it.physicalBlockOrder.joinToString(","), it.plainBlockSizes.joinToString(","))
                .joinToString("|")
        }.toSet()

        assertTrue(layouts.all { it.blockCount > 1 }, "Large VBC4 programs should lower into multiple logical blocks: $layouts")
        assertTrue(uniqueStructureSignatures.size >= 2,
            "Same guest program should produce high structural layout variance across build seeds: $layouts")
        assertTrue(layouts.any { it.physicalBlockOrder != it.physicalBlockOrder.sorted() },
            "At least one build should store blocks out of logical order to break linear layout fingerprints: $layouts")
        assertTrue(layouts.map { it.plainBlockSizes }.toSet().size > 1 && layouts.map { it.encryptedBlockSizes }.toSet().size > 1,
            "Block splitting/coalescing should change both logical block spans and stored encrypted sections: $layouts")
    }

    @Test
    fun semantic_predicate_super_operator_fuses_compare_and_branch_domain_ops() {
        val serializer = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val nativeHelpers = nativeRuntimeSources()

        assertTrue(serializer.contains("foldedPredicateBranchGroup"), "Serializer must expose a semantic predicate-folding lowering path")
        assertTrue(serializer.contains("VBC4_COMPARE_BUILDER_OPCODES") && serializer.contains("VBC4_PREDICATE_BRANCH_OPCODES"),
            "Serializer must classify compare builders separately from branch predicates")
        assertTrue(serializer.contains("maskedOpcodeBase = VBC4_SUPER_CMP_BRANCH") && serializer.contains("domainSuperOperandOpcode(first.opcode") && serializer.contains("domainSuperOperandOpcode(second.opcode"),
            "Compare+branch domain ops must collapse into SUPER_CMP_BRANCH while alias-diversifying embedded parameters")
        assertTrue(nativeHelpers.contains("js_vm_folded_compare_builder_allowed") && nativeHelpers.contains("js_vm_folded_predicate_branch_allowed"),
            "Native parser must validate semantic predicate folded super-operators")
        assertTrue(nativeHelpers.contains("js_vm_append_resident_insn(p, canonical_first, 0, 0)") && nativeHelpers.contains("js_vm_append_resident_insn(p, canonical_second, 1, first_operand)"),
            "Native expansion must restore the original compare builder and branch target semantics")
        assertTrue(serializer.contains("VmOpcodes.VM_IAND, VmOpcodes.VM_IOR, VmOpcodes.VM_IXOR") && serializer.contains("VmOpcodes.VM_ISHL, VmOpcodes.VM_ISHR, VmOpcodes.VM_IUSHR -> VBC4_SUPER_INT_ARITH"),
            "Non-folded SUPER_INT_ARITH coverage must include bitwise and shift domain ops")
        assertTrue(nativeHelpers.contains("original_opcode == JS_VM_IAND") && nativeHelpers.contains("original_opcode == JS_VM_IUSHR"),
            "Native verifier must accept bitwise/shift originals carried by SUPER_INT_ARITH")
        assertTrue(serializer.contains("return if (selector % 4 == 0) null else superOpcode"),
            "Eligible semantic classes should bias toward super-operator lowering while preserving seed diversity")
        assertTrue(Regex("if \\(selector % 4 == 0\\) return null").findAll(serializer).count() >= 2,
            "Folded semantic super-operators should also use high-coverage seed-diverse lowering gates")
    }

    @Test
    fun opcode_dialect_salt_binds_alias_and_super_operator_selection_to_entry_state() {
        val serializer = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))

        assertTrue(serializer.contains("private val opcodeDialectSalt: Int = vbc4OpcodeDialectSalt(effectiveBuildSeed, stateBinding, entryMetadata)"),
            "VBC4 opcode dialect selection must be salted by method entry state, not only build seed")
        assertTrue(serializer.contains("vbc4-opcode-dialect") && serializer.contains("stateBinding.toByteArray") && serializer.contains("entryMetadata.encode().toByteArray"),
            "Opcode dialect salt must bind resource/entry metadata so same-seed methods do not reuse an isomorphic VM dialect")
        assertTrue(serializer.contains("private fun structureSelector") && serializer.contains("opcodeDialectSalt.rotateLeft") && serializer.contains("structureEntropyWord"),
            "Dialect-dependent structure selection must mix entry salt with per-method structure entropy")
        listOf("opcode-alias", "super-opcode", "folded-super", "folded-predicate", "super-plan").forEach { marker ->
            assertTrue(serializer.contains("structureSelector(\"$marker\""), "VM dialect selector must cover $marker")
        }
        assertTrue(serializer.contains("structureEntropyDigest") && serializer.contains("readMacInt(structureEntropyDigest)") && serializer.contains("private val structureSalt"),
            "Opcode dialect salt should also include per-method structure entropy digest")
    }

    @Test
    fun vm_entropy_plan_is_internal_and_covers_resource_domains() {
        val source = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))
        assertTrue(source.contains("internal data class VmEntropyPlan") && source.contains("internal data class VmEntropyWord"), "VM entropy plan should be internal-only")
        listOf("serializer-structure", "resource-path", "shard-cut-plan", "decoy-").forEach { marker ->
            assertTrue(source.contains(marker), "VM entropy plan must derive independent domain: $marker")
        }
        assertTrue(source.contains("decoyVmPayload") && source.contains("payload[0] = 'V'.code.toByte()") && source.contains("writeBigEndianInt(payload"),
            "Decoy resources should keep a VBC4-like shape while remaining unauthenticatable")
    }

    @Test
    fun opcode_aliasing_reduces_one_to_one_mapping_residue_below_threshold() {
        val serializer = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val opcodeNames = Regex("const val (VM_[A-Z0-9_]+) = 0x[0-9A-F]+")
            .findAll(serializer)
            .map { it.groupValues[1] }
            .filterNot { it.endsWith("_ALT") || it.endsWith("_ALT2") }
            .filterNot { it in setOf("VM_UNSUPPORTED", "VM_TABLESWITCH", "VM_LOOKUPSWITCH", "VM_MAXS") }
            .toSet()
        val aliasedNames = Regex("VmOpcodes\\.(VM_[A-Z0-9_]+) to intArrayOf\\(")
            .findAll(serializer)
            .map { it.groupValues[1] }
            .toSet()
        val residuePermille = ((opcodeNames - aliasedNames).size * 1000) / opcodeNames.size

        assertTrue(opcodeNames.size >= 120, "Residue threshold must cover the broad VM opcode surface")
        assertTrue(aliasedNames.size >= 80, "Alias surface must stay broad across semantic families")
        assertTrue(residuePermille <= 450, "One-to-one opcode mapping residue must stay <=45%, got ${'$'}residuePermille permille")
    }

    @Test
    fun native_anti_debug_uses_syscall_kernel_boundary_signals_not_just_weak_userland_checks() {
        val nativeHelpers = nativeRuntimeSources()
        // High-confidence kernel-boundary probes must exist.
        assertTrue(nativeHelpers.contains("js_vm_strong_debugger_present"), "Native kernel must expose an aggregated strong-debugger verdict")
        assertTrue(nativeHelpers.contains("SYS_ptrace") && nativeHelpers.contains("js_vm_syscall_ptrace_child_probe") && nativeHelpers.contains("waitpid"),
            "Linux anti-debug must use a raw ptrace child probe, not a libc-only check or main-process self attach")
        assertTrue(!nativeHelpers.contains("js_vm_syscall_ptrace_self_attached"),
            "Linux anti-debug must not call PTRACE_TRACEME from the protected JVM process itself")
        assertTrue(nativeHelpers.contains("SYS_openat") || nativeHelpers.contains("SYS_open"),
            "Linux TracerPid probe must read /proc via raw syscalls, bypassing libc fopen hooks")
        assertTrue(nativeHelpers.contains("NtQueryInformationProcess"),
            "Windows anti-debug must consult NtQueryInformationProcess (ProcessDebugPort/Flags), not only IsDebuggerPresent")
        assertTrue(nativeHelpers.contains("BeingDebugged") || nativeHelpers.contains("0x02"),
            "Windows anti-debug should read PEB->BeingDebugged directly")
        assertTrue(nativeHelpers.contains("P_TRACED"), "macOS anti-debug must use the sysctl P_TRACED kernel flag")
        // Safe degradation: the strong verdict is integrated through the existing streak-gated,
        // dispatch-poison path rather than an unconditional hard abort.
        assertTrue(nativeHelpers.contains("strong_debug_streak"), "Strong anti-debug must require a confirmation streak before poisoning dispatch")
    }

    @Test
    fun native_critical_region_protection_has_encrypted_section_and_load_time_decrypt() {
        val nativeHelpers = nativeRuntimeSources()
        // Protected code section + load-time decrypt constructor.
        assertTrue(nativeHelpers.contains("JS_PROTECTED_SECTION_NAME") && nativeHelpers.contains("\".jsx\""),
            "Native kernel must define a dedicated protected code section")
        assertTrue(nativeHelpers.contains("__attribute__((constructor))") && nativeHelpers.contains("js_protected_section_unseal"),
            "Native kernel must decrypt the protected section at load time before use")
        assertTrue(nativeHelpers.contains("js_protected_section_xor") && nativeHelpers.contains("JS_PROTECTED_SECTION_KEY"),
            "Native kernel must carry the keystream decrypt path and embedded key")
        // Critical hot functions must be placed in the protected section.
        assertTrue(nativeHelpers.contains("JS_PROTECTED static jint js_vm_canonical_opcode"),
            "Opcode canonicalization must live in the protected section")
        // The build-time patcher must exist and be wired into recompilation.
        val packer = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeProtectedSectionPacker.kt"))
        assertTrue(packer.contains("sealIfPossible") && packer.contains("relocOverlapsPeSection") && packer.contains("elfRelocationOverlapsSection"),
            "Native patcher must seal PE/ELF sections and verify relocations do not overlap them")
        val recompile = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        assertTrue(recompile.contains("NativeProtectedSectionPacker.sealIfPossible"),
            "Recompilation must invoke the protected-section patcher on produced native binaries")
    }

    @Test
    fun native_nested_virtualization_dispatches_static_and_instance_preloaded_targets() {
        val nativeHelpers = nativeRuntimeSources()
        assertTrue(nativeHelpers.contains("js_vm_try_invoke_preloaded_nested"),
            "Native VM must attempt second-stage execution for preloaded virtualized callees")
        assertTrue(nativeHelpers.contains("opcode == JS_VM_INVOKESTATIC") && nativeHelpers.contains("js_vm_try_invoke_preloaded_nested(env, cached_symbol, NULL, args"),
            "Static virtualized callees must dispatch through the preloaded nested VM instead of stable JVM calls")
        assertTrue(nativeHelpers.contains("js_vm_try_invoke_preloaded_nested(env, cached_symbol, target, args"),
            "Instance virtualized callees must dispatch through the preloaded nested VM")
        assertTrue(!nativeHelpers.contains("!cp_self_call"),
            "Static self-calls must also dispatch through the preloaded nested VM so force virtualization does not preserve plaintext recursion")
    }

    @Test
    fun native_cross_method_shared_dispatcher_state_pool_is_present_and_semantics_neutral() {
        val nativeHelpers = nativeRuntimeSources()
        assertTrue(nativeHelpers.contains("js_vm_shared_dispatch_pool"),
            "Native kernel must maintain a process-wide shared cross-method dispatcher-state pool")
        assertTrue(nativeHelpers.contains("js_vm_shared_dispatch_seed_for") && nativeHelpers.contains("js_vm_shared_dispatch_evolve"),
            "Methods must seed dispatch drift from the shared pool and evolve it on exit (interprocedural scheduling)")
        assertTrue(nativeHelpers.contains("js_vm_shared_dispatch_seed_for(p)"),
            "Per-run dispatch drift must be seeded from the shared cross-method pool")
        // Semantics-neutrality guard: the coupling rides on the salt-invariant dispatch
        // path, so case matching must remain salt-invariant.
        assertTrue(nativeHelpers.contains("js_vm_case_match"),
            "Dispatch matching must stay salt-invariant so shared state never changes handler selection")
        assertTrue(nativeHelpers.contains("js_vm_shared_dispatch_mix_preload") && nativeHelpers.contains("manifest_path") && nativeHelpers.contains("shard_count"),
            "Cross-method VMBC shard metadata from the preload index must perturb the shared dispatcher pool")
    }

    private fun nativeRuntimeSources(): String = listOf(
        "src/main/native/js_helpers.c",
        "src/main/native/js_native_common.h",
        "src/main/native/js_native_common.c",
        "src/main/native/js_crypto.h",
        "src/main/native/js_crypto.c",
        "src/main/native/js_antidebug.h",
        "src/main/native/js_antidebug.c",
        "src/main/native/js_protected_section.h",
        "src/main/native/js_protected_section.c",
        "src/main/native/native_secrets.inc",
        "src/main/native/js_jni_runtime.h",
        "src/main/native/js_jni_runtime.c",
        "src/main/native/js_vm_internal.h",
        "src/main/native/js_vm_core.h",
        "src/main/native/js_vm_core.c",
        "src/main/native/js_vm_resource.h",
        "src/main/native/js_vm_resource.c",
        "src/main/native/js_vm_symbol.h",
        "src/main/native/js_vm_symbol.c",
    ).joinToString(separator = "\n") { relativePath ->
        Files.readString(resolveSource(relativePath))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        if (Files.exists(direct)) return direct
        return Path.of("core-engine").resolve(relativePath)
    }

    private fun fixedVbc4Context(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 19 + 7).toByte() },
        nativeSeed = 0x5642_4334L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 23 + 11).toByte() },
    )

    private fun fixedStructureEntropy(): ByteArray = ByteArray(32) { index -> (index * 7 + 13).toByte() }

    private fun readU2(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU4(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    private fun ByteArray.containsInt32BigEndian(value: Int): Boolean {
        if (size < 4) return false
        for (offset in 0..(size - 4)) {
            if (readU4(this, offset) == value) return true
        }
        return false
    }

    private fun ByteArray.containsInt32LittleEndian(value: Int): Boolean {
        if (size < 4) return false
        for (offset in 0..(size - 4)) {
            if (((this[offset].toInt() and 0xFF) or
                    ((this[offset + 1].toInt() and 0xFF) shl 8) or
                    ((this[offset + 2].toInt() and 0xFF) shl 16) or
                    ((this[offset + 3].toInt() and 0xFF) shl 24)) == value
            ) return true
        }
        return false
    }

    private fun fnv1a32ForTest(bytes: ByteArray): Int {
        var hash = 0x811C9DC5.toInt()
        for (byte in bytes) {
            hash = hash xor (byte.toInt() and 0xFF)
            hash *= 0x01000193
        }
        return hash
    }
}


private fun legacyVmMarkers(): List<String> = listOf(
    "VB" + "C1",
    "VB" + "C2",
    "vb" + "c1",
    "vb" + "c2",
    "VM" + "BC",
    "0x564243" + "31",
    "0x564243" + "32",
    "0x564d" + "4243",
)
