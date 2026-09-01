package io.github.hht0rro.javashroud

import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpRuntimeBridgeApiTest {
    @Test
    fun typed_native_bridge_exposes_only_page_bound_native_requests() {
        val helper = Class.forName("io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge")
        val expected = mapOf(
            "nativeInit" to arrayOf(String::class.java),
            "nativeHeartbeat" to emptyArray(),
            "nativeInstallSessionNonce" to arrayOf(ByteArray::class.java),
            "nativeInstallCatalog" to arrayOf(ByteArray::class.java, ByteArray::class.java),
            "nativeExecuteVmPage" to arrayOf(
                Long::class.javaPrimitiveType!!,
                ByteArray::class.java,
                Array<Any>::class.java,
            ),
            "nativeOpenStringPage" to arrayOf(ByteArray::class.java),
            "nativeReadClassPage" to arrayOf(ByteArray::class.java),
            "nativeConsumeNativeSegment" to arrayOf(ByteArray::class.java),
            "nativeInitializeDefense" to arrayOf(String::class.java, String::class.java),
            "nativeProbeDefense" to arrayOf(String::class.java, String::class.java),
            "nativeTransformDefense" to arrayOf(ByteArray::class.java, String::class.java),
            "nativeInvokeSite" to arrayOf(
                java.lang.invoke.MethodHandles.Lookup::class.java,
                String::class.java,
                java.lang.invoke.MethodType::class.java,
                ByteArray::class.java,
                Array<Any>::class.java,
                Boolean::class.javaPrimitiveType!!,
            ),
        )

        expected.forEach { (name, parameters) ->
            val method = helper.getDeclaredMethod(name, *parameters)
            assertTrue(Modifier.isNative(method.modifiers), "$name must remain a native current entry")
            assertTrue(Modifier.isStatic(method.modifiers), "$name must remain static for generated call sites")
        }
        assertEquals(
            expected.keys.toSet(),
            helper.declaredMethods.filter { Modifier.isNative(it.modifiers) }.mapTo(linkedSetOf()) { it.name }.toSet(),
            "The source helper must declare exactly the current typed JNI registrations",
        )

        val stringParameters = arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java)
        val nativeStringTerminal = helper.getDeclaredMethod("nativeOpenStringPage", ByteArray::class.java)
        val stringTerminal = helper.getDeclaredMethod("openQpString", *stringParameters)
        assertEquals(String::class.java, nativeStringTerminal.returnType)
        assertEquals(String::class.java, stringTerminal.returnType)
        assertFalse(Modifier.isPublic(nativeStringTerminal.modifiers), "native String terminal must remain package-private")
        assertTrue(Modifier.isPublic(stringTerminal.modifiers), "validated String terminal must remain callable from generated application dispatchers")

        val nativeChunkConsumer = helper.getDeclaredMethod(
            "nativeConsumeNativeSegment",
            ByteArray::class.java,
        )
        assertTrue(nativeChunkConsumer.returnType == Void.TYPE, "native chunk bridge must not return plaintext to Java")
        val publicChunkConsumer = helper.getDeclaredMethod(
            "consumeQpNativeChunk",
            ByteArray::class.java,
            Int::class.javaPrimitiveType!!,
            ByteArray::class.java,
        )
        assertTrue(publicChunkConsumer.returnType == Void.TYPE, "public native chunk bridge must remain a native-only consumer")

        val declared = helper.declaredMethods.associateBy { it.name }
        assertFalse("nativeMapAkenNativeChunk" in declared, "Qp must not retain the byte[] native chunk mapper")
        assertFalse("mapQpNativeChunk" in declared, "Qp must not retain the byte[] native chunk wrapper")
        assertFalse("nativeDecodeAkenPage" in declared, "Qp must not expose a generic page decoder")
        assertFalse("nativeDecodeAkenResource" in declared, "Qp must not expose arbitrary resource decoding")
        assertFalse("nativeInstallAkenKey" in declared, "Qp must not accept external or global key material")
        assertFalse("nativeInstallAkenCatalog" in declared, "retired catalog installer name must be absent")
    }

    @Test
    fun native_readiness_loader_is_independent_from_legacy_boot_chain() {
        val source = Files.readString(workspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"))
        val readinessStart = source.indexOf("private static synchronized void loadQpNativeKernel()")
        val readinessEnd = source.indexOf("private static byte[] requireQpPageResult", readinessStart)
        assertTrue(readinessStart >= 0 && readinessEnd > readinessStart, "Qp readiness block must remain locatable")
        val readiness = source.substring(readinessStart, readinessEnd)

        assertTrue(source.contains("QP_NATIVE_LOCATOR_RESOURCE = \"META-INF/jsrt/native.locator\""), "current readiness must use the Rust runtime locator root")
        assertTrue(source.contains("QP_NATIVE_BINDINGS_LOCATOR_RESOURCE = \"META-INF/jsrt/native.bindings.locator\""), "current readiness must use the Rust runtime bindings locator root")
        assertFalse(source.contains("META-INF/qp/native.locator"), "current readiness must not retain the retired logical locator path")
        assertFalse(source.contains("META-INF/qp/native.bindings.locator"), "current readiness must not retain the retired logical bindings path")
        assertTrue(source.contains("QP_NATIVE_RESOURCE_ROOT = \"META-INF/\""), "current locator routes must remain constrained to the final resource root")
        assertTrue(readiness.contains("readQpLocator"), "current readiness must authenticate the binary locator before extraction")
        assertTrue(readiness.contains("validateNativeImage"), "current readiness must validate the selected PE or ELF image and exports")
        assertTrue(readiness.contains("publishSealedNativeBindings"), "current readiness must publish final relocation metadata before native registration")
        assertTrue(source.contains("QP_CATALOG_INDEX_RESOURCE = \"META-INF/jsrt/catalog.index\""), "current readiness must locate the authenticated page catalog index")
        assertTrue(source.contains("installQpCatalog"), "current readiness must install the page catalog after native load")
        assertFalse(source.contains("directory.jsr1"), "catalog loader must not hard-code the retired directory file name")
        assertTrue(source.contains("readQpCatalogBundle"), "current load must read the catalog bundle from original page containers")
        assertTrue(readiness.contains("System.load("), "current readiness must load only the authenticated bundled artifact")
        assertTrue(readiness.contains("initializeNativeKernel("), "current readiness must prove nativeInit registration")
        assertTrue(readiness.contains("installQpSessionNonce()"), "current readiness must prove the session-nonce registration")
        assertTrue(readiness.contains("verifyQpNativeAbiAfterLoad"), "current readiness must prove the remaining five JNI registrations")
        assertTrue(readiness.contains("nativeHeartbeat"), "current ABI probe must reach the heartbeat route")
        assertTrue(readiness.contains("nativeExecuteVmPage"), "current ABI probe must reach the VM page route")
        assertTrue(readiness.contains("nativeOpenStringPage"), "current ABI probe must reach the String-returning page route")
        assertTrue(readiness.contains("nativeReadClassPage"), "current ABI probe must reach the class page route")
        assertTrue(readiness.contains("nativeConsumeNativeSegment"), "current ABI probe must reach the native-chunk route")

        val lowerSource = source.lowercase()
        for (retiredPlatformMarker in listOf("meta-inf/qp/", "macos", "darwin", "mach-o", ".dylib")) {
            assertFalse(lowerSource.contains(retiredPlatformMarker), "current helper source retained retired platform material: $retiredPlatformMarker")
        }

        for (legacy in listOf(
            "prepareJavaBootMaterialForLoad",
            "installBootMaterialIntoNative",
            "preloadRuntimeResourcesIntoNative",
            "verifyBootTokenAfterLoad",
            "nativeInstallBootMaterial",
            "nativeInstallBootEnvelope",
            "nativeIsBootMaterialReady",
            "nativeAbortBootMaterial",
            "loadBootSecret",
            "readBootKekSidecarBinary",
            "sealedNativeIndexText",
            "decodeRuntimeResource",
            "System.getenv",
        )) {
            assertFalse(readiness.contains(legacy), "Qp readiness must not re-enter the legacy boot path: $legacy")
        }

        val loadKernelStart = source.indexOf("public static synchronized void loadKernel(")
        val loadKernelEnd = source.indexOf("private static boolean targetPlatformAllowsCurrent", loadKernelStart)
        assertTrue(loadKernelStart >= 0 && loadKernelEnd > loadKernelStart, "public native loader block must remain locatable")
        val publicLoader = source.substring(loadKernelStart, loadKernelEnd)
        assertTrue(publicLoader.contains("loadQpNativeKernel()"), "legacy helper entrypoints must converge on the Qp raw native loader")
        assertFalse(publicLoader.contains("prepareJavaBootMaterialForLoad"), "public native loading must not require JSBM boot material")
        assertFalse(publicLoader.contains("tryLoadBundledNative("), "public native loading must not re-enter the legacy sealed-index path")
    }

    @Test
    fun native_locator_is_binary_v2_per_platform_and_rejects_legacy_envelopes() {
        val helperSource = Files.readString(workspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"))
        val parserStart = helperSource.indexOf("private static QpNativeLibrary readQpLocator")
        val parserEnd = helperSource.indexOf("private static boolean hasQpLocatorMagic", parserStart)
        assertTrue(parserStart >= 0 && parserEnd > parserStart, "Qp locator parser must remain locatable")
        val parser = helperSource.substring(parserStart, parserEnd)

        assertTrue(parser.contains("hasQpLocatorMagic"), "locator parser must require the binary D7 A4 91 E3 magic")
        assertTrue(parser.contains("QP_NATIVE_LOCATOR_VERSION"), "locator parser must enforce the current binary version")
        assertTrue(parser.contains("QP_NATIVE_LOCATOR_COMMITMENT_BYTES"), "locator parser must reserve a terminal commitment")
        assertTrue(parser.contains("readQpLocatorU16"), "locator parser must decode bounded big-endian record counts and routes")
        assertTrue(parser.contains("readQpLocatorPositiveU32"), "locator parser must validate positive u32 stored lengths")
        assertTrue(parser.contains("unmaskQpLocatorRoute"), "locator parser must unmask and validate binary routes")
        assertTrue(parser.contains("isQpNativeRouteBytes"), "locator parser must validate route bytes before ASCII decoding")
        assertTrue(parser.contains("nativeLocatorCommitment"), "locator parser must authenticate the exact binary payload")
        assertTrue(parser.contains("MessageDigest.isEqual"), "locator commitment must use constant-time comparison")
        assertTrue(parser.contains("seenRoutes"), "locator parser must reject duplicate routes")
        assertTrue(parser.contains("bindingSeen"), "locator parser must reject duplicate or non-terminal bindings")
        assertTrue(parser.contains("hasQpRejectedLegacyHeader"), "locator parser must reject legacy protocol headers")
        assertTrue(helperSource.contains("QP_NATIVE_LOCATOR_MAGIC_0 = 0xD7"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("QP_NATIVE_LOCATOR_MAGIC_1 = 0xA4"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("QP_NATIVE_LOCATOR_MAGIC_2 = 0x91"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("QP_NATIVE_LOCATOR_MAGIC_3 = 0xE3"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("QP_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN"), "route masking domain must remain explicit and versioned")
        assertFalse(parser.contains("\"QP_NATIVE_LOCATOR_RECORD\""), "binary locator parser must not retain textual record tags")
        assertFalse(parser.contains("\"QP_NATIVE_BINDINGS_LOCATOR_RECORD\""), "binary locator parser must not retain textual binding tags")
        assertFalse(parser.contains("parseQpNativeLength"), "binary locator parser must not parse decimal text lengths")
        assertFalse(parser.contains("parseQpNativeSha256"), "binary locator parser must not parse hexadecimal text digests")
        assertFalse(parser.contains("sealedNativeIndexText"), "raw locator parser must not traverse legacy JSBI")
        assertFalse(parser.contains("sealedNativeBindingText"), "raw locator parser must not load legacy bindings")
        assertFalse(parser.contains("decodeRuntimeResource"), "raw locator parser must not decode JSRP")

        val sealingSource = Files.readString(workspacePath("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"))
        val locatorSource = Files.readString(workspacePath("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpLocator.kt"))
        assertTrue(sealingSource.contains("QP_NATIVE_LOCATOR_LOGICAL_RESOURCE"), "sealing must rewrite the logical locator path")
        assertTrue(locatorSource.contains("QP_NATIVE_LOCATOR_LOGICAL_RESOURCE = \"META-INF/jsrt/native.locator\""), "the logical locator must use the current jsrt root")
        assertTrue(locatorSource.contains("QP_NATIVE_BINDINGS_LOCATOR_LOGICAL_RESOURCE = \"META-INF/jsrt/native.bindings.locator\""), "the bindings locator must use the current jsrt root")
        assertFalse(locatorSource.contains("META-INF/qp/native.locator"), "the serializer must not retain the retired logical locator path")
        assertFalse(locatorSource.contains("META-INF/qp/native.bindings.locator"), "the serializer must not retain the retired logical bindings path")
        assertTrue(sealingSource.contains("QpLocator.entry("), "sealing must create one locator row per final native resource")
        assertTrue(sealingSource.contains("storedBytes = nativeBytes"), "locator digest and length must derive from final sealed native bytes")
        assertTrue(sealingSource.contains("suffix = nativeSpec.loadSuffix"), "final sealed native route must retain the loader suffix")
        assertTrue(sealingSource.contains("return \"${'$'}{sealedResourceRoot(seed)}/"), "final sealed native paths must be randomized after sealing")
    }

    @Test
    fun typed_native_bridge_native_registration_is_purpose_split_and_fail_closed() {
        val ffi = Files.readString(workspacePath("core-engine/src/main/rust/crates/qp-ffi/src/lib.rs"))
        val relocation = Files.readString(workspacePath("core-engine/src/main/rust/crates/qp-ffi/src/relocation.rs"))
        for (marker in listOf(
            "nativeExecuteVmPage",
            "nativeOpenStringPage",
            "nativeReadClassPage",
            "nativeConsumeNativeSegment",
            "\"([B)Ljava/lang/String;\"",
            "\"([B)V\"",
        )) {
            assertTrue(relocation.contains(marker) || ffi.contains(marker), "current JNI registration must keep typed route $marker")
        }
        assertTrue(relocation.contains("QP-BINDING-V1|"), "JNI_OnLoad must recover renamed helpers from published binding keys")
        assertTrue(ffi.contains("j.l\\0") || ffi.contains("b\"j.l\\0\""), "JNI_OnLoad must read the published loader owner")
        assertTrue(ffi.contains("j.m\\0") || ffi.contains("b\"j.m\\0\""), "JNI_OnLoad must read published method bindings")
        assertTrue(ffi.contains("resolve_registration_plan"), "JNI_OnLoad must restore renamed helper names before RegisterNatives")
        assertFalse(ffi.contains("nativeDecodeAkenStringPage"), "retired whole-page String byte[] registration must be absent")
        assertFalse(ffi.contains("nativeMapAkenNativeChunk"), "obsolete byte[] native chunk registration must be absent")
        assertTrue(ffi.contains("Qp VM page route is unavailable"), "unwired VM route must fail closed")
        assertTrue(ffi.contains("Qp typed page route is unavailable"), "unwired string/class/native routes must fail closed")
        assertFalse(ffi.contains("jsn_k13"), "current JNI must not call the legacy generic runtime decoder")
        assertFalse(ffi.contains("js_runtime_resource_decode_owned"), "current JNI must not call the legacy resource decode core")
        assertFalse(ffi.contains("nativeInstallBoot"), "current JNI must not install legacy boot material")

        val owner = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge"
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest("QP-BINDING-V1|$owner".toByteArray(StandardCharsets.UTF_8))
        val key = digest.copyOfRange(0, 8).joinToString("") { byte -> "%02x".format(byte) }
        assertEquals(16, key.length)
        assertTrue(relocation.contains("QP-BINDING-V1|"), "Rust relocation domain must match Kotlin")
    }

    @Test
    fun native_image_validator_accepts_only_complete_amd64_cdylibs() {
        validateNativeImage("x86_64-pc-windows-gnu", peNativeImage())
        validateNativeImage("x86_64-unknown-linux-gnu.2.17", elfNativeImage())

        val missingRegistration = assertFailsWith<SecurityException> {
            validateNativeImage("x86_64-pc-windows-gnu", peNativeImage(NATIVE_BINDING_MARKERS.dropLast(1)))
        }
        assertTrue(missingRegistration.message.orEmpty().contains("nativeInvokeSite"))

        val executableImage = peNativeImage().also { putLe16(it, PE_OFFSET + 22, 0x0022) }
        assertFailsWith<SecurityException> {
            validateNativeImage("x86_64-pc-windows-gnu", executableImage)
        }
        assertFailsWith<SecurityException> {
            validateNativeImage("x86_64-unknown-linux-gnu", elfNativeImage())
        }
        assertFailsWith<SecurityException> {
            validateNativeImage("x86_64-unknown-linux-gnu.2.17", peNativeImage())
        }
    }

    @Test
    fun native_resource_validator_rejects_retired_and_non_current_routes() {
        val derivedRoot = io.github.hht0rro.javashroud.transforms.protection.qp.qpResourceDir()
        assertTrue(isNativeResourcePath("$derivedRoot/windows-x64/qp_ffi.dll"))
        assertTrue(isNativeResourcePath("$derivedRoot/linux-x64/libqp_ffi.so"))
        assertTrue(isNativeResourcePath("META-INF/ab/0123456789abcdef/cd/final.txt"))
        assertFalse(isNativeResourcePath("META-INF/jsrt/windows-x64/qp_ffi.dll"))
        assertFalse(isNativeResourcePath("META-INF/jsrt/linux-x64/libqp_ffi.so"))

        assertFalse(isNativeResourcePath("META-INF/jsrt/other-x64/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/jsrt/linux-x64/runtime.dylib"))
        assertFalse(isNativeResourcePath("META-INF/macos/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/macho/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/zig/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/js_kernel_old.dll"))
        assertFalse(isNativeResourcePath("META-INF/qp/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/.qp/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/js-native/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/native-src/runtime.so"))
        assertFalse(isNativeResourcePath("META-INF/.r/runtime.dll"))
        assertFalse(isNativeResourcePath("META-INF/jsrt/windows-x64/../runtime.dll"))
    }

    @Test
    fun retained_java_compatibility_entrypoints_fail_closed_without_a_native_fallback() {
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge.executeVmResource(
                1L,
                "META-INF/jsrt/vm.bin",
                emptyArray(),
            )
        }
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge.decodeRuntimeResourceForNative(byteArrayOf(1))
        }
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge.deriveClassEncryptionKey(
                byteArrayOf(1),
                byteArrayOf(2),
                32,
            )
        }
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge.decryptClassBytes(
                byteArrayOf(1),
                byteArrayOf(2),
                ByteArray(12),
                ByteArray(16),
                byteArrayOf(3),
                32,
            )
        }
    }

    private fun validateNativeImage(target: String, bytes: ByteArray) {
        try {
            VALIDATE_NATIVE_IMAGE.invoke(null, target, bytes)
        } catch (error: InvocationTargetException) {
            throw error.targetException
        }
    }

    private fun isNativeResourcePath(path: String): Boolean =
        IS_NATIVE_RESOURCE_PATH.invoke(null, path) as Boolean

    private fun peNativeImage(markers: List<String> = NATIVE_BINDING_MARKERS): ByteArray =
        ByteArray(FIXTURE_IMAGE_SIZE).also { bytes ->
            bytes[0] = 'M'.code.toByte()
            bytes[1] = 'Z'.code.toByte()
            putLe32(bytes, 0x3C, PE_OFFSET)
            "PE\u0000\u0000".toByteArray(StandardCharsets.ISO_8859_1).copyInto(bytes, PE_OFFSET)
            putLe16(bytes, PE_OFFSET + 4, 0x8664)
            putLe16(bytes, PE_OFFSET + 6, 1)
            putLe16(bytes, PE_OFFSET + 20, 0xF0)
            putLe16(bytes, PE_OFFSET + 22, 0x2022)
            putLe16(bytes, PE_OFFSET + 24, 0x20B)
            writeMarkers(bytes, 0x300, markers)
        }

    private fun elfNativeImage(markers: List<String> = NATIVE_BINDING_MARKERS): ByteArray =
        ByteArray(FIXTURE_IMAGE_SIZE).also { bytes ->
            bytes[0] = 0x7F
            bytes[1] = 'E'.code.toByte()
            bytes[2] = 'L'.code.toByte()
            bytes[3] = 'F'.code.toByte()
            bytes[4] = 2
            bytes[5] = 1
            bytes[6] = 1
            putLe16(bytes, 16, 3)
            putLe16(bytes, 18, 62)
            putLe32(bytes, 20, 1)
            putLe64(bytes, 32, 64)
            putLe16(bytes, 52, 64)
            putLe16(bytes, 54, 56)
            putLe16(bytes, 56, 1)
            writeMarkers(bytes, 0x100, markers)
        }

    private fun writeMarkers(bytes: ByteArray, offset: Int, markers: List<String>) {
        markers.joinToString("\u0000", postfix = "\u0000")
            .toByteArray(StandardCharsets.US_ASCII)
            .copyInto(bytes, offset)
    }

    private fun putLe16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
    }

    private fun putLe32(bytes: ByteArray, offset: Int, value: Int) {
        repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }

    private fun putLe64(bytes: ByteArray, offset: Int, value: Long) {
        repeat(8) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }

    private companion object {
        const val PE_OFFSET = 0x80
        const val FIXTURE_IMAGE_SIZE = 2048

        val NATIVE_BINDING_MARKERS = listOf(
            "JNI_OnLoad",
            "JNI_OnUnload",
            "qp_r1_runtime_binding_digest",
            "qp_r1_open_frame",
            "nativeInit",
            "nativeHeartbeat",
            "nativeInstallSessionNonce",
            "nativeInstallCatalog",
            "nativeExecuteVmPage",
            "nativeOpenStringPage",
            "nativeReadClassPage",
            "nativeConsumeNativeSegment",
            "nativeInitializeDefense",
            "nativeProbeDefense",
            "nativeTransformDefense",
            "nativeInvokeSite",
        )

        val VALIDATE_NATIVE_IMAGE =
            Class.forName("io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge")
                .getDeclaredMethod("validateNativeImage", String::class.java, ByteArray::class.java)
                .apply { isAccessible = true }

        val IS_NATIVE_RESOURCE_PATH =
            Class.forName("io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge")
                .getDeclaredMethod("isQpNativeResourcePath", String::class.java)
                .apply { isAccessible = true }
    }

    private fun workspacePath(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val candidate = current.resolve(relative)
            if (Files.exists(candidate)) return candidate
            current = current.parent ?: break
        }
        error("Unable to locate workspace file: $relative")
    }
}
