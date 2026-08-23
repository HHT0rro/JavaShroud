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

class AkenRuntimeBridgeApiTest {
    @Test
    fun typed_aken_bridge_exposes_only_page_bound_native_requests() {
        val helper = Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
        val expected = mapOf(
            "nativeInit" to arrayOf(String::class.java),
            "nativeHeartbeat" to emptyArray(),
            "nativeInstallAkenSessionNonce" to arrayOf(ByteArray::class.java),
            "nativeExecuteAkenVmPage" to arrayOf(
                Long::class.javaPrimitiveType!!,
                ByteArray::class.java,
                Int::class.javaPrimitiveType!!,
                ByteArray::class.java,
                Array<Any>::class.java,
            ),
            "nativeOpenAkenString" to arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java),
            "nativeReadAkenClassPage" to arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java),
            "nativeConsumeAkenNativeChunk" to arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java),
        )

        expected.forEach { (name, parameters) ->
            val method = helper.getDeclaredMethod(name, *parameters)
            assertTrue(Modifier.isNative(method.modifiers), "$name must remain a native R1 entry")
            assertTrue(Modifier.isStatic(method.modifiers), "$name must remain static for generated call sites")
        }
        assertEquals(
            expected.keys.toSet(),
            helper.declaredMethods.filter { Modifier.isNative(it.modifiers) }.mapTo(linkedSetOf()) { it.name }.toSet(),
            "The source helper must declare exactly the seven R1 JNI registrations",
        )

        val stringParameters = arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java)
        val nativeStringTerminal = helper.getDeclaredMethod("nativeOpenAkenString", *stringParameters)
        val stringTerminal = helper.getDeclaredMethod("openAkenString", *stringParameters)
        assertEquals(String::class.java, nativeStringTerminal.returnType)
        assertEquals(String::class.java, stringTerminal.returnType)
        assertFalse(Modifier.isPublic(nativeStringTerminal.modifiers), "native String terminal must remain package-private")
        assertFalse(Modifier.isPublic(stringTerminal.modifiers), "validated String terminal must remain package-private")

        val nativeChunkConsumer = helper.getDeclaredMethod(
            "nativeConsumeAkenNativeChunk",
            ByteArray::class.java,
            Int::class.javaPrimitiveType!!,
            ByteArray::class.java,
        )
        assertTrue(nativeChunkConsumer.returnType == Void.TYPE, "native chunk bridge must not return plaintext to Java")
        val publicChunkConsumer = helper.getDeclaredMethod(
            "consumeAkenNativeChunk",
            ByteArray::class.java,
            Int::class.javaPrimitiveType!!,
            ByteArray::class.java,
        )
        assertTrue(publicChunkConsumer.returnType == Void.TYPE, "public native chunk bridge must remain a native-only consumer")

        val declared = helper.declaredMethods.associateBy { it.name }
        assertFalse("nativeMapAkenNativeChunk" in declared, "AKEN must not retain the byte[] native chunk mapper")
        assertFalse("mapAkenNativeChunk" in declared, "AKEN must not retain the byte[] native chunk wrapper")
        assertFalse("nativeDecodeAkenPage" in declared, "AKEN must not expose a generic page decoder")
        assertFalse("nativeDecodeAkenResource" in declared, "AKEN must not expose arbitrary resource decoding")
        assertFalse("nativeInstallAkenKey" in declared, "AKEN must not accept external or global key material")
        assertFalse("nativeInstallAkenCatalog" in declared, "AKEN must not expose a central catalog installer")
    }

    @Test
    fun aken_readiness_loader_is_independent_from_legacy_boot_chain() {
        val source = Files.readString(workspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val readinessStart = source.indexOf("private static synchronized void loadAkenNativeKernel()")
        val readinessEnd = source.indexOf("private static byte[] requireAkenPageResult", readinessStart)
        assertTrue(readinessStart >= 0 && readinessEnd > readinessStart, "AKEN readiness block must remain locatable")
        val readiness = source.substring(readinessStart, readinessEnd)

        assertTrue(source.contains("AKEN_NATIVE_LOCATOR_RESOURCE = \"META-INF/jsrt/native.locator\""), "R1 readiness must use the Rust runtime locator root")
        assertTrue(source.contains("AKEN_NATIVE_BINDINGS_LOCATOR_RESOURCE = \"META-INF/jsrt/native.bindings.locator\""), "R1 readiness must use the Rust runtime bindings locator root")
        assertFalse(source.contains("META-INF/aken/native.locator"), "R1 readiness must not retain the retired logical locator path")
        assertFalse(source.contains("META-INF/aken/native.bindings.locator"), "R1 readiness must not retain the retired logical bindings path")
        assertTrue(source.contains("AKEN_NATIVE_RESOURCE_ROOT = \"META-INF/\""), "R1 locator routes must remain constrained to the final resource root")
        assertTrue(readiness.contains("readAkenNativeLocator"), "R1 readiness must authenticate the binary locator before extraction")
        assertTrue(readiness.contains("validateR1NativeImage"), "R1 readiness must validate the selected PE or ELF image and exports")
        assertTrue(readiness.contains("publishSealedNativeBindings"), "R1 readiness must publish final relocation metadata before native registration")
        assertTrue(source.contains("AKEN_R1_CATALOG_INDEX_RESOURCE = \"META-INF/jsrt/catalog.index\""), "R1 readiness must locate the authenticated page catalog index")
        assertTrue(source.contains("extractAkenR1CatalogSidecar"), "R1 readiness must extract the page catalog sidecar before nativeInit")
        assertTrue(readiness.contains("extractAkenR1CatalogSidecar"), "R1 load must extract the catalog sidecar before System.load")
        assertTrue(readiness.contains("System.load("), "R1 readiness must load only the authenticated bundled artifact")
        assertTrue(readiness.contains("initializeNativeKernel("), "R1 readiness must prove nativeInit registration")
        assertTrue(readiness.contains("installAkenSessionNonce()"), "R1 readiness must prove the session-nonce registration")
        assertTrue(readiness.contains("verifyAkenNativeAbiAfterLoad"), "R1 readiness must prove the remaining five JNI registrations")
        assertTrue(readiness.contains("nativeHeartbeat"), "R1 ABI probe must reach the heartbeat route")
        assertTrue(readiness.contains("nativeExecuteAkenVmPage"), "R1 ABI probe must reach the VM page route")
        assertTrue(readiness.contains("nativeOpenAkenString"), "R1 ABI probe must reach the String-returning page route")
        assertTrue(readiness.contains("nativeReadAkenClassPage"), "R1 ABI probe must reach the class page route")
        assertTrue(readiness.contains("nativeConsumeAkenNativeChunk"), "R1 ABI probe must reach the native-chunk route")

        val lowerSource = source.lowercase()
        for (retiredPlatformMarker in listOf("meta-inf/aken/", "macos", "darwin", "mach-o", ".dylib")) {
            assertFalse(lowerSource.contains(retiredPlatformMarker), "R1 helper source retained retired platform material: $retiredPlatformMarker")
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
            assertFalse(readiness.contains(legacy), "AKEN readiness must not re-enter the legacy boot path: $legacy")
        }

        val loadKernelStart = source.indexOf("public static synchronized void loadKernel(")
        val loadKernelEnd = source.indexOf("private static boolean targetPlatformAllowsCurrent", loadKernelStart)
        assertTrue(loadKernelStart >= 0 && loadKernelEnd > loadKernelStart, "public native loader block must remain locatable")
        val publicLoader = source.substring(loadKernelStart, loadKernelEnd)
        assertTrue(publicLoader.contains("loadAkenNativeKernel()"), "legacy helper entrypoints must converge on the AKEN raw native loader")
        assertFalse(publicLoader.contains("prepareJavaBootMaterialForLoad"), "public native loading must not require JSBM boot material")
        assertFalse(publicLoader.contains("tryLoadBundledNative("), "public native loading must not re-enter the legacy sealed-index path")
    }

    @Test
    fun aken_native_locator_is_binary_v2_per_platform_and_rejects_legacy_envelopes() {
        val helperSource = Files.readString(workspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val parserStart = helperSource.indexOf("private static AkenNativeLibrary readAkenNativeLocator")
        val parserEnd = helperSource.indexOf("private static boolean hasAkenLocatorMagic", parserStart)
        assertTrue(parserStart >= 0 && parserEnd > parserStart, "AKEN locator parser must remain locatable")
        val parser = helperSource.substring(parserStart, parserEnd)

        assertTrue(parser.contains("hasAkenLocatorMagic"), "locator parser must require the binary D7 A4 91 E3 magic")
        assertTrue(parser.contains("AKEN_NATIVE_LOCATOR_VERSION"), "locator parser must enforce the current binary version")
        assertTrue(parser.contains("AKEN_NATIVE_LOCATOR_COMMITMENT_BYTES"), "locator parser must reserve a terminal commitment")
        assertTrue(parser.contains("readAkenLocatorU16"), "locator parser must decode bounded big-endian record counts and routes")
        assertTrue(parser.contains("readAkenLocatorPositiveU32"), "locator parser must validate positive u32 stored lengths")
        assertTrue(parser.contains("unmaskAkenNativeLocatorRoute"), "locator parser must unmask and validate binary routes")
        assertTrue(parser.contains("isAkenNativeRouteBytes"), "locator parser must validate route bytes before ASCII decoding")
        assertTrue(parser.contains("akenNativeLocatorCommitment"), "locator parser must authenticate the exact binary payload")
        assertTrue(parser.contains("MessageDigest.isEqual"), "locator commitment must use constant-time comparison")
        assertTrue(parser.contains("seenRoutes"), "locator parser must reject duplicate routes")
        assertTrue(parser.contains("bindingSeen"), "locator parser must reject duplicate or non-terminal bindings")
        assertTrue(parser.contains("hasAkenRejectedLegacyHeader"), "locator parser must reject legacy protocol headers")
        assertTrue(helperSource.contains("AKEN_NATIVE_LOCATOR_MAGIC_0 = 0xD7"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("AKEN_NATIVE_LOCATOR_MAGIC_1 = 0xA4"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("AKEN_NATIVE_LOCATOR_MAGIC_2 = 0x91"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("AKEN_NATIVE_LOCATOR_MAGIC_3 = 0xE3"), "locator magic must remain non-ASCII")
        assertTrue(helperSource.contains("AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN"), "route masking domain must remain explicit and versioned")
        assertFalse(parser.contains("\"AKEN_NATIVE_LOCATOR_RECORD\""), "binary locator parser must not retain textual record tags")
        assertFalse(parser.contains("\"AKEN_NATIVE_BINDINGS_LOCATOR_RECORD\""), "binary locator parser must not retain textual binding tags")
        assertFalse(parser.contains("parseAkenNativeLength"), "binary locator parser must not parse decimal text lengths")
        assertFalse(parser.contains("parseAkenNativeSha256"), "binary locator parser must not parse hexadecimal text digests")
        assertFalse(parser.contains("sealedNativeIndexText"), "raw locator parser must not traverse legacy JSBI")
        assertFalse(parser.contains("sealedNativeBindingText"), "raw locator parser must not load legacy bindings")
        assertFalse(parser.contains("decodeRuntimeResource"), "raw locator parser must not decode JSRP")

        val sealingSource = Files.readString(workspacePath("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"))
        val locatorSource = Files.readString(workspacePath("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/AkenNativeLocator.kt"))
        assertTrue(sealingSource.contains("AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE"), "sealing must rewrite the logical locator path")
        assertTrue(locatorSource.contains("AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE = \"META-INF/jsrt/native.locator\""), "the logical locator must use the R1 jsrt root")
        assertTrue(locatorSource.contains("AKEN_NATIVE_BINDINGS_LOCATOR_LOGICAL_RESOURCE = \"META-INF/jsrt/native.bindings.locator\""), "the bindings locator must use the R1 jsrt root")
        assertFalse(locatorSource.contains("META-INF/aken/native.locator"), "the serializer must not retain the retired logical locator path")
        assertFalse(locatorSource.contains("META-INF/aken/native.bindings.locator"), "the serializer must not retain the retired logical bindings path")
        assertTrue(sealingSource.contains("AkenNativeLocator.entry("), "sealing must create one locator row per final native resource")
        assertTrue(sealingSource.contains("storedBytes = nativeBytes"), "locator digest and length must derive from final sealed native bytes")
        assertTrue(sealingSource.contains("suffix = nativeSpec.loadSuffix"), "final sealed native route must retain the loader suffix")
        assertTrue(sealingSource.contains("return \"${'$'}{sealedResourceRoot(seed)}/"), "final sealed native paths must be randomized after sealing")
    }

    @Test
    fun typed_aken_bridge_native_registration_is_purpose_split_and_fail_closed() {
        val ffi = Files.readString(workspacePath("core-engine/src/main/rust/crates/jsrt-ffi/src/lib.rs"))
        val relocation = Files.readString(workspacePath("core-engine/src/main/rust/crates/jsrt-ffi/src/relocation.rs"))
        for (marker in listOf(
            "nativeExecuteAkenVmPage",
            "nativeOpenAkenString",
            "nativeReadAkenClassPage",
            "nativeConsumeAkenNativeChunk",
            "\"([BI[B)Ljava/lang/String;\"",
            "\"([BI[B)V\"",
        )) {
            assertTrue(relocation.contains(marker) || ffi.contains(marker), "R1 JNI registration must keep typed route $marker")
        }
        assertTrue(relocation.contains("AKEN-BINDING-V1|"), "JNI_OnLoad must recover renamed helpers from published binding keys")
        assertTrue(ffi.contains("j.l\\0") || ffi.contains("b\"j.l\\0\""), "JNI_OnLoad must read the published loader owner")
        assertTrue(ffi.contains("j.m\\0") || ffi.contains("b\"j.m\\0\""), "JNI_OnLoad must read published method bindings")
        assertTrue(ffi.contains("resolve_registration_plan"), "JNI_OnLoad must restore renamed helper names before RegisterNatives")
        assertFalse(ffi.contains("nativeDecodeAkenStringPage"), "retired whole-page String byte[] registration must be absent")
        assertFalse(ffi.contains("nativeMapAkenNativeChunk"), "obsolete byte[] native chunk registration must be absent")
        assertTrue(ffi.contains("AKEN VM page route is unavailable"), "unwired VM route must fail closed")
        assertTrue(ffi.contains("AKEN typed page route is unavailable"), "unwired string/class/native routes must fail closed")
        assertFalse(ffi.contains("jsn_k13"), "R1 JNI must not call the legacy generic runtime decoder")
        assertFalse(ffi.contains("js_runtime_resource_decode_owned"), "R1 JNI must not call the legacy resource decode core")
        assertFalse(ffi.contains("nativeInstallBoot"), "R1 JNI must not install legacy boot material")

        val owner = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest("AKEN-BINDING-V1|$owner".toByteArray(StandardCharsets.UTF_8))
        val key = digest.copyOfRange(0, 8).joinToString("") { byte -> "%02x".format(byte) }
        assertEquals("3a7c2b4b146de48d", key)
        assertTrue(relocation.contains(key), "Rust relocation key must match the Kotlin binding domain")
    }

    @Test
    fun r1_image_validator_accepts_only_complete_amd64_cdylibs() {
        validateR1Image("x86_64-pc-windows-gnu", peR1Image())
        validateR1Image("x86_64-unknown-linux-gnu.2.17", elfR1Image())

        val missingRegistration = assertFailsWith<SecurityException> {
            validateR1Image("x86_64-pc-windows-gnu", peR1Image(R1_BINDING_MARKERS.dropLast(1)))
        }
        assertTrue(missingRegistration.message.orEmpty().contains("nativeConsumeAkenNativeChunk"))

        val executableImage = peR1Image().also { putLe16(it, PE_OFFSET + 22, 0x0022) }
        assertFailsWith<SecurityException> {
            validateR1Image("x86_64-pc-windows-gnu", executableImage)
        }
        assertFailsWith<SecurityException> {
            validateR1Image("x86_64-unknown-linux-gnu", elfR1Image())
        }
        assertFailsWith<SecurityException> {
            validateR1Image("x86_64-unknown-linux-gnu.2.17", peR1Image())
        }
    }

    @Test
    fun r1_resource_validator_rejects_retired_and_non_current_routes() {
        assertTrue(isR1ResourcePath("META-INF/jsrt/windows-x64/jsrt_ffi.dll"))
        assertTrue(isR1ResourcePath("META-INF/jsrt/linux-x64/libjsrt_ffi.so"))
        assertTrue(isR1ResourcePath("META-INF/ab/0123456789abcdef/cd/final.txt"))

        assertFalse(isR1ResourcePath("META-INF/jsrt/other-x64/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/jsrt/linux-x64/runtime.dylib"))
        assertFalse(isR1ResourcePath("META-INF/macos/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/macho/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/zig/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/js_kernel_old.dll"))
        assertFalse(isR1ResourcePath("META-INF/aken/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/.aken/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/js-native/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/native-src/runtime.so"))
        assertFalse(isR1ResourcePath("META-INF/.r/runtime.dll"))
        assertFalse(isR1ResourcePath("META-INF/jsrt/windows-x64/../runtime.dll"))
    }

    @Test
    fun retained_java_compatibility_entrypoints_fail_closed_without_a_native_fallback() {
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper.executeVmResource(
                1L,
                "META-INF/jsrt/vm.bin",
                emptyArray(),
            )
        }
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper.decodeRuntimeResourceForNative(byteArrayOf(1))
        }
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper.deriveClassEncryptionKey(
                byteArrayOf(1),
                byteArrayOf(2),
                32,
            )
        }
        assertFailsWith<SecurityException> {
            io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper.decryptClassBytes(
                byteArrayOf(1),
                byteArrayOf(2),
                ByteArray(12),
                ByteArray(16),
                byteArrayOf(3),
                32,
            )
        }
    }

    private fun validateR1Image(target: String, bytes: ByteArray) {
        try {
            VALIDATE_R1_IMAGE.invoke(null, target, bytes)
        } catch (error: InvocationTargetException) {
            throw error.targetException
        }
    }

    private fun isR1ResourcePath(path: String): Boolean =
        IS_R1_RESOURCE_PATH.invoke(null, path) as Boolean

    private fun peR1Image(markers: List<String> = R1_BINDING_MARKERS): ByteArray =
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

    private fun elfR1Image(markers: List<String> = R1_BINDING_MARKERS): ByteArray =
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

        val R1_BINDING_MARKERS = listOf(
            "JNI_OnLoad",
            "JNI_OnUnload",
            "jsrt_r1_runtime_binding_digest",
            "jsrt_r1_open_frame",
            "nativeInit",
            "nativeHeartbeat",
            "nativeInstallAkenSessionNonce",
            "nativeExecuteAkenVmPage",
            "nativeOpenAkenString",
            "nativeReadAkenClassPage",
            "nativeConsumeAkenNativeChunk",
        )

        val VALIDATE_R1_IMAGE =
            Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
                .getDeclaredMethod("validateR1NativeImage", String::class.java, ByteArray::class.java)
                .apply { isAccessible = true }

        val IS_R1_RESOURCE_PATH =
            Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
                .getDeclaredMethod("isAkenNativeResourcePath", String::class.java)
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
