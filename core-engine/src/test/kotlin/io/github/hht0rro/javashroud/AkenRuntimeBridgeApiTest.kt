package io.github.hht0rro.javashroud

import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenRuntimeBridgeApiTest {
    @Test
    fun typed_aken_bridge_exposes_only_page_bound_native_requests() {
        val helper = Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
        val expected = mapOf(
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
            assertTrue(Modifier.isNative(method.modifiers), "$name must remain a native page-bound entry")
            assertTrue(Modifier.isStatic(method.modifiers), "$name must remain static for generated call sites")
        }

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

        assertTrue(source.contains("AKEN_NATIVE_LOCATOR_RESOURCE = \"META-INF/aken/native.locator\""), "AKEN readiness must resolve its per-build raw locator")
        assertTrue(source.contains("AKEN_NATIVE_RESOURCE_ROOT = \"META-INF/\""), "AKEN locator routes must remain constrained to the native resource root")
        assertTrue(readiness.contains("readAkenNativeLocator"), "AKEN readiness must load the raw locator before native extraction")
        assertTrue(readiness.contains("publishSealedNativeBindings"), "AKEN readiness must publish public relocation metadata before native registration")
        assertTrue(readiness.contains("System.load("), "AKEN readiness must still load the bundled native artifact")
        assertTrue(readiness.contains("initializeNativeKernel("), "AKEN readiness must still initialize the native ABI")
        assertTrue(readiness.contains("installAkenSessionNonce()"), "AKEN readiness must install a per-JVM runtime session nonce")
        assertTrue(readiness.contains("verifyAkenNativeAbiAfterLoad"), "AKEN readiness must prove the typed JNI ABI is registered")
        assertTrue(readiness.contains("nativeExecuteAkenVmPage"), "AKEN ABI probe must reach the VM page route")
        assertTrue(readiness.contains("nativeOpenAkenString"), "AKEN ABI probe must reach the String-returning page route")
        assertTrue(readiness.contains("nativeReadAkenClassPage"), "AKEN ABI probe must reach the class page route")
        assertTrue(readiness.contains("nativeConsumeAkenNativeChunk"), "AKEN ABI probe must reach the native-chunk route")

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
        val parserEnd = helperSource.indexOf("public static native Object nativeExecuteVmResource", parserStart)
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
        assertTrue(sealingSource.contains("AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE"), "sealing must rewrite the logical locator path")
        assertTrue(sealingSource.contains("AkenNativeLocator.entry("), "sealing must create one locator row per final native resource")
        assertTrue(sealingSource.contains("storedBytes = nativeBytes"), "locator digest and length must derive from final sealed native bytes")
        assertTrue(sealingSource.contains("suffix = nativeSpec.loadSuffix"), "final sealed native route must retain the loader suffix")
        assertTrue(sealingSource.contains("return \"${'$'}{sealedResourceRoot(seed)}/"), "final sealed native paths must be randomized after sealing")
    }

    @Test
    fun typed_aken_bridge_native_registration_is_purpose_split_and_fail_closed() {
        val source = Files.readString(workspacePath("core-engine/src/main/native/js_jni_runtime.c"))
        for (name in listOf(
            "JS_OBFUSCATED_LEN_JNI_NATIVE_EXECUTE_AKEN_VM_PAGE",
            "JS_OBFUSCATED_LEN_JNI_NATIVE_OPEN_AKEN_STRING",
            "JS_OBFUSCATED_LEN_JNI_NATIVE_READ_AKEN_CLASS_PAGE",
            "JS_OBFUSCATED_LEN_JNI_NATIVE_CONSUME_AKEN_NATIVE_CHUNK",
        )) {
            assertTrue(source.contains(name), "JNI registration must use obfuscated binding material $name")
        }
        assertTrue(
            source.contains("js_native_name_obfuscated(js_obfuscated_JNI_NATIVE_OPEN_AKEN_STRING") &&
                source.contains("\"([BI[B)Ljava/lang/String;\", (void*)jsw_a1"),
            "string registration must return java.lang.String instead of a plaintext byte array",
        )
        assertFalse(source.contains("native" + "DecodeAkenStringPage"), "retired whole-page String byte[] registration must be absent")
        assertTrue(
            source.contains("js_native_name_obfuscated(js_obfuscated_JNI_NATIVE_CONSUME_AKEN_NATIVE_CHUNK") &&
                source.contains("\"([BI[B)V\", (void*)jsw_a3"),
            "native chunk registration must use a void JNI descriptor",
        )
        assertTrue(source.contains("js_aken_native_chunk_consume_opened_page"), "native chunk plaintext must terminate in a native-only consumer")
        assertFalse(source.contains("nativeMapAkenNativeChunk"), "obsolete byte[] native chunk registration must be absent")
        assertTrue(source.contains("AKEN VM page route is unavailable"), "unwired VM route must fail closed")
        assertTrue(source.contains("AKEN string page route is unavailable"), "unwired string route must fail closed")
        assertTrue(source.contains("AKEN class page route is unavailable"), "unwired class route must fail closed")
        assertTrue(source.contains("AKEN native chunk route is unavailable"), "unwired native route must fail closed")

        val bridgeStart = source.indexOf("static void js_aken_bridge_unavailable")
        val bridgeEnd = source.indexOf("static void js_protected_runtime_failure", bridgeStart)
        assertTrue(bridgeStart >= 0 && bridgeEnd > bridgeStart, "AKEN bridge block must remain locatable")
        val bridge = source.substring(bridgeStart, bridgeEnd)
        assertFalse(bridge.contains("jsn_k13"), "AKEN bridge must not call the legacy generic runtime decoder")
        assertFalse(bridge.contains("js_runtime_resource_decode_owned"), "AKEN bridge must not call the legacy resource decode core")
        assertFalse(bridge.contains("nativeInstallBoot"), "AKEN bridge must not install legacy boot material")

        val nativeInitStart = source.indexOf("static jint JNICALL jsw_k0")
        val nativeInitEnd = source.indexOf("static jint JNICALL jsw_k1", nativeInitStart)
        assertTrue(nativeInitStart >= 0 && nativeInitEnd > nativeInitStart, "nativeInit wrapper must remain locatable")
        val nativeInit = source.substring(nativeInitStart, nativeInitEnd)
        assertTrue(
            nativeInit.contains("js_jni_register_deferred_natives"),
            "AKEN nativeInit must register sealed optional helpers after raw relocation bindings are published",
        )
        assertTrue(source.contains("static int js_optional_natives_registered = 0"), "deferred optional registration must be idempotent")
        assertTrue(
            source.contains("js_obfuscated_JNI_NATIVE_INSTALL_AKEN_SESSION_NONCE") &&
                source.contains("JS_OBFUSCATED_LEN_JNI_NATIVE_INSTALL_AKEN_SESSION_NONCE"),
            "AKEN bridge must expose the per-JVM session nonce entrypoint through obfuscated binding material",
        )
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
