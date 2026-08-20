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
            "nativeDecodeAkenStringPage" to arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java),
            "nativeReadAkenClassPage" to arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java),
            "nativeConsumeAkenNativeChunk" to arrayOf(ByteArray::class.java, Int::class.javaPrimitiveType!!, ByteArray::class.java),
        )

        expected.forEach { (name, parameters) ->
            val method = helper.getDeclaredMethod(name, *parameters)
            assertTrue(Modifier.isNative(method.modifiers), "$name must remain a native page-bound entry")
            assertTrue(Modifier.isStatic(method.modifiers), "$name must remain static for generated call sites")
        }

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
        assertTrue(readiness.contains("nativeDecodeAkenStringPage"), "AKEN ABI probe must reach the string page route")
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
    fun aken_native_locator_is_raw_per_platform_and_rejects_legacy_envelopes() {
        val helperSource = Files.readString(workspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val parserStart = helperSource.indexOf("private static AkenNativeLibrary readAkenNativeLocator")
        val parserEnd = helperSource.indexOf("public static native Object nativeExecuteVmResource", parserStart)
        assertTrue(parserStart >= 0 && parserEnd > parserStart, "AKEN locator parser must remain locatable")
        val parser = helperSource.substring(parserStart, parserEnd)

        assertTrue(parser.contains("AKEN_NATIVE_LOCATOR_RECORD"), "locator parser must require its independent record tag")
        assertTrue(parser.contains("isAkenNativePlatform"), "locator parser must validate supported platforms")
        assertTrue(parser.contains("isAkenNativeResourcePath"), "locator parser must validate resource path grammar")
        assertTrue(parser.contains("isAkenNativeSuffix"), "locator parser must bind platform to native suffix")
        assertTrue(parser.contains("parseAkenNativeLength"), "locator parser must validate exact stored length")
        assertTrue(parser.contains("parseAkenNativeSha256"), "locator parser must validate SHA-256 text")
        assertTrue(parser.contains("hasAkenRejectedLegacyHeader"), "locator parser must reject legacy protocol headers")
        assertTrue(parser.contains("hasAkenHeader(bytes, 'J', 'S', 'B', 'I')"), "locator parser must reject legacy JSBI")
        assertTrue(parser.contains("hasAkenHeader(bytes, 'J', 'S', 'R', 'P')"), "locator parser must reject legacy JSRP")
        assertTrue(parser.contains("hasAkenHeader(bytes, 'J', 'S', 'B', 'M')"), "locator parser must reject legacy boot material")
        assertTrue(parser.contains("hasAkenHeader(bytes, 'J', 'S', 'B', 'K')"), "locator parser must reject legacy sidecar material")
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
            "nativeExecuteAkenVmPage",
            "nativeDecodeAkenStringPage",
            "nativeReadAkenClassPage",
            "nativeConsumeAkenNativeChunk",
        )) {
            assertTrue(source.contains(name), "JNI registration must include $name")
        }
        assertTrue(
            source.contains("""{js_native_name_full("nativeConsumeAkenNativeChunk"), "([BI[B)V", (void*)jsw_a3}"""),
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
        assertTrue(source.contains("nativeInstallAkenSessionNonce"), "AKEN bridge must expose the per-JVM session nonce entrypoint")
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
