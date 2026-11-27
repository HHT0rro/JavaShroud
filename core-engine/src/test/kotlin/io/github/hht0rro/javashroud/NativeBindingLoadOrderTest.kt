package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NativeBindingLoadOrderTest {
    @Test
    fun native_image_is_validated_and_bindings_are_published_before_jni_onload_then_rolled_back_on_failure() {
        val source = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"),
        )
        val methodStart = source.indexOf("private static boolean tryLoadQpBundledNativeResource")
        val methodEnd = source.indexOf("private static boolean verifyQpNativeAbiAfterLoad", methodStart)
        assertTrue(methodStart >= 0 && methodEnd > methodStart, "Current native resource loader must exist")
        val method = source.substring(methodStart, methodEnd)

        val extractedDigestGate = failClosedGate("!extractedNativeMatchesLocator(tempLib, locator)")
        assertOrdered(
            method,
            Regex.escape("System.getProperty(sealedLoaderPropertyName())"),
            Regex.escape("System.getProperty(sealedPackPropertyName())"),
            Regex.escape("System.getProperty(sealedBindingsPropertyName())"),
            Regex.escape("readAllBounded(in, locator.storedLength)"),
            failClosedGate("nativeBytes.length != locator.storedLength || hasQpRejectedLegacyHeader(nativeBytes)"),
            Regex.escape("validateNativeImage(platformTarget, nativeBytes)"),
            Regex.escape("sha256(nativeBytes)"),
            failClosedGate("!MessageDigest.isEqual(locator.sha256, actualDigest)"),
            Regex.escape("sealedNativeBindingBytes(locator)"),
            failClosedGate("sealedBindings == null || sealedBindings.length == 0"),
            Regex.escape("nativeExtractDirectories()"),
            Regex.escape("sealedQpPackBytes()"),
            Regex.escape("publishSealedNativeBootstrap(sealedPack, sealedBindings)"),
            extractedDigestGate,
            Regex.escape("System.load(tempLib.getAbsolutePath());"),
            extractedDigestGate,
            Regex.escape("initializeNativeKernel(platformTarget)"),
            failClosedGate("initResult < 0"),
            Regex.escape("installQpSessionNonce()"),
            Regex.escape("installQpCatalog()"),
            failClosedGate("!verifyQpNativeAbiAfterLoad()"),
            Regex.escape("loaded = true;"),
        )
        val rollback = method.substringAfter("if (!loaded) {", "").substringBefore('}')
        for (restore in listOf(
            "sealedNativeBindingsPublished = previousBindingsPublished;",
            "restoreLoaderProperty(previousLoaderOwner)",
            "restoreProperty(sealedPackPropertyName(), previousPackProperty)",
            "restoreProperty(sealedBindingsPropertyName(), previousBindingsProperty)",
        )) {
            assertTrue(restore in rollback, "Failed native loads must roll back: $restore")
        }
    }

    private fun failClosedGate(condition: String): String =
        """if\s*\(\s*""" + Regex.escape(condition) + """\s*\)\s*\{[^}]*\breturn false;\s*}"""

    private fun assertOrdered(source: String, vararg steps: String) {
        var next = 0
        for (step in steps) {
            val match = assertNotNull(Regex(step).find(source, next), "Missing or out-of-order native load step: $step")
            next = match.range.last + 1
        }
    }

    @Test
    fun native_raw_loader_does_not_reintroduce_legacy_boot_material() {
        val helperSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"),
        )
        val loaderStart = helperSource.indexOf("private static boolean tryLoadQpBundledNativeResource")
        val loaderEnd = helperSource.indexOf("\n    private static", loaderStart + 1)
        assertTrue(loaderStart >= 0 && loaderEnd > loaderStart)
        val loader = helperSource.substring(loaderStart, loaderEnd)
        assertTrue(
            loader.indexOf("System.load(tempLib.getAbsolutePath());") >= 0 &&
                !loader.contains("prepareJavaBootMaterialForLoad") &&
                !loader.contains("publishNativeShellBootSecret") &&
                !loader.contains("nativeInstallBootEnvelope"),
            "The Qp raw loader must load only the typed native artifact and must not publish legacy boot material.",
        )

        val ffi = Files.readString(Path.of("src/main/rust/crates/qp-ffi/src/lib.rs"))
        assertTrue(ffi.contains("([B)Ljava/lang/String;"))
        assertTrue(ffi.contains("nativeOpenStringPage"))
        assertTrue(ffi.contains("nativeReadClassPage"))
        assertFalse(Files.exists(Path.of("src/main/native/js_shell_stub.c")))
    }

    @Test
    fun string_encryption_uses_typed_native_bridge_and_fail_closed_order() {
        val source = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpTextBridge.java"),
        )
        assertTrue(source.contains("QpBridge.openQpString(encodedHandle, pageIndex, callSiteProof)"))
        assertTrue(source.indexOf("requireQpStringPageRequest") < source.indexOf("openQpString(encodedHandle, pageIndex, callSiteProof)"))
        assertTrue(source.contains("Qp string page native terminal is not registered for the sealed helper"))
        assertTrue(!source.contains("nativeDecodeString(payload"))
        assertTrue(!source.contains("QpBridge.loadKernel"))

        val kernelSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"),
        )
        val bridgeStart = kernelSource.indexOf("static String openQpString")
        val bridgeEnd = kernelSource.indexOf("public static byte[] readQpClassPage", bridgeStart)
        assertTrue(bridgeStart >= 0 && bridgeEnd > bridgeStart)
        val bridge = kernelSource.substring(bridgeStart, bridgeEnd)
        assertTrue(bridge.indexOf("requireQpPageRequest") < bridge.indexOf("ensureQpNativeKernel()"))
        assertTrue(bridge.indexOf("ensureQpNativeKernel()") < bridge.indexOf("nativeOpenStringPage"))
        assertTrue(kernelSource.contains("requires the sealed native kernel ("), "Qp page access must fail closed without a decoder fallback.")
        assertTrue(source.contains("catch (UnsatisfiedLinkError error)"))
    }

    @Test
    fun rust_relocation_uses_current_sha256_binding_identity() {
        val relocation = Files.readString(Path.of("src/main/rust/crates/qp-ffi/src/relocation.rs"))
        assertTrue(relocation.contains("QP-BINDING-V1|"))
        assertFalse(relocation.contains("fnv1a64"))
        assertFalse(Files.exists(Path.of("src/main/native/js_vm_core.c")))
    }

    @Test
    fun relocated_open_native_string_bridge_is_promoted_only_at_sealing_boundary() {
        val helperSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java"),
        )
        val sourceStart = helperSource.indexOf("static String openQpString")
        assertTrue(sourceStart >= 0, "Source bridge must remain a narrow package-private terminal")

        val sealingSource = Files.readString(
            Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"),
        )
        assertTrue(
            sealingSource.contains("openStringDescriptor") &&
                sealingSource.contains("sealedOpenStringName") &&
                sealingSource.contains("Opcodes.ACC_PUBLIC"),
            "Sealing must promote only the relocated typed String terminal for cross-package call-site linkage",
        )
        assertTrue(
            sealingSource.contains("method.access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_PROTECTED).inv()"),
            "Sealing must clear private/protected visibility before promoting the relocated bridge",
        )
    }
}
