package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeBindingLoadOrderTest {
    @Test
    fun r1_native_is_validated_and_bindings_are_published_before_jni_onload_then_rolled_back_on_failure() {
        val source = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"),
        )
        val methodStart = source.indexOf("private static boolean tryLoadAkenBundledNativeResource")
        val methodEnd = source.indexOf("private static boolean verifyAkenNativeAbiAfterLoad", methodStart)
        val method = source.substring(methodStart, methodEnd)

        assertTrue(method.indexOf("validateR1NativeImage(platformTarget, nativeBytes)") < method.indexOf("nativeExtractDirectories()"))
        assertTrue(method.indexOf("String bindingText = sealedNativeBindingText(locator)") < method.indexOf("nativeExtractDirectories()"))
        assertTrue(method.indexOf("publishSealedNativeBindings(bindingText);") < method.indexOf("extractedNativeMatchesLocator(tempLib, locator)"))
        assertTrue(method.indexOf("aken:native-extract-digest-mismatch") < method.indexOf("System.load(tempLib.getAbsolutePath());"))
        assertTrue(method.indexOf("System.load(tempLib.getAbsolutePath());") < method.indexOf("aken:native-loaded-digest-mismatch"))
        assertTrue(method.indexOf("aken:native-loaded-digest-mismatch") < method.indexOf("initializeNativeKernel(platformTarget)"))
        assertTrue(method.indexOf("System.load(tempLib.getAbsolutePath());") < method.indexOf("initializeNativeKernel(platformTarget)"))
        assertTrue(method.indexOf("initializeNativeKernel(platformTarget)") < method.indexOf("installAkenSessionNonce()"))
        assertTrue(method.indexOf("installAkenSessionNonce()") < method.indexOf("verifyAkenNativeAbiAfterLoad()"))
        assertTrue(method.contains("previousClassBindings"))
        assertTrue(method.contains("previousMethodBindings"))
        assertTrue(method.contains("previousFieldBindings"))
        assertTrue(method.contains("restoreProperty(sealedBindingPropertyName(), previousClassBindings)"))
        assertTrue(method.contains("restoreProperty(sealedMethodBindingPropertyName(), previousMethodBindings)"))
        assertTrue(method.contains("restoreProperty(sealedFieldBindingPropertyName(), previousFieldBindings)"))
    }

    @Test
    fun aken_raw_loader_does_not_reintroduce_legacy_boot_material() {
        val helperSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"),
        )
        val loaderStart = helperSource.indexOf("private static boolean tryLoadAkenBundledNativeResource")
        val loaderEnd = helperSource.indexOf("\n    private static", loaderStart + 1)
        assertTrue(loaderStart >= 0 && loaderEnd > loaderStart)
        val loader = helperSource.substring(loaderStart, loaderEnd)
        assertTrue(
            loader.indexOf("System.load(tempLib.getAbsolutePath());") >= 0 &&
                !loader.contains("prepareJavaBootMaterialForLoad") &&
                !loader.contains("publishNativeShellBootSecret") &&
                !loader.contains("nativeInstallBootEnvelope"),
            "The AKEN raw loader must load only the typed native artifact and must not publish legacy boot material.",
        )

        val ffi = Files.readString(Path.of("src/main/rust/crates/jsrt-ffi/src/lib.rs"))
        assertTrue(ffi.contains("([BI[B)Ljava/lang/String;"))
        assertTrue(ffi.contains("nativeOpenAkenString"))
        assertTrue(ffi.contains("nativeReadAkenClassPage"))
        assertFalse(Files.exists(Path.of("src/main/native/js_shell_stub.c")))
    }

    @Test
    fun string_encryption_uses_typed_aken_bridge_and_native_fail_closed_order() {
        val source = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.java"),
        )
        assertTrue(source.contains("JniMicrokernelHelper.openAkenString(encodedHandle, pageIndex, callSiteProof)"))
        assertTrue(source.indexOf("requireAkenStringPageRequest") < source.indexOf("openAkenString(encodedHandle, pageIndex, callSiteProof)"))
        assertTrue(source.contains("AKEN string page native terminal is not registered for the sealed helper"))
        assertTrue(!source.contains("nativeDecodeString(payload"))
        assertTrue(!source.contains("JniMicrokernelHelper.loadKernel"))

        val kernelSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"),
        )
        val bridgeStart = kernelSource.indexOf("static String openAkenString")
        val bridgeEnd = kernelSource.indexOf("public static byte[] readAkenClassPage", bridgeStart)
        assertTrue(bridgeStart >= 0 && bridgeEnd > bridgeStart)
        val bridge = kernelSource.substring(bridgeStart, bridgeEnd)
        assertTrue(bridge.indexOf("requireAkenPageRequest") < bridge.indexOf("ensureAkenNativeKernel()"))
        assertTrue(bridge.indexOf("ensureAkenNativeKernel()") < bridge.indexOf("nativeOpenAkenString"))
        assertTrue(kernelSource.contains("requires the sealed native kernel ("), "AKEN page access must fail closed without a decoder fallback.")
        assertTrue(source.contains("catch (UnsatisfiedLinkError error)"))
    }

    @Test
    fun rust_relocation_uses_current_sha256_binding_identity() {
        val relocation = Files.readString(Path.of("src/main/rust/crates/jsrt-ffi/src/relocation.rs"))
        assertTrue(relocation.contains("AKEN-BINDING-V1|"))
        assertFalse(relocation.contains("fnv1a64"))
        assertFalse(Files.exists(Path.of("src/main/native/js_vm_core.c")))
    }

    @Test
    fun relocated_open_aken_string_bridge_is_promoted_only_at_sealing_boundary() {
        val helperSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"),
        )
        val sourceStart = helperSource.indexOf("static String openAkenString")
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
