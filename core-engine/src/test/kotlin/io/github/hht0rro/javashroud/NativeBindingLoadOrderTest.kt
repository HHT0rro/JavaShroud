package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class NativeBindingLoadOrderTest {
    @Test
    fun sealed_native_bindings_are_published_before_jni_onload_and_restored_on_failure() {
        val source = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"),
        )
        val methodStart = source.indexOf("private static boolean tryLoadBundledNativeFromDirectory")
        val methodEnd = source.indexOf("private static int initializeNativeKernel", methodStart)
        val method = source.substring(methodStart, methodEnd)

        assertTrue(method.indexOf("publishSealedNativeBindings();") < method.indexOf("System.load(tempLib.getAbsolutePath());"))
        assertTrue(method.contains("previousClassBindings"))
        assertTrue(method.contains("previousMethodBindings"))
        assertTrue(method.contains("previousFieldBindings"))
        assertTrue(method.contains("restoreProperty(sealedBindingPropertyName(), previousClassBindings)"))
        assertTrue(method.contains("restoreProperty(sealedMethodBindingPropertyName(), previousMethodBindings)"))
        assertTrue(method.contains("restoreProperty(sealedFieldBindingPropertyName(), previousFieldBindings)"))
    }

    @Test
    fun max_shell_boot_secret_is_published_before_system_load() {
        val helperSource = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"),
        )
        val prepareStart = helperSource.indexOf("private static void prepareJavaBootMaterialForLoad")
        val prepareEnd = helperSource.indexOf("private static byte[] loadBootSecret", prepareStart)
        val prepare = helperSource.substring(prepareStart, prepareEnd)
        assertTrue(prepare.contains("publishNativeShellBootSecret(bootSecret)"))
        assertTrue(helperSource.indexOf("publishNativeShellBootSecret(bootSecret)") < helperSource.indexOf("System.load(tempLib.getAbsolutePath())"))

        val shellSource = Files.readString(Path.of("src/main/native/js_shell_stub.c"))
        assertTrue(shellSource.contains("takeBootSecretForNativeShell"))
        assertTrue(shellSource.contains("js_shell_load_boot_secret(env, boot_secret)"))
    }

    @Test
    fun string_encryption_reports_kernel_load_failure_before_native_call() {
        val source = Files.readString(
            Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.java"),
        )
        assertTrue(source.indexOf("JniMicrokernelHelper.isNativeLoaded()") < source.indexOf("nativeDecodeString(payload"))
        assertTrue(source.contains("JniMicrokernelHelper.getLoadStatus()"))
        assertTrue(source.contains("catch (UnsatisfiedLinkError error)"))
    }

    @Test
    fun native_vm_mhstatic_resolves_renamed_static_bindings_before_method_lookup() {
        val runtimeSource = Files.readString(Path.of("src/main/native/js_vm_core.c"))
        val invokeStart = runtimeSource.indexOf("js_vm_invoke_dynamic_static_target")
        val invokeEnd = runtimeSource.indexOf("static int js_vm_invoke_dynamic(", invokeStart)
        assertTrue(invokeStart >= 0 && invokeEnd > invokeStart)
        val invokeBody = runtimeSource.substring(invokeStart, invokeEnd)

        val bindingLookup = invokeBody.indexOf("js_lookup_bound_method(env, parts[3], parts[4], parts[5])")
        val methodLookup = invokeBody.indexOf("js_vm_lookup_valid_method_id(env, cls, lookup_name, parts[5], 1)")
        assertTrue(bindingLookup >= 0, "mhstatic VM dispatch must resolve keyed method bindings")
        assertTrue(methodLookup > bindingLookup, "mhstatic VM dispatch must apply the binding before JNI method lookup")
        assertTrue(invokeBody.contains("free(mapped_method)"), "mhstatic VM dispatch must release the mapped method name")
    }

    @Test
    fun keyed_optional_natives_are_retried_after_boot_material_installs_the_anchor() {
        val runtimeSource = Files.readString(Path.of("src/main/native/js_vm_core.c"))
        val installStart = runtimeSource.indexOf("jsn_k7(JNIEnv *env, jclass cls, jbyteArray material)")
        val installEnd = runtimeSource.indexOf("jsn_k11(JNIEnv *env, jclass cls)", installStart)
        assertTrue(installStart >= 0 && installEnd > installStart)
        val installBody = runtimeSource.substring(installStart, installEnd)

        val anchorReady = installBody.indexOf("js_runtime_boot_material_state = 2;")
        val deferredRegistration = installBody.indexOf("js_jni_register_deferred_natives(env)")
        assertTrue(anchorReady >= 0, "Boot material installation must publish the native key slots first.")
        assertTrue(
            deferredRegistration > anchorReady,
            "Keyed optional native registrations must be retried only after the anchor slot is available.",
        )

        val runtimeHeader = Files.readString(Path.of("src/main/native/js_jni_runtime.h"))
        assertTrue(runtimeHeader.contains("js_jni_register_deferred_natives"))
    }

    @Test
    fun native_vm_field_resolution_applies_renamed_field_bindings_before_jni_lookup() {
        val symbolSource = Files.readString(Path.of("src/main/native/js_vm_symbol.c"))
        val resolverStart = symbolSource.indexOf("JS_HIDDEN int js_vm_resolve_field_symbol")
        val resolverEnd = symbolSource.indexOf("JS_HIDDEN int js_vm_resolve_method_symbol", resolverStart)
        assertTrue(resolverStart >= 0 && resolverEnd > resolverStart)
        val resolverBody = symbolSource.substring(resolverStart, resolverEnd)
        val bindingLookup = resolverBody.indexOf("js_lookup_bound_field(env, fr.owner, fr.name, fr.desc)")
        val fieldLookup = resolverBody.indexOf("js_vm_lookup_field_id(env, cls, lookup_name, fr.desc")
        assertTrue(bindingLookup >= 0, "VM field resolution must consult keyed field bindings")
        assertTrue(fieldLookup > bindingLookup, "VM field resolution must apply the binding before JNI lookup")

        val runtimeHeader = Files.readString(Path.of("src/main/native/js_vm_core.h"))
        assertTrue(runtimeHeader.contains("js_lookup_bound_field"))
    }
}
