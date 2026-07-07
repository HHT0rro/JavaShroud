package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeToolchainProvisioner
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.currentVbc4BuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class NativeRecompilationTransformsTest {

    @Test
    fun native_recompilation_defaults_to_o2_when_js_vbc4_opt_is_unset() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val optBody = source.substringAfter("private fun nativeCompileOptLevel()").substringBefore("private fun nativeCompileExtraFlags")
        val compileBody = source.substringAfter("private fun compileWithZig(").substringBefore("internal fun generateDiversifiedSecrets")

        assertTrue(optBody.contains("System.getenv(\"JS_VBC4_OPT\")"), "JS_VBC4_OPT must remain the native optimization override")
        assertTrue(optBody.contains("else \"-O2\""), "Native compile optimization must default to -O2 when JS_VBC4_OPT is unset")
        assertFalse(compileBody.contains("\"-O0\""), "Default native compile command must not select -O0 when JS_VBC4_OPT is unset")
        assertFalse(compileBody.contains("rng.nextInt") && compileBody.contains("optLevel"), "Default optimization must not be randomized")
    }
    @Test
    fun generateDiversifiedSecrets_produces_different_output_for_different_seeds() {
        val rng1 = java.util.Random(12345L)
        val rng2 = java.util.Random(67890L)
        val secrets1 = NativeRecompilationTransforms.generateDiversifiedSecrets(12345L, rng1, defaultVbc4BuildContext())
        val secrets2 = NativeRecompilationTransforms.generateDiversifiedSecrets(67890L, rng2, defaultVbc4BuildContext())
        assertNotEquals(secrets1, secrets2, "Different seeds should produce different secrets")
    }

    @Test
    fun generateDiversifiedSecrets_contains_required_markers() {
        val rng = java.util.Random(42L)
        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(42L, rng, defaultVbc4BuildContext())
        assertTrue(secrets.contains("JS_SECRET_SEED"), "Should contain JS_SECRET_SEED define")
        assertTrue(secrets.contains("js_secret_SECURITY_EXCEPTION_CLASS"), "Should contain class name constant")
        assertTrue(secrets.contains("js_secret_RUNTIME_CLASS"), "Should contain Runtime class constant")
        assertTrue(secrets.contains("JS_SECRET_AES_KEY"), "Should contain AES key material for generated native strings")
        assertTrue(secrets.contains("JS_SECRET_AES_IV"), "Should contain AES IV material for generated native strings")
        assertTrue(secrets.contains("JS_SECRET_DECRYPT"), "Should contain the native string decode macro")
        assertFalse(secrets.contains("js_secret_keystream"), "Generated native secrets must not retain the old XOR keystream helper")
        assertTrue(secrets.contains("#endif"), "Should be properly closed")
    }

    @Test
    fun generateDiversifiedSecrets_decrypts_with_generated_aes_ctr_material() {
        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(42L, java.util.Random(42L), defaultVbc4BuildContext())
        val key = parseCByteArray(secrets, "JS_SECRET_AES_KEY")
        val iv = parseCByteArray(secrets, "JS_SECRET_AES_IV")
        val index = Regex("""#define JS_SECRET_INDEX_SYSTEM_CLASS (\d+)""").find(secrets)!!.groupValues[1].toInt()
        val encryptedSystemClass = parseCByteArray(secrets, "js_secret_SYSTEM_CLASS")

        assertEquals("java/lang/System", decryptNativeSecret(encryptedSystemClass, key, iv, index))
    }

    @Test
    fun generateAntiReverseGuards_contains_debug_detection() {
        val rng = java.util.Random(42L)
        val guards = NativeRecompilationTransforms.generateAntiReverseGuards(rng)
        assertTrue(guards.contains("_js_guard_is_debugged"), "Should contain debug check function")
        assertTrue(guards.contains("IsDebuggerPresent") || guards.contains("ptrace"), "Should contain platform debug API")
        assertTrue(guards.contains("_js_guard_timing_anomaly"), "Should contain timing check")
        assertTrue(guards.contains("_js_guard_hw_breakpoints"), "Should contain HW breakpoint check")
    }

    @Test
    fun generateAntiReverseGuards_contains_vm_detection() {
        val rng = java.util.Random(42L)
        val guards = NativeRecompilationTransforms.generateAntiReverseGuards(rng)
        assertTrue(guards.contains("_js_guard_vm_detected"), "Should contain VM detection")
        assertTrue(guards.contains("_js_guard_integrity_check"), "Should contain integrity check")
        assertTrue(guards.contains("_js_guard_all"), "Should contain composite guard")
    }


    @Test
    fun applySourceDiversification_preserves_source_structure() {
        val source = """
            #include <jni.h>
            #include <string.h>
            static int test_func(int x) {
                return x + 1;
            }
        """.trimIndent()
        val rng = java.util.Random(42L)
        val result = NativeRecompilationTransforms.applySourceDiversification(source, rng)
        assertTrue(result.contains("#include <jni.h>"), "Should preserve includes")
        assertTrue(result.contains("test_func"), "Should preserve original functions")
    }

    @Test
    fun applySourceDiversification_appends_after_final_preprocessor_block() {
        val source = """
            #include <jni.h>
            #if defined(__linux__)
            static int linux_only(void) {
                return 1;
            }
            #endif
        """.trimIndent()
        val result = NativeRecompilationTransforms.applySourceDiversification(source, java.util.Random(42L))
        val finalEndif = result.indexOf("#endif")
        val firstJunk = result.indexOf("static int _junk_")
        assertTrue(firstJunk > finalEndif, "Junk functions must be appended after preprocessor blocks")
    }

    @Test
    fun generateAntiReverseGuards_keeps_ptrace_linux_only() {
        val guards = NativeRecompilationTransforms.generateAntiReverseGuards(java.util.Random(42L))
        assertTrue(guards.contains("#elif defined(__linux__) || defined(__ANDROID__)"), "ptrace branch should be Linux-gated")
        assertFalse(guards.contains("#else\n#include <sys/ptrace.h>"), "macOS targets must not include Linux ptrace header")
    }

    @Test
    fun generateDiversifiedSecrets_embeds_matching_vbc4_build_key_shares() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x13572468L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0xA0 + index).toByte() },
        )

        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(42L, java.util.Random(42L), context)
        val reconstructed = reconstructNativeBuildKey(secrets)

        assertTrue(secrets.contains("JS_VBC4_BUILD_KEY_GENERATED"), "Native VBC4 build key marker must be generated")
        assertTrue(context.masterKey.contentEquals(reconstructed), "Generated native VBC4 slot table must reconstruct the Kotlin build master key")
        assertFalse(secrets.contains("JS_VBC4_BUILD_KEY_SHARE_A"), "Generated native VBC4 material must not expose a stable share A symbol")
        assertFalse(secrets.contains("JS_VBC4_BUILD_KEY_SHARE_B"), "Generated native VBC4 material must not expose a stable share B symbol")
        assertFalse(secrets.contains("static const unsigned char JS_VBC4_LAYOUT_DIGEST[32]"), "Generated native VBC4 material must not expose a stable layout digest symbol")
        assertTrue(secrets.contains("JS_VBC4_LAYOUT_DIGEST_AT"), "Native VBC4 layout digest must be exposed only through an accessor")
        assertTrue(secrets.contains("#define JS_VBC4_DISPATCH_MIX_A"), "Native VBC4 dispatch mix must be generated per build")
    }
    @Test
    fun generateDiversifiedSecrets_does_not_emit_flat_vbc4_master_material() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (0x40 + index).toByte() },
            nativeSeed = 0x2468ACE0L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0x10 + index * 3).toByte() },
        )

        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(99L, java.util.Random(99L), context)
        val slots = parseNativeSecretSlots(secrets)
        val reconstructed = reconstructNativeBuildKey(secrets)

        assertTrue(context.masterKey.contentEquals(reconstructed), "Split shares must reconstruct the scoped build master only when combined")
        slots.forEachIndexed { index, slot ->
            assertFalse(slot.contentEquals(context.masterKey), "Native slot $index must not be the flat VBC4 master key")
        }
        assertFalse(secrets.contains("JS_VBC4_MASTER_KEY"), "Generated native secrets must not expose a flat VBC4 master key symbol")
        assertFalse(secrets.contains("JS_VBC4_BUILD_KEY_SHARE_A") || secrets.contains("JS_VBC4_BUILD_KEY_SHARE_B"), "Generated native secrets must not expose a fixed A/B share recipe")
        assertFalse(secrets.contains("g_vbc4_inner_pad") || secrets.contains("g_vbc4_outer_pad"), "Generated native secrets must not expose long-lived VBC4 HMAC pads")
        assertFalse(secrets.contains(cBytesForTest(context.masterKey)), "Generated native secrets must not contain the contiguous flat VBC4 master key bytes")
    }

    @Test
    fun vbc4BuildContext_scope_uses_wiped_copy_without_mutating_caller_context() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index + 1).toByte() },
            nativeSeed = 0x10203040L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0x7F - index).toByte() },
        )
        val originalMaster = context.masterKey.copyOf()
        var scopedContext: Vbc4BuildContext? = null
        var scopedMasterCopy: ByteArray? = null

        withVbc4BuildContext(context) {
            scopedContext = currentVbc4BuildContextOrNull()
            scopedMasterCopy = scopedContext!!.copyMasterKey()
            assertFalse(scopedContext === context, "Thread-local VBC4 context must be a scoped copy, not the caller-owned key holder")
            assertTrue(originalMaster.contentEquals(scopedMasterCopy!!), "Scoped VBC4 context must start with equivalent build key material")
        }

        assertTrue(context.masterKey.contentEquals(originalMaster), "Caller-owned context must remain usable after the scoped copy is wiped")
        assertTrue(scopedContext!!.masterKey.all { it.toInt() == 0 }, "Scoped VBC4 master key copy must be wiped on scope exit")
        assertTrue(scopedContext!!.runtimeResourceKey.all { it.toInt() == 0 }, "Scoped VBC4 runtime resource key copy must be wiped on scope exit")
    }

    @Test
    fun nativeToolchainProvisioner_cacheDirectory_is_consistent() {
        val dir = NativeToolchainProvisioner.cacheDirectory()
        assertNotNull(dir, "Cache directory should not be null")
        assertTrue(dir.toString().contains("javashroud"), "Should contain javashroud in path")
        assertTrue(dir.toString().contains("zig"), "Should contain zig in path")
    }

    @Test
    fun zigTargets_contains_all_platforms() {
        val targets = NativeRecompilationTransforms.ZIG_TARGETS
        assertTrue(targets.containsKey("windows-x64"), "Should have windows-x64 target")
        assertTrue(targets.containsKey("linux-x64"), "Should have linux-x64 target")
        assertTrue(targets.containsKey("macos-x64"), "Should have macos-x64 target")
        assertTrue(targets.containsKey("macos-arm64"), "Should have macos-arm64 target")
    }
    @Test
    fun target_platform_auto_resolves_to_detected_supported_zig_target() {
        assertTrue(
            EmbeddedHelperDeployment.resolveNativeCompileTargetPlatforms("auto", "Linux", "x86_64") == listOf("linux-x64"),
            "targetPlatform=auto must resolve to the detected supported Zig target",
        )
    }

    @Test
    fun native_recompilation_uses_csprng_for_production_diversification() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))

        assertTrue(source.contains("nativeBuildSecureRandom(seed, vbc4BuildContext)"), "Production native diversification must start from CSPRNG material")
        assertTrue(source.contains("SecureRandom()"), "Production native diversification must use SecureRandom")
        assertFalse(source.contains("Random(seed xor vbc4BuildContext.nativeSeed)"), "Production native diversification must not be reproducible from seed xor nativeSeed")
        assertTrue(source.contains("protectedSectionKey"), "Native cache key and secrets must retain per-build protected-section material")
        assertTrue(source.contains("NativeKernelShellPacker.pack"), "standard Zig-compiled native artifacts must pass through the shell overlay packer after section sealing")
        assertTrue(source.contains("buildMaxPayloadBundle"), "max native artifacts must build an authenticated payload bundle after section sealing")
        assertTrue(source.contains("compileShellStubWithZig"), "max native artifacts must compile an outer stub shell")
    }
    @Test
    fun native_artifact_cache_key_covers_security_sensitive_inputs() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val keyBody = source.substringAfter("internal fun nativeArtifactCacheKey(").substringBefore("private fun digestNativeSourceTree")

        assertTrue(keyBody.contains("taskPlatform"), "Cache key must include the requested platform")
        assertTrue(keyBody.contains("zigTarget"), "Cache key must include the Zig target")
        assertTrue(keyBody.contains("outputName"), "Cache key must include the native output name")
        assertTrue(keyBody.contains("nativeCompileOptLevel()"), "Cache key must include compile optimization level")
        assertTrue(keyBody.contains("nativeCompileExtraFlags()"), "Cache key must include compile hardening flags")
        assertTrue(keyBody.contains("sourceDigest"), "Cache key must include generated native source content")
        assertTrue(keyBody.contains("toolchainIdentity"), "Cache key must include Zig toolchain identity")
        assertTrue(keyBody.contains("vbc4BuildContext.nativeSeed"), "Cache key must include VBC4 native seed")
        assertTrue(keyBody.contains("vbc4BuildContext.jarLayoutDigest"), "Cache key must include layout digest")
        assertTrue(keyBody.contains("vbc4BuildContext.masterKey"), "Cache key must include VBC4 build key material")
        assertTrue(keyBody.contains("vbc4BuildContext.runtimeResourceKey"), "Cache key must include runtime resource key material")
        assertTrue(keyBody.contains("protectedSectionKey"), "Cache key must include protected-section sealing material")
        assertTrue(keyBody.contains("nativeProtectionLevel"), "Cache key must include native protection level")
        assertTrue(keyBody.contains("nativePackingLevel"), "Cache key must include native shell packing level")
        assertTrue(keyBody.contains("nativeShellPackerVersion"), "Cache key must include native shell packer version")
        assertTrue(keyBody.contains("nativeShellPayloadProfile"), "Cache key must include max payload profile identity")
        assertTrue(keyBody.contains("nativeShellLoaderProfile"), "Cache key must include platform loader profile identity")
    }

    @Test
    fun native_max_source_digest_covers_stub_crypto_and_platform_loaders() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val nativeSources = source.substringAfter("private val NATIVE_SOURCE_FILES = listOf(").substringBefore(")")

        listOf(
            "js_shell_stub.c",
            "js_shell_stub.h",
            "js_shell_crypto.c",
            "js_shell_crypto.h",
            "js_shell_loader.h",
            "js_shell_loader_pe.c",
            "js_shell_loader_elf.c",
            "js_shell_loader_macho.c",
        ).forEach { fileName ->
            assertTrue(nativeSources.contains(fileName), "Native source digest must cover max shell source: $fileName")
        }
    }

    @Test
    fun native_artifact_cache_key_changes_when_shell_protocol_inputs_change() {
        val context = defaultVbc4BuildContext()
        val sourceDigest = ByteArray(32) { index -> (index * 3 + 1).toByte() }
        val protectedSectionKey = ByteArray(32) { index -> (0xA5 xor index).toByte() }
        fun key(
            packingLevel: String = "max",
            packerVersion: Int = 7,
            payloadProfile: String = "max-payload-zstd-chunk-v4-bogus-metadata",
            loaderProfile: String = "pe64-memory-loader-reloc-import-tlsrange-execbounds-v20",
            toolchainIdentity: String = "zig|test|0.16.0",
            platform: String = "windows-x64",
            zigTarget: String = "x86_64-windows-gnu",
        ): String = NativeRecompilationTransforms.nativeArtifactCacheKey(
            taskPlatform = platform,
            zigTarget = zigTarget,
            outputName = "js_kernel_windows-x64.dll",
            sourceDigest = sourceDigest,
            toolchainIdentity = toolchainIdentity,
            seed = 5150L,
            vbc4BuildContext = context,
            protectedSectionKey = protectedSectionKey,
            nativeProtectionLevel = "standard",
            nativePackingLevel = packingLevel,
            nativeShellPackerVersion = packerVersion,
            nativeShellPayloadProfile = payloadProfile,
            nativeShellLoaderProfile = loaderProfile,
        )

        val baseline = key()
        assertNotEquals(baseline, key(packingLevel = "standard"), "Cache key must change when max shell packing level changes")
        assertNotEquals(baseline, key(packerVersion = 8), "Cache key must change when shell protocol/packer version changes")
        assertNotEquals(baseline, key(payloadProfile = "max-payload-zstd-chunk-v5"), "Cache key must change when payload profile changes")
        assertNotEquals(baseline, key(loaderProfile = "pe64-memory-loader-reloc-import-tlsrange-execbounds-v21"), "Cache key must change when loader profile changes")
        assertNotEquals(baseline, key(toolchainIdentity = "zig|test|0.17.0"), "Cache key must change when toolchain identity changes")
        assertNotEquals(baseline, key(platform = "linux-x64", zigTarget = "x86_64-linux-gnu"), "Cache key must change when target platform changes")
    }

    @Test
    fun linux_max_shell_loader_maps_decoded_inner_elf_in_memory() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_loader_elf.c"))

        assertTrue(source.contains("payload->decoded_payload"), "Linux max shell loader must use decoded inner payload bytes, not the encoded blob")
        assertTrue(source.contains("ET_DYN") && source.contains("EM_X86_64"), "Linux max shell loader must validate a supported ELF64 shared object")
        assertTrue(source.contains("PT_LOAD") && source.contains("PT_DYNAMIC"), "Linux max shell loader must map load segments and parse the dynamic section")
        assertTrue(source.contains("MAP_PRIVATE | MAP_ANONYMOUS"), "Linux max shell loader must use anonymous in-memory mapping")
        assertTrue(source.contains("R_X86_64_RELATIVE") && source.contains("R_X86_64_JUMP_SLOT") && source.contains("R_X86_64_GLOB_DAT"), "Linux max shell loader must process core RELA relocation classes")
        assertTrue(source.contains("dlsym(RTLD_DEFAULT"), "Linux max shell loader must resolve host imports without writing a temp library")
        assertTrue(source.contains("init_array") && source.contains("JNI_OnLoad"), "Linux max shell loader must run initializers and resolve the inner JNI_OnLoad export")
        assertTrue(
            source.contains("js_shell_mapped_range_contains") &&
                source.contains("elf64 relocation target is outside the mapped image") &&
                source.contains("elf64 relocation table is outside the mapped image") &&
                source.contains("elf64 string table is outside the mapped image") &&
                source.contains("elf64 init array is outside the mapped image"),
            "Linux max shell loader must fail closed when dynamic, relocation, string, or init metadata points outside the anonymous image.",
        )
        assertTrue(
            source.contains("exec_low_vaddr") &&
                source.contains("code_low") &&
                source.contains("elf64 init function is outside executable image pages") &&
                source.contains("elf64 init array function is outside executable image pages") &&
                source.contains("elf64 exported JNI or ABI entry is outside executable image pages"),
            "Linux max shell loader must expose executable image bounds and reject initializer/export entrypoints outside executable pages.",
        )
        assertFalse(source.contains("elf64 anonymous memory loader is fail-closed until"), "Linux max shell loader must not remain the placeholder fail-closed skeleton")
    }

    @Test
    fun linux_manual_mapped_resource_loader_avoids_class_vtable_dispatch() {
        val resource = java.nio.file.Files.readString(resolveSource("src/main/native/js_vm_resource.c"))
        val core = java.nio.file.Files.readString(resolveSource("src/main/native/js_vm_core.c"))
        val symbol = java.nio.file.Files.readString(resolveSource("src/main/native/js_vm_symbol.c"))

        assertTrue(resource.contains("CallNonvirtualObjectMethod(env, class_obj, js_jni_cache.class_class, js_jni_cache.class_get_class_loader"), "Manual mapped resource loading must avoid virtual Class.getClassLoader dispatch")
        assertTrue(resource.contains("CallNonvirtualObjectMethod(env, class_obj, js_jni_cache.class_class, js_jni_cache.class_get_name"), "Manual mapped resource loading must avoid virtual Class.getName dispatch")
        assertTrue(resource.contains("CallNonvirtualObjectMethod(env, class_obj, js_jni_cache.class_class, js_jni_cache.class_get_resource_as_stream"), "Manual mapped resource loading must avoid virtual Class.getResourceAsStream dispatch")
        assertTrue(resource.contains("jclass loader_cls = (*env)->GetObjectClass(env, loader)"), "Manual mapped resource loading must resolve ClassLoader methods from the actual receiver class")
        assertTrue(resource.contains("jclass thread_obj_cls = (*env)->GetObjectClass(env, thread)"), "Manual mapped context loader lookup must resolve Thread methods from the actual receiver class")
        assertTrue(resource.contains("jclass stream_cls = (*env)->GetObjectClass(env, stream)"), "Manual mapped stream reads must resolve InputStream methods from the actual receiver class")
        assertFalse(resource.contains("js_jni_cache.initialized ? js_jni_cache.class_loader_get_resource_as_stream"), "Manual mapped resource loading must not reuse cached ClassLoader virtual method IDs")
        assertFalse(resource.contains("js_jni_cache.initialized ? js_jni_cache.thread_get_context_class_loader"), "Manual mapped resource loading must not reuse cached Thread virtual method IDs")
        assertFalse(resource.contains("js_jni_cache.initialized ? js_jni_cache.input_stream_read_all_bytes"), "Manual mapped resource loading must not reuse cached InputStream virtual method IDs")
        assertTrue(resource.contains("if (!js_vm_preload_in_progress)"), "Preload resource loading must not consult the dispatch-frame active host loader")
        val preloadBody = core.substringAfter("jsn_k9(JNIEnv *env, jclass cls)").substringBefore("JS_HIDDEN jbyteArray JNICALL jsn_k10")
        assertTrue(preloadBody.contains("js_vm_preload_in_progress++;"), "Native preload must enter preload mode before reading the VM index")
        val normalizedCore = core.replace("\r\n", "\n")
        assertTrue(
            normalizedCore.contains("#elif defined(__GNUC__) || defined(__clang__)\n#define JS_THREAD_LOCAL"),
            "Linux manual-mapped inner runtime must keep small VM runtime caches process-static instead of using ELF TLS",
        )
        assertFalse(core.contains("__thread static js_vm_program"), "Linux manual-mapped inner runtime must not require ELF TLS for active VM program state")
        assertFalse(core.contains("__thread static jobject"), "Linux manual-mapped inner runtime must not require ELF TLS for active host loader state")
        assertFalse(core.contains("js_vm_method_from_object(env, obj, \"intValue\""), "Manual mapped primitive unboxing must not perform runtime GetMethodID for final boxed JDK classes")
        assertTrue(core.contains("GetIntField(env, obj, js_jni_cache.integer_value_field"), "Manual mapped primitive unboxing must read cached boxed value fields instead of invoking boxed methods")
        assertTrue(core.contains("js_vm_alloc_boxed_value"), "Manual mapped primitive boxing must allocate wrappers without invoking boxed valueOf methods")
        assertTrue(core.contains("SetIntField(env, boxed, field, value.i"), "Manual mapped primitive boxing must write cached boxed value fields directly")
        assertFalse(core.contains("CallStaticObjectMethodA(env, js_jni_cache.integer_class, js_jni_cache.integer_value_of"), "Manual mapped primitive boxing must not call Integer.valueOf through CallStaticObjectMethodA")
        assertFalse(core.contains("CallStaticObjectMethod(env, js_jni_cache.integer_class, js_jni_cache.integer_value_of"), "Specialized int VM entrypoints must not call Integer.valueOf through CallStaticObjectMethod")
        val intVoidBody = core.substringAfter("jsn_r24(JNIEnv *env, jclass cls, jlong entryToken, jint arg0)").substringBefore("static const unsigned char JS_JSE_CLASS_DERIVE_LABEL")
        assertTrue(intVoidBody.contains("js_vm_execute_resource_int_void_by_token(env, cls, entryToken, arg0)"), "Specialized int VM entrypoints must pass primitive int locals directly into the native VM")
        assertFalse(intVoidBody.contains("NewObjectArray"), "Specialized int VM entrypoints must not allocate Object[] wrappers in the manual-mapped hot path")
        assertFalse(intVoidBody.contains("js_vm_box_jvalue_arg"), "Specialized int VM entrypoints must not allocate boxed Integer wrappers in the manual-mapped hot path")
        val intReturnBody = core.substringAfter("jsn_r25(JNIEnv *env, jclass cls, jlong entryToken)").substringBefore("static const unsigned char JS_JSE_CLASS_DERIVE_LABEL")
        assertTrue(intReturnBody.contains("jint result = js_vm_execute_resource_int_by_token(env, cls, entryToken)"), "Specialized int-return VM entrypoints must return primitive jint directly from the native VM")
        assertFalse(intReturnBody.contains("js_vm_execute_resource_by_token"), "Specialized int-return VM entrypoints must not use the Object-return dispatch path")
        assertFalse(intReturnBody.contains("js_vm_box_return"), "Specialized int-return VM entrypoints must not allocate boxed Integer returns in the manual-mapped hot path")
        val nestedInvokeBody = core.substringAfter("static int js_vm_try_invoke_preloaded_nested").substringBefore("JS_HIDDEN int js_vm_build_state_binding")
        assertTrue(nestedInvokeBody.contains("!target && symbol->argc == 0 && (char)symbol->ret_tag == 'I'"), "Nested static int VM invokes must use a primitive fast path before Object-return boxing")
        assertTrue(nestedInvokeBody.contains("js_vm_execute_prepared_program_int(env, nested_program, &int_result)"), "Nested static int VM invokes must execute directly into a primitive jint")
        assertTrue(nestedInvokeBody.contains("symbol->argc == 1 && symbol->arg_tags && symbol->arg_tags[0] == 'I' && (char)symbol->ret_tag == 'I'"), "Nested static int-to-int VM invokes must use a primitive fast path before Object-return boxing")
        assertTrue(nestedInvokeBody.contains("js_vm_execute_prepared_program_int_int(env, nested_program, int_arg, &int_result)"), "Nested static int-to-int VM invokes must execute directly into a primitive jint")
        assertTrue(core.contains("js_vm_valid_method_lookup"), "Manual mapped dynamic method fallback must validate lookup strings before JVM symbol lookup")
        assertTrue(core.contains("js_vm_lookup_valid_method_id"), "Manual mapped method lookup must copy bounded lookup strings before JVM symbol lookup")
        assertTrue(core.contains("js_vm_debug_method_lookup_probe") && core.contains("JavaShroud native VM method lookup"), "Manual mapped method lookup must support debug-gated lookup probes")
        assertFalse(core.contains("GetMethodID(env, target_cls, dyn_lookup, dyn_mr.desc"), "Dynamic virtual fallback must not pass VM metadata pointers directly to GetMethodID")
        assertFalse(core.contains("GetStaticMethodID(env, cls, parts[4], parts[5]"), "Dynamic static method-handle lookup must not pass parsed metadata pointers directly to GetStaticMethodID")
        assertTrue(symbol.contains("js_vm_valid_symbol_method_lookup"), "Manual mapped symbol resolution must validate method lookup strings before JVM symbol lookup")
        assertTrue(symbol.contains("js_vm_lookup_method_id"), "Initial symbol resolution must copy bounded lookup strings before GetMethodID/GetStaticMethodID")
        assertFalse(symbol.contains("GetMethodID(env, cls, lookup_name, mr.desc"), "Initial symbol resolution must not pass VM metadata pointers directly to GetMethodID")
    }

    @Test
    fun max_shell_stub_validates_inner_abi_table_before_dispatch() {
        val stub = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_stub.c"))
        val loaderHeader = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_loader.h"))
        val runtime = java.nio.file.Files.readString(resolveSource("src/main/native/js_jni_runtime.c"))

        assertTrue(loaderHeader.contains("code_low") && loaderHeader.contains("code_size"), "Loaded shell images must carry executable code bounds for ABI validation")
        assertTrue(stub.contains("js_shell_validate_inner_abi_table"), "Outer stub must validate the inner ABI table before dispatch")
        assertTrue(stub.contains("inner ABI table pointer is outside the mapped image"), "Outer stub must fail closed when the ABI table pointer is outside the mapped image")
        assertTrue(stub.contains("inner ABI function pointer is outside executable image pages"), "Outer stub must fail closed when ABI functions do not point at executable inner code")
        assertTrue(stub.contains("js_shell_inner_code_contains((const void *)g_inner_image.jni_on_load)"), "Outer stub must validate inner JNI_OnLoad before invoking it")
        assertTrue(stub.contains("g_shell_helper_class") && stub.contains("js_shell_effective_helper_class(cls)"), "Outer stub must pin the registered helper class for all inner ABI dispatch")
        assertTrue(stub.contains("js_shell_current_env"), "Outer stub must reacquire the current thread JNIEnv before inner ABI dispatch")
        assertTrue(stub.contains("js_shell_debug_env_probe"), "Outer stub must keep debug-gated JNI env probes for manual-mapped runtime diagnosis")
        assertTrue(stub.contains("JAVASHROUD_DEBUG_NATIVE_LOG"), "Outer stub debug probes must support file-backed diagnostics when test output is truncated")
        assertTrue(stub.contains("native-preload-runtime-resources") && stub.contains("execute-vm-resource"), "Outer stub debug probes must label preload and VM dispatch entrypoints")
        assertFalse(stub.contains("g_inner_abi->execute_vm_resource(env,"), "Outer stub must not pass a stale outer JNIEnv directly into inner VM dispatch")
        assertTrue(runtime.contains("if (!js_jni_runtime_manual_mapped_shell)"), "Manual-mapped inner JNI_OnLoad must not register inner native method pointers with the JVM")
    }

    @Test
    fun windows_max_shell_loader_maps_decoded_inner_pe_in_memory() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_loader_pe.c"))

        assertTrue(source.contains("payload->decoded_payload"), "Windows max shell loader must use decoded inner payload bytes, not the encoded blob")
        assertTrue(source.contains("IMAGE_FILE_MACHINE_AMD64") && source.contains("IMAGE_NT_OPTIONAL_HDR64_MAGIC"), "Windows max shell loader must validate a PE64 AMD64 DLL")
        assertTrue(source.contains("VirtualAlloc") && source.contains("IMAGE_FIRST_SECTION"), "Windows max shell loader must allocate an image and map sections")
        assertTrue(source.contains("IMAGE_REL_BASED_DIR64"), "Windows max shell loader must apply PE64 base relocations")
        assertTrue(source.contains("LoadLibraryA") && source.contains("GetProcAddress"), "Windows max shell loader must resolve imports in memory")
        assertTrue(source.contains("js_shell_validate_tls_callbacks") && source.contains("js_shell_run_tls_callbacks(image, tls_callbacks, DLL_PROCESS_ATTACH)"), "Windows max shell loader must validate and run PE TLS callbacks during manual attach")
        assertTrue(source.contains("pe64 TLS directory is outside the mapped image") && source.contains("pe64 TLS callback table is outside the mapped image"), "Windows max shell loader must fail closed when TLS metadata escapes the mapped image")
        assertTrue(source.contains("js_shell_plan_executable_bounds") && source.contains("out_image->code_low") && source.contains("out_image->code_size"), "Windows max shell loader must expose executable image bounds for ABI validation")
        assertTrue(source.contains("pe64 DllMain entrypoint is outside executable image pages") && source.contains("DLL_PROCESS_ATTACH"), "Windows max shell loader must validate and run DllMain process attach")
        assertTrue(source.contains("IMAGE_DIRECTORY_ENTRY_EXPORT") && source.contains("JNI_OnLoad"), "Windows max shell loader must resolve the inner JNI_OnLoad export")
        assertFalse(source.contains("pe64 memory loader is fail-closed until"), "Windows max shell loader must not remain the placeholder fail-closed skeleton")
    }

    @Test
    fun windows_max_shell_loader_keeps_manual_image_process_lifetime() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_loader_pe.c"))
        val runtime = java.nio.file.Files.readString(resolveSource("src/main/native/js_jni_runtime.c"))
        val stub = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_stub.c"))

        assertTrue(source.contains("ran tls callbacks for manual image") && source.contains("ran dllmain attach for manual image"), "Windows manual mapper must run attach callbacks after validation")
        assertFalse(source.contains("DLL_PROCESS_DETACH"), "Windows manual mapper must not run detach callbacks for the manually mapped inner kernel")
        assertTrue(source.contains("Keep the PE image process-lifetime"), "Windows manual mapper must avoid freeing native-method code pages")
        assertTrue(runtime.contains("js_protected_section_unseal_now();"), "Inner JNI_OnLoad must explicitly unseal protected sections before any protected VM code can run")
        assertTrue(stub.contains("g_inner_image.jni_on_load(g_shell_vm, 0)"), "Outer stub must pass a null reserved value into inner JNI_OnLoad")
        assertFalse(stub.contains("JS_SHELL_MANUAL_MAP_RESERVED"), "Outer stub must not pass a custom sentinel through the JVM-reserved JNI_OnLoad parameter")
    }

    @Test
    fun macos_max_shell_loader_validates_macho_but_remains_fail_closed() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/native/js_shell_loader_macho.c"))

        assertTrue(source.contains("JS_MH_MAGIC_64") && source.contains("JS_MH_DYLIB"), "macOS max shell loader must validate a Mach-O 64 dylib")
        assertTrue(source.contains("JS_CPU_TYPE_X86_64") && source.contains("JS_CPU_TYPE_ARM64"), "macOS max shell loader must cover x64 and arm64 payload identities")
        assertTrue(source.contains("JS_LC_SEGMENT_64") && source.contains("__TEXT") && source.contains("__LINKEDIT"), "macOS max shell loader must parse core segment commands")
        assertTrue(source.contains("js_macho_image_plan") && source.contains("js_shell_macho_plan_segment"), "macOS max shell loader must build an anonymous image layout plan from Mach-O segments")
        assertTrue(source.contains("JS_MACHO_PAGE_GRANULE") && source.contains("mapping_size") && source.contains("slide"), "macOS max shell loader must compute page-aligned mapping size and slide before execution support is enabled")
        assertTrue(source.contains("JS_VM_PROT_EXECUTE") && source.contains("text_low") && source.contains("text_high"), "macOS max shell loader must identify executable image bounds for future inner ABI pointer validation")
        assertTrue(source.contains("js_shell_macho_materialize_segments") && source.contains("mmap(0, (size_t)plan->mapping_size"), "macOS max shell loader must allocate an anonymous image mapping before execution support is enabled")
        assertTrue(source.contains("memcpy((unsigned char *)mapping + target_offset") && source.contains("mprotect("), "macOS max shell loader must copy segment file ranges and plan per-segment memory protections")
        assertTrue(source.contains("munmap(planned_mapping") && source.contains("segment materialization"), "macOS max shell loader must release the planned mapping while execution remains fail-closed")
        assertTrue(source.contains("js_shell_macho_apply_rebase_stream") && source.contains("js_shell_macho_apply_rebase_at"), "macOS max shell loader must apply validated rebase opcodes inside the anonymous mapping")
        assertTrue(source.contains("image_plan.slide = (uint64_t)(uintptr_t)planned_mapping - image_plan.vm_low"), "macOS max shell loader must derive rebase slide from the runtime anonymous mapping address")
        assertTrue(source.contains("mach-o rebase target is outside anonymous mapping") && source.contains("mach-o rebase application failed inside anonymous mapping"), "macOS max shell loader must fail closed when rebases target memory outside the planned image")
        assertTrue(source.contains("js_shell_macho_apply_bind_stream") && source.contains("js_shell_macho_apply_bind_at"), "macOS max shell loader must parse bind/lazy-bind opcodes against the anonymous mapping")
        assertTrue(source.contains("js_shell_macho_resolve_bind_symbol") && source.contains("dlsym(RTLD_DEFAULT, lookup)"), "macOS max shell loader must attempt to resolve dyld bind symbols from the host process before execution can be enabled")
        assertTrue(source.contains("symbol[0] == '_' ? symbol + 1u : symbol") && source.contains("mach-o bind symbol resolver could not resolve host symbol"), "macOS bind resolver must normalize Mach-O symbol names and keep unresolved host symbols fail-closed")
        assertTrue(source.contains("mach-o bind symbol addend overflows resolved address") && source.contains("mach-o bind symbol negative addend underflows resolved address"), "macOS bind resolver must fail closed when bind addends escape address bounds")
        assertTrue(source.contains("mach-o bind target is outside anonymous mapping") && source.contains("mach-o bind application failed inside anonymous mapping"), "macOS max shell loader must fail closed when bind slots target memory outside the planned image")
        assertTrue(source.contains("JS_LC_DYLD_INFO") && source.contains("rebase_off") && source.contains("weak_bind_off") && source.contains("lazy_bind_off"), "macOS max shell loader must validate dyld rebase/bind/weak-bind/lazy-bind ranges")
        assertTrue(source.contains("dyld->weak_bind_off") && source.contains("dyld->weak_bind_size") && source.contains("weak-bind/lazy-bind opcode stream"), "macOS max shell loader must parse and apply weak-bind opcodes before execution can be enabled")
        assertTrue(source.contains("js_shell_export_trie_has_symbol") && source.contains("_JNI_OnLoad"), "macOS max shell loader must validate the JNI_OnLoad export trie")
        assertTrue(source.contains("js_shell_macho_resolve_export_rva") && source.contains("js_shell_macho_resolve_export_pointer"), "macOS max shell loader must resolve export trie addresses into anonymous image pointers")
        assertTrue(source.contains("mach-o export entrypoint is outside executable image pages") && source.contains("mach-o export symbol address is outside anonymous mapping"), "macOS max shell loader must fail closed when resolved exports escape code or image bounds")
        assertTrue(source.contains("resolved_jni_on_load") && source.contains("resolved_native_abi_table"), "macOS max shell loader must resolve JNI_OnLoad and native ABI table exports before execution can be enabled")
        assertTrue(source.contains("js_shell_macho_prepare_loaded_image_plan") && source.contains("js_shell_loaded_image planned_image"), "macOS max shell loader must assemble a loaded image plan before execution can be enabled")
        assertTrue(source.contains("planned_image->image_base") && source.contains("planned_image->image_size") && source.contains("planned_image->code_low") && source.contains("planned_image->code_size"), "macOS loaded image plan must carry image and executable code bounds")
        assertTrue(source.contains("planned_image->jni_on_load") && source.contains("planned_image->native_abi_table_v1"), "macOS loaded image plan must bind JNI_OnLoad and native ABI table pointers")
        assertTrue(source.contains("mach-o loaded image JNI_OnLoad is outside executable code bounds") && source.contains("mach-o loaded image native ABI table is outside anonymous mapping"), "macOS loaded image plan must fail closed when resolved ABI pointers escape their expected bounds")
        assertTrue(source.contains("js_macho_initializer_section_plan") && source.contains("js_shell_macho_plan_initializer_section"), "macOS max shell loader must record initializer pointer sections from Mach-O section metadata")
        assertTrue(source.contains("js_shell_macho_validate_initializers") && source.contains("mach-o initializer pointer is outside executable image pages"), "macOS max shell loader must validate materialized initializer pointers before execution can be enabled")
        assertTrue(source.contains("initializer_section_count") && source.contains("JS_MACHO_MAX_INITIALIZER_SECTIONS"), "macOS max shell loader must cap initializer section metadata while parsing")
        assertTrue(source.contains("anonymous execution mapping stays fail-closed"), "macOS max shell loader must explicitly fail closed until true in-memory execution is implemented")
    }

    @Test
    fun linux_max_native_recompile_emits_outer_stub_shell_artifact() {
        val context = defaultVbc4BuildContext()
        val innerDiagnostics = withVbc4BuildContext(context) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 424242L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = listOf("linux-x64"),
                nativeProtectionLevel = "standard",
                nativePackingLevel = "off",
            )
        }
        val diagnostics = withVbc4BuildContext(context) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 424242L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = listOf("linux-x64"),
                nativeProtectionLevel = "standard",
                nativePackingLevel = "max",
            )
        }

        val result = diagnostics.results.singleOrNull()
        assertTrue(result != null, "linux-x64 max native recompilation should produce one shell artifact; messages=${diagnostics.messages.joinToString { it.message }}")
        val bytes = result!!.bytes
        assertTrue(bytes.containsAscii("JNI_OnLoad"), "outer shell must export JNI_OnLoad")
        assertTrue(bytes.containsAscii("JS_NATIVE_MAX_STUB_V1"), "outer shell must carry the max stub marker")
        assertTrue(bytes.containsAscii("JS_NATIVE_MAX_PAYLOAD_V1"), "outer shell must carry the authenticated max payload marker")
        assertFalse(bytes.containsAscii("JS_NATIVE_SHELL_LOADER_V1"), "max output must not be the standard overlay artifact")
        assertMaxStubReverseEvidence(bytes, "linux-x64")

        val innerBytes = innerDiagnostics.results.singleOrNull()?.bytes
        assertTrue(innerBytes != null, "linux-x64 off recompilation should expose the sealed inner kernel for reverse-evidence comparison")
        assertFalse(
            bytes.indexOfSlice(innerBytes!!.copyOfRange(0, minOf(96, innerBytes.size))) >= 0,
            "max outer stub must not contain the inner js_kernel ELF header as a raw embedded dynamic library",
        )
        assertFalse(
            containsAnyHighEntropyPlaintextSlice(haystack = bytes, needleSource = innerBytes),
            "max outer stub must not contain sampled high-entropy plaintext slices from the complete inner js_kernel",
        )
    }

    @Test
    fun jni_microkernel_helper_reports_failed_native_load_status() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val statusBody = source.substringAfter("public static String getLoadStatus()").substringBefore("public static boolean isNativeLoaded()")
        val classKeyBody = source.substringAfter("public static byte[] deriveClassEncryptionKey").substringBefore("private static byte[] concat")

        assertTrue(statusBody.contains("loadMessage == null || loadMessage.length() == 0"), "failed native load attempts must report loadMessage instead of collapsing to untried")
        assertTrue(classKeyBody.contains("no Java fallback ("), "class-encryption fail-closed errors must include native load status for real-JAR diagnostics")
    }

    @Test
    fun windows_max_native_recompile_emits_outer_stub_shell_artifact() {
        val diagnostics = withVbc4BuildContext(defaultVbc4BuildContext()) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 525252L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = listOf("windows-x64"),
                nativeProtectionLevel = "standard",
                nativePackingLevel = "max",
            )
        }

        val result = diagnostics.results.singleOrNull()
        assertTrue(result != null, "windows-x64 max native recompilation should produce one shell artifact; messages=${diagnostics.messages.joinToString { it.message }}")
        val bytes = result!!.bytes
        assertTrue(bytes.containsAscii("JNI_OnLoad"), "outer shell must export JNI_OnLoad")
        assertTrue(bytes.containsAscii("JS_NATIVE_MAX_STUB_V1"), "outer shell must carry the max stub marker")
        assertTrue(bytes.containsAscii("JS_NATIVE_MAX_PAYLOAD_V1"), "outer shell must carry the authenticated max payload marker")
        assertFalse(bytes.containsAscii("JS_NATIVE_SHELL_LOADER_V1"), "max output must not be the standard overlay artifact")
        assertMaxStubReverseEvidence(bytes, "windows-x64")
    }

    @Test
    fun macos_max_native_recompile_emits_fail_closed_outer_stub_shell_artifacts() {
        val diagnostics = withVbc4BuildContext(defaultVbc4BuildContext()) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 626262L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = listOf("macos-x64", "macos-arm64"),
                nativeProtectionLevel = "standard",
                nativePackingLevel = "max",
            )
        }

        assertEquals(emptyList(), diagnostics.messages.filter { it.level == "error" }.map { it.message }, "macOS max shell cross-compilation should not report errors")
        assertEquals(setOf("macos-x64", "macos-arm64"), diagnostics.results.map { it.platform }.toSet(), "max shell should emit both macOS outer stub targets")
        diagnostics.results.forEach { result ->
            assertTrue(result.bytes.containsAscii("JNI_OnLoad"), "${result.platform} outer shell must export JNI_OnLoad")
            assertTrue(result.bytes.containsAscii("JS_NATIVE_MAX_STUB_V1"), "${result.platform} outer shell must carry the max stub marker")
            assertTrue(result.bytes.containsAscii("JS_NATIVE_MAX_PAYLOAD_V1"), "${result.platform} outer shell must carry the authenticated max payload marker")
            assertTrue(result.bytes.containsAscii("JS_MACHO_ANON_EXEC_FAIL_CLOSED_V1"), "${result.platform} must retain explicit Mach-O fail-closed evidence until true anonymous execution is implemented")
            assertFalse(result.bytes.containsAscii("JS_NATIVE_SHELL_LOADER_V1"), "${result.platform} max output must not be the standard overlay artifact")
            assertMaxStubReverseEvidence(result.bytes, result.platform)
        }
    }

    @Test
    fun native_max_reverse_evidence_report_is_written_for_outer_stubs() {
        val context = defaultVbc4BuildContext()
        val platforms = listOf("windows-x64", "linux-x64")
        val innerDiagnostics = withVbc4BuildContext(context) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 737373L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = platforms,
                nativeProtectionLevel = "standard",
                nativePackingLevel = "off",
            )
        }
        val maxDiagnostics = withVbc4BuildContext(context) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 737373L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = platforms,
                nativeProtectionLevel = "standard",
                nativePackingLevel = "max",
            )
        }
        val macosDiagnostics = withVbc4BuildContext(context) {
            NativeRecompilationTransforms.recompileWithDiagnostics(
                seed = 737373L,
                classLoader = NativeRecompilationTransforms::class.java.classLoader,
                targetPlatforms = listOf("macos-x64", "macos-arm64"),
                nativeProtectionLevel = "standard",
                nativePackingLevel = "max",
            )
        }

        assertEquals(platforms.toSet(), maxDiagnostics.results.map { it.platform }.toSet(), "Windows/Linux max recompilation must produce reportable outer stubs")
        assertEquals(platforms.toSet(), innerDiagnostics.results.map { it.platform }.toSet(), "Windows/Linux off recompilation must produce inner kernels for plaintext comparison")
        assertEquals(setOf("macos-x64", "macos-arm64"), macosDiagnostics.results.map { it.platform }.toSet(), "macOS max recompilation must produce fail-closed reportable outer stubs. diagnostics=${macosDiagnostics.messages.joinToString(" | ") { "${it.level}:${it.message}" }}")

        val innerByPlatform = innerDiagnostics.results.associateBy { it.platform }
        val report = StringBuilder()
        report.appendLine("# JavaShroud Native Max Reverse Evidence")
        report.appendLine()
        report.appendLine("Generated by NativeRecompilationTransformsTest.native_max_reverse_evidence_report_is_written_for_outer_stubs")
        report.appendLine("Scope: artifact-level reverse indicators for max outer stub outputs; runtime JAR evidence is covered by RealJniMicrokernelFixtureRegressionTest.")
        report.appendLine("Protocol profile: max-payload-zstd-chunk-v4-bogus-metadata")
        report.appendLine("Windows/Linux loader profile: ${NativeRecompilationTransforms.nativeShellLoaderProfileForTest("windows-x64")} / ${NativeRecompilationTransforms.nativeShellLoaderProfileForTest("linux-x64")}")
        report.appendLine("macOS profile: Mach-O parser and metadata validation with explicit fail-closed anonymous execution boundary")
        report.appendLine()

        val allOuterResults = (maxDiagnostics.results + macosDiagnostics.results).sortedBy { it.platform }
        appendJarNativeEntryEvidence(report, allOuterResults)
        appendReverseToolAvailability(report)

        maxDiagnostics.results.sortedBy { it.platform }.forEach { result ->
            val innerBytes = innerByPlatform[result.platform]?.bytes
            assertTrue(innerBytes != null, "${result.platform} must have an off inner artifact for reverse-evidence comparison")
            assertMaxStubReverseEvidence(result.bytes, result.platform)
            val rawHeaderComparable = result.platform != "windows-x64"
            if (rawHeaderComparable) {
                assertFalse(
                    result.bytes.indexOfSlice(innerBytes!!.copyOfRange(0, minOf(96, innerBytes.size))) >= 0,
                    "${result.platform} max outer stub must not contain the inner raw dynamic-library header",
                )
            }
            assertFalse(
                containsAnyHighEntropyPlaintextSlice(haystack = result.bytes, needleSource = innerBytes),
                "${result.platform} max outer stub must not contain sampled high-entropy plaintext slices from the inner js_kernel",
            )
            appendReverseEvidenceReport(report, result.platform, result.bytes, innerBytes, rawHeaderComparable, failClosedReason = null)
        }

        macosDiagnostics.results.sortedBy { it.platform }.forEach { result ->
            assertTrue(result.bytes.containsAscii("JS_MACHO_ANON_EXEC_FAIL_CLOSED_V1"), "${result.platform} must retain its explicit Mach-O fail-closed evidence marker")
            assertMaxStubReverseEvidence(result.bytes, result.platform)
            appendReverseEvidenceReport(
                report,
                result.platform,
                result.bytes,
                innerBytes = null,
                rawHeaderComparable = false,
                failClosedReason = "Mach-O payload parser validates segments, sections, rebase/bind/lazy-bind streams and initializer metadata, but anonymous execution remains fail-closed until real macOS runtime validation is implemented.",
            )
        }

        val reportDir = workspaceRootForReports().resolve("build").resolve("core-engine").resolve("reports").resolve("native-max")
        java.nio.file.Files.createDirectories(reportDir)
        appendReverseToolOutputEvidence(report, reportDir, allOuterResults)
        val reportPath = reportDir.resolve("native-max-reverse-evidence.md")
        java.nio.file.Files.writeString(reportPath, report.toString(), Charsets.UTF_8)
        assertTrue(java.nio.file.Files.size(reportPath) > 0, "native max reverse evidence report must be written: $reportPath")
        val reportText = java.nio.file.Files.readString(reportPath)
        assertTrue(reportText.contains("## reverse-tool-output-evidence"), "native max reverse evidence report must include external reverse-tool output evidence")
        assertNativeMaxReverseEvidenceReportCoversReleaseGate(reportText)
    }

    @Test
    fun native_protection_level_changes_generated_guard_surface() {
        val standard = NativeRecompilationTransforms.generateAntiReverseGuards(java.util.Random(42L), "standard")
        val aggressive = NativeRecompilationTransforms.generateAntiReverseGuards(java.util.Random(42L), "aggressive")

        assertFalse(standard.contains("/proc/self/maps"), "standard native protection should not enable extra anti-unpack map scanning")
        assertTrue(aggressive.contains("/proc/self/maps") && aggressive.contains("frida") && aggressive.contains("dump"), "aggressive native protection must add stricter instrumentation and dump probes")
    }

    @Test
    fun native_artifact_cache_hit_requires_sealed_jni_abi_validation() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val readCacheBody = source.substringAfter("private fun readNativeArtifactCache(").substringBefore("private fun writeNativeArtifactCache")
        val writeCacheGate = source.substringAfter("if (!compileResult.fromCache &&").substringBefore("results.add")

        assertTrue(readCacheBody.contains("EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(bytes)"), "Cache hits must validate sealed JNI ABI before reuse")
        assertTrue(readCacheBody.contains("Files.deleteIfExists(cachePath)"), "Invalid cache entries must be discarded before recompilation")
        assertTrue(writeCacheGate.contains("EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(rawBytes)"), "Only ABI-valid native artifacts should be written to cache")
    }


    private fun parseCByteArray(source: String, name: String): ByteArray {
        val pattern = Regex("static const unsigned char $name\\[(?:\\d+)?] = \\{ ([^}]*) };")
        val values = pattern.find(source)?.groupValues?.get(1)
            ?: error("Missing C byte array $name")
        return values.split(",")
            .map { token -> token.trim().removePrefix("0x").removeSuffix("u").toInt(16).toByte() }
            .toByteArray()
    }

    private fun parseNativeSecretSlots(source: String): List<ByteArray> {
        val table = Regex("""(?s)static const unsigned char js_vbc4_native_secret_slots\[\d+]\[32] = \{\s*(.*?)\s*};""")
            .find(source)?.groupValues?.get(1)
            ?: error("Missing native secret slot table")
        return Regex("""\{([^}]*)}""").findAll(table)
            .map { match ->
                match.groupValues[1].split(",")
                    .map { token -> token.trim().removePrefix("0x").removeSuffix("u").toInt(16).toByte() }
                    .toByteArray()
            }
            .toList()
    }

    private fun reconstructNativeBuildKey(source: String): ByteArray {
        val slots = parseNativeSecretSlots(source)
        val slotOrder = Regex("""#define JS_VBC4_BUILD_KEY_SLOT_(\d+) (\d+)""").findAll(source)
            .toList()
            .sortedBy { it.groupValues[1].toInt() }
            .map { it.groupValues[2].toInt() }
            .toList()
        require(slotOrder.isNotEmpty()) { "Missing native build key slot order" }
        val out = ByteArray(VBC4_MASTER_KEY_SIZE)
        for (slotIndex in slotOrder) {
            val slot = slots[slotIndex]
            for (index in out.indices) out[index] = (out[index].toInt() xor slot[index].toInt()).toByte()
        }
        return out
    }

    private fun cBytesForTest(bytes: ByteArray): String = bytes.joinToString(", ") { byte ->
        "0x%02Xu".format(byte.toInt() and 0xFF)
    }


}

private fun assertNativeMaxReverseEvidenceReportCoversReleaseGate(reportText: String) {
    assertTrue(reportText.contains("Protocol profile: max-payload-zstd-chunk-v4-bogus-metadata"), "reverse evidence must record the max payload protocol profile")
    assertTrue(reportText.contains("Windows/Linux loader profile:"), "reverse evidence must record the real Windows/Linux loader profile boundary")
    assertTrue(reportText.contains(NativeRecompilationTransforms.nativeShellLoaderProfileForTest("windows-x64")), "reverse evidence must record the current Windows loader profile")
    assertTrue(reportText.contains(NativeRecompilationTransforms.nativeShellLoaderProfileForTest("linux-x64")), "reverse evidence must record the current Linux loader profile")
    assertTrue(reportText.contains("macOS profile: Mach-O parser and metadata validation with explicit fail-closed anonymous execution boundary"), "reverse evidence must keep macOS scoped to parser metadata and fail-closed evidence")
    assertTrue(reportText.contains("- native_entry_count: 4"), "reverse evidence must cover all four platform native entries")
    assertTrue(reportText.contains("- outer_stub_entry_count: 4"), "reverse evidence must prove all four packaged natives are max outer stubs")
    assertTrue(reportText.contains("- standard_overlay_entry_count: 0"), "reverse evidence must not accept standard overlay artifacts as max shell evidence")
    listOf("linux-x64", "windows-x64", "macos-x64", "macos-arm64").forEach { platform ->
        assertTrue(reportText.contains("platform=$platform"), "reverse evidence must list packaged native entry for $platform")
        val section = reportSection(reportText, "## $platform")
        assertTrue(section.contains("marker.JS_NATIVE_MAX_STUB_V1: 1"), "$platform reverse evidence must prove exactly one max stub marker")
        assertTrue(section.contains("marker.JS_NATIVE_MAX_PAYLOAD_V1: 1"), "$platform reverse evidence must prove exactly one max payload marker")
        assertTrue(section.contains("marker.JS_NATIVE_SHELL_LOADER_V1: 0"), "$platform reverse evidence must exclude standard overlay marker")
        assertTrue(section.contains("sensitive_plaintext_hits: none"), "$platform reverse evidence must record no sensitive plaintext hits")
        assertTrue(section.contains("suspicious_printable_tokens: none"), "$platform reverse evidence must record no suspicious printable tokens")
    }
    listOf("linux-x64", "windows-x64").forEach { platform ->
        val section = reportSection(reportText, "## $platform")
        assertTrue(section.contains("sampled_high_entropy_inner_plaintext_present: false"), "$platform max stub must not expose sampled high-entropy inner plaintext")
    }
    listOf("macos-x64", "macos-arm64").forEach { platform ->
        val section = reportSection(reportText, "## $platform")
        assertTrue(section.contains("marker.JS_MACHO_ANON_EXEC_FAIL_CLOSED_V1: 1"), "$platform must record explicit Mach-O fail-closed marker")
        assertTrue(section.contains("macho.segment_count:"), "$platform must record Mach-O segment metadata")
        assertTrue(section.contains("macho.has_text_segment: true"), "$platform must record __TEXT segment validation evidence")
        assertTrue(section.contains("macho.has_linkedit_segment: true"), "$platform must record __LINKEDIT segment validation evidence")
        assertTrue(section.contains("macho.has_dyld_info: true"), "$platform must record dyld info validation evidence")
        assertTrue(section.contains("macho.dyld_ranges_valid: true"), "$platform must record dyld rebase/bind/weak-bind/lazy-bind/export ranges as in-bounds")
        assertTrue(section.contains("macho.export_trie_contains_jni_onload: true"), "$platform must record export trie JNI_OnLoad evidence")
        assertTrue(section.contains("macho.loader_requires_native_abi_table: true"), "$platform must record loader-side native ABI table validation evidence")
        assertTrue(section.contains("fail_closed_reason:"), "$platform must document the Mach-O anonymous execution boundary")
    }

    val toolSection = reportSection(reportText, "## reverse-tool-output-evidence")
    listOf("linux-x64", "windows-x64", "macos-x64", "macos-arm64").forEach { platform ->
        val platformToolSection = reportSection(toolSection, "### $platform")
        assertTrue(platformToolSection.contains("strings.exit_code: 0"), "$platform external strings evidence must be captured")
        assertTrue(platformToolSection.contains("strings.forbidden_hits: none"), "$platform external strings evidence must not expose forbidden tokens")
    }
    val linuxToolSection = reportSection(toolSection, "### linux-x64")
    listOf("readelf", "nm").forEach { tool ->
        assertTrue(linuxToolSection.contains("$tool.exit_code: 0"), "Linux external $tool evidence must be captured")
        assertTrue(linuxToolSection.contains("$tool.contains_JNI_OnLoad: true"), "Linux external $tool evidence must preserve minimal JNI load surface")
        assertTrue(linuxToolSection.contains("$tool.forbidden_hits: none"), "Linux external $tool evidence must not expose forbidden tokens")
    }
    val windowsToolSection = reportSection(toolSection, "### windows-x64")
    assertTrue(
        windowsToolSection.contains("pe-objdump.exit_code: 0") || windowsToolSection.contains("pe-objdump: unavailable"),
        "Windows PE external structured evidence must be captured or explicitly recorded as unavailable",
    )
    if (windowsToolSection.contains("pe-objdump.exit_code: 0")) {
        assertTrue(windowsToolSection.contains("pe-objdump.contains_pe32_plus: true"), "Windows PE objdump evidence must identify PE32+")
        assertTrue(windowsToolSection.contains("pe-objdump.contains_dll: true"), "Windows PE objdump evidence must identify DLL characteristics")
        assertTrue(windowsToolSection.contains("pe-objdump.contains_export_directory: true"), "Windows PE objdump evidence must identify export directory")
        assertTrue(windowsToolSection.contains("pe-objdump.forbidden_hits: none"), "Windows PE objdump evidence must not expose forbidden tokens")
    }
}

private fun reportSection(reportText: String, heading: String): String {
    val start = reportText.indexOf(heading)
    assertTrue(start >= 0, "Missing report section: $heading")
    val next = reportText.indexOf("\n## ", start + heading.length)
    return if (next >= 0) reportText.substring(start, next) else reportText.substring(start)
}

private fun resolveSource(relativePath: String): java.nio.file.Path {
    val direct = java.nio.file.Path.of(relativePath)
    if (java.nio.file.Files.exists(direct)) return direct
    return java.nio.file.Path.of("core-engine").resolve(relativePath)
}

private fun workspaceRootForReports(): java.nio.file.Path {
    val cwd = java.nio.file.Path.of("").toAbsolutePath().normalize()
    return if (cwd.fileName?.toString() == "core-engine") cwd.parent else cwd
}

private fun decryptNativeSecret(encrypted: ByteArray, key: ByteArray, iv: ByteArray, index: Int): String {
    val counter = iv.copyOf()
    var carry = index
    var pos = counter.lastIndex
    while (pos >= 0 && carry != 0) {
        val total = (counter[pos].toInt() and 0xFF) + (carry and 0xFF)
        counter[pos] = total.toByte()
        carry = (carry ushr 8) + (total ushr 8)
        pos--
    }
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(counter))
    return cipher.doFinal(encrypted).toString(Charsets.UTF_8)
}

private fun ByteArray.containsAscii(value: String): Boolean {
    val needle = value.toByteArray(Charsets.US_ASCII)
    if (needle.isEmpty() || needle.size > size) return false
    return indices.any { start ->
        start <= size - needle.size && needle.indices.all { offset -> this[start + offset] == needle[offset] }
    }
}

private fun ByteArray.countAsciiOccurrences(value: String): Int {
    val needle = value.toByteArray(Charsets.US_ASCII)
    if (needle.isEmpty() || needle.size > size) return 0
    var count = 0
    var start = 0
    while (start <= size - needle.size) {
        var match = true
        for (offset in needle.indices) {
            if (this[start + offset] != needle[offset]) {
                match = false
                break
            }
        }
        if (match) {
            count++
            start += needle.size
        } else {
            start++
        }
    }
    return count
}

private fun assertMaxStubReverseEvidence(bytes: ByteArray, platform: String) {
    val forbiddenPlaintext = listOf(
        "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeExecuteVmResource",
        "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeDecryptString",
        "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeDeriveClassEncryptionKey",
        "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper",
        "nativeExecuteVmResource",
        "nativeDecryptString",
        "nativeDeriveClassEncryptionKey",
        "nativeRegisterVmResource",
        "nativePreloadVmResource",
        "js_vm_execute",
        "js_vm_resource_decode",
        "js_protected_section_unseal_now",
    )
    forbiddenPlaintext.forEach { value ->
        assertFalse(bytes.containsAscii(value), "$platform max outer stub must not expose inner helper/native symbol plaintext: $value")
    }
    assertTrue(bytes.countAsciiOccurrences("JNI_OnLoad") >= 1, "$platform max outer stub must expose the JNI_OnLoad load surface")
    assertTrue(bytes.countAsciiOccurrences("JS_NATIVE_MAX_PAYLOAD_V1") == 1, "$platform max outer stub should carry exactly one authenticated payload marker")
}

private fun appendJarNativeEntryEvidence(
    report: StringBuilder,
    outerResults: List<NativeRecompilationTransforms.RecompiledNative>,
) {
    val nativeEntries = outerResults.map { result -> "META-INF/js-native/${result.libName}" }
    assertEquals(nativeEntries.size, nativeEntries.toSet().size, "max outer native resources must have unique JAR entries")
    assertTrue(nativeEntries.isNotEmpty(), "reverse evidence must include max outer native JAR entries")
    assertTrue(
        outerResults.all { result ->
            result.bytes.containsAscii("JS_NATIVE_MAX_STUB_V1") &&
                result.bytes.containsAscii("JS_NATIVE_MAX_PAYLOAD_V1") &&
                !result.bytes.containsAscii("JS_NATIVE_SHELL_LOADER_V1")
        },
        "all reportable JAR native resources must be max outer stubs, not standard overlays",
    )

    report.appendLine("## jar-native-entry-evidence")
    report.appendLine()
    report.appendLine("- native_entry_count: ${nativeEntries.size}")
    report.appendLine("- outer_stub_entry_count: ${outerResults.count { it.bytes.containsAscii("JS_NATIVE_MAX_STUB_V1") && it.bytes.containsAscii("JS_NATIVE_MAX_PAYLOAD_V1") }}")
    report.appendLine("- standard_overlay_entry_count: ${outerResults.count { it.bytes.containsAscii("JS_NATIVE_SHELL_LOADER_V1") }}")
    nativeEntries.zip(outerResults).forEach { (entry, result) ->
        report.appendLine("- entry: $entry platform=${result.platform} sha256=${sha256Hex(result.bytes)} size=${result.bytes.size}")
    }
    report.appendLine()
}

private fun appendReverseToolAvailability(report: StringBuilder) {
    val tools = listOf("strings", "llvm-strings", "readelf", "llvm-readelf", "nm", "llvm-nm", "dumpbin")
    report.appendLine("## reverse-tool-availability")
    report.appendLine()
    tools.forEach { tool ->
        report.appendLine("- $tool: ${findExecutableForReport(tool) ?: "unavailable"}")
    }
    report.appendLine("- wsl.strings: ${if (wslToolAvailable("strings")) "available" else "unavailable"}")
    report.appendLine("- wsl.readelf: ${if (wslToolAvailable("readelf")) "available" else "unavailable"}")
    report.appendLine("- wsl.nm: ${if (wslToolAvailable("nm")) "available" else "unavailable"}")
    report.appendLine()
}

private fun appendReverseToolOutputEvidence(
    report: StringBuilder,
    reportDir: java.nio.file.Path,
    outerResults: List<NativeRecompilationTransforms.RecompiledNative>,
) {
    val inputDir = reportDir.resolve("tool-inputs")
    java.nio.file.Files.createDirectories(inputDir)
    report.appendLine("## reverse-tool-output-evidence")
    report.appendLine()
    report.appendLine("Scope: best-effort external reverse-tool summaries. Missing tools are recorded as unavailable; internal byte-level assertions above remain mandatory.")
    report.appendLine()

    outerResults.sortedBy { it.platform }.forEach { result ->
        val artifactPath = inputDir.resolve(result.libName)
        java.nio.file.Files.write(artifactPath, result.bytes)
        report.appendLine("### ${result.platform}")
        report.appendLine()
        appendStringsToolEvidence(report, artifactPath, result.platform)
        if (result.platform == "linux-x64") {
            appendStructuredToolEvidence(report, "readelf", listOf("-h", "-Ws"), artifactPath, result.platform)
            appendStructuredToolEvidence(report, "nm", listOf("-D"), artifactPath, result.platform)
        }
        if (result.platform == "windows-x64") {
            appendWindowsPeToolEvidence(report, artifactPath, result.platform)
        }
        report.appendLine()
    }
}

private fun appendStringsToolEvidence(report: StringBuilder, artifactPath: java.nio.file.Path, platform: String) {
    val result = runReverseTool("strings", listOf("-a", artifactPath.toString()), artifactPath)
    if (result == null) {
        report.appendLine("- strings: unavailable")
        return
    }
    val lines = result.output.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.take(400).toList()
    val forbiddenHits = reverseEvidenceForbiddenTokens().filter { token -> lines.any { it.contains(token) } }
    assertTrue(forbiddenHits.isEmpty(), "$platform external strings output must not expose forbidden inner helper/native tokens: $forbiddenHits")
    report.appendLine("- strings.exit_code: ${result.exitCode}")
    report.appendLine("- strings.line_count_sampled: ${lines.size}")
    report.appendLine("- strings.forbidden_hits: ${if (forbiddenHits.isEmpty()) "none" else forbiddenHits.joinToString()}")
    report.appendLine("- strings.sample: ${singleLineToolOutput(lines.take(8).joinToString()).take(360)}")
}

private fun appendStructuredToolEvidence(
    report: StringBuilder,
    tool: String,
    args: List<String>,
    artifactPath: java.nio.file.Path,
    platform: String,
) {
    val result = runReverseTool(tool, args + artifactPath.toString(), artifactPath)
    if (result == null) {
        report.appendLine("- $tool: unavailable")
        return
    }
    val output = result.output.take(12_000)
    val forbiddenHits = reverseEvidenceForbiddenTokens().filter { token -> output.contains(token) }
    assertTrue(forbiddenHits.isEmpty(), "$platform external $tool output must not expose forbidden inner helper/native tokens: $forbiddenHits")
    report.appendLine("- $tool.exit_code: ${result.exitCode}")
    report.appendLine("- $tool.contains_JNI_OnLoad: ${output.contains("JNI_OnLoad")}")
    report.appendLine("- $tool.forbidden_hits: ${if (forbiddenHits.isEmpty()) "none" else forbiddenHits.joinToString()}")
    report.appendLine("- $tool.sample: ${singleLineToolOutput(output).take(360)}")
}

private fun appendWindowsPeToolEvidence(report: StringBuilder, artifactPath: java.nio.file.Path, platform: String) {
    val result = runPeObjdump(artifactPath)
    if (result == null) {
        report.appendLine("- pe-objdump: unavailable")
        return
    }
    val output = result.output.take(12_000)
    val forbiddenHits = reverseEvidenceForbiddenTokens().filter { token -> output.contains(token) }
    assertTrue(forbiddenHits.isEmpty(), "$platform external PE objdump output must not expose forbidden inner helper/native tokens: $forbiddenHits")
    report.appendLine("- pe-objdump.exit_code: ${result.exitCode}")
    report.appendLine("- pe-objdump.contains_pe32_plus: ${output.contains("PE32+")}")
    report.appendLine("- pe-objdump.contains_dll: ${output.contains("DLL")}")
    report.appendLine("- pe-objdump.contains_export_directory: ${output.contains("Export Directory")}")
    report.appendLine("- pe-objdump.contains_import_directory: ${output.contains("Import Directory")}")
    report.appendLine("- pe-objdump.contains_base_relocation_directory: ${output.contains("Base Relocation Directory")}")
    report.appendLine("- pe-objdump.contains_tls_directory: ${output.contains("Thread Storage Directory")}")
    report.appendLine("- pe-objdump.forbidden_hits: ${if (forbiddenHits.isEmpty()) "none" else forbiddenHits.joinToString()}")
    report.appendLine("- pe-objdump.sample: ${singleLineToolOutput(output).take(360)}")
}

private fun reverseEvidenceForbiddenTokens(): List<String> = listOf(
    "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeExecuteVmResource",
    "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeDecryptString",
    "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeDeriveClassEncryptionKey",
    "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper",
    "nativeExecuteVmResource",
    "nativeDecryptString",
    "nativeDeriveClassEncryptionKey",
    "nativeRegisterVmResource",
    "nativePreloadVmResource",
    "js_vm_execute",
    "js_vm_resource_decode",
    "js_protected_section_unseal_now",
)

private data class ReverseToolResult(val exitCode: Int, val output: String)

private fun runReverseTool(tool: String, args: List<String>, artifactPath: java.nio.file.Path): ReverseToolResult? {
    findExecutableForReport(tool)?.let { executable ->
        return runProcessForReverseEvidence(listOf(executable) + args)
    }
    val wslPath = windowsPathToWslPath(artifactPath) ?: return null
    if (!wslToolAvailable(tool)) return null
    val wslArgs = args.map { arg -> if (arg == artifactPath.toString()) wslPath else arg }
    return runProcessForReverseEvidence(listOf("wsl.exe", "-d", "kali-linux", "--", tool) + wslArgs)
}

private fun runPeObjdump(artifactPath: java.nio.file.Path): ReverseToolResult? {
    val wslPath = windowsPathToWslPath(artifactPath)
    if (wslPath != null && wslToolAvailable("x86_64-w64-mingw32-objdump")) {
        return runProcessForReverseEvidence(listOf("wsl.exe", "-d", "kali-linux", "--", "x86_64-w64-mingw32-objdump", "-p", wslPath))
    }
    findExecutableForReport("llvm-objdump")?.let { executable ->
        return runProcessForReverseEvidence(listOf(executable, "-p", artifactPath.toString()))
    }
    findExecutableForReport("objdump")?.let { executable ->
        return runProcessForReverseEvidence(listOf(executable, "-p", artifactPath.toString()))
    }
    return null
}

private fun runProcessForReverseEvidence(command: List<String>): ReverseToolResult? = try {
    val process = ProcessBuilder(command).redirectErrorStream(true).start()
    val output = java.io.ByteArrayOutputStream()
    val reader = kotlin.concurrent.thread(start = true, isDaemon = true, name = "javashroud-reverse-tool-output") {
        process.inputStream.use { input -> input.copyTo(output) }
    }
    val finished = process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)
    if (!finished) {
        process.destroyForcibly()
        process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
        reader.join(1_000)
        null
    } else {
        reader.join(5_000)
        ReverseToolResult(process.exitValue(), output.toString(Charsets.UTF_8))
    }
} catch (_: Exception) {
    null
}

private fun wslToolAvailable(tool: String): Boolean = try {
    val process = ProcessBuilder("wsl.exe", "-d", "kali-linux", "--", "bash", "-lc", "command -v ${shellSingleQuote(tool)} >/dev/null 2>&1")
        .redirectErrorStream(true)
        .start()
    process.waitFor(8, java.util.concurrent.TimeUnit.SECONDS) && process.exitValue() == 0
} catch (_: Exception) {
    false
}

private fun windowsPathToWslPath(path: java.nio.file.Path): String? {
    val normalized = path.toAbsolutePath().normalize().toString().replace('\\', '/')
    if (normalized.length < 3 || normalized[1] != ':' || normalized[2] != '/') return null
    val drive = normalized[0].lowercaseChar()
    return "/mnt/$drive/${normalized.substring(3)}"
}

private fun shellSingleQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

private fun singleLineToolOutput(value: String): String = value
    .replace('\u0000', ' ')
    .replace('\r', ' ')
    .replace('\n', ' ')
    .replace(Regex("\\s+"), " ")
    .trim()

private fun findExecutableForReport(tool: String): String? {
    val pathExts = (System.getenv("PATHEXT") ?: ".COM;.EXE;.BAT;.CMD")
        .split(';')
        .filter { it.isNotBlank() }
    val candidates = if (tool.contains('.')) {
        listOf(tool)
    } else {
        listOf(tool) + pathExts.map { tool + it.lowercase() } + pathExts.map { tool + it.uppercase() }
    }
    return (System.getenv("PATH") ?: "")
        .split(java.io.File.pathSeparatorChar)
        .asSequence()
        .filter { it.isNotBlank() }
        .flatMap { dir -> candidates.asSequence().map { name -> java.nio.file.Path.of(dir, name) } }
        .firstOrNull { java.nio.file.Files.isRegularFile(it) && java.nio.file.Files.isExecutable(it) }
        ?.toAbsolutePath()
        ?.normalize()
        ?.toString()
}

private fun appendReverseEvidenceReport(
    report: StringBuilder,
    platform: String,
    outerBytes: ByteArray,
    innerBytes: ByteArray?,
    rawHeaderComparable: Boolean,
    failClosedReason: String?,
) {
    val forbiddenPlaintext = listOf(
        "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeExecuteVmResource",
        "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeDecryptString",
        "Java_io_github_hht0rro_javashroud_transforms_protection_JniMicrokernelHelper_nativeDeriveClassEncryptionKey",
        "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper",
        "nativeExecuteVmResource",
        "nativeDecryptString",
        "nativeDeriveClassEncryptionKey",
        "nativeRegisterVmResource",
        "nativePreloadVmResource",
        "js_vm_execute",
        "js_vm_resource_decode",
        "js_protected_section_unseal_now",
    )
    val sensitiveHits = forbiddenPlaintext.filter { outerBytes.containsAscii(it) }
    val rawHeaderPresent = innerBytes?.takeIf { rawHeaderComparable }?.let { inner ->
        outerBytes.indexOfSlice(inner.copyOfRange(0, minOf(96, inner.size))) >= 0
    }
    val sampledHighEntropyPlaintextPresent = innerBytes?.let { inner ->
        containsAnyHighEntropyPlaintextSlice(haystack = outerBytes, needleSource = inner)
    }
    val printableTokens = printableAsciiTokens(outerBytes)
    val suspiciousPrintableTokens = printableTokens.filter { token ->
        forbiddenPlaintext.any { forbidden -> token.contains(forbidden) } || token.contains("JniMicrokernelHelper")
    }

    report.appendLine("## $platform")
    report.appendLine()
    report.appendLine("- artifact_size: ${outerBytes.size}")
    report.appendLine("- sha256: ${sha256Hex(outerBytes)}")
    report.appendLine("- file_magic: ${nativeFileMagic(outerBytes)}")
    report.appendLine("- marker.JNI_OnLoad: ${outerBytes.countAsciiOccurrences("JNI_OnLoad")}")
    report.appendLine("- marker.JNI_OnUnload: ${outerBytes.countAsciiOccurrences("JNI_OnUnload")}")
    report.appendLine("- marker.JS_NATIVE_MAX_STUB_V1: ${outerBytes.countAsciiOccurrences("JS_NATIVE_MAX_STUB_V1")}")
    report.appendLine("- marker.JS_NATIVE_MAX_PAYLOAD_V1: ${outerBytes.countAsciiOccurrences("JS_NATIVE_MAX_PAYLOAD_V1")}")
    report.appendLine("- marker.JS_NATIVE_SHELL_LOADER_V1: ${outerBytes.countAsciiOccurrences("JS_NATIVE_SHELL_LOADER_V1")}")
    report.appendLine("- marker.JS_MACHO_ANON_EXEC_FAIL_CLOSED_V1: ${outerBytes.countAsciiOccurrences("JS_MACHO_ANON_EXEC_FAIL_CLOSED_V1")}")
    report.appendLine("- sensitive_plaintext_hits: ${if (sensitiveHits.isEmpty()) "none" else sensitiveHits.joinToString()}")
    report.appendLine("- printable_token_count_len6: ${printableTokens.size}")
    report.appendLine("- suspicious_printable_tokens: ${if (suspiciousPrintableTokens.isEmpty()) "none" else suspiciousPrintableTokens.take(8).joinToString()}")
    report.appendLine("- printable_token_sample: ${printableTokens.take(12).joinToString { it.take(96) }}")
    report.appendLine("- inner_raw_header_present: ${rawHeaderPresent ?: "not-applicable"}")
    report.appendLine("- sampled_high_entropy_inner_plaintext_present: ${sampledHighEntropyPlaintextPresent ?: "not-applicable"}")
    parseMachO64Metadata(outerBytes)?.let { macho ->
        report.appendLine("- macho.cpu_type: ${macho.cpuType}")
        report.appendLine("- macho.file_type: ${macho.fileType}")
        report.appendLine("- macho.load_command_count: ${macho.loadCommandCount}")
        report.appendLine("- macho.segment_count: ${macho.segmentCount}")
        report.appendLine("- macho.section_count: ${macho.sectionCount}")
        report.appendLine("- macho.initializer_section_count: ${macho.initializerSectionCount}")
        report.appendLine("- macho.has_text_segment: ${macho.hasTextSegment}")
        report.appendLine("- macho.has_linkedit_segment: ${macho.hasLinkeditSegment}")
        report.appendLine("- macho.has_dyld_info: ${macho.hasDyldInfo}")
        report.appendLine("- macho.dyld_ranges_valid: ${macho.dyldRangesValid}")
        report.appendLine("- macho.export_trie_size: ${macho.exportTrieSize}")
        report.appendLine("- macho.export_trie_contains_jni_onload: ${macho.exportTrieContainsJniOnLoad}")
        report.appendLine("- macho.loader_requires_native_abi_table: ${outerBytes.containsAscii("_js_native_abi_table_v1")}")
    }
    if (failClosedReason != null) {
        report.appendLine("- fail_closed_reason: $failClosedReason")
    }
    report.appendLine()
}

private data class MachO64Metadata(
    val cpuType: Int,
    val fileType: Int,
    val loadCommandCount: Int,
    val segmentCount: Int,
    val sectionCount: Int,
    val initializerSectionCount: Int,
    val hasTextSegment: Boolean,
    val hasLinkeditSegment: Boolean,
    val hasDyldInfo: Boolean,
    val dyldRangesValid: Boolean,
    val exportTrieSize: Long,
    val exportTrieContainsJniOnLoad: Boolean,
)

private fun parseMachO64Metadata(bytes: ByteArray): MachO64Metadata? {
    if (bytes.size < 32 || readUInt32Le(bytes, 0) != 0xFEEDFACFu) return null
    val cpuType = readInt32Le(bytes, 4)
    val fileType = readInt32Le(bytes, 12)
    val ncmds = readUInt32Le(bytes, 16).toInt()
    val sizeofcmds = readUInt32Le(bytes, 20).toLong()
    if (!rangeWithin(bytes.size, 32L, sizeofcmds)) return null

    var offset = 32
    val commandEnd = 32L + sizeofcmds
    var segmentCount = 0
    var sectionCount = 0
    var initializerSectionCount = 0
    var hasText = false
    var hasLinkedit = false
    var hasDyldInfo = false
    var dyldRangesValid = false
    var exportTrieSize = 0L
    var exportTrieContainsJniOnLoad = false

    repeat(ncmds) {
        if (offset + 8 > bytes.size || offset.toLong() + 8L > commandEnd) return null
        val cmd = readUInt32Le(bytes, offset)
        val cmdSize = readUInt32Le(bytes, offset + 4).toInt()
        if (cmdSize < 8 || offset.toLong() + cmdSize.toLong() > commandEnd || offset + cmdSize > bytes.size) return null
        if (cmd == 0x19u && cmdSize >= 72) {
            val segName = readFixedAscii(bytes, offset + 8, 16)
            val fileOff = readUInt64Le(bytes, offset + 40)
            val fileSize = readUInt64Le(bytes, offset + 48)
            val nsects = readUInt32Le(bytes, offset + 64).toInt()
            if (!rangeWithin(bytes.size, fileOff, fileSize)) return null
            if (nsects > 0 && 72L + nsects.toLong() * 80L > cmdSize.toLong()) return null
            if (segName == "__TEXT") hasText = true
            if (segName == "__LINKEDIT") hasLinkedit = true
            segmentCount++
            sectionCount += nsects
            var sectionOffset = offset + 72
            repeat(nsects) {
                val sectionFileOffset = readUInt32Le(bytes, sectionOffset + 48).toLong()
                val sectionSize = readUInt64Le(bytes, sectionOffset + 40)
                val sectionRelocOffset = readUInt32Le(bytes, sectionOffset + 56).toLong()
                val sectionRelocCount = readUInt32Le(bytes, sectionOffset + 60).toLong()
                val sectionFlags = readUInt32Le(bytes, sectionOffset + 64)
                if (sectionFileOffset != 0L && sectionSize != 0L && !rangeWithin(bytes.size, sectionFileOffset, sectionSize)) return null
                if (sectionRelocCount != 0L && !rangeWithin(bytes.size, sectionRelocOffset, sectionRelocCount * 8L)) return null
                if ((sectionFlags and 0xFFu) == 0x9u) initializerSectionCount++
                sectionOffset += 80
            }
        } else if ((cmd == 0x22u || cmd == 0x80000022u) && cmdSize >= 48) {
            hasDyldInfo = true
            val rebaseOff = readUInt32Le(bytes, offset + 8).toLong()
            val rebaseSize = readUInt32Le(bytes, offset + 12).toLong()
            val bindOff = readUInt32Le(bytes, offset + 16).toLong()
            val bindSize = readUInt32Le(bytes, offset + 20).toLong()
            val weakBindOff = readUInt32Le(bytes, offset + 24).toLong()
            val weakBindSize = readUInt32Le(bytes, offset + 28).toLong()
            val lazyBindOff = readUInt32Le(bytes, offset + 32).toLong()
            val lazyBindSize = readUInt32Le(bytes, offset + 36).toLong()
            val exportOff = readUInt32Le(bytes, offset + 40).toLong()
            exportTrieSize = readUInt32Le(bytes, offset + 44).toLong()
            dyldRangesValid = rangeWithin(bytes.size, rebaseOff, rebaseSize) &&
                rangeWithin(bytes.size, bindOff, bindSize) &&
                rangeWithin(bytes.size, weakBindOff, weakBindSize) &&
                rangeWithin(bytes.size, lazyBindOff, lazyBindSize) &&
                rangeWithin(bytes.size, exportOff, exportTrieSize)
            if (dyldRangesValid && exportTrieSize > 0) {
                val exportBytes = bytes.copyOfRange(exportOff.toInt(), (exportOff + exportTrieSize).toInt())
                exportTrieContainsJniOnLoad = machoExportTrieHasSymbol(exportBytes, "_JNI_OnLoad") ||
                    machoExportTrieHasSymbol(exportBytes, "JNI_OnLoad")
            }
        }
        offset += cmdSize
    }
    return MachO64Metadata(
        cpuType = cpuType,
        fileType = fileType,
        loadCommandCount = ncmds,
        segmentCount = segmentCount,
        sectionCount = sectionCount,
        initializerSectionCount = initializerSectionCount,
        hasTextSegment = hasText,
        hasLinkeditSegment = hasLinkedit,
        hasDyldInfo = hasDyldInfo,
        dyldRangesValid = dyldRangesValid,
        exportTrieSize = exportTrieSize,
        exportTrieContainsJniOnLoad = exportTrieContainsJniOnLoad,
    )
}

private fun rangeWithin(totalSize: Int, offset: Long, size: Long): Boolean =
    offset >= 0 && size >= 0 && offset <= totalSize.toLong() && size <= totalSize.toLong() - offset

private fun machoExportTrieHasSymbol(bytes: ByteArray, symbol: String): Boolean {
    val stack = ArrayDeque<Pair<Int, String>>()
    val visited = mutableSetOf<Int>()
    stack.add(0 to "")
    while (stack.isNotEmpty()) {
        val (nodeOffset, prefix) = stack.removeLast()
        if (nodeOffset !in bytes.indices || !visited.add(nodeOffset)) continue
        val terminalSizeResult = readUleb128(bytes, nodeOffset) ?: return false
        val terminalSize = terminalSizeResult.first
        var cursor = terminalSizeResult.second
        if (!rangeWithin(bytes.size, cursor.toLong(), terminalSize)) return false
        if (terminalSize > 0 && prefix == symbol) return true
        cursor += terminalSize.toInt()
        if (cursor !in bytes.indices) return false
        val childCount = bytes[cursor].toInt() and 0xFF
        cursor++
        repeat(childCount) {
            val edgeEnd = bytes.indexOfByte(0, cursor)
            if (edgeEnd < 0) return false
            val edge = bytes.copyOfRange(cursor, edgeEnd).toString(Charsets.US_ASCII)
            cursor = edgeEnd + 1
            val childOffsetResult = readUleb128(bytes, cursor) ?: return false
            cursor = childOffsetResult.second
            val childOffset = childOffsetResult.first
            if (childOffset < 0 || childOffset > Int.MAX_VALUE || childOffset >= bytes.size) return false
            stack.add(childOffset.toInt() to prefix + edge)
        }
    }
    return false
}

private fun ByteArray.indexOfByte(value: Int, startIndex: Int): Int {
    for (index in startIndex until size) {
        if ((this[index].toInt() and 0xFF) == value) return index
    }
    return -1
}

private fun readUleb128(bytes: ByteArray, offset: Int): Pair<Long, Int>? {
    var value = 0L
    var shift = 0
    var cursor = offset
    while (cursor in bytes.indices && shift < 63) {
        val current = bytes[cursor].toInt() and 0xFF
        value = value or ((current and 0x7F).toLong() shl shift)
        cursor++
        if ((current and 0x80) == 0) return value to cursor
        shift += 7
    }
    return null
}

private fun readFixedAscii(bytes: ByteArray, offset: Int, length: Int): String {
    val end = (offset until offset + length).firstOrNull { bytes[it] == 0.toByte() } ?: (offset + length)
    return bytes.copyOfRange(offset, end).toString(Charsets.US_ASCII)
}

private fun readInt32Le(bytes: ByteArray, offset: Int): Int = readUInt32Le(bytes, offset).toInt()

private fun readUInt32Le(bytes: ByteArray, offset: Int): UInt =
    ((bytes[offset].toUInt() and 0xFFu) or
        ((bytes[offset + 1].toUInt() and 0xFFu) shl 8) or
        ((bytes[offset + 2].toUInt() and 0xFFu) shl 16) or
        ((bytes[offset + 3].toUInt() and 0xFFu) shl 24))

private fun readUInt64Le(bytes: ByteArray, offset: Int): Long {
    var value = 0L
    for (index in 0 until 8) {
        value = value or ((bytes[offset + index].toLong() and 0xFFL) shl (index * 8))
    }
    return value
}

private fun sha256Hex(bytes: ByteArray): String =
    java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }

private fun nativeFileMagic(bytes: ByteArray): String = when {
    bytes.size >= 4 && bytes[0] == 0x7F.toByte() && bytes[1] == 'E'.code.toByte() && bytes[2] == 'L'.code.toByte() && bytes[3] == 'F'.code.toByte() -> "ELF"
    bytes.size >= 2 && bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte() -> "PE/COFF"
    bytes.size >= 4 && bytes[0] == 0xCF.toByte() && bytes[1] == 0xFA.toByte() && bytes[2] == 0xED.toByte() && bytes[3] == 0xFE.toByte() -> "Mach-O-64"
    bytes.size >= 4 && bytes[0] == 0xFE.toByte() && bytes[1] == 0xED.toByte() && bytes[2] == 0xFA.toByte() && bytes[3] == 0xCF.toByte() -> "Mach-O-64-BE"
    else -> "unknown"
}

private fun printableAsciiTokens(bytes: ByteArray, minLength: Int = 6): List<String> {
    val tokens = mutableListOf<String>()
    val current = StringBuilder()
    fun flush() {
        if (current.length >= minLength) tokens.add(current.toString())
        current.setLength(0)
    }
    for (byte in bytes) {
        val value = byte.toInt() and 0xFF
        if (value in 0x20..0x7E) {
            current.append(value.toChar())
        } else {
            flush()
        }
    }
    flush()
    return tokens.distinct().sorted()
}

private fun containsAnyHighEntropyPlaintextSlice(haystack: ByteArray, needleSource: ByteArray, sliceSize: Int = 512): Boolean {
    if (haystack.size < sliceSize || needleSource.size < sliceSize) return false
    var checked = 0
    var offset = 0
    val step = sliceSize
    while (offset + sliceSize <= needleSource.size && checked < 48) {
        val slice = needleSource.copyOfRange(offset, offset + sliceSize)
        if (slice.distinctByteCount() >= 64 && !slice.all { it.toInt() == 0 }) {
            checked++
            if (haystack.indexOfSlice(slice) >= 0) return true
        }
        offset += step
    }
    return false
}

private fun ByteArray.distinctByteCount(): Int {
    val seen = BooleanArray(256)
    var count = 0
    for (byte in this) {
        val value = byte.toInt() and 0xFF
        if (!seen[value]) {
            seen[value] = true
            count++
        }
    }
    return count
}

private fun ByteArray.indexOfSlice(needle: ByteArray): Int {
    if (needle.isEmpty()) return 0
    if (needle.size > size) return -1
    for (start in 0..(size - needle.size)) {
        var match = true
        for (index in needle.indices) {
            if (this[start + index] != needle[index]) {
                match = false
                break
            }
        }
        if (match) return start
    }
    return -1
}
