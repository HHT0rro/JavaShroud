package io.github.hht0rro.javashroud

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyAntiDumpProtection
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeHelperHardeningTest {
    @Test
    fun string_encryption_helper_uses_split_native_registration_and_fail_closed_java_layer() {
        val nativeSource = nativeRuntimeSources()
        val helperSource = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.java"))

        assertTrue(nativeSource.contains("jsn_r21"), "StringEncryptionHelper native decode entry must be implemented.")
        assertTrue(nativeSource.contains("jsn_r21") && nativeSource.contains("js_vbc4_aes_material") && nativeSource.contains("js_vbc4_hmac_sha256"), "String decode must use native AES-CTR with HMAC-derived key material.")
        assertTrue(
            nativeSource.contains("js_helper_owner(\"String\", \"Encryption\", \"\", \"Helper\")") &&
                nativeSource.contains("js_native_name(\"Decode\", \"String\", \"\")"),
            "StringEncryptionHelper registration must keep owner and method names split at registration time.",
        )
        assertFalse(
            nativeSource.contains("Java_io_github_hht0rro_javashroud_transforms_protection_StringEncryptionHelper"),
            "StringEncryptionHelper must not expose a traditional Java_* JNI export symbol.",
        )
        assertTrue(helperSource.contains("public static native byte[] nativeDecodeString(byte[] payload, int seed, int flags);"))
        assertTrue(!helperSource.contains("public static String decode("), "StringEncryptionHelper must not expose a Java string-decoder trampoline.")
        assertTrue(helperSource.contains("JniMicrokernelHelper.loadKernel"), "String helper must load through the JNI microkernel.")
        assertFalse(helperSource.contains("new String("), "StringEncryptionHelper must not construct Java strings around native decode bytes.")
        assertFalse(helperSource.contains("StandardCharsets"), "StringEncryptionHelper must not own charset conversion for native-decoded strings.")
        assertFalse(helperSource.contains("Base64"), "String helper must not retain legacy Base64 payload handling.")
    }
    @Test
    fun protection_helper_native_declarations_are_registered_without_exporting_traditional_jni_symbols() {
        val nativeSources = listOf(
            sourcePath("src/main/native/js_helpers.c"),
            sourcePath("src/main/native/js_kernel.c"),
            sourcePath("src/main/native/js_jni_runtime.c"),
        ).joinToString("\n") { Files.readString(it) }

        assertTrue(
            nativeSources.contains("JNIEXPORT jint JNICALL JNI_OnLoad"),
            "Native kernel must register helpers from JNI_OnLoad instead of relying on traditional JNI exports.",
        )
        assertTrue(
            !nativeSources.contains("Java_io_github_hht0rro_javashroud_transforms_protection_"),
            "Native source symbols must not expose traditional JavaShroud JNI names.",
        )
        assertTrue(
            nativeSources.contains("RegisterNatives") && nativeSources.contains("js_register_native_group"),
            "Native helpers must still be bound through JNI_OnLoad + RegisterNatives, with registration names built at runtime.",
        )
        for (fingerprint in listOf(
            "nativeExecuteVmResource",
            "nativeInstallRuntimeResourceKey",
            "nativePreloadRuntimeResources",
            "nativeCheckInstrumentation",
            "nativeCheckJvmTiAgents",
            "nativeCheckByteBuddy",
            "nativeGetVersion",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper",
        )) {
            assertTrue(
                !nativeSources.contains(fingerprint),
                "Native source must not retain fixed registration fingerprint '$fingerprint'.",
            )
        }
        assertTrue(
            !Files.readString(Path.of("src/main/native/build-native-kernel-linux.sh")).contains("Java_*"),
            "Linux native export script must not expose traditional Java_* JNI symbols.",
        )
        assertTrue(
            !Files.readString(Path.of("src/main/native/build-native-kernel-macos.sh")).contains("_Java_io_github"),
            "macOS native export script must not expose traditional Java_io_github JNI symbols.",
        )
    }

    @Test
    fun native_secret_table_decodes_core_jni_class_names_with_c_32bit_semantics() {
        val include = Files.readString(sourcePath("src/main/native/native_secrets.inc"))
        val seedMatch = Regex("""#define JS_SECRET_SEED (\d+)u""").find(include)
        assertTrue(seedMatch != null, "native_secrets.inc must declare JS_SECRET_SEED")
        val seed = seedMatch!!.groupValues[1].toUInt()

        assertEquals("java/lang/System", decodeNativeSecret(include, "SYSTEM_CLASS", seed))
        assertEquals("java/lang/Thread", decodeNativeSecret(include, "THREAD_CLASS", seed))
        assertEquals("java/lang/Runtime", decodeNativeSecret(include, "RUNTIME_CLASS", seed))
        assertEquals("java/lang/StackTraceElement", decodeNativeSecret(include, "STACK_TRACE_ELEMENT_CLASS", seed))
    }


    @Test
    fun native_runtime_defenses_skip_timing_sensitive_classes_before_clinit_injection() {
        val source = Files.readString(sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelTransforms.kt"))
        val checks = Regex("if \\(!matchedClassNames\\.contains\\(classArtifact\\.summary\\.internalName\\)\\) return@map classArtifact\\s+if \\(isJniLoaderTimingSensitiveClass\\(classArtifact\\.bytes\\)\\) return@map classArtifact")
            .findAll(source)
            .count()

        assertTrue(checks >= 5, "JNI loader and native runtime defenses must avoid injecting clinit work into timing-sensitive concurrent/lambda classes")
        assertTrue(source.contains("java/lang/Thread") && source.contains("java/util/concurrent/"),
            "Timing-sensitive detection must cover sleep and java.util.concurrent surfaces")
    }

    @Test
    fun anti_instrumentation_responses_have_distinct_native_semantics() {
        val nativeSource = nativeRuntimeSources()
        val responseBody = nativeFunctionBody(nativeSource, "js_runtime_guard_response(JNIEnv *env, const char *resp, const char *reason)")

        assertTrue(responseBody.contains("fprintf(stderr"), "log response must emit a native diagnostic")
        assertTrue(responseBody.contains("js_runtime_guard_degraded = 1"), "degrade response must set degraded native state")
        assertTrue(responseBody.contains("js_runtime_guard_strict_path = 1"), "switch-path response must select strict native path")
        assertTrue(responseBody.contains("throw_sec(env"), "refuse response must throw SecurityException")
        assertTrue(nativeSource.contains("jdwp") && nativeSource.contains("Instrumentation") && nativeSource.contains("mockito"), "standard/aggressive detection should cover debug and instrumentation traces")
    }

    @Test
    fun anti_dump_runtime_initialization_is_class_aware() {
        val transformSource = Files.readString(sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelTransforms.kt"))
        val helperSource = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/AntiDumpRuntimeHelper.java"))
        val nativeSource = nativeRuntimeSources()

        assertTrue(transformSource.contains("Type.getObjectType(ownerInternalName)"), "anti-dump transform must pass the protected owner class")
        assertTrue(helperSource.contains("nativeInitializeProtection(String protectionLevel, Class<?> ownerClass)"), "helper must expose class-aware native initialization")
        assertTrue(nativeSource.contains("(Ljava/lang/String;Ljava/lang/Class;)V") && nativeSource.contains("jsn_r4"), "JNI registration must bind the class-aware anti-dump overload")
    }

    @Test
    fun anti_dump_helpers_fail_closed_without_java_decode_fallbacks() {
        val runtimeHelper = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/AntiDumpRuntimeHelper.java"))
        val stringHelper = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/AntiDumpHelper.java"))

        assertTrue(runtimeHelper.contains("requires the sealed native kernel"), "jni-key-hold/full must reject when native is unavailable")
        assertTrue(runtimeHelper.contains("\"field-scramble\".equals(level)) return"), "field-scramble may retain Java-only field perturbation")
        assertFalse("Base64.getDecoder()" in stringHelper, "AntiDumpHelper must not keep Java Base64 decode fallback")
        assertFalse("new String(encodedBytes" in stringHelper, "AntiDumpHelper must not rebuild protected strings in Java when native is unavailable")
        assertTrue(stringHelper.contains("requires the sealed native kernel"), "AntiDumpHelper must fail closed on native absence")
    }

    @Test
    fun anti_dump_field_scramble_rewrites_string_field_accesses() {
        val internalName = "sample/AntiDumpFieldHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildAntiDumpFieldHost(internalName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "roundTrip", "(Ljava/lang/String;)Ljava/lang/String;", Opcodes.ACC_PUBLIC)),
                ),
            ),
        )

        val result = applyAntiDumpProtection(
            artifact = artifact,
            ruleMatches = listOf(RuleMatch(
                rule = RuleSpec(target = internalName, action = "anti-dump-protection"),
                selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
                matchedClassNames = listOf(internalName),
                matchedMembers = emptyList(),
            )),
            params = mapOf("protectionLevel" to "field-scramble"),
        )

        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex[internalName]!!.bytes).accept(node, ClassReader.SKIP_FRAMES)
        val helperCalls = node.methods.flatMap { method -> method.instructions.toArray().filterIsInstance<MethodInsnNode>() }
            .filter { it.owner.endsWith("AntiDumpRuntimeHelper") }
            .map { it.name }
            .toSet()

        assertTrue("scrambleString" in helperCalls, "PUTFIELD must scramble protected String field material")
        assertTrue("unscrambleString" in helperCalls, "GETFIELD must unscramble protected String field material")
    }

    private fun buildAntiDumpFieldHost(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        cw.visitField(Opcodes.ACC_PRIVATE, "secret", "Ljava/lang/String;", null, null).visitEnd()
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC, "roundTrip", "(Ljava/lang/String;)Ljava/lang/String;", null, null)
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitFieldInsn(Opcodes.PUTFIELD, internalName, "secret", "Ljava/lang/String;")
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitFieldInsn(Opcodes.GETFIELD, internalName, "secret", "Ljava/lang/String;")
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(2, 2)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
    @Test
    fun jni_vm_resource_execution_is_fail_closed_without_java_forwarder_fallback() {
        val helperBytes = loadJniMicrokernelHelperBytes()
        val executeCalls = mutableListOf<Pair<String, String>>()
        ClassReader(helperBytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor {
                if (name != "executeVmResource") return object : MethodVisitor(Opcodes.ASM9) {}
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, methodName: String, methodDescriptor: String, isInterface: Boolean) {
                        executeCalls += owner to methodName
                    }
                }
            }
        }, ClassReader.SKIP_FRAMES)

        val nativeIndex = executeCalls.indexOfFirst { it.second == "nativeExecuteVmResource" }
        val forwarderIndex = executeCalls.indexOfFirst { it.second == "tryExecuteForwarderFallback" }
        assertTrue(nativeIndex >= 0, "executeVmResource must call nativeExecuteVmResource. Calls=$executeCalls")
        assertTrue(forwarderIndex < 0, "VBC4-only mode must not retain Java forwarder fallback. Calls=$executeCalls")
    }

    @Test
    fun interface_proxy_helper_dispatch_is_fail_closed_when_native_kernel_is_unavailable() {
        val source = Files.readString(Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/InterfaceProxyHelper.java"))

        assertTrue(
            source.contains("throw new SecurityException(\"interface proxy dispatch requires bundled sealed JNI loader kernel"),
            "InterfaceProxyHelper.dispatch must fail closed when native loader kernel is unavailable.",
        )
        assertFalse(
            source.contains("if (!JniMicrokernelHelper.isNativeLoaded()) return"),
            "InterfaceProxyHelper.dispatch must not silently return when native kernel is absent.",
        )
    }

    @Test
    fun native_vm_programs_are_preloaded_into_native_memory_cache() {
        val nativeSource = nativeRuntimeSources()
        val helperSource = Files.readString(Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        assertTrue(
            nativeSource.contains("js_vm_ephemeral_cache_get") &&
                nativeSource.contains("js_vm_ephemeral_cache_put") &&
                nativeSource.contains("jsn_k9(JNIEnv *env, jclass cls)") &&
                nativeSource.contains("META-INF/.r/vm.idx") &&
                helperSource.contains("nativePreloadRuntimeResources();"),
            "Native VM resources must preload into a resident native program cache after kernel load.",
        )
        assertFalse(helperSource.contains("nativePreloadVmResource"), "Java helper must not expose per-resource VM preload bridging.")
        assertTrue(
            nativeSource.contains("#define JS_VM_NESTED_DISPATCH_MAX_DEPTH 1") &&
                nativeSource.contains("js_vm_nested_dispatch_depth >= JS_VM_NESTED_DISPATCH_MAX_DEPTH"),
            "Native-to-native VM nesting must be bounded so recursive virtualized methods fall back to JVM-managed dispatch.",
        )
        assertTrue(
            nativeSource.contains("dst->symbols = NULL;") &&
                nativeSource.contains("dst->symbol_count = 0;") &&
                nativeSource.contains("js_vm_symbol_cache_clear_entry(env, &execution.symbols[si])"),
            "Execution programs must own an isolated symbol cache instead of sharing source program realloc state.",
        )
        val preloadBody = nativeFunctionBody(nativeSource, "jsn_k9(JNIEnv *env, jclass cls)")
        assertTrue(
            preloadBody.contains("js_vm_load_resource_bytes") &&
                preloadBody.contains("js_runtime_resource_decode_owned") &&
                preloadBody.contains("js_vm_prepare_resource_program_bound(env, cls") &&
                preloadBody.contains("js_vm_ephemeral_cache_put"),
            "Runtime resource index decoding and per-resource preload dispatch must be native-owned.",
        )
        val executeBody = nativeFunctionBody(nativeSource, "js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args)")
        assertTrue(
            executeBody.contains("js_vm_ephemeral_cache_get") && !executeBody.contains("= js_vm_prepare_resource_program"),
            "nativeExecuteVmResource must be cache-only; resource stream reads are allowed only during native preload.",
        )
        assertTrue(
            nativeSource.contains("js_runtime_resource_decode_owned") &&
                nativeSource.contains("ZSTD_decompress") &&
                nativeSource.contains("js_runtime_resource_aes_ctr") &&
                nativeSource.contains("js_runtime_resource_key"),
            "Native VM resource preparation must decode authenticated zstd runtime-resource envelopes in native code.",
        )
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(decoded, (size_t)decoded_len);"),
            "Decoded resource envelopes must be wiped before release.",
        )
        assertTrue(
            !nativeSource.contains("jmethodID decode_mid") &&
                !nativeSource.contains("CallStaticObjectMethod(env, resource_cls, decode_mid") &&
                !nativeSource.contains("ReleaseByteArrayElements(env, decoded_array, decoded_raw, 0)"),
            "Native VM execution must not call back into Java to decode VM resource envelopes.",
        )
        assertTrue(
            !nativeSource.contains("js_vm_resource_crypt") &&
                !nativeSource.contains("js_vm_decode_resource_layer") &&
                !nativeSource.contains("jsrp-stream"),
            "Native VM must not retain the old seed/FNV stream runtime-resource decoder.",
        )
        assertTrue(
            nativeSource.contains("js_vm_execute_resource(env, cls, entryToken, resourcePath, args)") &&
                nativeSource.contains("PushLocalFrame(env, 4096)") &&
                nativeSource.contains("PopLocalFrame(env, result)") &&
                nativeSource.contains("PushLocalFrame(env, 256)") &&
                nativeSource.contains("survivor = (*env)->PopLocalFrame(env, nested_value.o)"),
            "JNI VM resource entry and nested native VM execution must use bounded local frames without dropping object returns.",
        )
        assertTrue(
            !nativeSource.contains("(void)entryToken;"),
            "JNI VM resource entry must not ignore the hashed entry token.",
        )
    }

    @Test
    fun native_vm_preload_registers_full_index_before_resource_resolution() {
        val nativeSource = nativeRuntimeSources()
        val preloadBody = nativeFunctionBody(nativeSource, "jsn_k9(JNIEnv *env, jclass cls)")

        val registerIndex = preloadBody.indexOf("js_vm_register_preload_index_entries(index_bytes, index_len)")
        val preloadFlagIndex = preloadBody.indexOf("js_vm_preload_in_progress++")
        val perResourceIndex = preloadBody.indexOf("js_vm_prepare_resource_program_bound(env, cls")
        assertTrue(registerIndex >= 0, "Preload must register every indexed entry before parsing any resource.")
        assertTrue(preloadFlagIndex > registerIndex, "Preload must expose a guarded re-entry window only after the index is registered.")
        assertTrue(perResourceIndex > preloadFlagIndex, "Per-resource parsing must happen after full-index registration.")
        assertTrue(preloadBody.contains("js_vm_preload_in_progress--"), "Preload must always leave the guarded re-entry window.")

        val executeBody = nativeFunctionBody(nativeSource, "js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args)")
        assertTrue(
            executeBody.contains("js_vm_preload_indexed_program_on_demand") &&
                executeBody.contains("js_vm_preload_in_progress") &&
                nativeSource.contains("native VM resource was not preloaded"),
            "Re-entrant execution during preload must on-demand load known indexed resources and still fail closed afterward.",
        )
    }

    @Test
    fun native_vm_preload_does_not_eagerly_link_static_members() {
        val nativeSource = nativeRuntimeSources()
        val prepareBody = nativeFunctionBody(nativeSource, "js_vm_prepare_symbol_cache(JNIEnv *env, js_vm_program *p)")

        assertFalse(prepareBody.contains("JS_VM_GETSTATIC"), "Preload must not resolve static fields because it can trigger target class initialization.")
        assertFalse(prepareBody.contains("JS_VM_INVOKESTATIC"), "Preload must not resolve static methods because it can trigger target class initialization.")
        assertTrue(prepareBody.contains("JS_VM_CHECKCAST"), "Preload may retain class-shape validation that does not execute target members.")
    }

    @Test
    fun native_vm_resident_block_rotation_rewraps_window_not_single_opcode_only() {
        val nativeSource = nativeRuntimeSources()
        val rotateBody = nativeFunctionBody(nativeSource, "js_vm_rotate_resident_block(js_vm_program *p")
        val executeBody = nativeFunctionBody(nativeSource, "js_vm_execute(JNIEnv *env, js_vm_program *p")

        assertTrue(
            nativeSource.contains("resident_rotation_epoch") &&
                rotateBody.contains("dispatch_drift_state") &&
                rotateBody.contains("window = 2 +") &&
                rotateBody.contains("for (int offset = 0; offset < window; offset++)") &&
                rotateBody.contains("p->resident_rotation_epoch ^=") &&
                rotateBody.contains("js_vbc4_wipe_volatile(opcodes"),
            "Resident self-heal must rotate a block/window with an epoch, not only rewrap one fetched opcode.",
        )
        assertTrue(
            executeBody.contains("js_vm_dispatch_drift_step(p, vm_dispatch_drift_state") &&
                executeBody.contains("js_vm_rotate_resident_block(p, fault_pc, dispatch_step, vm_dispatch_drift_state"),
            "Resident block rotation must be scheduled from dispatch drift so trigger points are per-build and cross-method coupled.",
        )
    }

    @Test
    fun native_dispatch_rotation_uses_dynamic_runtime_gate() {
        val nativeSource = nativeRuntimeSources()
        val gateBody = nativeFunctionBody(nativeSource, "js_vm_dispatch_rotation_due")
        val executeBody = nativeFunctionBody(nativeSource, "js_vm_execute(JNIEnv *env, js_vm_program *p")

        assertTrue(nativeSource.contains("js_vm_dispatch_rotation_due"), "VM dispatch should use a dynamic rotation gate")
        assertTrue(gateBody.contains("JS_VBC4_DISPATCH_STEP_MASK") && gateBody.contains("interval = 3u +") && gateBody.contains("phase"),
            "Dynamic gate should preserve the build mask as one input but add state-derived intervals")
        assertTrue(executeBody.contains("js_vm_dispatch_rotation_due(p, vm_dispatch_drift_state, dispatch_step, fault_pc, sp)"),
            "Execute loop must not schedule resident rotation solely from a fixed step mask")
    }

    @Test
    fun shared_dispatch_pool_mixes_runtime_entry_preload_and_resource_state() {
        val nativeSource = nativeRuntimeSources()
        val seedBody = nativeFunctionBody(nativeSource, "js_vm_shared_dispatch_seed_for")
        val preloadBody = nativeFunctionBody(nativeSource, "js_vm_shared_dispatch_mix_preload")

        assertTrue(nativeSource.contains("js_vm_runtime_thread_state") && nativeSource.contains("js_vm_probe_monotonic_ticks") && nativeSource.contains("js_vm_shared_dispatch_runtime_counter"),
            "Shared dispatch pool should mix runtime thread/counter/timing state")
        assertTrue(seedBody.contains("js_vm_program_path_digest(p)") && seedBody.contains("entry_token") && seedBody.contains("insn_count"),
            "Per-entry dispatch seed must include entry token, resource metadata digest, and program shape")
        assertTrue(preloadBody.contains("js_vm_path_mix32(resource_path)") && preloadBody.contains("js_vm_path_mix32(manifest_path)") && preloadBody.contains("shard_count"),
            "Preload order/resource/manifest state must perturb the shared dispatch pool")
    }

    @Test
    fun native_protected_section_covers_vbc4_hot_path_leafs() {
        val nativeSource = nativeRuntimeSources()

        listOf(
            "JS_PROTECTED static void js_rrk_xor_assemble",
            "JS_PROTECTED static jint js_vm_canonical_opcode",
            "JS_PROTECTED static uint32_t js_vm_reg_fold_step",
            "JS_PROTECTED static int js_vm_decode_nested_register_block",
        ).forEach { signature ->
            assertTrue(
                nativeSource.contains(signature),
                ".jsx protected section must cover VBC4 hot-path leaf '$signature'.",
            )
        }
        assertTrue(
            nativeSource.contains("JS_PROTECTED_SECTION_ENABLED") &&
                nativeSource.contains("section(JS_PROTECTED_SECTION_NAME)") &&
                nativeSource.contains("#define JS_PROTECTED_SECTION_NAME \".jsx\""),
            "Native protected-section macro must still emit the .jsx code section on supported PE/ELF targets.",
        )
    }

    @Test
    fun high_value_nested_vm_uses_native_micro_decoder_and_profile_fail_closed() {
        val nativeSource = nativeRuntimeSources()
        val nestedBody = nativeFunctionBody(nativeSource, "js_vm_decode_nested_register_block")

        assertTrue(nativeSource.contains("JS_VBC4_FLAG_NESTED_VM"), "Native parser must recognize the nested VM resource flag.")
        assertTrue(nativeSource.contains("JS_VBC4_NESTED_MAGIC"), "Nested VM block payload must carry a native-validated micro-stream magic.")
        assertTrue(nestedBody.contains("JS_PROTECTED") || nativeSource.contains("JS_PROTECTED static int js_vm_decode_nested_register_block"), "Nested VM decoder should live in the protected native section.")
        assertTrue(nestedBody.contains("JS_VBC4_NESTED_FIELD_OPCODE_BASE"), "Nested VM decoder must parse second-level field micro-ops.")
        assertTrue(nestedBody.contains("js_vbc4_nested_row_checksum"), "Nested VM decoder must validate row checksums before lowering to register rows.")
        assertTrue(nativeSource.contains("js_vm_decode_nested_register_block(block_plain"), "VBC4 parser must expand nested microcode before register validation.")
        assertTrue(nativeSource.contains("p->nested_vm_profile != p->method_local_profile"), "Metadata profile mismatch must fail closed instead of silently accepting a malformed nested block.")
    }

    @Test
    fun native_runtime_resources_reject_legacy_fnv_seed_mix_envelopes() {
        val nativeSource = nativeRuntimeSources()
        val helperSource = Files.readString(Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        assertTrue(
            !nativeSource.contains("js_vm_resource_fnv1a") &&
                !nativeSource.contains("js_vm_resource_keystream") &&
                !nativeSource.contains("js_vm_resource_mix"),
            "Runtime resource decoding must not retain legacy FNV or seed-derived user-reachable stream helpers; internal bitwise mixing remains allowed.",
        )
        val executeBody = nativeFunctionBody(nativeSource, "js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args)")
        assertTrue(
            executeBody.contains("js_vm_ephemeral_cache_get") && !executeBody.contains("= js_vm_prepare_resource_program"),
            "nativeExecuteVmResource must be cache-only; resource stream reads are allowed only during native preload.",
        )
        assertTrue(
            nativeSource.contains("js_runtime_resource_decode_owned") &&
                nativeSource.contains("js_runtime_resource_decode_current_owned") &&
                nativeSource.contains("jsrp-auth-v2") &&
                nativeSource.contains("raw[4] == 6") &&
                nativeSource.contains("js_runtime_hmac_sha256") &&
                !nativeSource.contains("js_vm_decode_resource_layer") &&
                !nativeSource.contains("js_vm_resource_hmac"),
            "Native VM must own current AES-CTR/HMAC/zstd runtime-resource unsealing after the helper installs the build-local key.",
        )
        assertTrue(
            helperSource.contains("version == RUNTIME_RESOURCE_VERSION") &&
                helperSource.contains("LEGACY_RUNTIME_RESOURCE_VERSION") &&
                helperSource.contains("decodeRuntimeResourceCurrent(raw)") &&
                helperSource.contains("decodeRuntimeResourceLegacy(raw)") &&
                helperSource.contains("throw new IllegalArgumentException(\"unsupported runtime resource envelope\")") &&
                !helperSource.contains("decoded != null ? decoded : raw") &&
                helperSource.contains("constantTimeEquals(expected, raw, tagOffset)") &&
                helperSource.contains("AES/CTR/NoPadding") &&
                !helperSource.contains("ZstdDecompressor") &&
                !helperSource.contains("zstdDecompressRuntimeResource"),
            "Java helper must fail closed without carrying Java zstd decode code in the obfuscated product.",
        )
        listOf(
            "HMAC-derived XOR",
            "XOR stream",
            "xor stream",
            "bytes[offset + i] ^ stream[i]",
            "stream[i] ^ bytes[offset + i]",
            "for (int i = 0; i < length; i++) bytes[offset + i]",
        ).forEach { marker ->
            assertFalse(helperSource.contains(marker), "Java helper must fail closed against legacy user-reachable XOR resource decoder marker: $marker")
        }
    }
    @Test
    fun native_vm_resource_execution_fails_closed_without_default_returns() {
        val nativeSource = nativeRuntimeSources()
        val executeBody = nativeFunctionBody(nativeSource, "js_vm_execute_resource(JNIEnv *env, jclass resource_cls, jlong entry_token, jstring resourcePath, jobjectArray args)")

        assertTrue(nativeSource.contains("js_vm_fail_closed(JNIEnv *env, const char *reason)"), "Native VM must expose a fail-closed helper for resource execution failures.")
        assertTrue(
            executeBody.contains("js_vm_fail_closed(env, NULL)") &&
                !executeBody.contains("integrity check failed") &&
                !executeBody.contains("instrumentation detected") &&
                !executeBody.contains("native VM resource unavailable"),
            "Native VM resource execution must use a unified fail-closed path without diagnostic strings.",
        )
        assertTrue(
            !executeBody.contains("js_vm_default_return"),
            "Native VM resource execution must not silently return boxed default values on failure.",
        )
    }

    @Test
    fun native_vm_unsupported_opcode_fails_hard_instead_of_silent_skip() {
        val nativeSource = nativeRuntimeSources()
        val unsupportedIdx = nativeSource.indexOf("JS_VM_CASE(JS_VM_UNSUPPORTED)")
        assertTrue(unsupportedIdx > 0, "Native source must contain JS_VM_UNSUPPORTED dispatch case.")
        val afterUnsupported = nativeSource.substring(unsupportedIdx, (unsupportedIdx + 100).coerceAtMost(nativeSource.length))
        assertTrue(
            afterUnsupported.contains("ok = 0;"),
            "JS_VM_UNSUPPORTED must fail hard by setting ok = 0 instead of silently skipping.",
        )
    }

    @Test
    fun vm_serializer_rejects_unsupported_opcodes_instead_of_emitting_runtime_sentinel() {
        val serializerSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))

        assertTrue(serializerSource.contains("unsupportedOpcode("), "Serializer must reject unsupported bytecode during VBC4 generation.")
        assertTrue(serializerSource.contains("throw UnsupportedOperationException"), "Unsupported bytecode must fail during generation instead of becoming VM bytecode.")
        assertTrue(!serializerSource.contains("emit(VmOpcodes.VM_UNSUPPORTED"), "Serializer must not emit VM_UNSUPPORTED programs that only fail at runtime.")
    }

    @Test
    fun native_vm_mac_gate_fails_before_plaintext_parsing_without_corrupting_opcode_unmask() {
        val nativeSource = nativeRuntimeSources()
        val earlyMacIdx = nativeSource.indexOf("Early MAC verification gates decryption")
        val cpEntryIdx = nativeSource.indexOf("Versioned CP section encryption")
        assertTrue(earlyMacIdx > 0, "Native parser must perform early MAC verification.")
        assertTrue(cpEntryIdx > earlyMacIdx, "Early MAC verification must run before plaintext CP parsing.")
        val earlyMacBlock = nativeSource.substring(earlyMacIdx, cpEntryIdx)
        assertTrue(
            earlyMacBlock.contains("JS_VM_PARSE_FAIL"),
            "Early MAC mismatch or missing tag must fail hard before decryption.",
        )

        val opcodeLine = nativeSource.lines().first { it.contains("js_vbc4_opcode_unmask") && it.contains("raw_opcode") }
        assertTrue(
            !opcodeLine.contains("mac_key"),
            "MAC-derived state must not directly corrupt normal opcode unmasking.",
        )
    }

    @Test
    fun native_vm_keeps_parsed_opcodes_encrypted_at_rest() {
        val nativeSource = nativeRuntimeSources()
        assertTrue(
            nativeSource.contains("js_vm_store_resident_opcode") && nativeSource.contains("js_vm_load_resident_opcode"),
            "Native VM must encode parsed opcodes for resident program storage and decode only when needed.",
        )
        assertTrue(
            nativeSource.contains("js_vm_insn active_insn = p->insns[pc]") &&
                nativeSource.contains("active_raw_opcode = p->insns[pc].opcode") &&
                nativeSource.contains("active_mask = js_vm_resident_opcode_mask(p, pc)") &&
                nativeSource.contains("active_epoch = p->insns[pc].opcode_epoch") &&
                (nativeSource.contains("active_insn.opcode = active_raw_opcode ^ active_mask") ||
                    nativeSource.contains("active_insn.opcode = js_vm_canonical_opcode(active_raw_opcode ^ active_mask)")),
            "VM execution must decode resident opcode into a per-iteration local instruction copy.",
        )
        assertTrue(
            nativeSource.contains(".opcode = js_vm_store_resident_opcode"),
            "Parser must not keep canonical opcodes directly in parsed program memory.",
        )
        assertTrue(
            nativeSource.contains("opcode_epoch") &&
                nativeSource.contains("js_vm_next_opcode_epoch") &&
                nativeSource.contains("js_vm_rewrap_resident_opcode(p, fault_pc, active_insn.opcode, dispatch_step++, pc, sp)"),
            "Resident opcode storage must drift at runtime so a memory snapshot cannot map a stable opcode table.",
        )
    }

    @Test
    fun native_vm_keeps_parsed_operands_encrypted_at_rest() {
        val nativeSource = nativeRuntimeSources()
        assertTrue(
            nativeSource.contains("js_vm_store_resident_operand") && nativeSource.contains("js_vm_load_resident_operand"),
            "Native VM must encode parsed operands for resident program storage and decode only into a temporary instruction copy.",
        )
        assertTrue(
            nativeSource.contains("decoded_ops[operand_index] = js_vm_load_resident_operand(p, resident_index, operand_index)"),
            "VM execution must decode operands into per-iteration temporary storage.",
        )
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(decoded_ops"),
            "Decoded operand storage must be wiped before the next dispatch iteration.",
        )
        assertTrue(
            nativeSource.contains("ops[0] = js_vm_store_resident_operand") && nativeSource.contains("ops[extra] = js_vm_store_resident_operand"),
            "Parser must not keep canonical operands directly in parsed program memory.",
        )
    }
    @Test
    fun native_vm_keeps_program_keys_encoded_at_rest() {
        val nativeSource = nativeRuntimeSources()
        assertTrue(
            nativeSource.contains("js_vm_store_resident_build_seed") &&
                nativeSource.contains("js_vm_load_resident_build_seed") &&
                nativeSource.contains("js_vm_store_resident_mac_key") &&
                nativeSource.contains("js_vm_load_resident_mac_key"),
            "Native VM must encode resident seed and MAC-derived key fields instead of storing them directly.",
        )
        assertTrue(
            nativeSource.contains("js_vm_init_resident_key_mask(p, vbc4_nonce)") &&
                nativeSource.contains("js_vm_store_resident_build_seed(p, build_seed)") &&
                nativeSource.contains("js_vm_store_resident_mac_key(p, mac_key ^ build_seed)"),
            "Parser must seal resource key material before keeping it in js_vm_program.",
        )
        assertTrue(
            (nativeSource.contains("js_vbc4_decrypt_block(plain, cp->enc_len, js_vm_load_resident_build_seed(p)") ||
                nativeSource.contains("cp_decrypt_seed = js_vm_load_resident_build_seed(p)")),
            "Lazy CP decryption must unwrap the resident seed only at the point of use.",
        )
        assertTrue(
            !nativeSource.contains("p->build_seed = build_seed;") &&
                !nativeSource.contains("p->mac_key = ((int)"),
            "Resident program key material must not be assigned as plaintext struct fields.",
        )
    }

    @Test
    fun native_vm_keeps_exception_table_encoded_at_rest() {
        val nativeSource = nativeRuntimeSources()
        assertTrue(
            nativeSource.contains("js_vm_store_resident_exception_field") &&
                nativeSource.contains("js_vm_load_resident_exception"),
            "Native VM must encode parsed exception table fields for resident program storage.",
        )
        assertTrue(
            nativeSource.contains("p->exceptions[i].start = js_vm_store_resident_exception_field") &&
                nativeSource.contains("p->exceptions[i].type_cp = js_vm_store_resident_exception_field"),
            "Parser must not keep canonical exception ranges or catch types directly in parsed program memory.",
        )
        assertTrue(
            nativeSource.contains("js_vbc4_exception_token(build_seed, i)") &&
                nativeSource.contains("if ((uint32_t)encoded_token != expected_token) JS_VM_PARSE_FAIL") &&
                nativeSource.contains("js_vbc4_exception_mask(build_seed, i, 0, expected_token)") &&
                nativeSource.contains("start ^= js_vbc4_exception_mask"),
            "Native parser must require per-entry exception tokens and unmask fields before resident storage.",
        )
        assertTrue(
            nativeSource.contains("js_vm_exception active_exception = js_vm_load_resident_exception(p, i)"),
            "Exception dispatch must decode exception table entries into a per-iteration local copy.",
        )
    }
    @Test
    fun native_vm_entry_integrity_state_participates_in_resource_key_derivation() {
        val nativeSource = nativeRuntimeSources()
        assertTrue(
            nativeSource.contains("static uint32_t js_vm_entry_integrity_state(void)") &&
                nativeSource.contains("js_check_trampoline((const void*)jsn_r20)") &&
                nativeSource.contains("js_detect_instrumentation()"),
            "Native VM resource entry must compute anti-hook/anti-instrumentation state.",
        )
        val integrityWriterStart = nativeSource.lastIndexOf("static void js_vm_write_entry_integrity_bytes(unsigned char out[4])")
        assertTrue(integrityWriterStart >= 0, "Native helper must define the VBC4 entry integrity writer.")
        val integrityWriterBody = nativeSource.substring(integrityWriterStart, nativeSource.indexOf("}\n", integrityWriterStart).let { if (it >= 0) it + 1 else nativeSource.length })
        assertTrue(
            integrityWriterBody.contains("js_vm_entry_integrity_state()"),
            "Entry integrity writer must fold dynamic anti-hook/anti-instrumentation state into VBC4 binding bytes.",
        )
        assertTrue(
            nativeSource.contains("js_vm_write_entry_integrity_bytes(entry_integrity)") &&
                nativeSource.contains("entry_integrity[0]") &&
                nativeSource.contains("js_vm_build_state_binding(entry_token, binding_resource_path, binding_buf") &&
                nativeSource.contains("js_vm_parse_program(decoded, decoded_len, parsed_program, binding_buf, binding_len)"),
            "Entry integrity state must be folded into the parser state binding used for VBC4 seed unwrapping.",
        )
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(entry_integrity, sizeof(entry_integrity))"),
            "Entry integrity bytes must be wiped after being folded into state binding.",
        )
    }
    @Test
    fun native_vm_state_bound_resources_derive_keys_from_runtime_context() {
        val nativeSource = nativeRuntimeSources()
        assertTrue(
            nativeSource.contains("JS_VBC4_REQUIRED_FLAGS") && nativeSource.contains("require full VBC4 max-strength feature set") &&
                nativeSource.contains("js_vbc4_unwrap_seed(vbc4_nonce, vbc4_wrapped_seed, state_binding, state_binding_len, &build_seed)"),
            "VBC4 resources must fail-hard unless runtime binding material participates in seed unwrapping.",
        )
        assertTrue(
                nativeSource.contains("out[binding_len++] = 0") &&
                nativeSource.contains("memcpy(out + binding_len, binding_resource_path, resource_len)") &&
                nativeSource.contains("memcpy(out + binding_len, layout_digest_hex, layout_len)") &&
                nativeSource.contains("entry_token") &&
                nativeSource.contains("resource_path ? resource_path") &&
                nativeSource.contains("entry_integrity") &&
                nativeSource.contains("JS_VBC4_LAYOUT_DIGEST"),
            "nativeExecuteVmResource path must bind entry token, resource path, entry integrity, and layout digest into the parser context.",
        )
        assertFalse(
            nativeSource.contains("js_vm_stack_context_state") ||
                nativeSource.contains("js_vm_thread_context_state") ||
                nativeSource.contains("stack_context") ||
                nativeSource.contains("thread_context"),
            "State-bound VBC4 parser keys must not depend on unstable runtime stack or thread context.",
        )
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(binding_buf, sizeof(binding_buf))"),
            "Runtime binding material must be wiped after parsing.",
        )
    }

    @Test
    fun native_vm_keeps_per_entry_constant_pool_encrypted_until_access() {
        val nativeSource = nativeRuntimeSources()
        val perEntryIdx = nativeSource.indexOf("keep entries encrypted and decode on first use")
        val blockIdsIdx = nativeSource.indexOf("block_ids = (int*)calloc", perEntryIdx)
        assertTrue(perEntryIdx > 0 && blockIdsIdx > perEntryIdx, "Native parser must have a per-entry CP path before instruction block parsing.")
        val perEntryBlock = nativeSource.substring(perEntryIdx, blockIdsIdx)
        assertTrue(
            nativeSource.contains("JS_VBC4_REQUIRED_FLAGS") && nativeSource.contains("require full VBC4 max-strength feature set") &&
                !nativeSource.contains("Legacy: entire CP block encrypted as one"),
            "Native parser must reject legacy VBC4 envelopes that omit MAC/state-bound/authenticated/per-entry CP flags.",
        )
        assertTrue(
            perEntryBlock.contains("p->cp[ci].enc") &&
                perEntryBlock.contains("p->cp[ci].stored_zstd") &&
                perEntryBlock.contains("js_vbc4_aes_material(build_seed, vbc4_nonce, JS_VBC4_SECTION_CONSTANT_POOL_ENTRY, ci, p->cp[ci].key, p->cp[ci].iv)") &&
                !perEntryBlock.contains("js_vbc4_decrypt_block(stored"),
            "Per-entry CP parser must store encrypted entries and prederive key/iv without decrypting plaintext during parse.",
        )
        assertTrue(
            nativeSource.contains("js_vm_decode_cp_entry(js_vm_program *p, int cp_idx, js_vm_cp *out)") &&
                nativeSource.contains("js_vbc4_decrypt_block_with_material(stored, cp->enc_len, cp->key, cp->iv)") &&
                nativeSource.contains("if (cp->stored_zstd)") &&
                nativeSource.contains("js_vbc4_zstd_decompress_owned(stored, (uint32_t)cp->stored_len, (uint32_t)cp->plain_len)") &&
                nativeSource.contains("else if (cp->stored_len == cp->plain_len)"),
            "Constant pool entries must decrypt on access using prederived key/iv and decompress only entries marked as zstd.",
        )
        val decoderBlock = nativeFunctionBody(nativeSource, "js_vm_decode_cp_entry(js_vm_program *p, int cp_idx, js_vm_cp *out)")
        assertTrue(
            decoderBlock.contains("js_vm_cp *cp = &p->cp[cp_idx]") &&
                !decoderBlock.contains("cp->type =") &&
                !decoderBlock.contains("cp->s =") &&
                !decoderBlock.contains("cp->i =") &&
                !decoderBlock.contains("cp->l ="),
            "Access-time CP decoder must not cache decrypted strings or numeric constants back into resident program memory.",
        )
        assertTrue(
            nativeSource.contains("js_vm_clear_decoded_cp(js_vm_cp *cp)") &&
                nativeSource.contains("js_vm_clear_decoded_cp(&cp)"),
            "Decoded CP entries must be wiped and freed immediately after local use.",
        )
    }

    @Test
    fun native_vm_free_program_wipes_structured_data_before_release() {
        val nativeSource = nativeRuntimeSources()
        // Verify CP strings are wiped before free
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(p->cp[i].s, sl)") ||
                nativeSource.contains("js_vbc4_wipe_volatile(p->cp[i].s,"),
            "js_vm_free_program must wipe constant pool strings before freeing.",
        )
        // Verify instruction operand arrays are wiped before free
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(p->insns[i].ops,"),
            "js_vm_free_program must wipe instruction operand arrays before freeing.",
        )
        // Verify the top-level struct is wiped (not just memset to zero)
        assertTrue(
            nativeSource.contains("js_vbc4_wipe_volatile(p, sizeof(*p))"),
            "js_vm_free_program must wipe the top-level program struct with volatile semantics.",
        )
    }

    @Test
    fun jni_microkernel_helper_does_not_use_fixed_native_temp_prefix() {
        val helperBytes = loadJniMicrokernelHelperBytes()
        val constants = mutableListOf<String>()
        ClassReader(helperBytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor {
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitLdcInsn(value: Any?) {
                        if (value is String) constants += value
                    }
                }
            }
        }, ClassReader.SKIP_FRAMES)

        assertTrue(
            "ldr" !in constants,
            "Native loader must not use a fixed temp-file prefix for extracted libraries. Constants=$constants",
        )
    }

    @Test
    fun jni_microkernel_helper_loads_bundled_native_from_explicit_extract_directories() {
        val helperBytes = loadJniMicrokernelHelperBytes()
        val callsByMethod = linkedMapOf<String, MutableList<Triple<String, String, String>>>()
        ClassReader(helperBytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor {
                val key = "$name$descriptor"
                val calls = callsByMethod.getOrPut(key) { mutableListOf() }
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, methodName: String, methodDescriptor: String, isInterface: Boolean) {
                        calls += Triple(owner, methodName, methodDescriptor)
                    }
                }
            }
        }, ClassReader.SKIP_FRAMES)

        val extractCalls = callsByMethod.getValue("tryLoadBundledNativeResource(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z")
        assertTrue(
            extractCalls.any { it.first == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper" && it.second == "nativeExtractDirectories" },
            "Bundled native loading must enumerate explicit extract directories before falling back to tmp. Calls=$extractCalls",
        )
        assertTrue(
            extractCalls.any { it.first == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper" && it.second == "tryLoadBundledNativeFromDirectory" },
            "Bundled native loading must retry System.load from each candidate directory. Calls=$extractCalls",
        )

        val directoryLoadCalls = callsByMethod.getValue("tryLoadBundledNativeFromDirectory(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[BLjava/io/File;)Z")
        assertTrue(
            directoryLoadCalls.any { it.first == "java/io/File" && it.second == "createTempFile" && it.third == "(Ljava/lang/String;Ljava/lang/String;Ljava/io/File;)Ljava/io/File;" },
            "Bundled native extraction must use File.createTempFile(prefix, suffix, directory) so Linux noexec tmp can be bypassed. Calls=$directoryLoadCalls",
        )
        assertTrue(
            directoryLoadCalls.any { it.first == "java/lang/System" && it.second == "load" },
            "Bundled native extraction must load the library from the selected candidate directory. Calls=$directoryLoadCalls",
        )
    }

    @Test
    fun jni_microkernel_helper_prefers_bundled_native_and_checks_required_vm_abi() {
        val helperBytes = loadJniMicrokernelHelperBytes()
        val callsByMethod = linkedMapOf<String, MutableList<Pair<String, String>>>()
        ClassReader(helperBytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor {
                val key = "$name$descriptor"
                val calls = callsByMethod.getOrPut(key) { mutableListOf() }
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, methodName: String, methodDescriptor: String, isInterface: Boolean) {
                        calls += owner to methodName
                    }
                }
            }
        }, ClassReader.SKIP_FRAMES)

        val loadKernelCalls = callsByMethod.getValue("loadKernel(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")
        val bundledIndex = loadKernelCalls.indexOfFirst { it.second == "tryLoadBundledNative" }
        val systemIndex = loadKernelCalls.indexOfFirst { it.second == "tryLoadNative" }
        assertTrue(bundledIndex >= 0, "loadKernel must attempt bundled native loading")
        assertTrue(systemIndex >= 0, "loadKernel may still fall back to system java.library.path loading")
        assertTrue(
            bundledIndex < systemIndex,
            "Bundled native library must be tried before system library path to avoid stale js_kernel shadowing. Calls=$loadKernelCalls",
        )

        val abiCalls = callsByMethod.getValue("verifyNativeAbiAfterLoad()Z")
        assertTrue(
            abiCalls.any { it.first == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper" && it.second == "nativeExecuteVmResource" },
            "Native load must verify nativeExecuteVmResource is linked before marking the kernel loaded. Calls=$abiCalls",
        )
    }

    @Test
    fun vm_dispatch_loop_has_anti_trace_trap_with_debugger_detection() {
        val source = nativeRuntimeSources()

        assertTrue(source.contains("js_vm_anti_trace_check"), "VM dispatch must have anti-trace check function")
        assertTrue(source.contains("vm_trace_state"), "VM dispatch must track anti-trace state across instructions")
        assertTrue(source.contains("js_vm_poison_dispatch_salt"), "VM dispatch must poison dispatch salt when trace detected")
        assertTrue(source.contains("js_vm_anti_trace_check(dispatch_step, &vm_trace_state)"), "Anti-trace check must be called in dispatch loop with step counter")
        assertTrue(source.contains("IsDebuggerPresent") || source.contains("TracerPid"), "Anti-trace must detect platform-specific debugger attachment")
        assertTrue(source.contains("dispatch_step & 31"), "Anti-trace must gate checks to avoid per-instruction overhead")
    }

    @Test
    fun vm_dispatcher_stub_has_dead_code_shadow_dispatch_for_pattern_confusion() {
        val source = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))

        assertTrue(source.contains("Opaque predicate: dead-code shadow dispatch"), "Dispatcher stub must contain dead-code shadow dispatch block")
        assertTrue(source.contains("fakeOwner") && source.contains("fakeMethod"), "Dispatcher stub must generate fake dispatch target identifiers")
        assertTrue(source.contains("shadowChance"), "Dispatcher stub must use randomized shadow dispatch insertion")
        assertTrue(source.contains("fakeResourcePath(fakeId, random)"), "Shadow dispatch fake resources must use neutral multi-level resource names")
        assertFalse(source.contains("\"META-INF/\" + fakeId(12) + \".dat\""), "Shadow dispatch must not leave a hardcoded .dat resource fingerprint")
    }

    @Test
    fun vm_constant_pool_decryption_poisoned_on_trace_detection() {
        val source = nativeRuntimeSources()

        assertTrue(source.contains("js_vm_trace_poison_seed"), "VM must have global trace poison seed for CP decryption")
        assertTrue(source.contains("js_vm_trace_poison_seed = 0"), "Trace poison must reset at each program execution start")
        assertTrue(source.contains("js_vm_trace_poison_seed = *trace_state"), "Trace detection must set CP poison seed")
        assertTrue(source.contains("cp_decrypt_seed") && source.contains("js_vm_trace_poison_seed"), "CP decryption must incorporate trace poison seed")
    }

    @Test
    fun vm_call_gate_registry_exists_for_method_to_resource_mapping() {
        val source = nativeRuntimeSources()

        assertTrue(source.contains("js_vm_call_gate"), "Native VM must have call gate registry for token-to-resource mapping")
        assertTrue(source.contains("js_vm_call_gate_register"), "Call gate must support registering entry tokens with resource paths")
        assertTrue(source.contains("js_vm_call_gate_lookup"), "Call gate must support looking up registered entry tokens")
        assertTrue(source.contains("JS_VM_CALL_GATE_SIZE"), "Call gate must have a defined registry size")
        assertTrue(source.contains("js_vm_call_gate_reset"), "Call gate must support reset for session isolation")
    }

    @Test
    fun vm_exception_table_contains_decoy_entries_beyond_instruction_range() {
        val source = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))

        assertTrue(source.contains("decoyCount"), "VM serializer must generate decoy exception entries")
        assertTrue(source.contains("decoyBase"), "Decoy exceptions must use crypto-derived offsets beyond instruction range")
        assertTrue(source.contains("Decoy ranges are placed BEYOND"), "Decoy exception ranges must be explicitly beyond real instructions")
    }

    @Test
    fun vm_state_binding_includes_anti_hook_integrity_in_key_derivation() {
        val source = nativeRuntimeSources()

        assertTrue(source.contains("js_vm_entry_integrity_state"), "VM must compute entry integrity state for binding")
        assertTrue(source.contains("js_vm_write_entry_integrity_bytes"), "VM must write integrity bytes into state binding")
        assertTrue(source.contains("binding_buf") && source.contains("entry_integrity"), "State binding must include entry integrity bytes")
        assertTrue(source.contains("js_vbc4_unwrap_seed"), "Build seed must be unwrapped through nonce and state binding")
        assertTrue(source.contains("js_check_trampoline") && source.contains("js_detect_instrumentation"), "Entry integrity must check for hooks and instrumentation")
    }

    @Test
    fun native_vm_normalizes_internal_names_before_classloader_calls() {
        val nativeSource = nativeRuntimeSources()
        val loadStart = nativeSource.indexOf("static jobject js_vm_load_class_from_args")
        val defineStart = nativeSource.indexOf("static jobject js_vm_define_class_from_args")
        val invokeStart = nativeSource.indexOf("static int js_vm_invoke_method", defineStart)
        assertTrue(loadStart >= 0 && defineStart > loadStart && invokeStart > defineStart, "Native ClassLoader bridges must be locatable.")
        val loadBody = nativeSource.substring(loadStart, defineStart)
        val defineBody = nativeSource.substring(defineStart, invokeStart)

        assertTrue(loadBody.contains("strchr(raw_name, '/')") && loadBody.contains("js_vm_binary_class_name(raw_name)"), "loadClass bridge must convert internal names to binary names.")
        assertTrue(defineBody.contains("strchr(raw_name, '/')") && defineBody.contains("js_vm_binary_class_name(raw_name)"), "defineClass bridge must convert internal names to binary names.")
        assertTrue(nativeSource.contains("is_class_loader_load_class") && nativeSource.contains("js_vm_load_class_from_args(env, target, mid, args, argc)"), "VM invoke path must route ClassLoader.loadClass through the normalizing bridge.")
        assertTrue(nativeSource.contains("is_class_loader_define_class") && nativeSource.contains("js_vm_define_class_from_args(env, target, args, argc)"), "VM invoke path must route ClassLoader.defineClass through the normalizing bridge.")
    }

    @Test
    fun native_vm_execution_uses_per_invocation_mutable_program_copy() {
        val nativeSource = nativeRuntimeSources()
        val executeRegisterBody = nativeFunctionBody(nativeSource, "js_vm_execute_register(JNIEnv *env, js_vm_program *p, jobjectArray args, char ret_desc, js_vm_value *ret)")

        assertTrue(executeRegisterBody.contains("js_vm_program execution;"), "Each invocation must allocate its own mutable execution program.")
        assertTrue(executeRegisterBody.contains("js_vm_build_execution_program_from_registers(p, &execution)"), "Each invocation must rebuild executable opcodes from immutable register IR.")
        assertTrue(executeRegisterBody.contains("js_vm_execute(env, &execution, args, ret_desc, ret)"), "The interpreter must run against the per-invocation copy.")
        assertTrue(executeRegisterBody.contains("js_vm_clear_execution_program(&execution)"), "The per-invocation copy must be wiped after execution.")
        assertFalse(executeRegisterBody.contains("js_vm_get_execution_program"), "Execution must not share a mutable cached program across EDT/background VM invocations.")
        assertFalse(nativeSource.contains("execution_cache"), "Parsed programs must never retain a shared mutable execution cache.")
    }

    @Test
    fun native_vm_preload_validates_without_caching_mutable_execution_program() {
        val nativeSource = nativeRuntimeSources()
        val preloadBody = nativeFunctionBody(nativeSource, "jsn_k8(JNIEnv *env, jclass cls, jlong entryToken, jstring resourcePath)")

        assertTrue(preloadBody.contains("js_vm_program validation;"), "Preload should build only a temporary validation execution program.")
        assertTrue(preloadBody.contains("js_vm_build_execution_program_from_registers(program, &validation)"), "Preload must validate register IR can lower to executable VM form.")
        assertTrue(preloadBody.contains("js_vm_clear_execution_program(&validation)"), "Temporary validation execution program must be wiped immediately.")
        assertFalse(preloadBody.contains("js_vm_get_execution_program"), "Preload must not create a cached mutable execution program shared by later calls.")
    }

    @Test
    fun native_vm_symbol_cache_does_not_retain_plaintext_symbols_on_invoke_path() {
        val nativeSource = nativeRuntimeSources()
        val cacheStart = nativeSource.indexOf("typedef struct {\n    int cp_idx;")
        val cacheEnd = nativeSource.indexOf("} js_vm_symbol_cache_entry;", cacheStart)
        assertTrue(cacheStart >= 0 && cacheEnd > cacheStart, "VBC4 symbol cache structure must be present.")
        val cacheStruct = nativeSource.substring(cacheStart, cacheEnd)
        assertFalse(cacheStruct.contains("char *desc"), "VBC4 symbol cache must not retain plaintext descriptors after prepare.")
        assertFalse(cacheStruct.contains("char *owner"), "VBC4 symbol cache must not retain plaintext owners after prepare.")
        assertFalse(cacheStruct.contains("char *name"), "VBC4 symbol cache must not retain plaintext method names after prepare.")
        assertTrue(cacheStruct.contains("char *arg_tags") && cacheStruct.contains("is_array_clone") && cacheStruct.contains("is_class_mirror"), "VBC4 symbol cache must retain only compact invoke metadata.")

        val invokeStart = nativeSource.lastIndexOf("static int js_vm_invoke_method(")
        assertTrue(invokeStart >= 0, "VBC4 invoke implementation must be present.")
        val invokeBody = nativeSource.substring(invokeStart).substringBefore("/* Per-run indirect locals addressing")
        assertFalse(invokeBody.contains("cached_symbol->desc"), "VBC4 invoke hot path must not read cached plaintext descriptors.")
        assertFalse(invokeBody.contains("cached_symbol->owner"), "VBC4 invoke hot path must not read cached plaintext owners.")
        assertFalse(invokeBody.contains("cached_symbol->name"), "VBC4 invoke hot path must not read cached plaintext method names.")
        assertTrue(invokeBody.contains("js_vm_pop_jni_args_cached") && invokeBody.contains("cached_symbol->arg_tags"), "VBC4 invoke hot path must use cached compact arg tags.")
    }

    @Test
    fun native_vm_method_symbol_keeps_mapped_lookup_name_alive_until_self_call_cache() {
        val nativeSource = nativeRuntimeSources()
        val resolver = nativeFunctionBody(nativeSource, "js_vm_resolve_method_symbol(JNIEnv *env, js_vm_program *p, int cp_idx, int symbol_kind, int opcode)")

        val getMethodIdx = resolver.indexOf("GetMethodID(env, cls, lookup_name, mr.desc)")
        val addIdx = resolver.indexOf("js_vm_symbol_cache_add(env, p, cp_idx, symbol_kind, cls, mid", getMethodIdx)
        val successFreeIdx = resolver.indexOf("\n    free(mapped_method);", addIdx)
        assertTrue(getMethodIdx >= 0 && addIdx > getMethodIdx && successFreeIdx > addIdx, "Mapped method lookup name must remain alive until self-call metadata is cached.")
    }

    @Test
    fun native_vm_dispatch_abi_uses_hashed_entry_token() {
        val helperSource = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val nativeSource = nativeRuntimeSources()
        val virtualizationSource = Files.readString(sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))

        assertTrue(helperSource.contains("nativeExecuteVmResource(long entryToken, String resourcePath, Object[] args)"))
        assertTrue(helperSource.contains("nativeExecuteVmResourceByToken(long entryToken, Object[] args)"))
        assertTrue(virtualizationSource.contains("private const val VM_TOKEN_DISPATCH_DESCRIPTOR = \"(J[Ljava/lang/Object;)Ljava/lang/Object;\""))
        assertTrue(virtualizationSource.contains("vmEntryToken("), "Dispatcher stubs must derive per-method entry tokens.")
        val dispatchSignatures = listOf("jsn_r20", "jsn_r22", "js_vm_execute_resource", "js_vm_execute_resource_by_token", "js_vm_prepare_resource_program")
            .map { functionName -> nativeFunctionSignature(nativeSource, functionName) }
        assertEquals(5, dispatchSignatures.count { it.isNotBlank() }, "Native VM dispatch entrypoints must be present.")
        dispatchSignatures.forEach { signature ->
            assertTrue(signature.contains("jlong entry_token") || signature.contains("jlong entryToken"), "Native VM ABI must use the hashed entry token.")
            assertFalse(signature.contains("jstring className"), "Native VM ABI must not expose plaintext class names.")
            assertFalse(signature.contains("jstring methodName"), "Native VM ABI must not expose plaintext method names.")
            assertFalse(signature.contains("jstring descriptor"), "Native VM ABI must not expose plaintext descriptors.")
        }
        assertTrue(nativeSource.contains("(J[Ljava/lang/Object;)Ljava/lang/Object;"), "Native registration must expose the token-only hot VM dispatch ABI.")
        assertTrue(nativeSource.contains("js_vm_call_gate_lookup(entry_token)"), "Token-only dispatch must resolve the preloaded resource path from the native call gate.")
        dispatchSignatures.filter { it.contains("jsn_r22") || it.contains("by_token") }.forEach { signature ->
            assertFalse(signature.contains("jstring resourcePath"), "Hot token-only VM ABI must not receive a Java resource-path string.")
        }
    }
    private fun sourcePath(relative: String): Path {
        val direct = Path.of(relative)
        if (Files.exists(direct)) return direct
        val nested = Path.of("core-engine").resolve(relative)
        if (Files.exists(nested)) return nested
        return direct
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
        "src/main/native/js_vm_internal.h",
        "src/main/native/js_vm_core.h",
        "src/main/native/js_vm_core.c",
        "src/main/native/js_vm_resource.h",
        "src/main/native/js_vm_resource.c",
        "src/main/native/js_vm_symbol.h",
        "src/main/native/js_vm_symbol.c",
        "src/main/native/js_jni_runtime.h",
        "src/main/native/js_jni_runtime.c",
    ).joinToString("\n") { path ->
        Files.readString(sourcePath(path)).replace("\r\n", "\n")
    }

    private fun nativeFunctionBody(source: String, signature: String): String {
        var start = source.indexOf(signature)
        while (start >= 0) {
            val afterSignature = start + signature.length
            val braceStart = source.indexOf('{', afterSignature)
            val semicolon = source.indexOf(';', afterSignature).let { if (it < 0) Int.MAX_VALUE else it }
            if (braceStart > afterSignature && braceStart < semicolon) return nativeBraceBody(source, braceStart, signature)
            start = source.indexOf(signature, start + signature.length)
        }
        assertTrue(false, "Native function body must be locatable: $signature")
        error("unreachable")
    }

    private fun nativeBraceBody(source: String, braceStart: Int, signature: String): String {
        var depth = 0
        for (index in braceStart until source.length) {
            when (source[index]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return source.substring(braceStart + 1, index)
                }
            }
        }
        error("Native function body must close: $signature")
    }

    private fun nativeFunctionSignature(source: String, functionName: String): String {
        val regex = Regex("""(?s)(?<![A-Za-z0-9_])${Regex.escape(functionName)}\s*\((.*?)\)""")
        return regex.findAll(source).firstOrNull { "JNIEnv" in it.groupValues[1] }?.groupValues?.get(1) ?: ""
    }

    private fun decodeNativeSecret(include: String, id: String, seed: UInt): String {
        val key = Regex("""static const unsigned char JS_SECRET_AES_KEY\[16\] = \{([^}]*)\};""").find(include)
            ?.groupValues?.get(1)?.parseCBytes()
        val iv = Regex("""static const unsigned char JS_SECRET_AES_IV\[16\] = \{([^}]*)\};""").find(include)
            ?.groupValues?.get(1)?.parseCBytes()
        requireNotNull(key) { "Missing JS_SECRET_AES_KEY" }
        requireNotNull(iv) { "Missing JS_SECRET_AES_IV" }
        val secretMatch = Regex("""static const unsigned char js_secret_${Regex.escape(id)}\[\] = \{([^}]*)\};""").find(include)
        requireNotNull(secretMatch) { "Missing native secret $id" }
        val encrypted = secretMatch.groupValues[1].parseCBytes()
        val indexMatch = Regex("""#define JS_SECRET_INDEX_${Regex.escape(id)} (\d+)""").find(include)
        requireNotNull(indexMatch) { "Missing native secret index $id" }
        return aesCtrCrypt(encrypted, key, iv, indexMatch.groupValues[1].toInt()).toString(Charsets.UTF_8)
    }

    private fun String.parseCBytes(): ByteArray = split(',')
        .map(String::trim)
        .filter(String::isNotEmpty)
        .map { it.removeSuffix("u").removePrefix("0x").toInt(16).toByte() }
        .toByteArray()

    private fun aesCtrCrypt(data: ByteArray, key: ByteArray, iv: ByteArray, index: Int): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
        val counter = iv.copyOf()
        var carry = index
        var pos = counter.lastIndex
        while (pos >= 0 && carry != 0) {
            val total = (counter[pos].toInt() and 0xFF) + (carry and 0xFF)
            counter[pos] = total.toByte()
            carry = (carry ushr 8) + (total ushr 8)
            pos--
        }
        cipher.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.IvParameterSpec(counter),
        )
        return cipher.doFinal(data)
    }
    private fun loadJniMicrokernelHelperBytes(): ByteArray {
        val resourcePath = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class"
        javaClass.classLoader.getResourceAsStream(resourcePath)?.use { return it.readBytes() }

        val candidates = listOf(
            Path.of("build", "core-engine", "classes", "java", "main").resolve(resourcePath),
            Path.of("core-engine", "build", "classes", "java", "main").resolve(resourcePath),
            Path.of("..", "build", "core-engine", "classes", "java", "main").resolve(resourcePath),
        )
        val compiledClass = candidates.firstOrNull { Files.exists(it) }
        return checkNotNull(compiledClass) {
            "JniMicrokernelHelper.class should be on the test classpath or in compiled Java output"
        }.let { Files.readAllBytes(it) }
    }
}
