package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RenamePlan
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.ObfuscatedIdentifierUtil
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.currentVbc4BuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyBootstrapTableEncryption
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization as applyMethodVirtualizationTransform
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MethodVirtualizationThresholdTest {
    private companion object {
        const val VBC4_FLAGS_OFFSET_FOR_TEST = 42
        const val VBC4_NESTED_VM_FLAG_FOR_TEST = 0x1000
    }

    private fun applyMethodVirtualization(
        artifact: BytecodeArtifact,
        ruleMatches: List<RuleMatch>,
        params: Map<String, Any>,
    ) = if (currentVbc4BuildContextOrNull() != null) {
        applyMethodVirtualizationTransform(artifact = artifact, ruleMatches = ruleMatches, params = params)
    } else {
        withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyMethodVirtualizationTransform(artifact = artifact, ruleMatches = ruleMatches, params = params)
        }
    }

    private fun decodedVbc4ResourceFlags(entries: List<JarEntryData>, context: Vbc4BuildContext): List<Int> =
        withVbc4BuildContext(context) {
            entries
                .filter { it.isVmResourceName() }
                .mapNotNull { RuntimeResourceCodec.decode(it.bytes) }
                .filter(::isRawVbc4Resource)
                .map { readU2At(it, VBC4_FLAGS_OFFSET_FOR_TEST) }
        }


    private fun isRawVbc4Resource(bytes: ByteArray): Boolean =
        bytes.size > VBC4_FLAGS_OFFSET_FOR_TEST + 1 &&
            bytes[0] == 'V'.code.toByte() &&
            bytes[1] == 'B'.code.toByte() &&
            bytes[2] == 'C'.code.toByte() &&
            bytes[3] == '4'.code.toByte() &&
            readU2At(bytes, 4) == 4

    private fun readU2At(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    @Test
    fun method_virtualization_skips_methods_above_instruction_threshold() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 1, "seed" to 42, "strictVirtualization" to false),
        )

        assertEquals(0, result.transformedClassCount, "Methods above maxInstructions should remain unchanged")
        assertEquals(0, result.transformedMemberCount, "Skipped methods must not count as transformed")
        assertTrue(result.artifact.jarEntries.none { it.isVmResourceName() }, "Skipped methods must not emit VM resources")
    }

    @Test
    fun method_virtualization_still_transforms_when_threshold_allows_it() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        assertTrue(result.transformedClassCount > 0, "High threshold should allow VM transformation")
        assertTrue(result.transformedMemberCount > 0, "High threshold should transform at least one method")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "VM transformation should emit VM resources")
    }

    @Test
    fun method_virtualization_critical_plus_selects_more_than_critical_auto() {
        val artifact = artifactFor(selectionClassBytes(), "example/VmSelection")

        val criticalAuto = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "strictVirtualization" to false),
        )
        val criticalPlus = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "critical-plus", "strictVirtualization" to false),
        )

        assertEquals(2, criticalAuto.transformedMemberCount, "baseline critical-auto count for the fixture")
        assertEquals(3, criticalPlus.transformedMemberCount, "critical-plus must also pull in medium pure-compute methods critical-auto skips")
    }

    @Test
    fun method_virtualization_critical_plus_selects_high_value_methods_and_honors_allow_deny_lists() {
        val artifact = artifactFor(highValueSelectionClassBytes(), "example/VmHighValue")
        val context = defaultVbc4BuildContext()

        val defaultHighValue = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmHighValue"),
                params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "critical-plus", "strictVirtualization" to true),
            )
        }
        val allowPlain = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmHighValue"),
                params = mapOf(
                    "maxInstructions" to 100,
                    "seed" to 42,
                    "methodSelection" to "critical-plus",
                    "strictVirtualization" to true,
                    "highValueMethods" to "plainValue",
                ),
            )
        }
        val denyVerify = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmHighValue"),
                params = mapOf(
                    "maxInstructions" to 100,
                    "seed" to 42,
                    "methodSelection" to "critical-plus",
                    "strictVirtualization" to true,
                    "highValueMethods" to "plainValue",
                    "highValueMethodDeny" to "verifyLicense",
                ),
            )
        }

        assertEquals(1, defaultHighValue.transformedMemberCount, "critical-plus must auto-select public high-value method names")
        assertTrue(methodCallsVmDispatcher(defaultHighValue.artifact.classArtifactIndex.getValue("example/VmHighValue").bytes, "verifyLicense", "()I"))
        assertTrue(!methodCallsVmDispatcher(defaultHighValue.artifact.classArtifactIndex.getValue("example/VmHighValue").bytes, "plainValue", "()I"))
        assertEquals(2, allowPlain.transformedMemberCount, "highValueMethods must include named VM-compatible methods")
        assertEquals(1, denyVerify.transformedMemberCount, "highValueMethodDeny must exclude auto-selected high-value false positives")
        assertTrue(!methodCallsVmDispatcher(denyVerify.artifact.classArtifactIndex.getValue("example/VmHighValue").bytes, "verifyLicense", "()I"))
        assertTrue(methodCallsVmDispatcher(denyVerify.artifact.classArtifactIndex.getValue("example/VmHighValue").bytes, "plainValue", "()I"))
    }

    @Test
    fun method_virtualization_high_value_methods_emit_nested_vm_resource_flag() {
        val highValueArtifact = artifactFor(highValueSelectionClassBytes(), "example/VmHighValue")
        val ordinaryArtifact = artifactFor(simpleClassBytes(), "example/VmThreshold")
        val context = defaultVbc4BuildContext()

        val highValue = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = highValueArtifact,
                ruleMatches = ruleMatchesFor("example/VmHighValue"),
                params = mapOf(
                    "maxInstructions" to 100,
                    "seed" to 42,
                    "methodSelection" to "critical-plus",
                    "strictVirtualization" to true,
                    "highValueMethods" to "plainValue",
                ),
            )
        }
        val ordinary = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = ordinaryArtifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "critical-plus", "strictVirtualization" to true),
            )
        }

        val highValueFlags = decodedVbc4ResourceFlags(highValue.artifact.jarEntries, context)
        val ordinaryFlags = decodedVbc4ResourceFlags(ordinary.artifact.jarEntries, context)
        assertTrue(highValueFlags.any { it and VBC4_NESTED_VM_FLAG_FOR_TEST != 0 }, "High-value methods must mark VBC4 resources as nested-VM protected")
        assertTrue(ordinaryFlags.isNotEmpty() || highValueFlags.isNotEmpty(), "VM transformation must emit decodable VBC4 resources")
        assertTrue(ordinaryFlags.none { it and VBC4_NESTED_VM_FLAG_FOR_TEST != 0 }, "Ordinary non-high-value methods must not carry the nested-VM flag")
    }

    @Test
    fun method_virtualization_high_value_methods_are_backed_by_nested_micro_stream_writer() {
        val highValueArtifact = artifactFor(highValueSelectionClassBytes(), "example/VmHighValue")
        val context = defaultVbc4BuildContext()

        val highValue = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = highValueArtifact,
                ruleMatches = ruleMatchesFor("example/VmHighValue"),
                params = mapOf(
                    "maxInstructions" to 100,
                    "seed" to 42,
                    "methodSelection" to "critical-plus",
                    "strictVirtualization" to true,
                    "highValueMethods" to "plainValue",
                ),
            )
        }

        val highValueFlags = decodedVbc4ResourceFlags(highValue.artifact.jarEntries, context)
        val serializerSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        assertTrue(highValueFlags.any { it and VBC4_NESTED_VM_FLAG_FOR_TEST != 0 }, "Fixture must emit a nested-VM resource")
        assertTrue(serializerSource.contains("serializeNestedBlock"), "Nested VBC4 resources must be written through a second-level micro-op stream")
        assertTrue(serializerSource.contains("VBC4_NESTED_MAGIC"), "Nested VBC4 resources must carry a native-validated micro-stream envelope")
        assertTrue(serializerSource.contains("vbc4NestedFieldOrder"), "Nested micro-op fields must be per-build permuted rather than plain register rows")
    }

    @Test
    fun method_virtualization_strict_honors_default_broad_selection() {
        val artifact = artifactFor(selectionClassBytes(), "example/VmSelection")

        val criticalAuto = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "strictVirtualization" to false),
        )
        val strict = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "strictVirtualization" to true),
        )

        assertEquals(2, criticalAuto.transformedMemberCount, "baseline critical-auto count for the fixture")
        assertEquals(2, strict.transformedMemberCount, "strictVirtualization should keep fail-closed behavior for selected methods without overriding broad methodSelection")
    }

    @Test
    fun method_virtualization_all_compatible_includes_public_and_synchronized_methods() {
        val artifact = artifactFor(publicSynchronizedClassBytes(), "example/VmPublicSync")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmPublicSync"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(2, result.transformedMemberCount, "all-compatible strict mode should virtualize public overridable and synchronized compatible methods")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Virtualized public/synchronized methods should emit VM resources")
    }

    @Test
    fun method_virtualization_all_compatible_includes_static_field_and_type_flow_methods() {
        val artifact = artifactFor(staticFieldAndTypeFlowClassBytes(), "example/VmStaticCast")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmStaticCast"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(3, result.transformedMemberCount, "all-compatible strict mode must keep GETSTATIC/CHECKCAST/INSTANCEOF shapes in the VBC4 candidate set")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Static-field/type-flow methods should emit VM resources")
    }

    @Test
    fun method_virtualization_all_compatible_skips_synthetic_bridge_methods() {
        val artifact = artifactFor(
            classBytes = syntheticBridgeClassBytes(),
            internalName = "example/VmSyntheticBridge",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "call", "()Ljava/lang/Long;", Opcodes.ACC_PUBLIC),
                MemberSummary(MemberKind.METHOD, "call", "()Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSyntheticBridge"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )
        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmSyntheticBridge").bytes

        assertEquals(1, result.transformedMemberCount, "all-compatible must leave synthetic bridge glue as direct bytecode to avoid recursive ABI bridge dispatch")
        assertTrue(methodCallsVmDispatcher(classBytes, "call", "()Ljava/lang/Long;"), "Real bridge target should still be virtualized")
        assertTrue(!methodCallsVmDispatcher(classBytes, "call", "()Ljava/lang/Object;"), "Synthetic bridge method must remain a direct forwarder")
    }

    @Test
    fun method_virtualization_skips_enum_values_helper_to_avoid_preload_recursion() {
        val artifact = artifactFor(
            classBytes = enumValuesClassBytes(),
            internalName = "example/VmStone",
            accessFlags = Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL or Opcodes.ACC_SUPER or Opcodes.ACC_ENUM,
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmStone"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )
        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmStone").bytes

        assertEquals(1, result.transformedMemberCount, "strict all-compatible should still virtualize ordinary enum methods")
        assertTrue(!methodCallsVmDispatcher(classBytes, "\$values", "()[Lexample/VmStone;"), "Enum synthetic values helper must remain direct bytecode during native VM preload")
        assertTrue(methodCallsVmDispatcher(classBytes, "ordinary", "()I"), "Ordinary compatible enum methods should still be virtualized")
    }

    @Test
    fun native_bridge_dispatcher_virtualizes_main_string_array_and_passes_verifier() {
        val artifact = artifactFor(mainStringArrayClassBytes(), "example/VmMainArray")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmMainArray"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "__nativeOnlyInterpreter" to true),
        )

        assertEquals(1, result.transformedMemberCount, "strict all-compatible native-only mode must virtualize JVM main(String[]) instead of leaving it as plaintext")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Virtualized main(String[]) should emit a VBC4 VM resource")
        val transformedMain = result.artifact.classArtifactIndex.getValue("example/VmMainArray").bytes
        assertTrue(methodHasEntryGuardField(transformedMain), "Virtualized JVM main must keep a guarded entry forwarder instead of skipping the entry point")
        assertTrue(methodCallsSyntheticMainHelper(transformedMain), "JVM main(String[]) must forward to the migrated helper with a guard parameter")
        assertTrue(methodCallsVmDispatcher(transformedMain, syntheticMainHelperName(transformedMain), "([Ljava/lang/String;Z)V"), "Migrated main helper must contain the native VM dispatcher call")
        assertTrue(!methodCallsVmDispatcher(transformedMain, "main", "([Ljava/lang/String;)V"), "Public JVM entry must remain a forwarder, not the native dispatcher body")
        val outputDir = Files.createTempDirectory("vm-main-array-verify")
        try {
            val classFile = outputDir.resolve("example/VmMainArray.class")
            Files.createDirectories(classFile.parent)
            Files.write(classFile, result.artifact.classArtifactIndex.getValue("example/VmMainArray").bytes)
            URLClassLoader(arrayOf(outputDir.toUri().toURL()), null).use { loader ->
                loader.loadClass("example.VmMainArray")
            }
        } finally {
            outputDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun explicit_main_entry_selection_migrates_body_and_virtualizes_helper() {
        val artifact = artifactFor(mainStringArrayClassBytes(), "example/VmMainArray")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = listOf(
                RuleMatch(
                    rule = RuleSpec(target = "example/VmMainArray#main:([Ljava/lang/String;)V", action = "method-virtualization"),
                    selector = TargetSelector(classPattern = "example/VmMainArray", memberPattern = "main", memberDescriptorPattern = "([Ljava/lang/String;)V"),
                    matchedClassNames = listOf("example/VmMainArray"),
                    matchedMembers = listOf(MatchedMember("example/VmMainArray", MemberKind.METHOD, "main", "([Ljava/lang/String;)V")),
                ),
            ),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "strictVirtualization" to true, "__nativeOnlyInterpreter" to true),
        )

        assertEquals(1, result.transformedMemberCount, "Explicit JVM main selection must migrate and virtualize the entry body")
        val transformedMain = result.artifact.classArtifactIndex.getValue("example/VmMainArray").bytes
        val helperName = syntheticMainHelperName(transformedMain)
        assertTrue(methodCallsSyntheticMainHelper(transformedMain), "Public JVM main must remain as an ABI forwarder")
        assertTrue(methodCallsVmDispatcher(transformedMain, helperName, "([Ljava/lang/String;Z)V"), "Migrated explicit main helper must contain the native VM dispatcher")
        assertTrue(!methodCallsVmDispatcher(transformedMain, "main", "([Ljava/lang/String;)V"), "Public JVM entry must not be skipped or left as the VM dispatcher body")
    }

    @Test
    fun method_virtualization_strict_accepts_runnable_lambda_metafactory() {
        val artifact = artifactFor(runnableLambdaClassBytes(), "example/VmLambda")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmLambda"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(2, result.transformedMemberCount, "strict all-compatible should virtualize the lambda factory method and its target")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Runnable lambda virtualized methods should emit VBC4 VM resources")
    }

    @Test
    fun method_virtualization_strict_accepts_bootstrap_encrypted_string_concat() {
        val original = artifactFor(encryptedStringConcatClassBytes(), "example/VmEncryptedConcat")
        val encrypted = applyBootstrapTableEncryption(
            artifact = original,
            ruleMatches = ruleMatchesFor("example/VmEncryptedConcat", "invoke-dynamic-indirection"),
            params = mapOf("seed" to 7),
        ).artifact

        val result = applyMethodVirtualization(
            artifact = encrypted,
            ruleMatches = ruleMatchesFor("example/VmEncryptedConcat"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(1, result.transformedMemberCount, "strict all-compatible must virtualize methods whose supported indy is wrapped by invoke-dynamic-indirection")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Bootstrap-encrypted invokedynamic methods should emit VBC4 VM resources")
    }

    @Test
    fun method_virtualization_treats_huge_long_threshold_as_unbounded() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to Long.MAX_VALUE, "seed" to 42),
        )

        assertTrue(result.transformedMemberCount > 0, "Huge Long threshold should not overflow into a tiny limit")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Huge threshold should still emit VM resources")
    }

    @Test
    fun method_virtualization_method_selection_controls_broad_class_rules() {
        val artifact = artifactFor(selectionClassBytes(), "example/VmSelection")

        val safe = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "safe", "strictVirtualization" to false),
        )
        val criticalAuto = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "strictVirtualization" to false),
        )
        val allCompatible = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to false),
        )

        assertEquals(1, safe.transformedMemberCount, "safe should preserve the old narrow broad-selection behavior")
        assertEquals(2, criticalAuto.transformedMemberCount, "critical-auto should add VM-compatible methods with critical signals")
        assertEquals(3, allCompatible.transformedMemberCount, "all-compatible should force every VM-compatible broad-rule method")
    }

    @Test
    fun method_virtualization_caps_broad_auto_selected_methods() {
        val artifact = artifactFor(selectionClassBytes(), "example/VmSelection")

        val capped = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 1),
        )

        assertEquals(1, capped.transformedMemberCount, "Broad class rules should honor maxBroadVirtualizedMethods to keep full configurations testable")
    }

    @Test
    fun method_virtualization_strict_still_honors_broad_method_selection() {
        val artifact = artifactFor(publicSynchronizedClassBytes(), "example/VmPublicSync")

        val strictCriticalPlus = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmPublicSync"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "critical-plus", "strictVirtualization" to true),
        )
        val strictAllCompatible = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmPublicSync"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(1, strictCriticalPlus.transformedMemberCount, "strict mode should fail closed for selected methods but must not ignore methodSelection on broad class rules")
        assertEquals(2, strictAllCompatible.transformedMemberCount, "all-compatible remains the explicit maximum coverage mode")
    }

    @Test
    fun method_virtualization_uses_independent_csprng_for_method_keys() {
        val source = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))
        val nativeKernelSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelTransforms.kt"))
        assertTrue(source.contains("method-virtualization-key-stream-v1"), "Method key material must use the per-build VBC4 context-derived key stream, not the user-seeded structural RNG")
        assertTrue(source.contains("methodKeySeed(keyRandom)"), "Per-method VM seeds must come from keyRandom")
        assertTrue(!source.lines().any { it.contains("= methodKeySeed(random)") }, "Per-method VM seeds must not be reproducible from the user-visible seed")
        assertTrue(!source.contains("xor className.hashCode()") && !source.contains("xor methodName.hashCode()"), "Method seeds must not be derived from known class or method names")
        assertTrue(nativeKernelSource.contains("val nativeKeyRandom = java.security.SecureRandom()"), "Native kernel VM key material must use an independent CSPRNG")
        assertTrue(nativeKernelSource.contains("methodKeySeed(nativeKeyRandom)"), "Native kernel VM method seeds must come from nativeKeyRandom")
        assertTrue(!nativeKernelSource.contains("diversificationSeed xor") && !nativeKernelSource.contains("internalName.hashCode()"), "Native kernel VM seeds must not mix known class names into user-visible seeds")
        assertTrue(!nativeKernelSource.lines().any { it.contains("= methodKeySeed(random)") }, "Native kernel VM resource seeds must not come from user-seeded structural RNG")
    }

    @Test
    fun same_user_seed_does_not_reproduce_vm_resource_ciphertexts() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")
        val first = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "__nativeOnlyInterpreter" to true),
        )
        val second = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "__nativeOnlyInterpreter" to true),
        )

        val firstResources = first.artifact.jarEntries.filter { it.isVmResourceName() }.map { it.bytes.toList() }
        val secondResources = second.artifact.jarEntries.filter { it.isVmResourceName() }.map { it.bytes.toList() }
        assertTrue(firstResources.isNotEmpty() && secondResources.isNotEmpty(), "Native VM virtualization must emit resources")
        assertTrue(firstResources != secondResources, "Same user seed must not reproduce per-method VM resource ciphertexts")
    }

    @Test
    fun vm_preload_index_includes_manifest_and_shard_coordinates() {
        val artifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val context = defaultVbc4BuildContext()
        val result = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible"),
            )
        }

        val indexEntry = result.artifact.jarEntries.single { it.name == "META-INF/.r/vm.idx" }
        val index = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(indexEntry.bytes)!!.decodeToString().trim().lines()
        }
        assertTrue(index.isNotEmpty(), "Preload index must contain entries")
        assertTrue(index.all { it.split('|').size >= 4 }, "Preload index must include manifest and shard coordinates")
    }

    @Test
    fun vm_preload_index_uses_interprocedural_schedule_order() {
        val artifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val context = defaultVbc4BuildContext()
        val result = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible"),
            )
        }
        val decodedResources = withVbc4BuildContext(context) {
            result.artifact.jarEntries
                .filter { it.isVmResourceName() }
                .mapNotNull { entry -> RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it.decodeToString() } }
                .toMap()
        }
        val emittedManifestOrder = decodedResources.filterValues { it.startsWith("VBC4S|1|") }.keys.toList()
        val indexEntry = result.artifact.jarEntries.single { it.name == "META-INF/.r/vm.idx" }
        val preloadManifestOrder = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(indexEntry.bytes)!!.decodeToString().trim().lines().map { it.split('|')[2] }
        }

        assertTrue(preloadManifestOrder.size >= 2, "Fixture must produce multiple VM preload entries")
        assertEquals(emittedManifestOrder.toSet(), preloadManifestOrder.toSet(), "Preload schedule must cover every emitted VM manifest")
        assertTrue(preloadManifestOrder != emittedManifestOrder, "Cross-method VM preload schedule must not preserve local resource emission order")
    }
    @Test
    fun native_vm_bytecode_is_sliced_across_opaque_resources_and_reassembled_by_manifest() {
        val artifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val context = defaultVbc4BuildContext()
        val decodedResources = withVbc4BuildContext(context) {
            val result = applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible"),
            )
            assertTrue(result.transformedMemberCount > 0, "Fixture must virtualize methods before slicing assertions")
            result.artifact.jarEntries
                .filter { it.isVmResourceName() || it.name == "META-INF/.r/vm.idx" }
                .mapNotNull { entry -> RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it } }
                .toMap()
        }
        val manifests = decodedResources.filterValues { bytes -> bytes.decodeToString().startsWith("VBC4S|1|") }
        val preloadEntries = decodedResources["META-INF/.r/vm.idx"]!!
            .decodeToString()
            .trim()
            .lines()
            .associate { line ->
                val parts = line.split('|')
                parts[2] to ManifestPreloadEntry(
                    entryTokenHex = parts[0],
                    resourcePath = parts[1],
                    manifestPath = parts[2],
                    shardCount = parts[3],
                )
            }

        assertTrue(manifests.size >= 2, "Executable VM entries should be slice manifests instead of localized monolithic VBC4 payloads")
        assertTrue(manifests.isNotEmpty(), "VM slicing must emit at least one executable manifest")
        val meshDigests = mutableSetOf<String>()
        val meshMaterials = mutableListOf<MeshMaterial>()
        val peerOrdinalsByManifest = mutableMapOf<String, MutableSet<Int>>()
        for ((manifestPath, manifestBytes) in manifests) {
            val lines = manifestBytes.decodeToString().trim().lines()
            val header = lines.first().split('|')
            val totalSize = header[2].toInt()
            val shardCount = header[3].toInt()
            assertTrue(header.size >= 7, "Manifest header must include cross-method mesh metadata")
            meshDigests += header[4]
            assertEquals(manifests.size, header[6].toInt(), "Manifest mesh must cover every virtualized method entry")
            val preloadEntry = requireNotNull(preloadEntries[manifestPath]) { "Manifest must be listed in VM preload index" }
            meshMaterials += manifestMeshMaterial(preloadEntry, lines)
            val assembled = ByteArray(totalSize)
            assertTrue(shardCount in 2..4, "VMBC must be distributed across 2-4 shard resources")
            val shardLines = lines.drop(1)
            val rowIndices = shardLines.map { it.split('|')[0].toInt() }
            assertEquals(shardCount, shardLines.size, "Manifest must enumerate every shard")
            assertTrue(rowIndices != rowIndices.sorted(), "Manifest shard rows must be mesh-ordered, not linear by shard index")
            for (line in shardLines) {
                val parts = line.split('|')
                val offset = parts[1].toInt()
                val length = parts[2].toInt()
                val shardPath = parts[4]
                assertTrue(parts.size >= 8 && parts[5].length == 16 && parts[7].length == 16, "Shard rows must include mesh and cross-method peer link tokens")
                val peerOrdinal = parts[6].toInt()
                assertTrue(peerOrdinal in 0 until manifests.size, "Shard peer ordinal must point at a manifest in the interprocedural mesh")
                assertTrue(peerOrdinal != header[5].toInt(), "Shard peer link must point at another method manifest when multiple methods are virtualized")
                peerOrdinalsByManifest.getOrPut(manifestPath) { mutableSetOf() } += peerOrdinal
                val shardBytes = decodedResources[shardPath]
                assertTrue(shardBytes != null, "Manifest shard path must resolve to an emitted opaque resource")
                assertEquals(length, shardBytes!!.size, "Shard length metadata must match decoded bytes")
                shardBytes.copyInto(assembled, offset)
            }
            assertEquals('V'.code.toByte(), assembled[0], "Reassembled VMBC must preserve VBC4 magic")
            assertEquals('B'.code.toByte(), assembled[1], "Reassembled VMBC must preserve VBC4 magic")
            assertEquals('C'.code.toByte(), assembled[2], "Reassembled VMBC must preserve VBC4 magic")
            assertEquals('4'.code.toByte(), assembled[3], "Reassembled VMBC must preserve VBC4 magic")
        }
        assertTrue(peerOrdinalsByManifest.values.all { it.isNotEmpty() }, "Every sliced manifest must carry cross-method peer links")
        assertTrue(peerOrdinalsByManifest.values.flatten().toSet().size >= 2,
            "Shard peer links should distribute across the interprocedural manifest mesh")
        assertEquals(1, meshDigests.size, "Every sliced method manifest must share one interprocedural mesh digest")
        assertEquals(meshDigests.single(), sha256Hex(meshMaterials.sortedBy { it.sortKey }.joinToString(separator = "\u0000") { it.material }),
            "Interprocedural mesh digest must bind each manifest's real shard coordinates and digests")
    }

    @Test
    fun method_virtualization_honors_method_level_rule_when_threshold_allows_it() {
        val artifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = listOf(
                RuleMatch(
                    rule = RuleSpec(target = "example/VmThreshold#hot:()I", action = "method-virtualization"),
                    selector = TargetSelector(classPattern = "example/VmThreshold", memberPattern = "hot", memberDescriptorPattern = "()I"),
                    matchedClassNames = listOf("example/VmThreshold"),
                    matchedMembers = listOf(MatchedMember("example/VmThreshold", MemberKind.METHOD, "hot", "()I")),
                ),
            ),
            params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42),
        )

        val vmResources = result.artifact.jarEntries.map { it.name }.filter { it.isVmResourceName() }
        assertEquals(1, result.transformedMemberCount, "Method-level rule should virtualize only the selected method")
        assertTrue(vmResources.size > 1, "Selected method should emit decoy VM resources alongside the executable resource")
        assertTrue(vmResources.none { it.contains("__jvm") || it.contains("VmThreshold") || it.contains("hot") || it.contains("cold") }, "VM resource names must not expose class or method semantics")
    }

    @Test
    fun method_virtualization_strict_virtualizes_class_level_monitor_methods() {
        val artifact = artifactFor(
            classBytes = mixedCompatibleAndUnsupportedClassBytes(),
            internalName = "example/VmMixedUnsupported",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "ok", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                MemberSummary(MemberKind.METHOD, "monitor", "(Ljava/lang/Object;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmMixedUnsupported"),
            params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(2, result.transformedMemberCount, "Strict broad virtualization must virtualize monitor-bearing compatible methods instead of replaying plaintext")
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Strict monitor virtualization should emit VBC4 resources")
    }


    @Test
    fun method_virtualization_virtualizes_explicit_monitor_methods() {
        val unsupportedBytes = unsupportedExplicitClassBytes()
        assertTrue(hasMonitorEnterInMethod(unsupportedBytes, "monitor", "(Ljava/lang/Object;)V"), "Fixture must exercise a monitor instruction")
        val artifact = artifactFor(unsupportedBytes, "example/VmUnsupported", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "monitor", "(Ljava/lang/Object;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = listOf(
                RuleMatch(
                    rule = RuleSpec(target = "example/VmUnsupported#monitor:(Ljava/lang/Object;)V", action = "method-virtualization"),
                    selector = TargetSelector(classPattern = "example/VmUnsupported", memberPattern = "monitor", memberDescriptorPattern = "(Ljava/lang/Object;)V"),
                    matchedClassNames = listOf("example/VmUnsupported"),
                    matchedMembers = listOf(MatchedMember("example/VmUnsupported", MemberKind.METHOD, "monitor", "(Ljava/lang/Object;)V")),
                ),
            ),
            params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42),
        )

        assertEquals(1, result.transformedMemberCount, "Explicit monitor method should be virtualized rather than replayed")
    }

    @Test
    fun method_virtualization_strict_broad_rule_virtualizes_monitor_methods() {
        val unsupportedBytes = unsupportedExplicitClassBytes()
        val artifact = artifactFor(unsupportedBytes, "example/VmUnsupported", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "monitor", "(Ljava/lang/Object;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmUnsupported"),
            params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "strictVirtualization" to true),
        )

        assertEquals(1, result.transformedMemberCount, "Strict broad rule should virtualize monitor method instead of leaving plaintext")
    }

    @Test
    fun method_virtualization_adds_opaque_decoy_vm_resources() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val vmResources = result.artifact.jarEntries.filter { it.isVmResourceName() }
        assertTrue(result.transformedMemberCount > 0, "VM virtualization must transform the fixture method")
        assertTrue(vmResources.size > result.transformedMemberCount, "VM virtualization must emit decoy resources in addition to executable resources")
        assertTrue(vmResources.map { it.name }.toSet().size == vmResources.size, "Decoy and executable VM resources must not collide by path")
        assertTrue(vmResources.none { it.name.startsWith("__jvm/") || it.name.endsWith(".vbc") }, "Decoy VM resource layout must not keep legacy VBC4 path fingerprints")
        assertTrue(vmResources.any { it.bytes.size != vmResources.first().bytes.size }, "Decoy VM resources should include size jitter to resist resource clustering")
    }

    @Test
    fun method_virtualization_keeps_resource_names_opaque_with_fixed_handler_morphing() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val vmResources = result.artifact.jarEntries.map { it.name }.filter { it.isVmResourceName() }
        assertTrue(result.transformedMemberCount > 0, "VBC4 fixed handler morphing must allow VM virtualization")
        assertTrue(vmResources.isNotEmpty(), "VBC4 virtualization should emit VM resources")
        assertTrue(vmResources.none { it.startsWith("__jvm/") || it.endsWith(".vbc") }, "VM resource layout must not keep legacy VBC4 path fingerprints")
    }

    @Test
    fun dispatcher_stub_rebuilds_identity_constants_without_plain_constant_pool_tokens() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmThreshold").bytes
        val constants = stringConstantsInMethod(classBytes, "value", "()I")
        val resourceNames = result.artifact.jarEntries.map { it.name }.filter { it.isVmResourceName() }

        assertTrue(resourceNames.isNotEmpty(), "VM dispatch stub must still be backed by an emitted resource")
        assertTrue(ObfuscatedIdentifierUtil.classToken("example/VmThreshold") !in constants, "Dispatcher stub must not keep class token as a plain LDC constant")
        assertTrue(ObfuscatedIdentifierUtil.methodToken("value", "()I") !in constants, "Dispatcher stub must not keep method token as a plain LDC constant")
        assertTrue("()I" !in constants, "Dispatcher stub must not keep descriptor as a plain LDC constant")
        assertTrue(resourceNames.none { it in constants }, "Dispatcher stub must not keep VM resource path as a plain LDC constant")
        assertTrue(constants.isEmpty(), "The generated dispatcher stub should rebuild all identity strings at runtime. Constants=$constants")
        assertTrue(methodCallsVmDispatcherWithDescriptor(classBytes, "value", "()I", "(J[Ljava/lang/Object;)Ljava/lang/Object;"), "Hot VM dispatcher stub must use the token-only ABI.")
    }

    @Test
    fun void_dispatcher_stubs_use_specialized_token_abi_without_object_array() {
        val artifact = artifactFor(voidSpecializedClassBytes(), "example/VmSpecialized")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSpecialized"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmSpecialized").bytes
        assertTrue(
            methodCallsVmDispatcherMethodWithDescriptor(classBytes, "noop", "()V", "executeVmResourceVoid", "(J)V"),
            "Static void VM stub must use the no-args token-only void ABI.",
        )
        assertTrue(
            methodCallsVmDispatcherMethodWithDescriptor(classBytes, "acceptInt", "(I)V", "executeVmResourceIntVoid", "(JI)V"),
            "Static int-to-void VM stub must use the int-specialized token-only void ABI.",
        )
    }

    @Test
    fun strict_all_compatible_virtualizes_security_manager_permission_checks() {
        val artifact = artifactFor(securityManagerClassBytes(), "example/Sman")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/Sman"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/Sman").bytes
        assertTrue(
            methodCallsVmDispatcherWithDescriptor(classBytes, "checkPermission", "(Ljava/security/Permission;)V", "(J[Ljava/lang/Object;)Ljava/lang/Object;"),
            "SecurityManager checkPermission must be virtualized under strict all-compatible mode instead of leaking plaintext guard logic.",
        )
    }

    @Test
    fun strict_all_compatible_virtualizes_reflection_and_console_count_logic() {
        val artifact = artifactFor(
            classBytes = reflectionCountClassBytes(),
            internalName = "example/Count",
            extraClasses = mapOf("example/Countee" to counteeClassBytes()),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/Count"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/Count").bytes
        assertTrue(
            methodCallsVmDispatcherWithDescriptor(classBytes, "run", "()V", "(J[Ljava/lang/Object;)Ljava/lang/Object;"),
            "Reflection count checks mixed with console output must be virtualized under strict all-compatible mode instead of leaking plaintext branch logic.",
        )
    }
    @Test
    fun fixed_handler_morphing_emits_dispatcher_morph_block() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")
        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmThreshold").bytes
        val morphStores = countVarOpcodeInMethod(classBytes, "value", "()I", Opcodes.ISTORE)

        assertTrue(morphStores > 0, "VBC4 fixed handler morphing must emit a morph block with opaque integer ops. morphStores=$morphStores")
    }

    private fun simpleClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmThreshold", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitInsn(Opcodes.ICONST_1)
        value.visitInsn(Opcodes.ICONST_2)
        value.visitInsn(Opcodes.IADD)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(2, 0)
        value.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun voidSpecializedClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmSpecialized", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val noop = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "noop", "()V", null, null)
        noop.visitCode()
        noop.visitInsn(Opcodes.NOP)
        noop.visitInsn(Opcodes.RETURN)
        noop.visitMaxs(0, 0)
        noop.visitEnd()
        val acceptInt = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "acceptInt", "(I)V", null, null)
        acceptInt.visitCode()
        acceptInt.visitVarInsn(Opcodes.ILOAD, 0)
        acceptInt.visitInsn(Opcodes.POP)
        acceptInt.visitInsn(Opcodes.RETURN)
        acceptInt.visitMaxs(1, 1)
        acceptInt.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun securityManagerClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/Sman", null, "java/lang/SecurityManager", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/SecurityManager", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val check = writer.visitMethod(Opcodes.ACC_PUBLIC, "checkPermission", "(Ljava/security/Permission;)V", null, null)
        check.visitCode()
        check.visitLdcInsn(-79683442)
        check.visitVarInsn(Opcodes.ISTORE, 2)
        check.visitIincInsn(2, 7)
        check.visitVarInsn(Opcodes.ILOAD, 2)
        check.visitInsn(Opcodes.POP)
        check.visitInsn(Opcodes.RETURN)
        check.visitMaxs(1, 3)
        check.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun reflectionCountClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/Count", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val fail = Label()
        val end = Label()
        val run = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null)
        run.visitCode()
        run.visitLdcInsn(Type.getObjectType("example/Countee"))
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getFields", "()[Ljava/lang/reflect/Field;", false)
        run.visitInsn(Opcodes.ARRAYLENGTH)
        run.visitInsn(Opcodes.ICONST_1)
        run.visitJumpInsn(Opcodes.IF_ICMPNE, fail)
        run.visitLdcInsn(Type.getObjectType("example/Countee"))
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredFields", "()[Ljava/lang/reflect/Field;", false)
        run.visitInsn(Opcodes.ARRAYLENGTH)
        run.visitInsn(Opcodes.ICONST_4)
        run.visitJumpInsn(Opcodes.IF_ICMPNE, fail)
        run.visitLdcInsn(Type.getObjectType("example/Countee"))
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethods", "()[Ljava/lang/reflect/Method;", false)
        run.visitInsn(Opcodes.ARRAYLENGTH)
        run.visitInsn(Opcodes.ICONST_4)
        run.visitJumpInsn(Opcodes.IF_ICMPLE, fail)
        run.visitLdcInsn(Type.getObjectType("example/Countee"))
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethods", "()[Ljava/lang/reflect/Method;", false)
        run.visitInsn(Opcodes.ARRAYLENGTH)
        run.visitInsn(Opcodes.ICONST_4)
        run.visitJumpInsn(Opcodes.IF_ICMPNE, fail)
        run.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        run.visitLdcInsn("PASS")
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        run.visitJumpInsn(Opcodes.GOTO, end)
        run.visitLabel(fail)
        run.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        run.visitLdcInsn("FAIL")
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        run.visitLabel(end)
        run.visitInsn(Opcodes.RETURN)
        run.visitMaxs(2, 1)
        run.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun counteeClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/Countee", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PUBLIC, "visible", "I", null, null)?.visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE, "a", "I", null, null)?.visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE, "b", "I", null, null)?.visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE, "c", "I", null, null)?.visitEnd()
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        repeat(4) { index ->
            val method = writer.visitMethod(Opcodes.ACC_PUBLIC, "m$index", "()V", null, null)
            method.visitCode()
            method.visitInsn(Opcodes.RETURN)
            method.visitMaxs(0, 1)
            method.visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }
    private fun encryptedStringConcatClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmEncryptedConcat", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val text = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "text", "(I)Ljava/lang/String;", null, null)
        text.visitCode()
        text.visitVarInsn(Opcodes.ILOAD, 0)
        text.visitInvokeDynamicInsn(
            "makeConcatWithConstants",
            "(I)Ljava/lang/String;",
            org.objectweb.asm.Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/StringConcatFactory",
                "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                false,
            ),
            "v=\u0001",
        )
        text.visitInsn(Opcodes.ARETURN)
        text.visitMaxs(1, 1)
        text.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun twoMethodClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmThreshold", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        for ((name, valueInsn) in listOf("hot" to Opcodes.ICONST_1, "cold" to Opcodes.ICONST_2)) {
            val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, name, "()I", null, null)
            method.visitCode()
            method.visitInsn(valueInsn)
            method.visitInsn(Opcodes.IRETURN)
            method.visitMaxs(1, 0)
            method.visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun syntheticBridgeClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmSyntheticBridge", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val target = writer.visitMethod(Opcodes.ACC_PUBLIC, "call", "()Ljava/lang/Long;", null, null)
        target.visitCode()
        target.visitLdcInsn(7L)
        target.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
        target.visitInsn(Opcodes.ARETURN)
        target.visitMaxs(2, 1)
        target.visitEnd()
        val bridge = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC, "call", "()Ljava/lang/Object;", null, null)
        bridge.visitCode()
        bridge.visitVarInsn(Opcodes.ALOAD, 0)
        bridge.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "example/VmSyntheticBridge", "call", "()Ljava/lang/Long;", false)
        bridge.visitInsn(Opcodes.ARETURN)
        bridge.visitMaxs(1, 1)
        bridge.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun selectionClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmSelection", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "counter", "I", null, null).visitEnd()
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val safe = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "safeTiny", "()I", null, null)
        safe.visitCode()
        safe.visitInsn(Opcodes.ICONST_1)
        safe.visitInsn(Opcodes.IRETURN)
        safe.visitMaxs(1, 0)
        safe.visitEnd()
        val critical = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "criticalField", "()I", null, null)
        critical.visitCode()
        critical.visitFieldInsn(Opcodes.GETSTATIC, "example/VmSelection", "counter", "I")
        critical.visitInsn(Opcodes.ICONST_1)
        critical.visitInsn(Opcodes.IADD)
        critical.visitInsn(Opcodes.IRETURN)
        critical.visitMaxs(2, 0)
        critical.visitEnd()
        val compatible = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "compatibleLarge", "()I", null, null)
        compatible.visitCode()
        repeat(20) {
            compatible.visitInsn(Opcodes.ICONST_1)
            compatible.visitInsn(Opcodes.POP)
        }
        compatible.visitInsn(Opcodes.ICONST_2)
        compatible.visitInsn(Opcodes.IRETURN)
        compatible.visitMaxs(1, 0)
        compatible.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun highValueSelectionClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmHighValue", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val verify = writer.visitMethod(Opcodes.ACC_PUBLIC, "verifyLicense", "()I", null, null)
        verify.visitCode()
        verify.visitInsn(Opcodes.ICONST_1)
        verify.visitInsn(Opcodes.IRETURN)
        verify.visitMaxs(1, 1)
        verify.visitEnd()
        val plain = writer.visitMethod(Opcodes.ACC_PUBLIC, "plainValue", "()I", null, null)
        plain.visitCode()
        plain.visitInsn(Opcodes.ICONST_2)
        plain.visitInsn(Opcodes.IRETURN)
        plain.visitMaxs(1, 1)
        plain.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun mainStringArrayClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmMainArray", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val main = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        main.visitCode()
        main.visitVarInsn(Opcodes.ALOAD, 0)
        main.visitInsn(Opcodes.ARRAYLENGTH)
        val done = Label()
        main.visitJumpInsn(Opcodes.IFEQ, done)
        main.visitLabel(done)
        main.visitInsn(Opcodes.RETURN)
        main.visitMaxs(1, 1)
        main.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun publicSynchronizedClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmPublicSync", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val publicMethod = writer.visitMethod(Opcodes.ACC_PUBLIC, "publicValue", "()I", null, null)
        publicMethod.visitCode()
        publicMethod.visitInsn(Opcodes.ICONST_1)
        publicMethod.visitInsn(Opcodes.IRETURN)
        publicMethod.visitMaxs(1, 1)
        publicMethod.visitEnd()
        val synchronizedMethod = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNCHRONIZED, "syncValue", "()I", null, null)
        synchronizedMethod.visitCode()
        synchronizedMethod.visitInsn(Opcodes.ICONST_2)
        synchronizedMethod.visitInsn(Opcodes.IRETURN)
        synchronizedMethod.visitMaxs(1, 0)
        synchronizedMethod.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun staticFieldAndTypeFlowClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmStaticCast", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "counter", "I", null, null).visitEnd()
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitIntInsn(Opcodes.BIPUSH, 7)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "example/VmStaticCast", "counter", "I")
        clinit.visitInsn(Opcodes.RETURN)
        clinit.visitMaxs(1, 0)
        clinit.visitEnd()
        val readCounter = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "readCounter", "()I", null, null)
        readCounter.visitCode()
        readCounter.visitFieldInsn(Opcodes.GETSTATIC, "example/VmStaticCast", "counter", "I")
        readCounter.visitInsn(Opcodes.IRETURN)
        readCounter.visitMaxs(1, 0)
        readCounter.visitEnd()
        val castString = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "castString", "(Ljava/lang/Object;)Ljava/lang/String;", null, null)
        castString.visitCode()
        castString.visitVarInsn(Opcodes.ALOAD, 0)
        castString.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String")
        castString.visitInsn(Opcodes.ARETURN)
        castString.visitMaxs(1, 1)
        castString.visitEnd()
        val typeName = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "typeName", "(Ljava/lang/Object;)Ljava/lang/String;", null, null)
        typeName.visitCode()
        val notString = Label()
        val done = Label()
        typeName.visitVarInsn(Opcodes.ALOAD, 0)
        typeName.visitTypeInsn(Opcodes.INSTANCEOF, "java/lang/String")
        typeName.visitJumpInsn(Opcodes.IFEQ, notString)
        typeName.visitLdcInsn("string")
        typeName.visitJumpInsn(Opcodes.GOTO, done)
        typeName.visitLabel(notString)
        typeName.visitLdcInsn("other")
        typeName.visitLabel(done)
        typeName.visitInsn(Opcodes.ARETURN)
        typeName.visitMaxs(1, 1)
        typeName.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun enumValuesClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL or Opcodes.ACC_SUPER or Opcodes.ACC_ENUM, "example/VmStone", null, "java/lang/Enum", null)
        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL or Opcodes.ACC_ENUM, "A", "Lexample/VmStone;", null, null).visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL or Opcodes.ACC_SYNTHETIC, "\$VALUES", "[Lexample/VmStone;", null, null).visitEnd()
        val init = writer.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "(Ljava/lang/String;I)V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitVarInsn(Opcodes.ALOAD, 1)
        init.visitVarInsn(Opcodes.ILOAD, 2)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Enum", "<init>", "(Ljava/lang/String;I)V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(3, 3)
        init.visitEnd()
        val values = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, "\$values", "()[Lexample/VmStone;", null, null)
        values.visitCode()
        values.visitInsn(Opcodes.ICONST_1)
        values.visitTypeInsn(Opcodes.ANEWARRAY, "example/VmStone")
        values.visitInsn(Opcodes.DUP)
        values.visitInsn(Opcodes.ICONST_0)
        values.visitFieldInsn(Opcodes.GETSTATIC, "example/VmStone", "A", "Lexample/VmStone;")
        values.visitInsn(Opcodes.AASTORE)
        values.visitInsn(Opcodes.ARETURN)
        values.visitMaxs(4, 0)
        values.visitEnd()
        val ordinary = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "ordinary", "()I", null, null)
        ordinary.visitCode()
        ordinary.visitInsn(Opcodes.ICONST_1)
        ordinary.visitInsn(Opcodes.IRETURN)
        ordinary.visitMaxs(1, 0)
        ordinary.visitEnd()
        val clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitTypeInsn(Opcodes.NEW, "example/VmStone")
        clinit.visitInsn(Opcodes.DUP)
        clinit.visitLdcInsn("A")
        clinit.visitInsn(Opcodes.ICONST_0)
        clinit.visitMethodInsn(Opcodes.INVOKESPECIAL, "example/VmStone", "<init>", "(Ljava/lang/String;I)V", false)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "example/VmStone", "A", "Lexample/VmStone;")
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, "example/VmStone", "\$values", "()[Lexample/VmStone;", false)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "example/VmStone", "\$VALUES", "[Lexample/VmStone;")
        clinit.visitInsn(Opcodes.RETURN)
        clinit.visitMaxs(4, 0)
        clinit.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun runnableLambdaClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmLambda", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val run = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "make", "()Ljava/lang/Runnable;", null, null)
        run.visitCode()
        run.visitInvokeDynamicInsn(
            "run",
            "()Ljava/lang/Runnable;",
            org.objectweb.asm.Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/LambdaMetafactory",
                "metafactory",
                "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                false,
            ),
            Type.getMethodType("()V"),
            org.objectweb.asm.Handle(Opcodes.H_INVOKESTATIC, "example/VmLambda", "target", "()V", false),
            Type.getMethodType("()V"),
        )
        run.visitInsn(Opcodes.ARETURN)
        run.visitMaxs(1, 0)
        run.visitEnd()
        val target = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "target", "()V", null, null)
        target.visitCode()
        target.visitInsn(Opcodes.RETURN)
        target.visitMaxs(0, 0)
        target.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun mixedCompatibleAndUnsupportedClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmMixedUnsupported", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val ok = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "ok", "()I", null, null)
        ok.visitCode()
        ok.visitInsn(Opcodes.ICONST_1)
        ok.visitInsn(Opcodes.IRETURN)
        ok.visitMaxs(1, 0)
        ok.visitEnd()
        val monitor = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "monitor", "(Ljava/lang/Object;)V", null, null)
        monitor.visitCode()
        monitor.visitVarInsn(Opcodes.ALOAD, 0)
        monitor.visitInsn(Opcodes.MONITORENTER)
        monitor.visitVarInsn(Opcodes.ALOAD, 0)
        monitor.visitInsn(Opcodes.MONITOREXIT)
        monitor.visitInsn(Opcodes.RETURN)
        monitor.visitMaxs(1, 1)
        monitor.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun unsupportedExplicitClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmUnsupported", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "monitor", "(Ljava/lang/Object;)V", null, null)
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitInsn(Opcodes.MONITORENTER)
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitInsn(Opcodes.MONITOREXIT)
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(1, 1)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun hasMonitorEnterInMethod(classBytes: ByteArray, methodName: String, descriptor: String): Boolean {
        var hasMonitorEnter = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitInsn(insnOpcode: Int) {
                        if (insnOpcode == Opcodes.MONITORENTER) hasMonitorEnter = true
                    }
                }
            }
        }, 0)
        return hasMonitorEnter
    }

    private fun stringConstantsInMethod(classBytes: ByteArray, methodName: String, descriptor: String): List<String> {
        val constants = mutableListOf<String>()
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitLdcInsn(value: Any?) {
                        if (value is String) constants += value
                    }
                }
            }
        }, 0)
        return constants
    }

    private fun countVarOpcodeInMethod(classBytes: ByteArray, methodName: String, descriptor: String, opcode: Int): Int {
        var count = 0
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitVarInsn(insnOpcode: Int, varIndex: Int) {
                        if (insnOpcode == opcode) count++
                    }
                }
            }
        }, 0)
        return count
    }

    private fun methodHasEntryGuardField(classBytes: ByteArray): Boolean {
        var hasGuard = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitField(access: Int, name: String, descriptor: String, signature: String?, value: Any?): org.objectweb.asm.FieldVisitor? {
                if (name.startsWith("\$m\$entryGuard") && descriptor == "Z" && access and Opcodes.ACC_STATIC != 0) hasGuard = true
                return null
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return hasGuard
    }

    private fun syntheticMainHelperName(classBytes: ByteArray): String {
        var helperName: String? = null
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name.startsWith("\$m\$") && descriptor == "([Ljava/lang/String;Z)V") helperName = name
                return null
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return helperName ?: error("Synthetic migrated main helper was not emitted")
    }

    private fun methodCallsSyntheticMainHelper(classBytes: ByteArray): Boolean {
        var callsHelper = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != "main" || desc != "([Ljava/lang/String;)V") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, methodDescriptor: String, isInterface: Boolean) {
                        if (opcode == Opcodes.INVOKESTATIC && name.startsWith("\$m\$") && methodDescriptor == "([Ljava/lang/String;Z)V") callsHelper = true
                    }
                }
            }
        }, 0)
        return callsHelper
    }

    private fun methodCallsVmDispatcher(classBytes: ByteArray, methodName: String, descriptor: String): Boolean {
        return vmDispatcherDescriptors(classBytes, methodName, descriptor).isNotEmpty()
    }

    private fun methodCallsVmDispatcherWithDescriptor(classBytes: ByteArray, methodName: String, descriptor: String, dispatchDescriptor: String): Boolean {
        return dispatchDescriptor in vmDispatcherDescriptors(classBytes, methodName, descriptor)
    }

    private fun methodCallsVmDispatcherMethodWithDescriptor(
        classBytes: ByteArray,
        methodName: String,
        descriptor: String,
        dispatchMethod: String,
        dispatchDescriptor: String,
    ): Boolean {
        return dispatchMethod to dispatchDescriptor in vmDispatcherCalls(classBytes, methodName, descriptor)
    }

    private fun vmDispatcherDescriptors(classBytes: ByteArray, methodName: String, descriptor: String): List<String> {
        return vmDispatcherCalls(classBytes, methodName, descriptor).map { it.second }
    }

    private fun vmDispatcherCalls(classBytes: ByteArray, methodName: String, descriptor: String): List<Pair<String, String>> {
        val calls = mutableListOf<Pair<String, String>>()
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, methodDescriptor: String, isInterface: Boolean) {
                        if (owner.endsWith("JniMicrokernelHelper") && name.startsWith("executeVmResource")) calls += name to methodDescriptor
                    }
                }
            }
        }, 0)
        return calls
    }

    private fun artifactFor(
        classBytes: ByteArray,
        internalName: String,
        methodSummaries: List<MemberSummary> = emptyList(),
        accessFlags: Int = Opcodes.ACC_PUBLIC,
        extraClasses: Map<String, ByteArray> = emptyMap(),
    ): BytecodeArtifact {
        val summary = ClassAnalysisSummary(
            internalName = internalName,
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = accessFlags,
            fieldCount = 0,
            methodCount = methodSummaries.size,
            fieldSummaries = emptyList(),
            methodSummaries = methodSummaries,
        )
        val classArtifact = ClassArtifact(
            entryName = "$internalName.class",
            summary = summary,
            bytes = classBytes,
        )
        val extraArtifacts = extraClasses.map { (name, bytes) ->
            val extraSummary = ClassAnalysisSummary(
                internalName = name,
                superName = "java/lang/Object",
                interfaceNames = emptyList(),
                accessFlags = Opcodes.ACC_PUBLIC,
                fieldCount = 0,
                methodCount = 0,
                fieldSummaries = emptyList(),
                methodSummaries = emptyList(),
            )
            ClassArtifact(
                entryName = "$name.class",
                summary = extraSummary,
                bytes = bytes,
            )
        }
        val allArtifacts = listOf(classArtifact) + extraArtifacts
        val ruleMatches = ruleMatchesFor(internalName)
        return BytecodeArtifact(
            jarEntries = allArtifacts.map { JarEntryData(it.entryName, it.bytes) },
            classArtifacts = allArtifacts,
            classArtifactIndex = allArtifacts.associateBy { it.summary.internalName },
            analysisSummary = JarAnalysisSummary(
                classCount = allArtifacts.size,
                resourceCount = 0,
                manifestPresent = false,
                classSummaries = allArtifacts.map { it.summary },
                classNameIndex = allArtifacts.associate { it.summary.internalName to it.summary },
                ruleMatches = ruleMatches,
                renamePlan = RenamePlan(emptyList()),
            ),
        )
    }


    private data class ManifestPreloadEntry(
        val entryTokenHex: String,
        val resourcePath: String,
        val manifestPath: String,
        val shardCount: String,
    )

    private data class MeshMaterial(
        val sortKey: String,
        val material: String,
    )

    private fun manifestMeshMaterial(entry: ManifestPreloadEntry, lines: List<String>): MeshMaterial {
        val header = lines.first().split('|')
        val totalSize = header[2]
        val shards = lines.drop(1)
            .map { line ->
                val parts = line.split('|')
                "${parts[0]}|${parts[1]}|${parts[2]}|${parts[3]}|${parts[4]}"
            }
            .sortedBy { it.substringBefore('|').toInt() }
            .joinToString(separator = "\u0000")
        return MeshMaterial(
            sortKey = "${entry.manifestPath}\u0000${entry.resourcePath}",
            material = "${entry.entryTokenHex}|${entry.resourcePath}|${entry.manifestPath}|${entry.shardCount}|$totalSize\u0000$shards",
        )
    }

    private fun sha256Hex(text: String): String = MessageDigest.getInstance("SHA-256")
        .digest(text.toByteArray(Charsets.UTF_8))
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xFF) }

    private fun String.isVmResourceName(): Boolean = startsWith("META-INF/") && !endsWith(".class") && !endsWith("/") && length > "META-INF/".length + 10

    private fun JarEntryData.isVmResourceName(): Boolean = name.isVmResourceName()

    private fun ruleMatchesFor(internalName: String, action: String = "method-virtualization"): List<RuleMatch> = listOf(
        RuleMatch(
            rule = RuleSpec(target = internalName, action = action),
            selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
            matchedClassNames = listOf(internalName),
            matchedMembers = emptyList(),
        ),
    )
}
