package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildRuleMatches
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
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSetScope
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.bytecode.applyCondyConstantIndirection
import io.github.hht0rro.javashroud.bytecode.indirectMethodCalls
import io.github.hht0rro.javashroud.transforms.protection.ObfuscatedIdentifierUtil
import io.github.hht0rro.javashroud.transforms.protection.QpResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.QpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.currentQpBuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.requireQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.withQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.defaultQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization as applyMethodVirtualizationTransform
import io.github.hht0rro.javashroud.transforms.protection.MethodBodyCapture
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.bytecode.hideClassMembers
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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MethodVirtualizationThresholdTest {
    private fun applyMethodVirtualization(
        artifact: BytecodeArtifact,
        ruleMatches: List<RuleMatch>,
        params: Map<String, Any>,
    ) = if (currentQpBuildContextOrNull() != null) {
        applyMethodVirtualizationTransform(artifact = artifact, ruleMatches = ruleMatches, params = params)
    } else {
        withQpBuildContext(defaultQpBuildContext()) {
            applyMethodVirtualizationTransform(artifact = artifact, ruleMatches = ruleMatches, params = params)
        }
    }

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
    }

    @Test
    fun method_virtualization_rejects_unknown_controls() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")
        val rules = ruleMatchesFor("example/VmThreshold")

        val retired = assertFailsWith<IllegalArgumentException> {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = rules,
                params = mapOf("retiredControl" to true),
            )
        }
        assertTrue(retired.message.orEmpty().contains("unsupported"))

        val fixed = assertFailsWith<IllegalArgumentException> {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = rules,
                params = mapOf("qpStateBoundEncoding" to false),
            )
        }
        assertTrue(fixed.message.orEmpty().contains("fixed on"))
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
        val context = defaultQpBuildContext()

        val defaultHighValue = withQpBuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmHighValue"),
                params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "critical-plus", "strictVirtualization" to true),
            )
        }
        val allowPlain = withQpBuildContext(context) {
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
        val denyVerify = withQpBuildContext(context) {
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
    fun method_virtualization_high_value_methods_are_backed_by_nested_micro_stream_writer() {
        val highValueArtifact = artifactFor(highValueSelectionClassBytes(), "example/VmHighValue")
        val context = defaultQpBuildContext()

        val highValue = withQpBuildContext(context) {
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

        val serializerSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpSerializer.kt"))
        assertTrue(serializerSource.contains("serializeNestedBlock"), "Nested VM resources must be written through a second-level micro-op stream")
        assertTrue(serializerSource.contains("QP_NESTED_MAGIC"), "Nested VM resources must carry a native-validated micro-stream envelope")
        assertTrue(serializerSource.contains("nestedFieldOrder"), "Nested micro-op fields must be per-build permuted rather than plain register rows")
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
    }

    @Test
    fun method_virtualization_all_compatible_includes_static_field_and_type_flow_methods() {
        val artifact = artifactFor(staticFieldAndTypeFlowClassBytes(), "example/VmStaticCast")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmStaticCast"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(3, result.transformedMemberCount, "all-compatible strict mode must keep GETSTATIC/CHECKCAST/INSTANCEOF shapes in the native VM candidate set")
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
    fun strict_all_compatible_virtualizes_engine_generated_condy_constants() {
        val classBytes = applyCondyConstantIndirection(condyConstantsClassBytes())
        val artifact = artifactFor(classBytes, "example/VmCondyConstants")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmCondyConstants"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )
        val transformed = result.artifact.classArtifactIndex.getValue("example/VmCondyConstants").bytes

        assertTrue(result.transformedMemberCount >= 1, "strict all-compatible must keep condy-indirected constants in the virtualized set")
        assertTrue(methodCallsVmDispatcher(transformed, "value", "()I"), "Condy-bearing method should be replaced by the native VM dispatcher")
        val projectDir = Path.of(System.getProperty("user.dir"))
        val sourceRoot = if (Files.exists(projectDir.resolve("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpSerializer.kt"))) projectDir else projectDir.resolve("core-engine")
        val serializerSource = Files.readString(sourceRoot.resolve("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpSerializer.kt"))
        val nativeSource = Files.readString(sourceRoot.resolve("src/main/rust/crates/qp-vm/src/lib.rs"))
        val executorSource = Files.readString(sourceRoot.resolve("src/main/rust/crates/qp-vm/src/executor.rs"))
        assertTrue(serializerSource.contains("VM_LDC_CONDY"), "Serializer must keep a dedicated guarded ConstantDynamic LDC opcode")
        assertTrue(nativeSource.contains("LDC_CONDY") && executorSource.contains("LDC_CONDY"), "Rust VM must execute guarded ConstantDynamic LDC values")
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

        assertEquals(1, result.transformedMemberCount, "The lambda factory may be virtualized while the SAM callback remains a JVM boundary")
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
    }

    @Test
    fun method_virtualization_treats_zero_instruction_threshold_as_unbounded() {
        val artifact = artifactFor(selectionClassBytes(), "example/VmSelection")

        assertFailsWith<IllegalArgumentException> {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmSelection"),
                params = mapOf("maxInstructions" to 1, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
            )
        }
        val unbounded = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSelection"),
            params = mapOf("maxInstructions" to 0, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        assertEquals(3, unbounded.transformedMemberCount, "Workbench maxInstructions=0 must mean unbounded, not a one-instruction cap")
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
    fun selected_only_class_scope_honors_broad_method_cap_in_actual_transform() {
        val artifact = artifactFor(
            classBytes = selectionClassBytes(),
            internalName = "example/VmSelection",
            methodSummaries = selectionClassMethodSummaries(),
        )
        val selectedOnlyMatches = selectedOnlyRuleMatches(
            artifact = artifact,
            rules = listOf(RuleSpec("*", "method-virtualization")),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = selectedOnlyMatches,
            params = mapOf(
                "maxInstructions" to 100,
                "seed" to 42,
                "methodSelection" to "all-compatible",
                "strictVirtualization" to true,
                "maxBroadVirtualizedMethods" to 1,
            ),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmSelection").bytes
        assertEquals(1, result.transformedMemberCount, "selected-only class ranges must still honor maxBroadVirtualizedMethods")
        assertTrue(methodCallsVmDispatcher(classBytes, "safeTiny", "()I"), "The first compatible class-scoped method should be virtualized within the cap")
        assertTrue(!methodCallsVmDispatcher(classBytes, "criticalField", "()I"), "Class-scoped methods beyond the cap must remain direct")
        assertTrue(!methodCallsVmDispatcher(classBytes, "compatibleLarge", "()I"), "Class-scoped methods beyond the cap must remain direct")
    }

    @Test
    fun selected_only_independent_scope_excludes_local_method_without_global_rules() {
        val artifact = artifactFor(
            classBytes = selectionClassBytes(),
            internalName = "example/VmSelection",
            methodSummaries = selectionClassMethodSummaries(),
        )
        val selectedOnlyMatches = selectedOnlyRuleMatches(
            artifact = artifact,
            rules = listOf(
                RuleSpec("*", "method-virtualization"),
                RuleSpec("example/VmSelection#compatibleLarge:()I", "exclude"),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = selectedOnlyMatches,
            params = mapOf(
                "maxInstructions" to 100,
                "seed" to 42,
                "methodSelection" to "all-compatible",
                "strictVirtualization" to true,
                "maxBroadVirtualizedMethods" to 0,
            ),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmSelection").bytes
        assertEquals(2, result.transformedMemberCount, "independent scope exclusions must remove only their exact local method")
        assertTrue(methodCallsVmDispatcher(classBytes, "safeTiny", "()I"), "An unexcluded method must remain in the independent scope")
        assertTrue(methodCallsVmDispatcher(classBytes, "criticalField", "()I"), "An unexcluded sibling must remain in the independent scope")
        assertTrue(!methodCallsVmDispatcher(classBytes, "compatibleLarge", "()I"), "The explicitly excluded method must remain direct")
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
        assertTrue(source.contains("method-virtualization-key-stream-v1"), "Method key material must use a CSPRNG stream personalized by the native VM context, not the user-seeded structural RNG")
        assertTrue(source.contains("VmEntropyPlan.method(keyRandom"), "Per-method VM entropy must come from the build-local CSPRNG")
        assertTrue(!source.lines().any { it.contains("= methodKeySeed(random)") }, "Per-method VM seeds must not be reproducible from the user-visible seed")
        assertTrue(!source.contains("xor className.hashCode()") && !source.contains("xor methodName.hashCode()"), "Method seeds must not be derived from known class or method names")
        assertTrue(nativeKernelSource.contains("val nativeKeyRandom = java.security.SecureRandom()"), "Native kernel VM key material must use an independent CSPRNG")
        assertTrue(nativeKernelSource.contains("methodKeySeed(nativeKeyRandom)"), "Native kernel VM method seeds must come from nativeKeyRandom")
        assertTrue(!nativeKernelSource.contains("diversificationSeed xor") && !nativeKernelSource.contains("internalName.hashCode()"), "Native kernel VM seeds must not mix known class names into user-visible seeds")
        assertTrue(!nativeKernelSource.lines().any { it.contains("= methodKeySeed(random)") }, "Native kernel VM resource seeds must not come from user-seeded structural RNG")
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

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmThreshold").bytes
        assertEquals(1, result.transformedMemberCount, "Method-level rule should virtualize only the selected method")
        assertTrue(methodCallsVmDispatcher(classBytes, "hot", "()I"))
        assertFalse(methodCallsVmDispatcher(classBytes, "cold", "()I"))
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
    fun method_virtualization_keeps_resource_names_opaque_with_fixed_handler_morphing() {
        val artifact = artifactFor(simpleClassBytes(), "example/VmThreshold")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmThreshold"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val vmResources = result.artifact.jarEntries.map { it.name }.filter { it.isVmResourceName() }
        assertTrue(result.transformedMemberCount > 0, "Fixed handler morphing must allow VM virtualization")
        assertTrue(vmResources.isEmpty(), "Current method virtualization must stage Qp candidates instead of legacy standalone VM resources")
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

        assertTrue(ObfuscatedIdentifierUtil.classToken("example/VmThreshold") !in constants, "Dispatcher stub must not keep class token as a plain LDC constant")
        assertTrue(ObfuscatedIdentifierUtil.methodToken("value", "()I") !in constants, "Dispatcher stub must not keep method token as a plain LDC constant")
        assertTrue("()I" !in constants, "Dispatcher stub must not keep descriptor as a plain LDC constant")
        assertTrue(resourceNames.none { it in constants }, "Dispatcher stub must not keep VM resource path as a plain LDC constant")
        assertTrue(constants.isEmpty(), "The generated dispatcher stub should rebuild all identity strings at runtime. Constants=$constants")
        assertTrue(
            methodCallsVmDispatcherMethodWithDescriptor(
                classBytes,
                "value",
                "()I",
                "executeQpVmPage",
                "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            ),
            "VM dispatcher stubs must use the authenticated current Qp page ABI.",
        )
    }

    @Test
    fun dispatcher_stubs_use_authenticated_current_native_page_abi() {
        val artifact = artifactFor(voidSpecializedClassBytes(), "example/VmSpecialized")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/VmSpecialized"),
            params = mapOf("maxInstructions" to 100, "seed" to 42),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/VmSpecialized").bytes
        val currentDescriptor = "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;"
        listOf(
            "noop" to "()V",
            "acceptInt" to "(I)V",
            "value" to "()I",
            "hot" to "(I)I",
        ).forEach { (name, descriptor) ->
            assertTrue(
                methodCallsVmDispatcherMethodWithDescriptor(
                    classBytes,
                    name,
                    descriptor,
                    "executeQpVmPage",
                    currentDescriptor,
                ),
                "$name$descriptor must use the current authenticated Qp Object[] bridge.",
            )
        }
    }

    @Test
    fun strict_all_compatible_preserves_security_manager_permission_boundary() {
        val artifact = artifactFor(securityManagerClassBytes(), "example/Sman")

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/Sman"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/Sman").bytes
        assertFalse(
            methodCallsVmDispatcher(classBytes, "checkPermission", "(Ljava/security/Permission;)V"),
            "SecurityManager permission checks must remain a JVM boundary so SecurityException semantics are preserved.",
        )
    }

    @Test
    fun strict_all_compatible_preserves_reflection_and_console_boundary() {
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
        assertFalse(
            methodCallsVmDispatcher(classBytes, "run", "()V"),
            "Reflection and console interaction must remain on the JVM boundary for exact host semantics.",
        )
    }

    @Test
    fun all_compatible_preserves_elapsed_time_benchmark_root_boundary() {
        val artifact = artifactFor(
            classBytes = elapsedTimeBenchmarkClassBytes(),
            internalName = "example/BenchCalc",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "runAll", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                MemberSummary(MemberKind.METHOD, "call", "(I)V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                MemberSummary(MemberKind.METHOD, "runAdd", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                MemberSummary(MemberKind.METHOD, "runStr", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                MemberSummary(MemberKind.METHOD, "touch", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/BenchCalc"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/BenchCalc").bytes
        assertFalse(methodCallsVmDispatcher(classBytes, "runAll", "()V"), "The elapsed-time root must remain a JVM boundary to avoid distorting the measured loop")
        listOf("call" to "(I)V", "runAdd" to "()V", "runStr" to "()V", "touch" to "()V").forEach { (name, descriptor) ->
            assertTrue(
                methodCallsVmDispatcher(classBytes, name, descriptor),
                "$name$descriptor must still be virtualized after member-hide marks it synthetic",
            )
        }
    }

    @Test
    fun all_compatible_virtualizes_member_hide_synthetic_compute_helpers() {
        val artifact = artifactFor(
            classBytes = elapsedTimeBenchmarkClassBytes(syntheticHelpers = true),
            internalName = "example/BenchCalc",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "runAll", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC),
                MemberSummary(MemberKind.METHOD, "call", "(I)V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC),
                MemberSummary(MemberKind.METHOD, "runAdd", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC),
                MemberSummary(MemberKind.METHOD, "runStr", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC),
                MemberSummary(MemberKind.METHOD, "touch", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/BenchCalc"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/BenchCalc").bytes
        assertFalse(methodCallsVmDispatcher(classBytes, "runAll", "()V"), "The elapsed-time root must remain a JVM boundary even after member-hide")
        listOf("call" to "(I)V", "runAdd" to "()V", "runStr" to "()V", "touch" to "()V").forEach { (name, descriptor) ->
            assertTrue(
                methodCallsVmDispatcher(classBytes, name, descriptor),
                "$name$descriptor must be virtualized even when member-hide set ACC_SYNTHETIC",
            )
        }
    }

    @Test
    fun official_pool_lambda_implementation_stays_on_jvm() {
        val classBytes = officialResourceBytes("pack/tests/basics/runable/Task.class")
        val artifact = artifactFor(
            classBytes = classBytes,
            internalName = "pack/tests/basics/runable/Task",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "run", "()V", Opcodes.ACC_PUBLIC),
                MemberSummary(
                    MemberKind.METHOD,
                    "lambda\$run\$0",
                    "(Lpack/tests/basics/runable/Exec;)V",
                    Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
                ),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("pack/tests/basics/runable/Task"),
            params = mapOf(
                "maxInstructions" to 0,
                "seed" to 42,
                "methodSelection" to "all-compatible",
                "strictVirtualization" to true,
                "maxBroadVirtualizedMethods" to 0,
            ),
        )

        val transformed = result.artifact.classArtifactIndex.getValue("pack/tests/basics/runable/Task").bytes
        assertFalse(
            methodCallsVmDispatcher(transformed, "lambda\$run\$0", "(Lpack/tests/basics/runable/Exec;)V"),
            "LambdaMetafactory implementation of Task.run must stay on the JVM",
        )
        assertFalse(methodCallsVmDispatcher(transformed, "run", "()V"), "Task.run is a thread-pool timing root and must stay on the JVM")
    }

    @Test
    fun renamed_lambda_implementation_handle_stays_on_jvm() {
        val classBytes = renameOfficialTaskLambda("renamedPoolWorker")
        val artifact = artifactFor(
            classBytes = classBytes,
            internalName = "pack/tests/basics/runable/Task",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "run", "()V", Opcodes.ACC_PUBLIC),
                MemberSummary(
                    MemberKind.METHOD,
                    "renamedPoolWorker",
                    "(Lpack/tests/basics/runable/Exec;)V",
                    Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
                ),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("pack/tests/basics/runable/Task"),
            params = mapOf(
                "maxInstructions" to 0,
                "seed" to 42,
                "methodSelection" to "all-compatible",
                "strictVirtualization" to true,
                "maxBroadVirtualizedMethods" to 0,
            ),
        )

        val transformed = result.artifact.classArtifactIndex.getValue("pack/tests/basics/runable/Task").bytes
        assertFalse(
            methodCallsVmDispatcher(transformed, "renamedPoolWorker", "(Lpack/tests/basics/runable/Exec;)V"),
            "A renamed LambdaMetafactory implementation must still stay on the JVM",
        )
    }

    @Test
    fun official_calc_keeps_runAll_on_jvm_and_virtualizes_private_helpers() {
        val classBytes = officialCalcClassBytes()
        val artifact = artifactFor(
            classBytes = classBytes,
            internalName = "pack/tests/bench/Calc",
            methodSummaries = officialCalcMethodSummaries(),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("pack/tests/bench/Calc"),
            params = mapOf(
                "maxInstructions" to 0,
                "seed" to 42,
                "methodSelection" to "all-compatible",
                "strictVirtualization" to true,
                "maxBroadVirtualizedMethods" to 0,
            ),
        )

        val transformed = result.artifact.classArtifactIndex.getValue("pack/tests/bench/Calc").bytes
        assertFalse(methodCallsVmDispatcher(transformed, "runAll", "()V"), "Official Calc.runAll must remain the elapsed-time JVM boundary")
        listOf("call" to "(I)V", "runAdd" to "()V", "runStr" to "()V").forEach { (name, descriptor) ->
            assertTrue(
                methodCallsVmDispatcher(transformed, name, descriptor),
                "Official Calc.$name$descriptor must be virtualized",
            )
        }
    }

    @Test
    fun official_calc_still_virtualizes_helpers_after_member_hide() {
        val hidden = hideClassMembers(officialCalcClassBytes())
        val artifact = artifactFor(
            classBytes = hidden,
            internalName = "pack/tests/bench/Calc",
            methodSummaries = officialCalcMethodSummaries(synthetic = true),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("pack/tests/bench/Calc"),
            params = mapOf(
                "maxInstructions" to 0,
                "seed" to 42,
                "methodSelection" to "all-compatible",
                "strictVirtualization" to true,
                "maxBroadVirtualizedMethods" to 0,
            ),
        )

        val transformed = result.artifact.classArtifactIndex.getValue("pack/tests/bench/Calc").bytes
        assertFalse(methodCallsVmDispatcher(transformed, "runAll", "()V"), "Official Calc.runAll must stay on the JVM after member-hide")
        listOf("call" to "(I)V", "runAdd" to "()V", "runStr" to "()V").forEach { (name, descriptor) ->
            assertTrue(
                methodCallsVmDispatcher(transformed, name, descriptor),
                "Official Calc.$name$descriptor must still be virtualized after member-hide ACC_SYNTHETIC",
            )
        }
    }

    @Test
    fun official_calc_helpers_fold_to_static_count_increment() {
        val classBytes = officialCalcClassBytes()
        assertEquals(5, foldedOfficialCalcInstructionCount(classBytes, "runAdd", "()V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC))
        assertEquals(5, foldedOfficialCalcInstructionCount(classBytes, "runStr", "()V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC))
        assertEquals(5, foldedOfficialCalcInstructionCount(classBytes, "call", "(I)V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC))
    }

    @Test
    fun all_compatible_preserves_real_thread_pool_timing_root() {
        val artifact = artifactFor(
            classBytes = realTaskLikeThreadPoolClassBytes(),
            internalName = "example/TaskLike",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "run", "()V", Opcodes.ACC_PUBLIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/TaskLike"),
            params = mapOf("maxInstructions" to 400, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/TaskLike").bytes
        assertFalse(methodCallsVmDispatcher(classBytes, "run", "()V"), "ThreadPoolExecutor timing roots must remain a JVM boundary")
    }

    @Test
    fun critical_auto_preserves_sleeping_worker_methods() {
        val artifact = artifactFor(
            classBytes = sleepingWorkerClassBytes(),
            internalName = "example/SleepingWorker",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "work", "()V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/SleepingWorker"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "critical-auto", "strictVirtualization" to false),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/SleepingWorker").bytes
        assertFalse(methodCallsVmDispatcher(classBytes, "work", "()V"), "critical-auto must leave sleeping worker callbacks on the JVM timing boundary")
    }

    @Test
    fun all_compatible_preserves_thread_pool_timing_root_after_indy_indirection() {
        val artifact = artifactFor(
            classBytes = indirectMethodCalls(realTaskLikeThreadPoolClassBytes()),
            internalName = "example/TaskLike",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "run", "()V", Opcodes.ACC_PUBLIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/TaskLike"),
            params = mapOf("maxInstructions" to 400, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/TaskLike").bytes
        assertFalse(methodCallsVmDispatcher(classBytes, "run", "()V"), "Indy-wrapped Thread.sleep/ThreadPoolExecutor roots must remain a JVM boundary")
        val node = org.objectweb.asm.tree.ClassNode()
        ClassReader(classBytes).accept(node, ClassReader.SKIP_FRAMES)
        assertTrue(
            node.methods.orEmpty().flatMap { it.instructions?.toArray()?.asList().orEmpty() }
                .none { it is org.objectweb.asm.tree.InvokeDynamicInsnNode && it.name == "sleep" },
            "Thread.sleep must remain a direct JVM call rather than an indy timing boundary",
        )
    }

    @Test
    fun all_compatible_preserves_class_loader_resource_boundary_methods() {
        val artifact = artifactFor(
            classBytes = classLoaderBoundaryClassBytes(),
            internalName = "example/BoundaryLoader",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;", Opcodes.ACC_PUBLIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/BoundaryLoader"),
            params = mapOf("maxInstructions" to 400, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/BoundaryLoader").bytes
        assertFalse(methodCallsVmDispatcher(classBytes, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;"), "ClassLoader lookup and resource boundaries must remain direct JVM code")
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

        assertTrue(morphStores > 0, "Fixed handler morphing must emit a morph block with opaque integer ops. morphStores=$morphStores")
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

    private fun condyConstantsClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/VmCondyConstants", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitLdcInsn("abc")
        value.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false)
        value.visitLdcInsn(4)
        value.visitInsn(Opcodes.IADD)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(2, 0)
        value.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun officialResourceBytes(path: String): ByteArray {
        val stream = requireNotNull(javaClass.getResourceAsStream("/official-test-jar/$path")) {
            "Official TEST.jar fixture is missing: $path"
        }
        return stream.use { it.readBytes() }
    }

    private fun officialCalcClassBytes(): ByteArray = officialResourceBytes("pack/tests/bench/Calc.class")

    private fun renameOfficialTaskLambda(newName: String): ByteArray {
        val node = org.objectweb.asm.tree.ClassNode()
        ClassReader(officialResourceBytes("pack/tests/basics/runable/Task.class")).accept(node, 0)
        val oldName = "lambda\$run\$0"
        for (method in node.methods) {
            if (method.name == oldName) method.name = newName
            method.instructions?.forEach { instruction ->
                when (instruction) {
                    is org.objectweb.asm.tree.InvokeDynamicInsnNode -> {
                        instruction.bsmArgs = instruction.bsmArgs.map { argument ->
                            val handle = argument as? org.objectweb.asm.Handle ?: return@map argument
                            if (handle.owner == node.name && handle.name == oldName) {
                                org.objectweb.asm.Handle(handle.tag, handle.owner, newName, handle.desc, handle.isInterface)
                            } else {
                                argument
                            }
                        }.toTypedArray()
                    }
                    is org.objectweb.asm.tree.MethodInsnNode -> {
                        if (instruction.owner == node.name && instruction.name == oldName) instruction.name = newName
                    }
                }
            }
        }
        val writer = org.objectweb.asm.ClassWriter(0)
        node.accept(writer)
        return writer.toByteArray()
    }

    private fun officialCalcMethodSummaries(synthetic: Boolean = false): List<MemberSummary> {
        val extra = if (synthetic) Opcodes.ACC_SYNTHETIC else 0
        return listOf(
            MemberSummary(MemberKind.METHOD, "runAll", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or extra),
            MemberSummary(MemberKind.METHOD, "call", "(I)V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or extra),
            MemberSummary(MemberKind.METHOD, "runAdd", "()V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or extra),
            MemberSummary(MemberKind.METHOD, "runStr", "()V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or extra),
        )
    }

    private fun foldedOfficialCalcInstructionCount(
        classBytes: ByteArray,
        methodName: String,
        descriptor: String,
        access: Int,
    ): Int {
        val capture = MethodBodyCapture()
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                visitedAccess: Int,
                name: String,
                desc: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? = if (name == methodName && desc == descriptor) capture else null
        }, 0)
        capture.optimizeWithQpCompiler("pack/tests/bench/Calc", methodName, descriptor, access)
        return capture.instructionCount
    }

    private fun elapsedTimeBenchmarkClassBytes(syntheticHelpers: Boolean = false): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/BenchCalc", null, "java/lang/Object", null)
        val helperAccess = Opcodes.ACC_STATIC or if (syntheticHelpers) Opcodes.ACC_SYNTHETIC else 0

        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "count", "I", null, null).visitEnd()

        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val call = writer.visitMethod(Opcodes.ACC_PRIVATE or helperAccess, "call", "(I)V", null, null)
        call.visitCode()
        val recurse = Label()
        val done = Label()
        call.visitVarInsn(Opcodes.ILOAD, 0)
        call.visitJumpInsn(Opcodes.IFNE, recurse)
        call.visitFieldInsn(Opcodes.GETSTATIC, "example/BenchCalc", "count", "I")
        call.visitInsn(Opcodes.ICONST_1)
        call.visitInsn(Opcodes.IADD)
        call.visitFieldInsn(Opcodes.PUTSTATIC, "example/BenchCalc", "count", "I")
        call.visitJumpInsn(Opcodes.GOTO, done)
        call.visitLabel(recurse)
        call.visitVarInsn(Opcodes.ILOAD, 0)
        call.visitInsn(Opcodes.ICONST_1)
        call.visitInsn(Opcodes.ISUB)
        call.visitMethodInsn(Opcodes.INVOKESTATIC, "example/BenchCalc", "call", "(I)V", false)
        call.visitLabel(done)
        call.visitInsn(Opcodes.RETURN)
        call.visitMaxs(2, 1)
        call.visitEnd()

        val runAdd = writer.visitMethod(Opcodes.ACC_PUBLIC or helperAccess, "runAdd", "()V", null, null)
        runAdd.visitCode()
        runAdd.visitInsn(Opcodes.DCONST_0)
        runAdd.visitVarInsn(Opcodes.DSTORE, 0)
        val addLoop = Label()
        val addDone = Label()
        runAdd.visitLabel(addLoop)
        runAdd.visitVarInsn(Opcodes.DLOAD, 0)
        runAdd.visitLdcInsn(100.1)
        runAdd.visitInsn(Opcodes.DCMPG)
        runAdd.visitJumpInsn(Opcodes.IFGE, addDone)
        runAdd.visitVarInsn(Opcodes.DLOAD, 0)
        runAdd.visitLdcInsn(0.99)
        runAdd.visitInsn(Opcodes.DADD)
        runAdd.visitVarInsn(Opcodes.DSTORE, 0)
        runAdd.visitJumpInsn(Opcodes.GOTO, addLoop)
        runAdd.visitLabel(addDone)
        runAdd.visitFieldInsn(Opcodes.GETSTATIC, "example/BenchCalc", "count", "I")
        runAdd.visitInsn(Opcodes.ICONST_1)
        runAdd.visitInsn(Opcodes.IADD)
        runAdd.visitFieldInsn(Opcodes.PUTSTATIC, "example/BenchCalc", "count", "I")
        runAdd.visitInsn(Opcodes.RETURN)
        runAdd.visitMaxs(4, 2)
        runAdd.visitEnd()

        val runStr = writer.visitMethod(Opcodes.ACC_PUBLIC or helperAccess, "runStr", "()V", null, null)
        runStr.visitCode()
        runStr.visitLdcInsn("")
        runStr.visitVarInsn(Opcodes.ASTORE, 0)
        val strLoop = Label()
        val strDone = Label()
        runStr.visitLabel(strLoop)
        runStr.visitVarInsn(Opcodes.ALOAD, 0)
        runStr.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false)
        runStr.visitIntInsn(Opcodes.BIPUSH, 101)
        runStr.visitJumpInsn(Opcodes.IF_ICMPGE, strDone)
        runStr.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
        runStr.visitInsn(Opcodes.DUP)
        runStr.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)
        runStr.visitVarInsn(Opcodes.ALOAD, 0)
        runStr.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
        runStr.visitLdcInsn("ax")
        runStr.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
        runStr.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
        runStr.visitVarInsn(Opcodes.ASTORE, 0)
        runStr.visitJumpInsn(Opcodes.GOTO, strLoop)
        runStr.visitLabel(strDone)
        runStr.visitFieldInsn(Opcodes.GETSTATIC, "example/BenchCalc", "count", "I")
        runStr.visitInsn(Opcodes.ICONST_1)
        runStr.visitInsn(Opcodes.IADD)
        runStr.visitFieldInsn(Opcodes.PUTSTATIC, "example/BenchCalc", "count", "I")
        runStr.visitInsn(Opcodes.RETURN)
        runStr.visitMaxs(3, 1)
        runStr.visitEnd()

        val touch = writer.visitMethod(Opcodes.ACC_PUBLIC or helperAccess, "touch", "()V", null, null)
        touch.visitCode()
        touch.visitFieldInsn(Opcodes.GETSTATIC, "example/BenchCalc", "count", "I")
        touch.visitInsn(Opcodes.ICONST_1)
        touch.visitInsn(Opcodes.IADD)
        touch.visitFieldInsn(Opcodes.PUTSTATIC, "example/BenchCalc", "count", "I")
        touch.visitInsn(Opcodes.RETURN)
        touch.visitMaxs(2, 0)
        touch.visitEnd()

        val runAll = writer.visitMethod(Opcodes.ACC_PUBLIC or helperAccess, "runAll", "()V", null, null)
        runAll.visitCode()
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false)
        runAll.visitVarInsn(Opcodes.LSTORE, 0)
        runAll.visitInsn(Opcodes.ICONST_0)
        runAll.visitVarInsn(Opcodes.ISTORE, 2)
        val loopStart = Label()
        val loopExit = Label()
        runAll.visitLabel(loopStart)
        runAll.visitVarInsn(Opcodes.ILOAD, 2)
        runAll.visitIntInsn(Opcodes.SIPUSH, 1000)
        runAll.visitJumpInsn(Opcodes.IF_ICMPGE, loopExit)
        runAll.visitIntInsn(Opcodes.BIPUSH, 100)
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "example/BenchCalc", "call", "(I)V", false)
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "example/BenchCalc", "runAdd", "()V", false)
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "example/BenchCalc", "runStr", "()V", false)
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "example/BenchCalc", "touch", "()V", false)
        runAll.visitIincInsn(2, 1)
        runAll.visitJumpInsn(Opcodes.GOTO, loopStart)
        runAll.visitLabel(loopExit)
        runAll.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        runAll.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
        runAll.visitInsn(Opcodes.DUP)
        runAll.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)
        runAll.visitLdcInsn("Calc: ")
        runAll.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
        runAll.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false)
        runAll.visitVarInsn(Opcodes.LLOAD, 0)
        runAll.visitInsn(Opcodes.LSUB)
        runAll.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(J)Ljava/lang/StringBuilder;", false)
        runAll.visitLdcInsn("ms")
        runAll.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
        runAll.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
        runAll.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        val ok = Label()
        runAll.visitFieldInsn(Opcodes.GETSTATIC, "example/BenchCalc", "count", "I")
        runAll.visitIntInsn(Opcodes.SIPUSH, 4000)
        runAll.visitJumpInsn(Opcodes.IF_ICMPEQ, ok)
        runAll.visitTypeInsn(Opcodes.NEW, "java/lang/RuntimeException")
        runAll.visitInsn(Opcodes.DUP)
        runAll.visitLdcInsn("[ERROR]: Errors occurred in calc!")
        runAll.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "(Ljava/lang/String;)V", false)
        runAll.visitInsn(Opcodes.ATHROW)
        runAll.visitLabel(ok)
        runAll.visitInsn(Opcodes.RETURN)
        runAll.visitMaxs(5, 3)
        runAll.visitEnd()

        val clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitInsn(Opcodes.ICONST_0)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "example/BenchCalc", "count", "I")
        clinit.visitInsn(Opcodes.RETURN)
        clinit.visitMaxs(1, 0)
        clinit.visitEnd()

        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classLoaderBoundaryClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/BoundaryLoader", null, "java/lang/ClassLoader", null)

        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/ClassLoader", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val method = writer.visitMethod(Opcodes.ACC_PUBLIC, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;", null, null)
        method.visitCode()
        method.visitLdcInsn(Type.getObjectType("example/BoundaryLoader"))
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;", false)
        method.visitLdcInsn("example/BoundaryLoader.class")
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false)
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "example/BoundaryLoader", "readAllBytes", "(Ljava/io/InputStream;)[B", false)
        method.visitVarInsn(Opcodes.ASTORE, 2)
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitVarInsn(Opcodes.ALOAD, 2)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitVarInsn(Opcodes.ALOAD, 2)
        method.visitInsn(Opcodes.ARRAYLENGTH)
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "example/BoundaryLoader", "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;", false)
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(6, 3)
        method.visitEnd()

        val readAllBytes = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "readAllBytes", "(Ljava/io/InputStream;)[B", null, null)
        readAllBytes.visitCode()
        readAllBytes.visitInsn(Opcodes.ACONST_NULL)
        readAllBytes.visitInsn(Opcodes.ARETURN)
        readAllBytes.visitMaxs(1, 1)
        readAllBytes.visitEnd()

        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun sleepingWorkerClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/SleepingWorker", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val work = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "work", "()V", null, null)
        work.visitCode()
        work.visitLdcInsn(200L)
        work.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "sleep", "(J)V", false)
        work.visitInsn(Opcodes.RETURN)
        work.visitMaxs(2, 0)
        work.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun realTaskLikeThreadPoolClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/TaskLike", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "score", "I", null, null).visitEnd()
        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "tpe", "Ljava/util/concurrent/ThreadPoolExecutor;", null, null).visitEnd()

        val lambda = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "lambda${'$'}run${'$'}0", "(I)V", null, null)
        lambda.visitCode()
        lambda.visitFieldInsn(Opcodes.GETSTATIC, "example/TaskLike", "score", "I")
        lambda.visitVarInsn(Opcodes.ILOAD, 0)
        lambda.visitInsn(Opcodes.IADD)
        lambda.visitFieldInsn(Opcodes.PUTSTATIC, "example/TaskLike", "score", "I")
        lambda.visitInsn(Opcodes.RETURN)
        lambda.visitMaxs(2, 1)
        lambda.visitEnd()

        val run = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, arrayOf("java/lang/Exception"))
        run.visitCode()
        val sleep1Start = Label()
        val sleep1End = Label()
        val sleep1Handler = Label()
        val sleep2Start = Label()
        val sleep2End = Label()
        val sleep2Handler = Label()
        val rejectStart = Label()
        val rejectEnd = Label()
        val rejectHandler = Label()
        val fail = Label()
        val done = Label()
        run.visitTryCatchBlock(sleep1Start, sleep1End, sleep1Handler, "java/lang/InterruptedException")
        run.visitTryCatchBlock(sleep2Start, sleep2End, sleep2Handler, "java/lang/InterruptedException")
        run.visitTryCatchBlock(rejectStart, rejectEnd, rejectHandler, "java/util/concurrent/RejectedExecutionException")

        run.visitLabel(rejectStart)
        run.visitFieldInsn(Opcodes.GETSTATIC, "example/TaskLike", "tpe", "Ljava/util/concurrent/ThreadPoolExecutor;")
        run.visitInsn(Opcodes.ICONST_3)
        run.visitInvokeDynamicInsn(
            "run",
            "(I)Ljava/lang/Runnable;",
            org.objectweb.asm.Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/LambdaMetafactory",
                "metafactory",
                "(Ljava/lang/invoke/MethodHandles${'$'}Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                false,
            ),
            Type.getMethodType("()V"),
            org.objectweb.asm.Handle(Opcodes.H_INVOKESTATIC, "example/TaskLike", "lambda${'$'}run${'$'}0", "(I)V", false),
            Type.getMethodType("()V"),
        )
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/ThreadPoolExecutor", "submit", "(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;", false)
        run.visitInsn(Opcodes.POP)

        run.visitLabel(sleep1Start)
        run.visitLdcInsn(50L)
        run.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "sleep", "(J)V", false)
        run.visitLabel(sleep1End)
        val afterSleep1 = Label()
        run.visitJumpInsn(Opcodes.GOTO, afterSleep1)
        run.visitLabel(sleep1Handler)
        run.visitVarInsn(Opcodes.ASTORE, 1)
        run.visitLabel(afterSleep1)

        run.visitFieldInsn(Opcodes.GETSTATIC, "example/TaskLike", "tpe", "Ljava/util/concurrent/ThreadPoolExecutor;")
        run.visitInsn(Opcodes.ICONST_2)
        run.visitInvokeDynamicInsn(
            "run",
            "(I)Ljava/lang/Runnable;",
            org.objectweb.asm.Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/LambdaMetafactory",
                "metafactory",
                "(Ljava/lang/invoke/MethodHandles${'$'}Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                false,
            ),
            Type.getMethodType("()V"),
            org.objectweb.asm.Handle(Opcodes.H_INVOKESTATIC, "example/TaskLike", "lambda${'$'}run${'$'}0", "(I)V", false),
            Type.getMethodType("()V"),
        )
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/ThreadPoolExecutor", "submit", "(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;", false)
        run.visitInsn(Opcodes.POP)

        run.visitLabel(sleep2Start)
        run.visitLdcInsn(50L)
        run.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "sleep", "(J)V", false)
        run.visitLabel(sleep2End)
        val afterSleep2 = Label()
        run.visitJumpInsn(Opcodes.GOTO, afterSleep2)
        run.visitLabel(sleep2Handler)
        run.visitVarInsn(Opcodes.ASTORE, 1)
        run.visitLabel(afterSleep2)

        run.visitFieldInsn(Opcodes.GETSTATIC, "example/TaskLike", "tpe", "Ljava/util/concurrent/ThreadPoolExecutor;")
        run.visitIntInsn(Opcodes.BIPUSH, 100)
        run.visitInvokeDynamicInsn(
            "run",
            "(I)Ljava/lang/Runnable;",
            org.objectweb.asm.Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/LambdaMetafactory",
                "metafactory",
                "(Ljava/lang/invoke/MethodHandles${'$'}Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                false,
            ),
            Type.getMethodType("()V"),
            org.objectweb.asm.Handle(Opcodes.H_INVOKESTATIC, "example/TaskLike", "lambda${'$'}run${'$'}0", "(I)V", false),
            Type.getMethodType("()V"),
        )
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/ThreadPoolExecutor", "submit", "(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;", false)
        run.visitInsn(Opcodes.POP)
        run.visitLabel(rejectEnd)
        val afterReject = Label()
        run.visitJumpInsn(Opcodes.GOTO, afterReject)
        run.visitLabel(rejectHandler)
        run.visitVarInsn(Opcodes.ASTORE, 1)
        run.visitFieldInsn(Opcodes.GETSTATIC, "example/TaskLike", "score", "I")
        run.visitIntInsn(Opcodes.BIPUSH, 10)
        run.visitInsn(Opcodes.IADD)
        run.visitFieldInsn(Opcodes.PUTSTATIC, "example/TaskLike", "score", "I")
        run.visitLabel(afterReject)

        run.visitLdcInsn(300L)
        run.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "sleep", "(J)V", false)
        run.visitFieldInsn(Opcodes.GETSTATIC, "example/TaskLike", "score", "I")
        run.visitIntInsn(Opcodes.BIPUSH, 30)
        run.visitJumpInsn(Opcodes.IF_ICMPNE, fail)
        run.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        run.visitLdcInsn("PASS")
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        run.visitJumpInsn(Opcodes.GOTO, done)
        run.visitLabel(fail)
        run.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        run.visitLdcInsn("FAIL")
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        run.visitLabel(done)
        run.visitInsn(Opcodes.RETURN)
        run.visitMaxs(6, 2)
        run.visitEnd()

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
        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitIntInsn(Opcodes.BIPUSH, 7)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(1, 0)
        value.visitEnd()
        val hot = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "hot", "(I)I", null, null)
        hot.visitCode()
        hot.visitVarInsn(Opcodes.ILOAD, 0)
        hot.visitInsn(Opcodes.ICONST_1)
        hot.visitInsn(Opcodes.IADD)
        hot.visitInsn(Opcodes.IRETURN)
        hot.visitMaxs(2, 1)
        hot.visitEnd()
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
                        if (owner.endsWith("QpBridge") && name == "executeQpVmPage") {
                            calls += name to methodDescriptor
                        }
                    }
                }
            }
        }, 0)
        return calls
    }

    private fun countObjectArrayAllocationsBeforeVmDispatcher(classBytes: ByteArray, methodName: String, descriptor: String): Int {
        var count = 0
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                var beforeRealDispatcher = true
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitTypeInsn(opcode: Int, type: String) {
                        if (beforeRealDispatcher && opcode == Opcodes.ANEWARRAY && type == "java/lang/Object") count++
                    }

                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, methodDescriptor: String, isInterface: Boolean) {
                    if (owner.endsWith("QpBridge") && name == "executeQpVmPage") {
                            beforeRealDispatcher = false
                        }
                    }
                }
            }
        }, 0)
        return count
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


    private fun String.isVmResourceName(): Boolean = startsWith("META-INF/") && !endsWith(".class") && !endsWith("/") && length > "META-INF/".length + 10

    private fun JarEntryData.isVmResourceName(): Boolean = name.isVmResourceName()

    private fun selectionClassMethodSummaries(): List<MemberSummary> = listOf(
        MemberSummary(MemberKind.METHOD, "safeTiny", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
        MemberSummary(MemberKind.METHOD, "criticalField", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
        MemberSummary(MemberKind.METHOD, "compatibleLarge", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
    )

    private fun selectedOnlyRuleMatches(
        artifact: BytecodeArtifact,
        rules: List<RuleSpec>,
    ): List<RuleMatch> = buildRuleMatches(
        ruleSet = RuleSet(rules = rules, scope = RuleSetScope.SELECTED_ONLY),
        classSummaries = artifact.classArtifacts.map { it.summary },
    )

    private fun ruleMatchesFor(internalName: String, action: String = "method-virtualization"): List<RuleMatch> = listOf(
        RuleMatch(
            rule = RuleSpec(target = internalName, action = action),
            selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
            matchedClassNames = listOf(internalName),
            matchedMembers = emptyList(),
        ),
    )
}



