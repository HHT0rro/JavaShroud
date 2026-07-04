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
import io.github.hht0rro.javashroud.bytecode.applyCondyConstantIndirection
import io.github.hht0rro.javashroud.bytecode.indirectMethodCalls
import io.github.hht0rro.javashroud.transforms.protection.ObfuscatedIdentifierUtil
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.currentVbc4BuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyBootstrapTableEncryption
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization as applyMethodVirtualizationTransform
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
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
            val decodedByName = entries
                .filter { it.isVmResourceName() }
                .mapNotNull { entry -> RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it } }
                .toMap()
            val rawResources = decodedByName.values.filter(::isRawVbc4Resource)
            val slicedResources = decodedByName.values.mapNotNull { bytes -> reassembleSlicedVbc4(bytes, decodedByName) }
            (rawResources + slicedResources).map { readU2At(it, VBC4_FLAGS_OFFSET_FOR_TEST) }
        }

    private fun reassembleSlicedVbc4(manifestBytes: ByteArray, decodedByName: Map<String, ByteArray>): ByteArray? {
        val lines = runCatching { manifestBytes.decodeToString().trim().lines() }.getOrNull() ?: return null
        val header = lines.firstOrNull()?.split('|') ?: return null
        if (header.size < 4 || header[0] != "VBC4S" || header[1] != "1") return null
        val totalSize = header[2].toIntOrNull() ?: return null
        val out = ByteArray(totalSize)
        for (line in lines.drop(1)) {
            val parts = line.split('|')
            if (parts.size < 5) return null
            val offset = parts[1].toIntOrNull() ?: return null
            val length = parts[2].toIntOrNull() ?: return null
            val shard = decodedByName[parts[4]] ?: return null
            if (shard.size != length || offset < 0 || offset + length > out.size) return null
            shard.copyInto(out, offset)
        }
        return out.takeIf(::isRawVbc4Resource)
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
        assertTrue(result.artifact.jarEntries.any { it.isVmResourceName() }, "Condy-bearing virtualization should emit a VBC4 resource")
        val projectDir = Path.of(System.getProperty("user.dir"))
        val sourceRoot = if (Files.exists(projectDir.resolve("src/main/native/js_vm_core.c"))) projectDir else projectDir.resolve("core-engine")
        val serializerSource = Files.readString(sourceRoot.resolve("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val nativeSource = Files.readString(sourceRoot.resolve("src/main/native/js_vm_core.c"))
        assertTrue(serializerSource.contains("VM_LDC_CONDY"), "Serializer must keep a dedicated guarded ConstantDynamic LDC opcode")
        assertTrue(nativeSource.contains("JS_VM_LDC_CONDY") && nativeSource.contains("js_vm_cp_condy_value"), "Native VM must execute guarded ConstantDynamic LDC values")
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
        assertTrue(unbounded.artifact.jarEntries.any { it.isVmResourceName() }, "Unbounded zero threshold should emit VM resources")
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
        assertTrue(source.contains("method-virtualization-key-stream-v1"), "Method key material must use a CSPRNG stream personalized by VBC4 context, not the user-seeded structural RNG")
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
        val context = defaultVbc4BuildContext()
        val params = mapOf("maxInstructions" to 100, "seed" to 42, "__nativeOnlyInterpreter" to true)
        val first = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = params,
            )
        }
        val second = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = params,
            )
        }

        val firstEntries = first.artifact.jarEntries.filter { it.isVmResourceName() }
        val secondEntries = second.artifact.jarEntries.filter { it.isVmResourceName() }
        val firstResources = firstEntries.map { it.bytes.toList() }
        val secondResources = secondEntries.map { it.bytes.toList() }
        val firstNames = firstEntries.map { it.name }
        val secondNames = secondEntries.map { it.name }
        assertTrue(firstResources.isNotEmpty() && secondResources.isNotEmpty(), "Native VM virtualization must emit resources")
        assertEquals(first.transformedMemberCount, second.transformedMemberCount, "Randomization must not change the selected method count")
        assertTrue(
            firstNames != secondNames || firstResources != secondResources,
            "Same artifact, rules, params, seed, and VBC4 context must not reproduce VM resource paths or ciphertexts",
        )
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

        val indexEntry = result.artifact.jarEntries.single { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }
        val index = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(indexEntry.bytes)!!.decodeToString().trim().lines()
        }
        assertTrue(index.isNotEmpty(), "Preload index must contain entries")
        assertTrue(index.all { it.split('|').size >= 4 }, "Preload index must include manifest and shard coordinates")
    }

    @Test
    fun vm_preload_index_replaces_existing_index_entry_during_reobfuscation() {
        val baseArtifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))
        val context = defaultVbc4BuildContext()
        val legacyIndexLine = "123456789abcdef0|META-INF/.r/legacy.vm|META-INF/.r/legacy.manifest|2"
        val artifact = withVbc4BuildContext(context) {
            baseArtifact.copy(
                jarEntries = baseArtifact.jarEntries + JarEntryData(
                    VBC4_VM_PRELOAD_INDEX_RESOURCE,
                    RuntimeResourceCodec.encode(
                        bytes = "$legacyIndexLine\n".toByteArray(Charsets.UTF_8),
                        kind = RuntimeResourceKind.NativeIndex,
                        seed = 7,
                        variantId = 1,
                        layerCount = 4,
                        compress = false,
                    ),
                ),
            )
        }

        val result = withVbc4BuildContext(context) {
            applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible"),
            )
        }

        assertEquals(1, result.artifact.jarEntries.count { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE })
        assertEquals(1, result.artifact.jarEntries.count { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE })
        val decodedIndex = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(result.artifact.jarEntries.single { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE }.bytes)!!.decodeToString()
        }
        assertTrue(decodedIndex.lines().contains(legacyIndexLine), "Re-obfuscation must keep the prior VM preload token/resource mapping")
        val currentIndex = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(result.artifact.jarEntries.single { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }.bytes)!!.decodeToString()
        }
        assertTrue(currentIndex.lines().none { it == legacyIndexLine }, "Current-run VM index must stay separate from the prior runtime index")
    }

    @Test
    fun runtime_sealing_keeps_single_vm_preload_index_after_virtualization() {
        val artifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            val virtualized = applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible"),
            ).artifact
            RuntimeArtifactSealing.seal(virtualized, 0x4A53524CL, rewritesVmRuntime = true)
        }

        assertEquals(0, sealed.jarEntries.count { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE })
        assertEquals(1, sealed.jarEntries.count { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE })
    }

    @Test
    fun runtime_sealing_preserves_prior_vm_preload_index_after_revirtualization() {
        val baseArtifact = artifactFor(twoMethodClassBytes(), "example/VmThreshold", methodSummaries = listOf(
            MemberSummary(MemberKind.METHOD, "hot", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "cold", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        ))
        val context = defaultVbc4BuildContext()
        val legacyLine = "123456789abcdef0|META-INF/.r/legacy.vm|META-INF/.r/legacy.manifest|2"
        val artifact = withVbc4BuildContext(context) {
            baseArtifact.copy(
                jarEntries = baseArtifact.jarEntries + listOf(
                    JarEntryData(
                        VBC4_VM_PRELOAD_INDEX_RESOURCE,
                        RuntimeResourceCodec.encode(
                            bytes = "$legacyLine\n".toByteArray(Charsets.UTF_8),
                            kind = RuntimeResourceKind.NativeIndex,
                            seed = 7,
                            variantId = 1,
                            layerCount = 4,
                            compress = false,
                        ),
                    ),
                    JarEntryData("META-INF/.r/legacy.vm", RuntimeResourceCodec.encode("VBC4\u0000payload".toByteArray(), RuntimeResourceKind.VmBytecode, seed = 9, variantId = 1, layerCount = 4, compress = false)),
                    JarEntryData("META-INF/.r/legacy.manifest", RuntimeResourceCodec.encode("VBC4S|1|x\n".toByteArray(), RuntimeResourceKind.VmBytecode, seed = 10, variantId = 1, layerCount = 4, compress = false)),
                ),
            )
        }

        val sealed = withVbc4BuildContext(context) {
            val virtualized = applyMethodVirtualization(
                artifact = artifact,
                ruleMatches = ruleMatchesFor("example/VmThreshold"),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 42, "methodSelection" to "all-compatible"),
            ).artifact
            RuntimeArtifactSealing.seal(virtualized, 0x4A53524CL, rewritesVmRuntime = true)
        }

        assertEquals(1, sealed.jarEntries.count { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE })
        assertEquals(1, sealed.jarEntries.count { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE })
        val decodedIndex = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(sealed.jarEntries.single { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE }.bytes)!!.decodeToString()
        }
        assertTrue(decodedIndex.contains("|META-INF/.r/legacy.vm|META-INF/.r/legacy.manifest\n"), "Sealed index must retain prior VM binding paths")
        assertTrue(decodedIndex.lines().any { it.startsWith("A|META-INF/.r/legacy.vm|") }, "Sealed index must expose alias metadata for renamed prior VM resources")
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
        val indexEntry = result.artifact.jarEntries.single { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }
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
                .filter { it.isVmResourceName() || it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }
                .mapNotNull { entry -> RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it } }
                .toMap()
        }
        val manifests = decodedResources.filterValues { bytes -> bytes.decodeToString().startsWith("VBC4S|1|") }
        val preloadEntries = decodedResources[VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE]!!
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
            assertTrue(shardCount in 2..6, "VMBC must be distributed across a CSPRNG-selected non-empty shard set")
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
    fun all_compatible_virtualizes_elapsed_time_benchmark_loops_under_strict_broad_rules() {
        val artifact = artifactFor(
            classBytes = elapsedTimeBenchmarkClassBytes(),
            internalName = "example/BenchCalc",
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "runAll", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            ),
        )

        val result = applyMethodVirtualization(
            artifact = artifact,
            ruleMatches = ruleMatchesFor("example/BenchCalc"),
            params = mapOf("maxInstructions" to 100, "seed" to 42, "methodSelection" to "all-compatible", "strictVirtualization" to true, "maxBroadVirtualizedMethods" to 0),
        )

        val classBytes = result.artifact.classArtifactIndex.getValue("example/BenchCalc").bytes
        assertTrue(methodCallsVmDispatcher(classBytes, "runAll", "()V"), "Strict all-compatible must virtualize native-compatible elapsed-time benchmark roots instead of leaking direct bytecode")
        assertTrue(methodCallsVmDispatcher(classBytes, "call", "(I)V"), "Strict all-compatible must virtualize recursive benchmark helpers when VBC4 supports the bytecode shape")
        assertTrue(methodCallsVmDispatcher(classBytes, "touch", "()V"), "Strict all-compatible must virtualize benchmark helpers invoked inside measured loops")
        assertTrue(result.transformedMemberCount >= 3, "Strict all-compatible should cover the benchmark root and helpers. transformed=${result.transformedMemberCount}")
    }

    @Test
    fun all_compatible_virtualizes_real_task_like_thread_pool_timing_root() {
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
        assertTrue(result.transformedMemberCount >= 1, "Strict all-compatible should virtualize native-compatible task-like thread-pool timing roots")
        assertTrue(methodCallsVmDispatcher(classBytes, "run", "()V"), "Task-like thread-pool timing roots must not remain direct bytecode under strict all-compatible selection")
    }

    @Test
    fun all_compatible_virtualizes_task_like_thread_pool_timing_root_after_indy_indirection() {
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
        assertTrue(result.transformedMemberCount >= 1, "Strict all-compatible should virtualize task-like timing roots even after invoke-dynamic-indirection wraps static timing calls")
        assertTrue(methodCallsVmDispatcher(classBytes, "run", "()V"), "Indy-wrapped Thread.sleep calls must not keep the timing root out of strict all-compatible virtualization")
    }

    @Test
    fun all_compatible_virtualizes_class_loader_resource_boundary_methods() {
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
        assertTrue(methodCallsVmDispatcher(classBytes, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;"), "Strict all-compatible must virtualize native-compatible ClassLoader findClass boundaries")
        assertTrue(result.transformedMemberCount >= 1, "Strict all-compatible should cover the class-loader boundary method")
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

    private fun elapsedTimeBenchmarkClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/BenchCalc", null, "java/lang/Object", null)

        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "count", "I", null, null).visitEnd()

        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val call = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "call", "(I)V", null, null)
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

        val runAdd = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "runAdd", "()V", null, null)
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

        val runStr = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "runStr", "()V", null, null)
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

        val touch = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "touch", "()V", null, null)
        touch.visitCode()
        touch.visitFieldInsn(Opcodes.GETSTATIC, "example/BenchCalc", "count", "I")
        touch.visitInsn(Opcodes.ICONST_1)
        touch.visitInsn(Opcodes.IADD)
        touch.visitFieldInsn(Opcodes.PUTSTATIC, "example/BenchCalc", "count", "I")
        touch.visitInsn(Opcodes.RETURN)
        touch.visitMaxs(2, 0)
        touch.visitEnd()

        val runAll = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "runAll", "()V", null, null)
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



