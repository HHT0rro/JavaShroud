package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.capabilities.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SchemaCapabilitiesTest {

    @Test
    fun engineSchemaVersion_returns_non_blank() {
        assertTrue(engineSchemaVersion().isNotBlank())
    }

    @Test
    fun engineVersion_returns_non_blank() {
        assertTrue(engineVersion().isNotBlank())
    }

    @Test
    fun vbcVersion_returns_non_blank() {
        assertTrue(vbcVersion().isNotBlank())
    }

    @Test
    fun buildCapabilityTagDefinitions_contains_all_tags() {
        val tags = buildCapabilityTagDefinitions()
        val tagIds = tags.map { it.id }
        assertTrue(tagIds.contains("metadata"), "Expected 'metadata' tag")
        assertTrue(tagIds.contains("renaming"), "Expected 'renaming' tag")
        assertTrue(tagIds.contains("encryption"), "Expected 'encryption' tag")
        assertTrue(tagIds.contains("obfuscation"), "Expected 'obfuscation' tag")
        assertTrue(tagIds.contains("hiding"), "Expected 'hiding' tag")
        assertTrue(tagIds.contains("loader-protection"), "Expected 'loader-protection' tag")
        assertTrue(tagIds.contains("helper-deployment"), "Expected 'helper-deployment' tag")
        assertTrue(tagIds.contains("runtime-defense"), "Expected 'runtime-defense' tag")
        assertTrue(tagIds.contains("vm-protection"), "Expected 'vm-protection' tag")
        assertTrue(tagIds.contains("aggressive"), "Expected 'aggressive' tag")
        assertTrue(tagIds.contains("native-kernel"), "Expected 'native-kernel' tag")
    }

    @Test
    fun buildMetadataCapabilityDefinitions_returns_current_metadata_modules() {
        val modules = buildMetadataCapabilityDefinitions()
        assertEquals(1, modules.size)
        val ids = modules.map { it.id }
        assertTrue(ids.contains("strip-compile-debug-info"))
    }

    @Test
    fun buildRenamingCapabilityDefinitions_returns_four_modules() {
        val modules = buildRenamingCapabilityDefinitions()
        assertEquals(4, modules.size)
        val ids = modules.map { it.id }
        assertTrue(ids.contains("rename-classes"))
        assertTrue(ids.contains("rename-packages"))
        assertTrue(ids.contains("rename-methods"))
        assertTrue(ids.contains("rename-fields"))
    }

    @Test
    fun shufflePackageSegmentCount_is_only_exposed_for_package_renaming() {
        val modules = buildRenamingCapabilityDefinitions()
        val modulesWithParam = modules.filter { module ->
            module.params.any { it.key == "shufflePackageSegmentCount" }
        }
        assertEquals(listOf("rename-packages"), modulesWithParam.map { it.id })

        val param = modulesWithParam.single().params.single { it.key == "shufflePackageSegmentCount" }
        assertEquals(true, param.defaultValue?.asBoolean())
        assertTrue(param.description.contains("包路径重命名"))
        assertTrue(param.description.contains("原始包路径层级"))
    }

    @Test
    fun invoke_dynamic_indirection_schema_has_no_fake_bootstrap_strategy_param() {
        val module = buildObfuscationCapabilityDefinitions().single { it.id == "invoke-dynamic-indirection" }

        assertTrue(module.params.isEmpty())
    }

    @Test
    fun reference_proxy_schema_has_no_fake_proxy_style_param() {
        val module = buildObfuscationCapabilityDefinitions().single { it.id == "reference-proxy" }

        assertTrue(module.params.isEmpty())
    }

    @Test
    fun control_flow_flattening_schema_exposes_only_implemented_params() {
        val module = buildObfuscationCapabilityDefinitions().single { it.id == "control-flow-flattening" }
        val paramKeys = module.params.map { it.key }

        assertEquals(listOf("density", "handlerComplexity", "pattern"), paramKeys)
    }

    @Test
    fun all_metadata_modules_have_metadata_tag() {
        val modules = buildMetadataCapabilityDefinitions()
        for (module in modules) {
            assertTrue(module.tagIds.contains("metadata"), "Module ${module.id} should have 'metadata' tag")
        }
    }

    @Test
    fun all_renaming_modules_have_renaming_tag() {
        val modules = buildRenamingCapabilityDefinitions()
        for (module in modules) {
            assertTrue(module.tagIds.contains("renaming"), "Module ${module.id} should have 'renaming' tag")
        }
    }

    @Test
    fun all_schema_modules_have_known_stability() {
        val knownStabilities = setOf("stable", "experimental", "aggressive", "research")
        for (module in buildEngineSchemaPayload().modules) {
            assertTrue(
                module.stability in knownStabilities,
                "Module ${module.id} should use a known stability label",
            )
        }
    }

    @Test
    fun buildEngineSchemaPayload_has_correct_structure() {
        val payload = buildEngineSchemaPayload()
        assertEquals(engineSchemaVersion(), payload.schemaVersion)
        assertEquals(engineVersion(), payload.engineVersion)
        assertEquals(vbcVersion(), payload.vbcVersion)
        assertTrue(payload.tags.size >= 11, "Expected protection category tags")
        assertEquals(
            buildMetadataCapabilityDefinitions().size +
                buildRenamingCapabilityDefinitions().size +
                buildEncryptionCapabilityDefinitions().size +
                buildObfuscationCapabilityDefinitions().size +
                buildHidingCapabilityDefinitions().size +
                buildLoaderProtectionCapabilityDefinitions().size +
                buildHelperDeploymentCapabilityDefinitions().size +
                buildRuntimeDefenseCapabilityDefinitions().size +
                buildVmProtectionCapabilityDefinitions().size +
                buildNativeKernelCapabilityDefinitions().size,
            payload.modules.size,
        )
        assertTrue(payload.modules.any { it.params.isNotEmpty() }, "Parameterized modules should be exposed")
    }

    @Test
    fun buildEngineSchemaPayload_does_not_expose_internal_planner() {
        val payload = buildEngineSchemaPayload()
        assertFalse(payload.tags.any { it.id == "planner" }, "Internal planner tag should not be exposed")
        assertFalse(payload.modules.any { it.id == "pass-ordering-planner" }, "Internal planner should not be exposed as a module")
        assertFalse(payload.defaultPipeline.contains("pass-ordering-planner"), "Default pipeline should not include internal planner")
        assertFalse(
            payload.orderingConstraints.any { it.before == "pass-ordering-planner" || it.after == "pass-ordering-planner" },
            "Ordering constraints should not reference the internal planner",
        )
    }

    @Test
    fun default_pipeline_contains_only_safe_non_opt_in_modules() {
        val payload = buildEngineSchemaPayload()
        val moduleIndex = payload.modules.associateBy { it.id }

        assertEquals(
            listOf("strip-compile-debug-info"),
            payload.defaultPipeline,
            "Default pipeline should only strip compile debug attributes by default",
        )

        for (passId in payload.defaultPipeline) {
            val module = moduleIndex[passId]
            assertTrue(module != null, "Default pipeline references unknown module '$passId'")
            assertFalse(module!!.requiresOptIn, "Default pipeline must not include opt-in pass '$passId'")
            assertFalse(
                module.risk == "high" || module.risk == "ultra-high",
                "Default pipeline must not include high-risk pass '$passId' (${module.risk})",
            )
            assertTrue(
                module.requiresRuntimeFlags.isEmpty(),
                "Default pipeline must not include pass '$passId' requiring runtime flags ${module.requiresRuntimeFlags}",
            )
            assertTrue(
                module.platformConstraints.isEmpty(),
                "Default pipeline must not include platform-constrained pass '$passId'",
            )
        }
    }

    @Test
    fun anti_instrumentation_detection_level_exposes_only_implemented_options() {
        val antiInstrumentation = buildEngineSchemaPayload().modules.single { it.id == "anti-instrumentation" }
        val detectionLevel = antiInstrumentation.params.single { it.key == "detectionLevel" }

        assertEquals("standard", detectionLevel.defaultValue?.asText())
        assertEquals(listOf("standard", "aggressive"), detectionLevel.options)
    }

    @Test
    fun real_jar_semantics_or_helper_fingerprint_risky_modules_require_opt_in() {
        val moduleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val riskyOnReflectionOrLayoutSensitiveJars = listOf(
            "anti-decompiler-structure",
            "condy-constant-indirection",
            "control-flow-obfuscation",
            "control-flow-flattening",
            "field-string-encryption",
            "integer-constant-obfuscation",
            "invoke-dynamic-indirection",
            "member-hide",
            "reference-proxy",
            "static-init-perturbation",
            "string-encryption",
            "anti-symbolic-execution",
            "rename-classes",
            "rename-packages",
            "rename-methods",
            "rename-fields",
        )

        for (passId in riskyOnReflectionOrLayoutSensitiveJars) {
            val module = moduleIndex[passId]
            assertTrue(module != null, "Schema should expose module '$passId'")
            assertEquals("high", module!!.risk, "Real TEST.jar probes show '$passId' is not a low-risk safe pass")
            assertTrue(module.requiresOptIn, "Real TEST.jar probes show '$passId' must require explicit opt-in")
            assertTrue(
                module.compatibilityNotes.isNotBlank(),
                "Risky module '$passId' should explain the runtime compatibility or fingerprint hazard",
            )
        }
    }

    @Test
    fun buildEngineSchemaPayload_modules_are_sorted_by_id() {
        val payload = buildEngineSchemaPayload()
        val ids = payload.modules.map { it.id }
        assertEquals(ids.sorted(), ids, "Modules should be sorted by id")
    }

    @Test
    fun buildEngineSchemaPayload_tags_are_sorted_by_order() {
        val payload = buildEngineSchemaPayload()
        val orders = payload.tags.map { it.order }
        assertEquals(orders.sorted(), orders, "Tags should be sorted by order")
    }

    @Test
    fun buildEngineSchemaPayload_includes_ordering_constraints() {
        val payload = buildEngineSchemaPayload()
        assertTrue(payload.orderingConstraints.isNotEmpty(), "Schema should include ordering constraints")
    }

    @Test
    fun class_encryption_rejects_vm_payload_combinations_until_encrypted_remap_exists() {
        val hardConflicts = buildEngineSchemaPayload().compatibility
            .filter { it.severity == "hard" }
            .map { it.passIds.toSet() }
            .toSet()

        assertEquals(
            setOf(setOf("class-encryption-loader", "method-virtualization")),
            hardConflicts,
            "Only the encrypted payload remapping boundary should remain a hard conflict.",
        )

        assertTrue(
            setOf("class-encryption-loader", "method-virtualization") in hardConflicts,
            "class encryption must not package VM-dispatch bytecode that later sealing cannot remap",
        )
    }

    @Test
    fun native_runtime_guards_declare_required_jni_loader_dependency() {
        val moduleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val dependentIds = listOf(
            "anti-instrumentation",
            "anti-dump-protection",
            "environment-bound-keys",
            "method-body-delayed-decryption",
        )

        for (id in dependentIds) {
            val module = moduleIndex[id]
            assertTrue(module != null, "Module '$id' should exist in schema")
            assertEquals(listOf("jni-microkernel-loader"), module!!.requiredPassIds, "Module '$id' should require jni-microkernel-loader")
        }
    }

    @Test
    fun jni_microkernel_loader_accepts_string_encryption_as_native_companion() {
        val moduleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val jniModule = moduleIndex["jni-microkernel-loader"]
        assertTrue(jniModule != null, "jni-microkernel-loader should exist in schema")
        assertTrue(
            "string-encryption" in jniModule!!.requiresAnyPassIds,
            "jni-microkernel-loader must treat native-backed string-encryption as a valid companion pass.",
        )
    }
    @Test
    fun jni_microkernel_loader_hides_diversified_virtualization_param_but_defaults_enabled() {
        val moduleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val jniModule = moduleIndex["jni-microkernel-loader"]
        assertTrue(jniModule != null, "jni-microkernel-loader should exist in schema")

        val param = jniModule!!.params.singleOrNull { it.key == "diversifiedVirtualization" }
        assertTrue(param != null, "diversifiedVirtualization should exist as an engine-owned default param")
        assertEquals(true, param!!.defaultValue?.asBoolean(), "diversifiedVirtualization should default enabled")
        assertTrue(param.hidden, "diversifiedVirtualization should be hidden from UI controls")
    }

    @Test
    fun jni_microkernel_loader_schema_exposes_native_kernel_component_sets() {
        val moduleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val jniModule = moduleIndex["jni-microkernel-loader"]
        assertTrue(jniModule != null, "jni-microkernel-loader should exist in schema")

        val param = jniModule!!.params.singleOrNull { it.key == "kernelComponents" }
        assertTrue(param != null, "kernelComponents should exist")
        assertEquals("loader", param!!.defaultValue?.asText(), "loader remains the compatibility default")
        assertEquals(listOf("loader", "decrypt", "vm", "guards", "all"), param.options)
    }

    @Test
    fun jni_microkernel_loader_schema_exposes_native_recompilation_params() {
        val moduleIndex = buildEngineSchemaPayload().modules.associateBy { it.id }
        val jniModule = moduleIndex["jni-microkernel-loader"]
        assertTrue(jniModule != null, "jni-microkernel-loader should exist in schema")

        val nativeRecompilation = jniModule!!.params.singleOrNull { it.key == "nativeRecompilation" }
        assertTrue(nativeRecompilation != null, "nativeRecompilation param should exist")
        assertEquals(true, nativeRecompilation!!.defaultValue?.booleanValue(), "nativeRecompilation should default to true")
        assertFalse(nativeRecompilation.hidden, "nativeRecompilation should be visible as the obfuscation-time compilation option")

        val protectionLevel = jniModule.params.singleOrNull { it.key == "nativeProtectionLevel" }
        assertTrue(protectionLevel != null, "nativeProtectionLevel param should exist")
        assertEquals("standard", protectionLevel!!.defaultValue?.asText(), "nativeProtectionLevel should default to standard")
        assertEquals(listOf("standard", "aggressive"), protectionLevel.options)

        assertTrue(
            jniModule.params.none { it.key == "codeSectionEncryption" },
            "codeSectionEncryption should not be exposed until a real JNI_OnLoad self-decrypt path exists",
        )
    }

    @Test
    fun method_virtualization_schema_exposes_only_vbc4_user_controls() {
        val module = buildEngineSchemaPayload().modules.single { it.id == "method-virtualization" }
        val paramKeys = module.params.map { it.key }

        assertEquals(
            listOf("seed", "methodSelection", "strictVirtualization", "maxInstructions", "maxBroadVirtualizedMethods", "highValueMethods", "highValueMethodDeny", "vbc4StateBoundEncoding", "vbc4HandlerMorphing", "vbc4StrengthMax", "vbc4InterpreterDiversity", "vbc4HashedJniSymbols", "vbc4ExecutableRegisterIr", "vbc4SuperOperators", "vbc4IntegrityKeyBinding", "vbc4EphemeralRootMaterial"),
            paramKeys,
            "method-virtualization must expose only VBC4 controls plus hidden high-value selectors and fixed high-strength defaults",
        )
        assertEquals("critical-plus", module.params.single { it.key == "methodSelection" }.defaultValue?.asText(), "VM should default to critical-plus auto-selection")
        assertEquals(true, module.params.single { it.key == "strictVirtualization" }.defaultValue?.asBoolean(), "VM should default to strict virtualization")
        assertEquals(99999, module.params.single { it.key == "maxInstructions" }.defaultValue?.asInt(), "VM default instruction threshold must stay at full-strength coverage")
        assertEquals(99999, module.params.single { it.key == "maxBroadVirtualizedMethods" }.defaultValue?.asInt(), "Broad class rules should default to maximum coverage")
        assertTrue(module.params.filter { it.key in setOf("highValueMethods", "highValueMethodDeny") }.all { it.hidden && it.type == "string" }, "High-value selector allow/deny lists must stay hidden string controls")
        assertTrue(module.params.filter { it.key.startsWith("vbc4") }.all { it.hidden && it.defaultValue?.asBoolean() == true }, "VBC4 high-strength invariants must be hidden fixed defaults")
        assertFalse(paramKeys.any { it in setOf("vmStrength", "fusionLevel", "stateBoundEncoding", "handlerMorphing", "vmDialect", "vmDiversityLevel") }, "Legacy/low-strength VM controls must not be exposed")
    }

    @Test
    fun engine_schema_does_not_leak_internal_vm_or_key_material_controls() {
        val payload = buildEngineSchemaPayload()
        val schemaText = buildString {
            append(payload.tags.joinToString("\n") { listOf(it.id, it.name, it.description).joinToString(" ") })
            append('\n')
            append(payload.modules.joinToString("\n") { module ->
                listOf(
                    module.id,
                    module.name,
                    module.description,
                    module.compatibilityNotes,
                    module.requiredPassIds.joinToString(" "),
                    module.requiresAnyPassIds.joinToString(" "),
                    module.params.joinToString(" ") { param ->
                        listOf(param.key, param.description, param.options.orEmpty().joinToString(" ")).joinToString(" ")
                    },
                ).joinToString(" ")
            })
            append('\n')
            append(payload.defaultPipeline.joinToString(" "))
            append('\n')
            append(payload.orderingConstraints.joinToString("\n") { "${it.before} ${it.after} ${it.reason}" })
        }

        val forbiddenFragments = listOf(
            "pass-ordering-planner",
            "__nativeOnlyInterpreter",
            "deriveSubKey",
            "runtimeResourceKey",
            "masterKey",
            "nativeSeed",
            "jarLayoutDigest",
            "microcode",
            "shared dispatch pool",
            "slice manifest",
        )
        for (fragment in forbiddenFragments) {
            assertFalse(schemaText.contains(fragment, ignoreCase = true), "Schema must not expose internal implementation detail '$fragment'")
        }
    }

    @Test
    fun schema_references_only_declared_modules() {
        val payload = buildEngineSchemaPayload()
        val moduleIds = payload.modules.map { it.id }.toSet()
        val referencedIds = (
            payload.defaultPipeline +
                payload.compatibility.flatMap { it.passIds } +
                payload.orderingConstraints.flatMap { listOf(it.before, it.after) } +
                payload.modules.flatMap { it.requiredPassIds + it.requiresAnyPassIds }
            ).toSet()

        val unknownIds = referencedIds - moduleIds
        assertTrue(unknownIds.isEmpty(), "Schema references undeclared modules: $unknownIds")
    }

    @Test
    fun loader_protection_modules_have_correct_risk() {
        val modules = buildLoaderProtectionCapabilityDefinitions()
        for (module in modules) {
            assertTrue(module.risk in listOf("low", "medium", "high", "ultra-high"), "Module ${module.id} should have a valid risk level")
        }
    }
}
