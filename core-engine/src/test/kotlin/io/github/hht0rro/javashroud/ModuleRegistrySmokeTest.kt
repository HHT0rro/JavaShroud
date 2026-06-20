package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.modules.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ModuleRegistrySmokeTest {
    @Test
    fun buildModuleRegistry_contains_all_declared_modules() {
        val registry = buildModuleRegistry()
        val expectedIds = (
            buildMetadataModules() + buildRenamingModules() + buildEncryptionModules() +
                buildObfuscationModules() + buildHidingModules() + buildLoaderProtectionModules() +
                buildHelperDeploymentModules() + buildRuntimeDefenseModules() +
                buildVmProtectionModules() + buildNativeKernelModules()
            ).map { module -> module.definition.id }
            .toSet()

        assertEquals(expectedIds, registry.keys)
    }

    @Test
    fun buildMetadataModules_preserves_declared_order() {
        val ids = buildMetadataModules().map { module -> module.definition.id }

        assertEquals(
            listOf(
                "strip-compile-debug-info",
            ),
            ids,
        )
    }

    @Test
    fun buildRenamingModules_preserves_declared_order() {
        val ids = buildRenamingModules().map { module -> module.definition.id }

        assertEquals(
            listOf(
                "rename-classes",
                "rename-packages",
                "rename-methods",
                "rename-fields",
            ),
            ids,
        )
    }

    @Test
    fun buildEncryptionModules_preserves_declared_order() {
        val ids = buildEncryptionModules().map { module -> module.definition.id }

        assertEquals(
            listOf("string-encryption", "field-string-encryption"),
            ids,
        )
    }

    @Test
    fun buildObfuscationModules_preserves_declared_order() {
        val ids = buildObfuscationModules().map { module -> module.definition.id }

        assertEquals(
            listOf(
                "integer-constant-obfuscation",
                "static-init-perturbation",
                "anti-decompiler-structure",
                "invoke-dynamic-indirection",
                "control-flow-obfuscation",
                "reference-proxy",
                "control-flow-flattening",
                "condy-constant-indirection",
            ),
            ids,
        )
    }

    @Test
    fun buildHidingModules_contains_member_hide() {
        val ids = buildHidingModules().map { module -> module.definition.id }

        assertEquals(
            listOf("member-hide"),
            ids,
        )
    }

    @Test
    fun buildLoaderProtectionModules_contains_expected_ids() {
        val ids = buildLoaderProtectionModules().map { module -> module.definition.id }
        assertTrue(ids.contains("class-encryption-loader"))
        assertTrue(ids.contains("method-body-delayed-decryption"))
    }

    @Test
    fun buildHelperDeploymentModules_contains_expected_ids() {
        val ids = buildHelperDeploymentModules().map { module -> module.definition.id }
        assertEquals(emptyList(), ids)
    }

    @Test
    fun buildRuntimeDefenseModules_contains_expected_ids() {
        val ids = buildRuntimeDefenseModules().map { module -> module.definition.id }
        assertTrue(ids.contains("callsite-rotation-protection"))
        assertTrue(ids.contains("environment-bound-keys"))
        assertTrue(ids.contains("anti-symbolic-execution"))
        assertTrue(ids.contains("exception-semantic-virtualization"))
    }

    @Test
    fun buildVmProtectionModules_contains_expected_ids() {
        val ids = buildVmProtectionModules().map { module -> module.definition.id }
        assertEquals(listOf("method-virtualization"), ids)
    }

    @Test
    fun buildModuleRegistry_does_not_expose_internal_planner() {
        assertFalse(buildModuleRegistry().containsKey("pass-ordering-planner"))
    }
}
