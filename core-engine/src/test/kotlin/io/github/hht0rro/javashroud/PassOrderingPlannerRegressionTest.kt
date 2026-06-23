package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.compatibility.buildOrderingConstraints
import io.github.hht0rro.javashroud.compatibility.hardConflictPairs
import io.github.hht0rro.javashroud.compatibility.softConflictPairs
import io.github.hht0rro.javashroud.transforms.protection.planPassOrdering
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PassOrderingPlannerRegressionTest {
    @Test
    fun planner_orders_method_virtualization_before_callsite_rotation() {
        val result = planPassOrdering(
            passIds = listOf("callsite-rotation-protection", "method-virtualization", "jni-microkernel-loader"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(result.accepted, "Planner should accept virtualization plus callsite rotation pipeline: ${result.diagnostics}")
        assertBefore(result.orderedPasses, "jni-microkernel-loader", "method-virtualization")
        assertBefore(result.orderedPasses, "method-virtualization", "callsite-rotation-protection")
    }
    @Test
    fun planner_orders_rename_before_virtualization() {
        val result = planPassOrdering(
            passIds = listOf("method-virtualization", "rename-packages", "rename-classes", "rename-methods", "rename-fields"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(result.accepted, "Planner should accept retained rename plus virtualization pipeline: ${result.diagnostics}")
        assertBefore(result.orderedPasses, "rename-packages", "method-virtualization")
        assertBefore(result.orderedPasses, "rename-classes", "method-virtualization")
        assertBefore(result.orderedPasses, "rename-methods", "method-virtualization")
        assertBefore(result.orderedPasses, "rename-fields", "method-virtualization")
    }

    @Test
    fun planner_orders_string_and_field_encryption_before_loader() {
        val result = planPassOrdering(
            passIds = listOf("class-encryption-loader", "field-string-encryption", "string-encryption"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(result.accepted, "Planner should accept retained encryption plus loader pipeline: ${result.diagnostics}")
        assertBefore(result.orderedPasses, "string-encryption", "field-string-encryption")
        assertBefore(result.orderedPasses, "field-string-encryption", "class-encryption-loader")
    }

    @Test
    fun planner_orders_class_and_package_renaming_before_string_encryption() {
        val result = planPassOrdering(
            passIds = listOf("string-encryption", "rename-packages", "rename-classes"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(result.accepted, "Planner should accept rename plus string encryption pipeline: ${result.diagnostics}")
        assertBefore(result.orderedPasses, "rename-packages", "string-encryption")
        assertBefore(result.orderedPasses, "rename-classes", "string-encryption")
    }

    @Test
    fun planner_keeps_full_native_encryption_subgraph_acyclic() {
        val result = planPassOrdering(
            passIds = listOf(
                "string-encryption",
                "class-encryption-loader",
                "environment-bound-keys",
                "field-string-encryption",
                "jni-microkernel-loader",
                "method-body-delayed-decryption",
                "rename-classes",
                "rename-fields",
                "rename-methods",
                "rename-packages",
            ),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(result.accepted, "Planner should not report cycles for full native encryption subgraph: ${result.diagnostics}")
        assertTrue(
            result.diagnostics.none { it.causeId == "circular-dependency" },
            "Planner should avoid falling back to original order: ${result.diagnostics}",
        )
        assertBefore(result.orderedPasses, "rename-classes", "string-encryption")
        assertBefore(result.orderedPasses, "rename-packages", "string-encryption")
        assertBefore(result.orderedPasses, "string-encryption", "field-string-encryption")
        assertBefore(result.orderedPasses, "field-string-encryption", "class-encryption-loader")
        assertBefore(result.orderedPasses, "class-encryption-loader", "jni-microkernel-loader")
        assertBefore(result.orderedPasses, "jni-microkernel-loader", "environment-bound-keys")
        assertBefore(result.orderedPasses, "rename-fields", "method-body-delayed-decryption")
    }

    @Test
    fun planner_rejects_remaining_hard_conflict() {
        val result = planPassOrdering(
            passIds = listOf("class-encryption-loader", "method-virtualization"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(!result.accepted, "Planner should reject retained hard conflict")
    }

    @Test
    fun planner_accepts_reduced_default_pipeline() {
        val result = planPassOrdering(
            passIds = listOf("strip-compile-debug-info"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
        )

        assertTrue(result.accepted, "Planner should accept reduced default pipeline")
        assertEquals(listOf("strip-compile-debug-info"), result.orderedPasses)
    }

    private fun assertBefore(orderedPasses: List<String>, before: String, after: String) {
        val beforeIndex = orderedPasses.indexOf(before)
        val afterIndex = orderedPasses.indexOf(after)
        assertTrue(beforeIndex >= 0, "Missing pass '$before' in $orderedPasses")
        assertTrue(afterIndex >= 0, "Missing pass '$after' in $orderedPasses")
        assertTrue(beforeIndex < afterIndex, "Expected '$before' before '$after', actual=$orderedPasses")
    }
}
