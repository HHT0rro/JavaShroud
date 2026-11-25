package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.kernel.buildRunSummaryMessage
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.passes.buildDisabledPassMessage
import io.github.hht0rro.javashroud.passes.buildPassMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PassEventMessageSupportTest {
    @Test
    fun buildDisabledPassMessage_includes_pass_id() {
        assertEquals("Skipped disabled pass: id=strip-compile-debug-info", buildDisabledPassMessage("strip-compile-debug-info"))
    }

    @Test
    fun buildPassMessage_includes_all_transform_metrics() {
        val message = buildPassMessage(
            passId = "rename-classes",
            classCount = 10,
            resourceCount = 3,
            ruleMatches = listOf(
                RuleMatch(
                    rule = RuleSpec(target = "class sample.**", action = "rename"),
                    selector = TargetSelector(
                        classPattern = "sample/**",
                        memberPattern = null,
                        memberDescriptorPattern = null,
                    ),
                    matchedClassNames = listOf("sample/Foo", "sample/Bar"),
                    matchedMembers = listOf(
                        MatchedMember(
                            owner = "sample/Foo",
                            kind = MemberKind.FIELD,
                            name = "oldField",
                            descriptor = "I",
                        ),
                    ),
                ),
            ),
            transformedClassCount = 5,
            transformedMemberCount = 2,
            plannedRenameCount = 8,
        )

        assertTrue(message.contains("Executed pass: id=rename-classes"))
        assertTrue(message.contains(", classes=10"))
        assertTrue(message.contains(", resources=3"))
        assertTrue(message.contains(", matchedClasses=2"))
        assertTrue(message.contains(", matchedMembers=1"))
        assertTrue(message.contains(", transformedClasses=5"))
        assertTrue(message.contains(", transformedMembers=2"))
        assertTrue(message.contains(", plannedRenames=8"))
    }

    @Test
    fun buildRunSummaryMessage_includes_aggregate_metrics() {
        val message = buildRunSummaryMessage(
            executedPassCount = 5,
            totalTransformedClasses = 120,
            totalTransformedMembers = 45,
            totalPlannedRenames = 200,
            outputJarPath = "/output/result.jar",
        )

        assertTrue(message.contains("Run completed: passes=5"))
        assertTrue(message.contains("transformedClasses=120"))
        assertTrue(message.contains("transformedMembers=45"))
        assertTrue(message.contains("plannedRenames=200"))
        assertTrue(message.contains("output=/output/result.jar"))
    }
}
