package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildRenamePlan
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RuleMatcherSmokeTest {
    @Test
    fun buildRuleMatches_matches_class_and_members() {
        val classSummary = ClassAnalysisSummary(
            internalName = "sample/Foo",
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = 0,
            fieldCount = 1,
            methodCount = 1,
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "barField", "I", 0)),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "barMethod", "()V", 0)),
        )

        val ruleSet = RuleSet(
            rules = listOf(RuleSpec(target = "sample/Foo#bar*:*", action = "plan-member-rename")),
        )

        val matches = buildRuleMatches(ruleSet, listOf(classSummary))
        assertEquals(1, matches.size)
        assertEquals(listOf("sample/Foo"), matches.first().matchedClassNames)
        assertEquals(2, matches.first().matchedMembers.size)
    }

    @Test
    fun buildRenamePlan_generates_stable_member_prefixes() {
        val classSummary = ClassAnalysisSummary(
            internalName = "sample/Foo",
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = 0,
            fieldCount = 1,
            methodCount = 1,
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "barField", "I", 0)),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "barMethod", "()V", 0)),
        )

        val ruleSet = RuleSet(
            rules = listOf(RuleSpec(target = "sample/Foo#bar*:*", action = "plan-member-rename")),
        )

        val plan = buildRenamePlan(buildRuleMatches(ruleSet, listOf(classSummary)))
        assertEquals(2, plan.entries.size)
        assertTrue(plan.entries.any { it.kind == MemberKind.FIELD && it.plannedName.startsWith("f") })
        assertTrue(plan.entries.any { it.kind == MemberKind.METHOD && it.plannedName.startsWith("m") })
    }

    @Test
    fun buildRenamePlan_deduplicates_repeated_member_matches() {
        val duplicatedField = MemberSummary(MemberKind.FIELD, "barField", "I", 0)
        val classSummary = ClassAnalysisSummary(
            internalName = "sample/Foo",
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = 0,
            fieldCount = 1,
            methodCount = 0,
            fieldSummaries = listOf(duplicatedField),
            methodSummaries = emptyList(),
        )

        val ruleSet = RuleSet(
            rules = listOf(
                RuleSpec(target = "sample/Foo#barField:I", action = "plan-member-rename"),
                RuleSpec(target = "sample/Foo#bar*:I", action = "plan-member-rename"),
            ),
        )

        val plan = buildRenamePlan(buildRuleMatches(ruleSet, listOf(classSummary)))
        assertEquals(1, plan.entries.size)
        assertEquals("barField", plan.entries.single().originalName)
        assertEquals("f0000", plan.entries.single().plannedName)
    }
}
