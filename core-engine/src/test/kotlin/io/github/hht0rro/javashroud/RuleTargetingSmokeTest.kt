package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import kotlin.test.Test
import kotlin.test.assertEquals

class RuleTargetingSmokeTest {
    @Test
    fun eligibleMembersForAction_excludes_members_and_classes() {
        val fooClass = testClassArtifact(
            internalName = "sample/Foo",
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "keepField", "I", 0)),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "keepMethod", "()V", 0)),
        )
        val barClass = testClassArtifact(
            internalName = "sample/Bar",
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "dropField", "I", 0)),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "dropMethod", "()V", 0)),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(fooClass, barClass))
        val ruleSet = RuleSet(
            rules = listOf(
                RuleSpec(target = "sample/*", action = "rename-methods"),
                RuleSpec(target = "sample/Bar", action = "exclude"),
                RuleSpec(target = "sample/Foo#keepField:I", action = "exclude"),
            ),
        )

        val eligibleMembers = eligibleMembersForAction(
            classArtifacts = artifact.classArtifacts,
            ruleMatches = buildRuleMatches(ruleSet, artifact.analysisSummary.classSummaries),
            action = "rename-methods",
        )

        assertEquals(1, eligibleMembers.size)
        assertEquals("sample/Foo", eligibleMembers.single().owner)
        assertEquals("keepMethod", eligibleMembers.single().name)
    }

    @Test
    fun eligibleClassNamesForAction_falls_back_to_non_excluded_classes() {
        val fooClass = testClassArtifact(internalName = "sample/Foo")
        val barClass = testClassArtifact(internalName = "sample/Bar")
        val artifact = testAttachedArtifact(classArtifacts = listOf(fooClass, barClass))
        val ruleSet = RuleSet(
            rules = listOf(
                RuleSpec(target = "sample/Bar", action = "exclude"),
            ),
        )

        val eligibleClasses = eligibleClassNamesForAction(
            classArtifacts = artifact.classArtifacts,
            ruleMatches = buildRuleMatches(ruleSet, artifact.analysisSummary.classSummaries),
            action = "rename-classes",
        )

        assertEquals(setOf("sample/Foo"), eligibleClasses)
    }

    @Test
    fun eligibleClassNamesForAction_supports_package_exclude_and_child_obfuscate_override() {
        val fooClass = testClassArtifact(internalName = "sample/Foo")
        val barClass = testClassArtifact(internalName = "sample/Bar")
        val artifact = testAttachedArtifact(classArtifacts = listOf(fooClass, barClass))
        val ruleSet = RuleSet(
            rules = listOf(
                RuleSpec(target = "sample/*", action = "exclude"),
                RuleSpec(target = "sample/Foo", action = "obfuscate"),
            ),
        )

        val eligibleClasses = eligibleClassNamesForAction(
            classArtifacts = artifact.classArtifacts,
            ruleMatches = buildRuleMatches(ruleSet, artifact.analysisSummary.classSummaries),
            action = "rename-classes",
        )

        assertEquals(setOf("sample/Foo"), eligibleClasses)
    }

    @Test
    fun eligibleMembersForAction_supports_parent_class_exclude_and_member_obfuscate_override() {
        val fooClass = testClassArtifact(
            internalName = "sample/Foo",
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "field", "I", 0)),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "method", "()V", 0)),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(fooClass))
        val ruleSet = RuleSet(
            rules = listOf(
                RuleSpec(target = "sample/Foo", action = "exclude"),
                RuleSpec(target = "sample/Foo#method:()V", action = "obfuscate"),
            ),
        )

        val eligibleMembers = eligibleMembersForAction(
            classArtifacts = artifact.classArtifacts,
            ruleMatches = buildRuleMatches(ruleSet, artifact.analysisSummary.classSummaries),
            action = "rename-methods",
        )

        assertEquals(1, eligibleMembers.size)
        assertEquals("method", eligibleMembers.single().name)
    }
}
