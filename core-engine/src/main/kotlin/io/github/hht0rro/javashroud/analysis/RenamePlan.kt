package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RenamePlan
import io.github.hht0rro.javashroud.model.analysis.RenamePlanEntry
import io.github.hht0rro.javashroud.model.analysis.RuleMatch

fun buildRenamePlan(ruleMatches: List<RuleMatch>): RenamePlan =
    RenamePlan(entries = buildRenamePlanEntries(ruleMatches))

fun buildRenamePlan(ruleMatches: List<RuleMatch>, classSummaries: List<ClassAnalysisSummary>): RenamePlan =
    RenamePlan(entries = buildRenamePlanEntries(ruleMatches, classSummaries))

private const val PLAN_MEMBER_RENAME_ACTION = "plan-member-rename"

internal fun buildRenamePlanEntries(ruleMatches: List<RuleMatch>): List<RenamePlanEntry> =
    matchedMembersForRenamePlan(ruleMatches).mapIndexed(::buildRenamePlanEntry)

internal fun buildRenamePlanEntries(ruleMatches: List<RuleMatch>, classSummaries: List<ClassAnalysisSummary>): List<RenamePlanEntry> {
    val explicitMembers = matchedMembersForRenamePlan(ruleMatches)
    val members = if (explicitMembers.isNotEmpty()) explicitMembers else materializeRenamePlanMembers(classSummaries)
    return members.mapIndexed(::buildRenamePlanEntry)
}

private fun matchedMembersForRenamePlan(ruleMatches: List<RuleMatch>): List<MatchedMember> = ruleMatches
    .filter { ruleMatch: RuleMatch -> ruleMatch.rule.action == PLAN_MEMBER_RENAME_ACTION }
    .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedMembers }
    .distinctBy { matchedMember: MatchedMember -> buildMatchedMemberIdentity(matchedMember) }

private fun materializeRenamePlanMembers(classSummaries: List<ClassAnalysisSummary>): List<MatchedMember> = classSummaries
    .flatMap { classSummary ->
        (classSummary.fieldSummaries + classSummary.methodSummaries)
            .filterNot { member -> member.name == "<init>" || member.name == "<clinit>" }
            .map { member ->
                MatchedMember(
                    owner = classSummary.internalName,
                    kind = member.kind,
                    name = member.name,
                    descriptor = member.descriptor,
                )
            }
    }
    .distinctBy { matchedMember: MatchedMember -> buildMatchedMemberIdentity(matchedMember) }

private fun buildRenamePlanEntry(index: Int, matchedMember: MatchedMember): RenamePlanEntry = RenamePlanEntry(
    owner = matchedMember.owner,
    kind = matchedMember.kind,
    originalName = matchedMember.name,
    descriptor = matchedMember.descriptor,
    plannedName = buildPlannedName(matchedMember.kind, index),
)

private fun buildPlannedName(kind: MemberKind, index: Int): String {
    val prefix = when (kind) {
        MemberKind.FIELD -> "f"
        MemberKind.METHOD -> "m"
    }
    return prefix + index.toString().padStart(4, '0')
}
