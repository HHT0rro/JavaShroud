package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.RuleMatch

fun matchedClassNamesForAction(ruleMatches: List<RuleMatch>, action: String): Set<String> {
    val matchedRuleSet = actionRuleMatches(ruleMatches, action)
    return resolveMatchedClassNames(matchedRuleSet, excludedClassNames(ruleMatches))
}

fun matchedMembersForAction(ruleMatches: List<RuleMatch>, action: String): List<MatchedMember> {
    val matchedRuleSet = actionRuleMatches(ruleMatches, action)
    return resolveMatchedMembers(
        matchedRuleSet = matchedRuleSet,
        excludedClassNames = excludedClassNames(ruleMatches),
        excludedMembers = excludedMembers(ruleMatches),
    )
}

internal fun actionRuleMatches(ruleMatches: List<RuleMatch>, action: String): List<RuleMatch> =
    ruleMatches.filter { ruleMatch: RuleMatch -> ruleMatch.rule.action == action }

internal fun filteredMatchedMembers(
    matchedMembers: List<MatchedMember>,
    excludedClassNames: Set<String>,
    excludedMembers: Set<String>,
): List<MatchedMember> = matchedMembers
    .filterNot { matchedMember: MatchedMember -> excludedClassNames.contains(matchedMember.owner) }
    .filterNot { matchedMember: MatchedMember -> excludedMembers.contains(buildMatchedMemberIdentity(matchedMember)) }

internal fun resolveMatchedClassNames(
    matchedRuleSet: List<RuleMatch>,
    excludedClassNames: Set<String>,
): Set<String> {
    val explicitlyMatchedClassNames = matchedRuleSet
        .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames }
        .toSet()
    if (explicitlyMatchedClassNames.isNotEmpty()) {
        return explicitlyMatchedClassNames.filterNot(excludedClassNames::contains).toSet()
    }

    return allClassNames(matchedRuleSet).filterNot(excludedClassNames::contains).toSet()
}

internal fun resolveMatchedMembers(
    matchedRuleSet: List<RuleMatch>,
    excludedClassNames: Set<String>,
    excludedMembers: Set<String>,
): List<MatchedMember> {
    val matchedMembers = matchedRuleSet.flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedMembers }
    val explicitlyMatchedMembers = filteredMatchedMembers(
        matchedMembers = matchedMembers,
        excludedClassNames = excludedClassNames,
        excludedMembers = excludedMembers,
    )
    if (explicitlyMatchedMembers.isNotEmpty()) {
        return explicitlyMatchedMembers
    }

    return matchedMembers
        .filterNot { matchedMember: MatchedMember -> excludedClassNames.contains(matchedMember.owner) }
        .filterNot { matchedMember: MatchedMember -> excludedMembers.contains(buildMatchedMemberIdentity(matchedMember)) }
        .distinctBy(::buildMatchedMemberIdentity)
}

internal fun buildMatchedMemberIdentity(matchedMember: MatchedMember): String {
    return matchedMember.owner + "#" + matchedMember.kind + ":" + matchedMember.name + ":" + matchedMember.descriptor
}
