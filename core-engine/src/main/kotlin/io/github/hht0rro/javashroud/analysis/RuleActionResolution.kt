package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.RuleMatch

fun matchedClassNamesForAction(ruleMatches: List<RuleMatch>, action: String): Set<String> {
    val matchedRuleSet = actionRuleMatches(ruleMatches, action)
    return resolveMatchedClassNames(
        matchedRuleSet = matchedRuleSet,
        excludedClassNames = excludedClassNames(ruleMatches),
        explicitlyObfuscatedMemberIdentities = explicitObfuscateMemberIdentities(ruleMatches),
    )
}

fun matchedMembersForAction(ruleMatches: List<RuleMatch>, action: String): List<MatchedMember> {
    val matchedRuleSet = actionRuleMatches(ruleMatches, action)
    return resolveMatchedMembers(
        matchedRuleSet = matchedRuleSet,
        excludedClassNames = excludedClassNames(ruleMatches),
        excludedMembers = excludedMembers(ruleMatches),
        explicitlyObfuscatedMemberIdentities = explicitObfuscateMemberIdentities(ruleMatches),
    )
}

internal fun actionRuleMatches(ruleMatches: List<RuleMatch>, action: String): List<RuleMatch> =
    ruleMatches.filter { ruleMatch: RuleMatch -> ruleMatch.rule.action == action }

internal fun filteredMatchedMembers(
    matchedMembers: List<MatchedMember>,
    excludedClassNames: Set<String>,
    excludedMembers: Set<String>,
    explicitlyObfuscatedMemberIdentities: Set<String> = emptySet(),
): List<MatchedMember> = matchedMembers
    .filterNot { matchedMember: MatchedMember ->
        excludedClassNames.contains(matchedMember.owner) &&
            buildMatchedMemberIdentity(matchedMember) !in explicitlyObfuscatedMemberIdentities
    }
    .filterNot { matchedMember: MatchedMember -> excludedMembers.contains(buildMatchedMemberIdentity(matchedMember)) }

internal fun resolveMatchedClassNames(
    matchedRuleSet: List<RuleMatch>,
    excludedClassNames: Set<String>,
    explicitlyObfuscatedMemberIdentities: Set<String> = emptySet(),
): Set<String> {
    val explicitlyMatchedClassNames = matchedRuleSet
        .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames }
        .toSet()
    return explicitlyMatchedClassNames
        .filter { className ->
            className !in excludedClassNames ||
                explicitlyObfuscatedMemberIdentities.any { identity -> identity.startsWith("$className#") }
        }
        .toSet()
}

internal fun resolveMatchedMembers(
    matchedRuleSet: List<RuleMatch>,
    excludedClassNames: Set<String>,
    excludedMembers: Set<String>,
    explicitlyObfuscatedMemberIdentities: Set<String> = emptySet(),
): List<MatchedMember> {
    val matchedMembers = matchedRuleSet.flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedMembers }
    return filteredMatchedMembers(
        matchedMembers = matchedMembers,
        excludedClassNames = excludedClassNames,
        excludedMembers = excludedMembers,
        explicitlyObfuscatedMemberIdentities = explicitlyObfuscatedMemberIdentities,
    ).distinctBy(::buildMatchedMemberIdentity)
}

internal fun buildMatchedMemberIdentity(matchedMember: MatchedMember): String {
    return matchedMember.owner + "#" + matchedMember.kind + ":" + matchedMember.name + ":" + matchedMember.descriptor
}
