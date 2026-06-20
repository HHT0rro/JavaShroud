package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.RuleMatch

internal fun excludedClassNames(ruleMatches: List<RuleMatch>): Set<String> {
    val explicitObfuscateClassNames = explicitObfuscateClassNames(ruleMatches)
    return ruleMatches
        .filter { ruleMatch: RuleMatch ->
            ruleMatch.rule.action == "exclude" && ruleMatch.selector.memberPattern == null
        }
        .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames }
        .filterNot(explicitObfuscateClassNames::contains)
        .toSet()
}

internal fun excludedMembers(ruleMatches: List<RuleMatch>): Set<String> {
    val explicitObfuscateMemberIdentities = explicitObfuscateMemberIdentities(ruleMatches)
    return ruleMatches
        .filter { ruleMatch: RuleMatch -> ruleMatch.rule.action == "exclude" }
        .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedMembers }
        .map(::buildMatchedMemberIdentity)
        .filterNot(explicitObfuscateMemberIdentities::contains)
        .toSet()
}

internal fun allClassNames(ruleMatches: List<RuleMatch>): Set<String> {
    return ruleMatches
        .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames }
        .toSet()
}

private fun explicitObfuscateClassNames(ruleMatches: List<RuleMatch>): Set<String> = ruleMatches
    .filter { ruleMatch: RuleMatch -> ruleMatch.rule.action == "obfuscate" && ruleMatch.selector.memberPattern == null }
    .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames }
    .toSet()

internal fun explicitObfuscateMemberIdentities(ruleMatches: List<RuleMatch>): Set<String> = explicitObfuscateMembers(ruleMatches)
    .map(::buildMatchedMemberIdentity)
    .toSet()

internal fun explicitObfuscateMembers(ruleMatches: List<RuleMatch>) = ruleMatches
    .filter { ruleMatch: RuleMatch -> ruleMatch.rule.action == "obfuscate" }
    .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedMembers }
