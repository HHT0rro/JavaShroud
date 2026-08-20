package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.RuleMatch

/** Resolves the most specific class/member rule without relying on list order. */
private fun mostSpecificRuleForClass(
    ruleMatches: List<RuleMatch>,
    className: String,
): RuleMatch? = ruleMatches
    .asSequence()
    .filter { match -> match.selector.memberPattern == null && className in match.matchedClassNames }
    .maxWithOrNull(compareBy<RuleMatch> { match -> selectorSpecificity(match) }.thenBy { match -> match.rule.action == "obfuscate" })

private fun mostSpecificRuleForMember(
    ruleMatches: List<RuleMatch>,
    member: io.github.hht0rro.javashroud.model.analysis.MatchedMember,
): RuleMatch? = ruleMatches
    .asSequence()
    .filter { match ->
        if (match.selector.memberPattern == null) {
            member.owner in match.matchedClassNames
        } else {
            match.matchedMembers.any { candidate ->
                buildMatchedMemberIdentity(candidate) == buildMatchedMemberIdentity(member)
            }
        }
    }
    .maxWithOrNull(compareBy<RuleMatch> { match -> selectorSpecificity(match) }.thenBy { match -> match.rule.action == "obfuscate" })

private fun selectorSpecificity(match: RuleMatch): Int {
    val classSpecificity = when {
        match.selector.classPattern == "*" -> 0
        match.selector.classPattern.endsWith("/*") -> 1
        else -> 2
    }
    val memberSpecificity = when {
        match.selector.memberPattern == null -> 0
        match.selector.memberPattern == "*" -> 1
        match.selector.memberPattern.endsWith("*") -> 2
        else -> 3
    }
    val descriptorSpecificity = when {
        match.selector.memberDescriptorPattern == null -> 0
        match.selector.memberDescriptorPattern == "*" -> 1
        match.selector.memberDescriptorPattern.endsWith("*") -> 2
        else -> 3
    }
    return classSpecificity * 100 + memberSpecificity * 10 + descriptorSpecificity
}

internal fun excludedClassNames(ruleMatches: List<RuleMatch>): Set<String> = allClassNames(ruleMatches)
    .filter { className -> mostSpecificRuleForClass(ruleMatches, className)?.rule?.action == "exclude" }
    .toSet()

internal fun excludedMembers(ruleMatches: List<RuleMatch>): Set<String> = ruleMatches
    .flatMap { it.matchedMembers }
    .distinctBy(::buildMatchedMemberIdentity)
    .filter { member -> mostSpecificRuleForMember(ruleMatches, member)?.rule?.action == "exclude" }
    .map(::buildMatchedMemberIdentity)
    .toSet()

internal fun allClassNames(ruleMatches: List<RuleMatch>): Set<String> = ruleMatches
    .flatMap { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames }
    .toSet()

internal fun explicitObfuscateMemberIdentities(ruleMatches: List<RuleMatch>): Set<String> = explicitObfuscateMembers(ruleMatches)
    .map(::buildMatchedMemberIdentity)
    .toSet()

internal fun explicitObfuscateMembers(ruleMatches: List<RuleMatch>) = ruleMatches
    .flatMap { it.matchedMembers }
    .distinctBy(::buildMatchedMemberIdentity)
    .filter { member -> mostSpecificRuleForMember(ruleMatches, member)?.rule?.action == "obfuscate" }
