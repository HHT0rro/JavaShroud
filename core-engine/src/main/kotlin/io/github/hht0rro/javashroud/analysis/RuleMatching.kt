package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec

fun buildRuleMatches(ruleSet: RuleSet, classSummaries: List<ClassAnalysisSummary>): List<RuleMatch> =
    ruleSet.rules.map { ruleSpec -> buildRuleMatch(ruleSpec, classSummaries) }

internal fun buildRuleMatch(ruleSpec: RuleSpec, classSummaries: List<ClassAnalysisSummary>): RuleMatch {
    val selector = parseTargetSelector(ruleSpec.target)
    val matchedClasses = matchedClasses(classSummaries, selector.classPattern)

    return RuleMatch(
        rule = ruleSpec,
        selector = selector,
        matchedClassNames = matchedClassNames(matchedClasses),
        matchedMembers = matchedMembers(matchedClasses, selector.memberPattern, selector.memberDescriptorPattern),
    )
}

private fun matchedClasses(
    classSummaries: List<ClassAnalysisSummary>,
    classPattern: String,
): List<ClassAnalysisSummary> = classSummaries.filter { classSummary: ClassAnalysisSummary ->
    matchesClassPattern(classSummary.internalName, classPattern)
}

private fun matchedClassNames(classSummaries: List<ClassAnalysisSummary>): List<String> =
    classSummaries.map { classSummary: ClassAnalysisSummary -> classSummary.internalName }

private fun matchedMembers(
    classSummaries: List<ClassAnalysisSummary>,
    memberPattern: String?,
    memberDescriptorPattern: String?,
) = classSummaries.flatMap { classSummary: ClassAnalysisSummary ->
    buildMatchedMembers(classSummary, memberPattern, memberDescriptorPattern)
}

internal fun parseTargetSelector(target: String): TargetSelector {
    val separatorIndex = target.indexOf('#')
    if (separatorIndex < 0) {
        return TargetSelector(classPattern = normalizeClassPattern(target), memberPattern = null, memberDescriptorPattern = null)
    }

    val classPattern = normalizeClassPattern(target.substring(0, separatorIndex))
    val memberSelector = target.substring(separatorIndex + 1)
    if (classPattern.isBlank()) {
        throw IllegalArgumentException("Config validation failed: rule target class pattern is blank, target=" + target)
    }
    if (memberSelector.isBlank()) {
        throw IllegalArgumentException("Config validation failed: rule target member pattern is blank, target=" + target)
    }

    val descriptorSeparatorIndex = memberSelector.indexOf(':')
    return if (descriptorSeparatorIndex < 0) {
        TargetSelector(classPattern = classPattern, memberPattern = memberSelector, memberDescriptorPattern = null)
    } else {
        val memberPattern = memberSelector.substring(0, descriptorSeparatorIndex)
        val memberDescriptorPattern = memberSelector.substring(descriptorSeparatorIndex + 1)
        if (memberPattern.isBlank()) {
            throw IllegalArgumentException("Config validation failed: rule target member name pattern is blank, target=" + target)
        }
        if (memberDescriptorPattern.isBlank()) {
            throw IllegalArgumentException("Config validation failed: rule target member descriptor pattern is blank, target=" + target)
        }
        TargetSelector(
            classPattern = classPattern,
            memberPattern = memberPattern,
            memberDescriptorPattern = memberDescriptorPattern,
        )
    }
}

private fun normalizeClassPattern(classPattern: String): String {
    val trimmed = classPattern.trim()
    return when {
        trimmed == "*" -> trimmed
        trimmed.endsWith(".*") -> trimmed.removeSuffix(".*").replace('.', '/') + "/*"
        trimmed.contains('/') -> trimmed
        else -> trimmed.replace('.', '/')
    }
}

internal fun buildMatchedMembers(
    classSummary: ClassAnalysisSummary,
    memberPattern: String?,
    memberDescriptorPattern: String?,
): List<MatchedMember> {
    if (memberPattern == null) {
        return emptyList()
    }

    return (classSummary.fieldSummaries + classSummary.methodSummaries)
        .filter { memberSummary: MemberSummary ->
            matchesMemberPattern(memberSummary.name, memberPattern) &&
                matchesDescriptorPattern(memberSummary.descriptor, memberDescriptorPattern)
        }
        .map { memberSummary: MemberSummary ->
            MatchedMember(
                owner = classSummary.internalName,
                kind = memberSummary.kind,
                name = memberSummary.name,
                descriptor = memberSummary.descriptor,
            )
        }
}

internal fun matchesClassPattern(className: String, classPattern: String): Boolean {
    return when {
        classPattern == "*" -> true
        classPattern.endsWith("/*") -> className.startsWith(classPattern.removeSuffix("/*"))
        else -> className == classPattern
    }
}

private fun matchesMemberPattern(memberName: String, memberPattern: String): Boolean {
    return when {
        memberPattern == "*" -> true
        memberPattern.endsWith("*") -> memberName.startsWith(memberPattern.removeSuffix("*"))
        else -> memberName == memberPattern
    }
}

private fun matchesDescriptorPattern(descriptor: String, descriptorPattern: String?): Boolean {
    if (descriptorPattern == null) {
        return true
    }
    return when {
        descriptorPattern == "*" -> true
        descriptorPattern.endsWith("*") -> descriptor.startsWith(descriptorPattern.removeSuffix("*"))
        else -> descriptor == descriptorPattern
    }
}
