package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.model.analysis.RuleMatch

internal fun buildDisabledPassMessage(passId: String): String = "Skipped disabled pass: id=" + passId

fun buildPassMessage(
    passId: String,
    classCount: Int,
    resourceCount: Int,
    ruleMatches: List<RuleMatch>,
    transformedClassCount: Int,
    transformedMemberCount: Int,
    plannedRenameCount: Int,
): String {
    val matchedClassCount = ruleMatches.sumOf { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames.size }
    val matchedMemberCount = ruleMatches.sumOf { ruleMatch: RuleMatch -> ruleMatch.matchedMembers.size }
    return buildString {
        append("Executed pass: id=")
        append(passId)
        append(", classes=")
        append(classCount)
        append(", resources=")
        append(resourceCount)
        append(", matchedClasses=")
        append(matchedClassCount)
        append(", matchedMembers=")
        append(matchedMemberCount)
        append(", transformedClasses=")
        append(transformedClassCount)
        append(", transformedMembers=")
        append(transformedMemberCount)
        append(", plannedRenames=")
        append(plannedRenameCount)
    }
}
