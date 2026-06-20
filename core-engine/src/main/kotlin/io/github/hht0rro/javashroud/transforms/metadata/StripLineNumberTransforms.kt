package io.github.hht0rro.javashroud.transforms.metadata

import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.bytecode.stripLineNumbers
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.naming.buildMethodKey
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun stripLineNumbers(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedMembers = eligibleMembersForAction(artifact.classArtifacts, ruleMatches, "strip-line-numbers")
        .filter { matchedMember: MatchedMember -> matchedMember.kind == MemberKind.METHOD }
    val matchedClassNames = matchedMembers.map { matchedMember: MatchedMember -> matchedMember.owner }.toSet()
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) {
            classArtifact
        } else {
            val selectedMethodKeys = matchedMembers
                .filter { matchedMember: MatchedMember -> matchedMember.owner == classArtifact.summary.internalName }
                .map { matchedMember: MatchedMember -> buildMethodKey(matchedMember.name, matchedMember.descriptor) }
                .toSet()
            classArtifact.copy(bytes = stripLineNumbers(classArtifact.bytes, selectedMethodKeys))
        }
    }

    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = matchedClassNames.size,
        transformedMemberCount = matchedMembers.size,
    )
}
