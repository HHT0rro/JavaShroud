package io.github.hht0rro.javashroud.transforms.metadata

import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.bytecode.addSyntheticFlags
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.naming.buildMemberKey
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun markSyntheticMembers(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedMembers = eligibleMembersForAction(artifact.classArtifacts, ruleMatches, "mark-synthetic-members")
    val matchedClassNames = matchedMembers.map { matchedMember: MatchedMember -> matchedMember.owner }.toSet()
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) {
            classArtifact
        } else {
            val selectedMemberKeys = matchedMembers
                .filter { matchedMember: MatchedMember -> matchedMember.owner == classArtifact.summary.internalName }
                .map { matchedMember: MatchedMember -> buildMemberKey(matchedMember.kind, matchedMember.name, matchedMember.descriptor) }
                .toSet()
            val updatedBytes = addSyntheticFlags(classArtifact.bytes, selectedMemberKeys)
            reanalyzedClassArtifact(classArtifact, updatedBytes)
        }
    }

    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = matchedClassNames.size,
        transformedMemberCount = matchedMembers.size,
    )
}
