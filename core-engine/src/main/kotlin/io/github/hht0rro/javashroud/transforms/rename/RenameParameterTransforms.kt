package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.bytecode.renameLocalVariables
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.naming.buildMethodKey
import io.github.hht0rro.javashroud.naming.canRenameMethod
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun renameParameters(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedMembers = eligibleMembersForAction(artifact.classArtifacts, ruleMatches, "rename-parameters")
        .filter { matchedMember: MatchedMember -> matchedMember.kind == MemberKind.METHOD }
        .filter { matchedMember: MatchedMember -> canRenameMethod(matchedMember.name) }
    val matchedMembersByOwner = matchedMembers.groupBy { matchedMember: MatchedMember -> matchedMember.owner }
    if (matchedMembersByOwner.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        val ownerMatchedMembers = matchedMembersByOwner[classArtifact.summary.internalName]
        if (ownerMatchedMembers == null) {
            classArtifact
        } else {
            val selectedMethodKeys = ownerMatchedMembers
                .map { matchedMember: MatchedMember -> buildMethodKey(matchedMember.name, matchedMember.descriptor) }
                .toSet()
            val updatedBytes = renameLocalVariables(classArtifact.bytes, selectedMethodKeys)
            reanalyzedClassArtifact(classArtifact, updatedBytes)
        }
    }

    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = matchedMembersByOwner.size,
        transformedMemberCount = matchedMembers.size,
    )
}
