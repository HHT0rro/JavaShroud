package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode

fun eligibleClassNamesForAction(classArtifacts: List<ClassArtifact>, ruleMatches: List<RuleMatch>, action: String): Set<String> {
    val explicitlyMatchedClassNames = matchedClassNamesForAction(ruleMatches, action)
    if (explicitlyMatchedClassNames.isNotEmpty()) {
        return explicitlyMatchedClassNames
    }

    return fallbackEligibleClassNames(classArtifacts, excludedClassNames(ruleMatches))
}

fun eligibleMembersForAction(classArtifacts: List<ClassArtifact>, ruleMatches: List<RuleMatch>, action: String): List<MatchedMember> {
    val explicitlyMatchedMembers = matchedMembersForAction(ruleMatches, action)
    if (explicitlyMatchedMembers.isNotEmpty()) {
        return explicitlyMatchedMembers
    }

    return fallbackEligibleMembers(classArtifacts, ruleMatches)
}

/** Internal helper package prefix injected by EmbeddedHelperDeployment. */
private const val HELPER_PKG_PREFIX = "io/github/hht0rro/javashroud/transforms/protection/"

internal fun fallbackEligibleClassNames(
    classArtifacts: List<ClassArtifact>,
    excludedClassNames: Set<String>,
): Set<String> = classArtifacts
    .map { classArtifact: ClassArtifact -> classArtifact.summary.internalName }
    .filterNot(excludedClassNames::contains)
    .filterNot { it.startsWith(HELPER_PKG_PREFIX) }
    .toSet()

internal fun fallbackEligibleMembers(
    classArtifacts: List<ClassArtifact>,
    ruleMatches: List<RuleMatch>,
): List<MatchedMember> {
    val explicitlyObfuscatedMembers = explicitObfuscateMembers(ruleMatches)
    return (
        materializeEligibleMembers(
            classArtifacts = classArtifacts,
            excludedClassNames = excludedClassNames(ruleMatches),
            excludedMembers = excludedMembers(ruleMatches),
        ) + explicitlyObfuscatedMembers
        ).distinctBy(::buildMatchedMemberIdentity)
}

internal fun materializeEligibleMembers(
    classArtifacts: List<ClassArtifact>,
    excludedClassNames: Set<String>,
    excludedMembers: Set<String>,
): List<MatchedMember> = classArtifacts
    .filterNot { classArtifact: ClassArtifact -> excludedClassNames.contains(classArtifact.summary.internalName) }
    .flatMap { classArtifact: ClassArtifact -> currentBytecodeMembers(classArtifact) }
    .filterNot { matchedMember: MatchedMember -> excludedMembers.contains(buildMatchedMemberIdentity(matchedMember)) }

private fun currentBytecodeMembers(classArtifact: ClassArtifact): List<MatchedMember> {
    val node = ClassNode()
    return try {
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        val owner = node.name ?: classArtifact.summary.internalName
        node.fields.map { field ->
            MatchedMember(owner = owner, kind = MemberKind.FIELD, name = field.name, descriptor = field.desc)
        } + node.methods.map { method ->
            MatchedMember(owner = owner, kind = MemberKind.METHOD, name = method.name, descriptor = method.desc)
        }
    } catch (_: Exception) {
        (classArtifact.summary.fieldSummaries + classArtifact.summary.methodSummaries).map { memberSummary ->
            MatchedMember(
                owner = classArtifact.summary.internalName,
                kind = memberSummary.kind,
                name = memberSummary.name,
                descriptor = memberSummary.descriptor,
            )
        }
    }
}
