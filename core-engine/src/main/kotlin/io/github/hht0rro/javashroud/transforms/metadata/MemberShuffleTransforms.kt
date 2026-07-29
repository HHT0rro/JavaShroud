package io.github.hht0rro.javashroud.transforms.metadata

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.buildLocalPermutation
import io.github.hht0rro.javashroud.bytecode.shuffleClassMembers
import io.github.hht0rro.javashroud.artifact.updateArtifactClassAndJarOrder
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import java.security.MessageDigest

fun shuffleMembers(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "member-shuffle")
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }
    val artifactShape = artifactShape(artifact)
    val buildEntropy = requireVbc4BuildContext().deriveSubKey(
        "javashroud-member-shuffle-layout-v1",
        32,
        artifactShape,
    )

    return try {
        shuffleArtifact(artifact, matchedClassNames, buildEntropy, artifactShape.toHex())
    } finally {
        buildEntropy.fill(0)
        artifactShape.fill(0)
    }
}

private fun shuffleArtifact(
    artifact: BytecodeArtifact,
    matchedClassNames: Set<String>,
    buildEntropy: ByteArray,
    artifactIdentity: String,
): TransformResult {
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val shuffledBytes = shuffleClassMembers(
                classBytes = classArtifact.bytes,
                buildEntropy = buildEntropy,
                classIdentity = classArtifact.summary.internalName,
            )
            if (!shuffledBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, shuffledBytes)
            } else {
                classArtifact
            }
        } else {
            classArtifact
        }
    }

    val shuffledClassArtifacts = buildLocalPermutation(
        values = updatedClassArtifacts,
        buildEntropy = buildEntropy,
        domain = "class-order",
        scopeIdentity = artifactIdentity,
        identity = ClassArtifact::entryName,
    )
    val manifestEntries = artifact.jarEntries.filter(::isManifestEntry)
    val ordinaryJarEntries = artifact.jarEntries.filterNot(::isManifestEntry)
    val shuffledJarEntries = manifestEntries + buildLocalPermutation(
        values = ordinaryJarEntries,
        buildEntropy = buildEntropy,
        domain = "jar-entry-order",
        scopeIdentity = artifactIdentity,
        identity = JarEntryData::name,
    )
    val updatedArtifact = updateArtifactClassAndJarOrder(
        artifact = artifact,
        updatedClassArtifacts = shuffledClassArtifacts,
        updatedJarEntries = shuffledJarEntries,
    )
    return TransformResult(
        artifact = updatedArtifact,
        transformedClassCount = classCount,
        transformedMemberCount = updatedClassArtifacts
            .filter { it.summary.internalName in matchedClassNames }
            .sumOf { it.summary.fieldCount + it.summary.methodCount },
    )
}

private fun isManifestEntry(entry: JarEntryData): Boolean =
    entry.name.equals("META-INF/MANIFEST.MF", ignoreCase = true)

private fun artifactShape(artifact: BytecodeArtifact): ByteArray = MessageDigest.getInstance("SHA-256").run {
    update("javashroud-member-shuffle-artifact-shape-v1".toByteArray(Charsets.US_ASCII))
    artifact.classArtifacts.map(ClassArtifact::entryName).sorted().forEach { name ->
        update(1)
        update(name.toByteArray(Charsets.UTF_8))
        update(0)
    }
    artifact.jarEntries.map(JarEntryData::name).sorted().forEach { name ->
        update(2)
        update(name.toByteArray(Charsets.UTF_8))
        update(0)
    }
    digest()
}

private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }
