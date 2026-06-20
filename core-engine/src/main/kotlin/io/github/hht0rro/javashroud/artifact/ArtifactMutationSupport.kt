package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact

fun updateArtifactClassSet(artifact: BytecodeArtifact, updatedClassArtifacts: List<ClassArtifact>): BytecodeArtifact =
    copiedArtifactWithClasses(
        artifact = artifact,
        classArtifacts = updatedClassArtifacts,
        analysisSummary = refreshArtifactSummary(
            analysisSummary = artifact.analysisSummary,
            updatedClassArtifacts = updatedClassArtifacts,
        ),
    )

fun updateRenamedArtifactClasses(
    artifact: BytecodeArtifact,
    updatedClassArtifacts: List<ClassArtifact>,
    classRenameMap: Map<String, String>,
): BytecodeArtifact {
    val updatedJarEntries = renamedJarEntries(artifact.jarEntries, classRenameMap)
    return copiedArtifactWithJarEntries(
        artifact = artifact,
        jarEntries = updatedJarEntries,
        classArtifacts = updatedClassArtifacts,
        analysisSummary = rebuildRenamedArtifactSummary(
            analysisSummary = artifact.analysisSummary,
            renamedJarEntries = updatedJarEntries,
            updatedClassArtifacts = updatedClassArtifacts,
        ),
    )
}
