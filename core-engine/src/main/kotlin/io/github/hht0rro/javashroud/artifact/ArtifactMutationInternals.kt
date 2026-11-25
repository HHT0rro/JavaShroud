package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData

internal fun updatedArtifactClassIndex(classArtifacts: List<ClassArtifact>) = classArtifactIndex(classArtifacts)

internal fun copiedArtifactWithClasses(
    artifact: BytecodeArtifact,
    classArtifacts: List<ClassArtifact>,
    analysisSummary: JarAnalysisSummary,
): BytecodeArtifact = artifact.copy(
    classArtifacts = classArtifacts,
    classArtifactIndex = updatedArtifactClassIndex(classArtifacts),
    analysisSummary = analysisSummary,
)

internal fun copiedArtifactWithJarEntries(
    artifact: BytecodeArtifact,
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
    analysisSummary: JarAnalysisSummary,
): BytecodeArtifact = artifact.copy(
    jarEntries = jarEntries,
    classArtifacts = classArtifacts,
    classArtifactIndex = updatedArtifactClassIndex(classArtifacts),
    analysisSummary = analysisSummary,
)
