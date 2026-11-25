package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData

internal fun resourceCount(jarEntries: List<JarEntryData>, classCount: Int): Int = jarEntries.size - classCount

internal fun assembledBytecodeArtifact(
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
    analysisSummary: JarAnalysisSummary,
): BytecodeArtifact = BytecodeArtifact(
    jarEntries = jarEntries,
    classArtifacts = classArtifacts,
    classArtifactIndex = classArtifactIndex(classArtifacts),
    analysisSummary = analysisSummary,
)
