package io.github.hht0rro.javashroud.model.artifact

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary

data class JarEntryData(
    val name: String,
    val bytes: ByteArray,
)

data class ClassArtifact(
    val entryName: String,
    val summary: ClassAnalysisSummary,
    val bytes: ByteArray,
)

data class BytecodeArtifact(
    val jarEntries: List<JarEntryData>,
    val classArtifacts: List<ClassArtifact>,
    val classArtifactIndex: Map<String, ClassArtifact>,
    val analysisSummary: JarAnalysisSummary,
)
