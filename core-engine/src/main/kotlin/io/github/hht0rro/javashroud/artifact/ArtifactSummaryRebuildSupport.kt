package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData

internal fun refreshArtifactSummary(
    analysisSummary: JarAnalysisSummary,
    updatedClassArtifacts: List<ClassArtifact>,
): JarAnalysisSummary {
    val updatedClassSummaries = classSummaries(updatedClassArtifacts)
    return analysisSummary.copy(
        classSummaries = updatedClassSummaries,
        classNameIndex = classSummaryIndex(updatedClassSummaries),
    )
}

internal fun rebuildRenamedArtifactSummary(
    analysisSummary: JarAnalysisSummary,
    renamedJarEntries: List<JarEntryData>,
    updatedClassArtifacts: List<ClassArtifact>,
): JarAnalysisSummary {
    val updatedClassSummaries = classSummaries(updatedClassArtifacts)
    val updatedClassCount = updatedClassSummaries.size
    return analysisSummary.copy(
        classCount = updatedClassCount,
        resourceCount = resourceCount(renamedJarEntries, updatedClassCount),
        classSummaries = updatedClassSummaries,
        classNameIndex = classSummaryIndex(updatedClassSummaries),
    )
}
