package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact

internal fun classArtifactIndex(classArtifacts: List<ClassArtifact>): Map<String, ClassArtifact> =
    classArtifacts.associateBy { classArtifact: ClassArtifact -> classArtifact.summary.internalName }

internal fun classSummaries(classArtifacts: List<ClassArtifact>): List<ClassAnalysisSummary> =
    classArtifacts.map { classArtifact: ClassArtifact -> classArtifact.summary }

internal fun classSummaryIndex(classSummaries: List<ClassAnalysisSummary>): Map<String, ClassAnalysisSummary> =
    classSummaries.associateBy { classSummary: ClassAnalysisSummary -> classSummary.internalName }
