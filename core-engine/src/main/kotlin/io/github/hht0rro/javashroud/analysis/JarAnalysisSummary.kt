package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.artifact.classSummaries
import io.github.hht0rro.javashroud.artifact.classSummaryIndex
import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.RenamePlan
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig

fun buildJarAnalysisSummary(
    config: ObfuscationConfig,
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
    manifestPresent: Boolean,
): JarAnalysisSummary = assembledJarAnalysisSummary(
    config = config,
    jarEntries = jarEntries,
    classArtifacts = classArtifacts,
    manifestPresent = manifestPresent,
)

fun attachAnalysisSummary(
    config: ObfuscationConfig,
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
    manifestPresent: Boolean,
): BytecodeArtifact = attachedAnalysisArtifact(
    config = config,
    jarEntries = jarEntries,
    classArtifacts = classArtifacts,
    manifestPresent = manifestPresent,
)

internal data class JarAnalysisState(
    val classSummaries: List<ClassAnalysisSummary>,
    val resourceCount: Int,
    val ruleMatches: List<RuleMatch>,
    val renamePlan: RenamePlan,
)

internal fun buildJarAnalysisState(
    config: ObfuscationConfig,
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
): JarAnalysisState {
    val analyzedClassSummaries = classSummaries(classArtifacts)
    val ruleMatches = buildRuleMatches(config.ruleSet, analyzedClassSummaries)
    return JarAnalysisState(
        classSummaries = analyzedClassSummaries,
        resourceCount = resourceCount(jarEntries, analyzedClassSummaries.size),
        ruleMatches = ruleMatches,
        renamePlan = buildRenamePlan(ruleMatches, analyzedClassSummaries),
    )
}

internal fun buildJarAnalysisSummary(
    state: JarAnalysisState,
    manifestPresent: Boolean,
): JarAnalysisSummary = JarAnalysisSummary(
    classCount = state.classSummaries.size,
    resourceCount = state.resourceCount,
    manifestPresent = manifestPresent,
    classSummaries = state.classSummaries,
    classNameIndex = classSummaryIndex(state.classSummaries),
    ruleMatches = state.ruleMatches,
    renamePlan = state.renamePlan,
)

internal fun assembledJarAnalysisSummary(
    config: ObfuscationConfig,
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
    manifestPresent: Boolean,
): JarAnalysisSummary {
    val state = buildJarAnalysisState(config, jarEntries, classArtifacts)
    return buildJarAnalysisSummary(
        state = state,
        manifestPresent = manifestPresent,
    )
}
