package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.protocol.ClassTreeNode
import io.github.hht0rro.javashroud.model.protocol.JarInspectionPayload
import java.nio.file.Path
import kotlin.io.path.absolutePathString

fun inspectJarClasses(inputJarPath: Path): JarInspectionPayload {
    val normalizedInputPath = normalizeJarInspectionPath(inputJarPath)
    val rawLoadResult = loadRawClassEntries(normalizedInputPath)
    val summary = buildJarInspectionSummary(normalizedInputPath, rawLoadResult)
    val classSummaries = summary.classSummaries.sortedBy { classSummary: ClassAnalysisSummary -> classSummary.internalName }
    val nodes = buildClassTreeNodes(classSummaries)

    return buildJarInspectionPayload(normalizedInputPath, classSummaries, nodes)
}

internal fun normalizeJarInspectionPath(inputJarPath: Path): Path = inputJarPath.toAbsolutePath().normalize()

internal fun buildJarInspectionConfig(inputJarPath: Path): ObfuscationConfig = ObfuscationConfig(
    inputJarPath = inputJarPath.absolutePathString(),
    outputJarPath = inputJarPath.absolutePathString(),
    passes = emptyList(),
    ruleSet = RuleSet(rules = emptyList()),
)

internal fun buildJarInspectionSummary(
    inputJarPath: Path,
    rawLoadResult: RawJarLoadResult,
): JarAnalysisSummary = buildJarAnalysisSummary(
    config = buildJarInspectionConfig(inputJarPath),
    jarEntries = rawLoadResult.classEntries.map { rawClassEntry ->
        io.github.hht0rro.javashroud.model.artifact.JarEntryData(rawClassEntry.entry.name, rawClassEntry.bytes)
    },
    classArtifacts = buildClassArtifactsFromRawEntries(rawLoadResult.classEntries, inputJarPath),
    manifestPresent = rawLoadResult.manifestPresent,
)

internal fun buildJarInspectionPayload(
    inputJarPath: Path,
    classSummaries: List<ClassAnalysisSummary>,
    nodes: List<ClassTreeNode>,
): JarInspectionPayload = JarInspectionPayload(
    jarPath = inputJarPath.absolutePathString(),
    classCount = classSummaries.size,
    packageCount = countPackageNodes(nodes),
    nodes = nodes,
)
