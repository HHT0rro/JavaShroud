package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.artifact.assembledBytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import java.nio.file.Path

fun loadBytecodeArtifact(config: ObfuscationConfig): BytecodeArtifact {
    val inputJarPath = resolveInputJarPath(config)
    val jarReadResult = readJarEntries(inputJarPath)
    return buildLoadedBytecodeArtifact(config, inputJarPath, jarReadResult)
}

internal fun resolveInputJarPath(config: ObfuscationConfig): Path = Path.of(config.inputJarPath)

internal fun buildLoadedBytecodeArtifact(
    config: ObfuscationConfig,
    inputJarPath: Path,
    jarReadResult: JarReadResult,
): BytecodeArtifact = attachAnalysisSummary(
    config = config,
    jarEntries = buildJarEntryData(jarReadResult.entries),
    classArtifacts = buildClassArtifactsFromJarEntries(jarReadResult.entries, inputJarPath),
    manifestPresent = jarReadResult.manifestPresent,
)

internal fun attachedAnalysisArtifact(
    config: ObfuscationConfig,
    jarEntries: List<JarEntryData>,
    classArtifacts: List<ClassArtifact>,
    manifestPresent: Boolean,
): BytecodeArtifact = assembledBytecodeArtifact(
    jarEntries = jarEntries,
    classArtifacts = classArtifacts,
    analysisSummary = buildJarAnalysisSummary(config, jarEntries, classArtifacts, manifestPresent),
)
