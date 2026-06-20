package io.github.hht0rro.javashroud.kernel

import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import java.nio.file.Path

fun buildBootstrapEvents(configPath: Path): List<EngineEvent> = listOf(
    EngineEvent(
        level = "info",
        type = "log",
        message = buildBootstrapMessage(configPath),
        progress = 0,
        outPath = null,
    ),
)

fun buildSummaryEvent(config: ObfuscationConfig, summary: JarAnalysisSummary): EngineEvent = buildSummaryEvent(
    config = config,
    classCount = summary.classCount,
    resourceCount = summary.resourceCount,
    manifestPresent = summary.manifestPresent,
    ruleMatches = summary.ruleMatches,
    renamePlanSize = summary.renamePlan.entries.size,
)

fun buildSummaryEvent(
    config: ObfuscationConfig,
    classCount: Int,
    resourceCount: Int,
    manifestPresent: Boolean,
    ruleMatches: List<RuleMatch>,
    renamePlanSize: Int,
): EngineEvent = EngineEvent(
    level = "info",
    type = "log",
    message = buildArtifactSummaryMessage(
        config = config,
        classCount = classCount,
        resourceCount = resourceCount,
        manifestPresent = manifestPresent,
        ruleMatches = ruleMatches,
        renamePlanSize = renamePlanSize,
    ),
    progress = 15,
    outPath = null,
)

fun buildRunSummaryEvent(
    executedPassCount: Int,
    totalTransformedClasses: Int,
    totalTransformedMembers: Int,
    totalPlannedRenames: Int,
    outputJarPath: String,
): EngineEvent = EngineEvent(
    level = "success",
    type = "log",
    message = buildRunSummaryMessage(
        executedPassCount = executedPassCount,
        totalTransformedClasses = totalTransformedClasses,
        totalTransformedMembers = totalTransformedMembers,
        totalPlannedRenames = totalPlannedRenames,
        outputJarPath = outputJarPath,
    ),
    progress = 95,
    outPath = null,
)

fun buildDoneEvent(outputJarPath: String): EngineEvent = EngineEvent(
    level = "success",
    type = "done",
    message = buildDoneMessage(outputJarPath),
    progress = 100,
    outPath = outputJarPath,
)

fun buildPassProgressEvent(passId: String, completedPassCount: Int, totalPassCount: Int): EngineEvent = EngineEvent(
    level = "info",
    type = "progress",
    message = "Executed pass: id=" + passId,
    progress = calculateProgress(completedPassCount, totalPassCount),
    outPath = null,
)

fun buildPassTickEvent(passId: String, passIndex: Int, totalPassCount: Int, isStart: Boolean): EngineEvent = EngineEvent(
    level = "info",
    type = "progress",
    message = passId,
    progress = calculatePassTickProgress(passIndex, totalPassCount, isStart),
    outPath = null,
)

fun calculateProgress(completedPassCount: Int, totalPassCount: Int): Int {
    if (totalPassCount <= 0) {
        throw IllegalArgumentException("Cannot calculate progress: totalPassCount=" + totalPassCount)
    }

    val progressFloor = 15
    val progressCeiling = 90
    val progressRange = progressCeiling - progressFloor
    return progressFloor + (completedPassCount.toDouble() / totalPassCount.toDouble() * progressRange).toInt().coerceIn(0, progressRange)
}

fun calculatePassTickProgress(passIndex: Int, totalPassCount: Int, isStart: Boolean): Int {
    if (totalPassCount <= 0) {
        throw IllegalArgumentException("Cannot calculate progress: totalPassCount=" + totalPassCount)
    }

    val progressFloor = 15
    val progressCeiling = 90
    val progressRange = progressCeiling - progressFloor
    val tickIndex = passIndex * 2 + if (isStart) 0 else 1
    val totalTicks = totalPassCount * 2
    return progressFloor + ((tickIndex + 1).toDouble() / totalTicks.toDouble() * progressRange).toInt().coerceIn(0, progressRange)
}

internal fun buildBootstrapMessage(configPath: Path): String =
    "Engine started with config=" + configPath.toAbsolutePath().normalize()

internal fun buildDoneMessage(outputJarPath: String): String =
    "Engine completed analysis and wrote output jar=" + outputJarPath

fun buildArtifactSummaryMessage(
    config: ObfuscationConfig,
    classCount: Int,
    resourceCount: Int,
    manifestPresent: Boolean,
    ruleMatches: List<RuleMatch>,
    renamePlanSize: Int,
): String {
    val matchedRuleCount = ruleMatches.count { ruleMatch: RuleMatch ->
        ruleMatch.matchedClassNames.isNotEmpty() || ruleMatch.matchedMembers.isNotEmpty()
    }
    val matchedClassCount = ruleMatches.sumOf { ruleMatch: RuleMatch -> ruleMatch.matchedClassNames.size }
    val matchedMemberCount = ruleMatches.sumOf { ruleMatch: RuleMatch -> ruleMatch.matchedMembers.size }
    return buildString {
        append("Loaded input jar=")
        append(config.inputJarPath)
        append(", classes=")
        append(classCount)
        append(", resources=")
        append(resourceCount)
        append(", manifestPresent=")
        append(manifestPresent)
        append(", matchedRules=")
        append(matchedRuleCount)
        append(", matchedClasses=")
        append(matchedClassCount)
        append(", matchedMembers=")
        append(matchedMemberCount)
        append(", plannedRenames=")
        append(renamePlanSize)
    }
}

internal fun buildRunSummaryMessage(
    executedPassCount: Int,
    totalTransformedClasses: Int,
    totalTransformedMembers: Int,
    totalPlannedRenames: Int,
    outputJarPath: String,
): String = buildString {
    append("Run completed: passes=")
    append(executedPassCount)
    append(", transformedClasses=")
    append(totalTransformedClasses)
    append(", transformedMembers=")
    append(totalTransformedMembers)
    append(", plannedRenames=")
    append(totalPlannedRenames)
    append(", output=")
    append(outputJarPath)
}