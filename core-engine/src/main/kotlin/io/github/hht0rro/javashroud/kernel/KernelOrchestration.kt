package io.github.hht0rro.javashroud.kernel

import io.github.hht0rro.javashroud.analysis.loadBytecodeArtifact
import io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.passes.RegisteredPass
import io.github.hht0rro.javashroud.passes.buildRegisteredPasses
import io.github.hht0rro.javashroud.passes.requireExecutablePass
import io.github.hht0rro.javashroud.transforms.protection.buildVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.nio.file.Path

data class KernelPreparation(
    val artifact: BytecodeArtifact,
    val summaryEvent: EngineEvent,
    val initialContext: PassContext,
)

fun prepareKernelRun(config: ObfuscationConfig, artifact: BytecodeArtifact): KernelPreparation {
    val summary = artifact.analysisSummary
    return KernelPreparation(
        artifact = artifact,
        summaryEvent = buildSummaryEvent(config = config, summary = summary),
        initialContext = PassContext(config = config, artifact = artifact, events = emptyList()),
    )
}

internal fun executeKernelRun(
    config: ObfuscationConfig,
    configPath: Path,
    emit: (EngineEvent) -> Unit = {},
): EngineRunResult {
    val bootstrapEvents = buildBootstrapEvents(configPath)
    bootstrapEvents.forEach(emit)
    val preparation = prepareKernelRun(config = config, artifact = loadBytecodeArtifact(config))
    emit(preparation.summaryEvent)
    val registeredPasses = buildRegisteredPasses(config)
    val enabledPassIds = config.passes.filter { it.enabled }.map { it.id }
    val availablePassIds = io.github.hht0rro.javashroud.passes.executablePassRegistry.keys
    val optInPassIds = registeredPasses.filter { it.executable.descriptor.definition.requiresOptIn }.map { it.spec.id }.toSet()
    val planningResult = io.github.hht0rro.javashroud.transforms.protection.planPassOrdering(
        passIds = enabledPassIds,
        orderingConstraints = io.github.hht0rro.javashroud.compatibility.buildOrderingConstraints(),
        hardConflicts = io.github.hht0rro.javashroud.compatibility.hardConflictPairs,
        softConflicts = io.github.hht0rro.javashroud.compatibility.softConflictPairs,
        availablePassIds = availablePassIds,
        optInPassIds = optInPassIds,
        mode = "auto-sort",
        strictness = "warn",
    )
    if (!planningResult.accepted) {
        val warningEvent = EngineEvent(
            level = "warn",
            type = "warn",
            message = planningFailureMessage(planningResult) + " Falling back to original pass order.",
            progress = null,
            outPath = null,
        )
        emit(warningEvent)
        return executeKernelRunWithFallbackOrder(
            config = config,
            configPath = configPath,
            preparation = preparation,
            registeredPasses = registeredPasses,
            planningResult = planningResult.copy(orderedPasses = enabledPassIds),
            enabledPassIds = enabledPassIds,
            emit = emit,
        )
    }
    val knownBrokenPassWarnings = buildKnownBrokenPassWarnings(enabledPassIds)
    knownBrokenPassWarnings.forEach(emit)
    val reorderedPasses = if (planningResult.orderedPasses != enabledPassIds) {
        val passMap = registeredPasses.associateBy { it.spec.id }
        planningResult.orderedPasses.mapNotNull { passMap[it] }
    } else {
        registeredPasses
    }
    return executeWithOrderedPasses(
        config = config,
        preparation = preparation,
        reorderedPasses = reorderedPasses,
        emit = emit,
    )
}

internal fun executeKernelRunWithFallbackOrder(
    config: ObfuscationConfig,
    configPath: Path,
    preparation: KernelPreparation,
    registeredPasses: List<RegisteredPass>,
    planningResult: io.github.hht0rro.javashroud.transforms.protection.PlanningResult,
    enabledPassIds: List<String>,
    emit: (EngineEvent) -> Unit = {},
): EngineRunResult {
    val passMap = registeredPasses.associateBy { it.spec.id }
    val reorderedPasses = planningResult.orderedPasses.mapNotNull { passMap[it] }
    return executeWithOrderedPasses(
        config = config,
        preparation = preparation,
        reorderedPasses = reorderedPasses,
        emit = emit,
    )
}

internal fun executeWithOrderedPasses(
    config: ObfuscationConfig,
    preparation: KernelPreparation,
    reorderedPasses: List<RegisteredPass>,
    emit: (EngineEvent) -> Unit = {},
): EngineRunResult {
    val vbc4BuildContext = buildVbc4BuildContext(config, preparation.artifact)
    return withVbc4BuildContext(vbc4BuildContext) {
        val knownBrokenPassWarnings = buildKnownBrokenPassWarnings(reorderedPasses.filter { it.spec.enabled }.map { it.spec.id })
        knownBrokenPassWarnings.forEach(emit)
        val passExecution = executeRegisteredPasses(
            initialContext = preparation.initialContext,
            registeredPasses = reorderedPasses,
            emit = emit,
        )
        val executedPassIds = reorderedPasses.filter { it.spec.enabled }.map { it.spec.id }
        val artifactWithHelpers = io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = passExecution.context.artifact,
            executedPassIds = executedPassIds,
        )
        val artifactWithNative = io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment.bundleNativeLibrariesIfAvailable(
            artifact = artifactWithHelpers,
            executedPassIds = executedPassIds,
            config = config,
            emit = emit,
        )
        val artifactWithProcessedHelpers = applyEnabledBasicPassesToHelpers(
            config = config,
            artifactContext = passExecution.context.copy(artifact = artifactWithNative),
            registeredPasses = reorderedPasses,
        )
        val artifactForWrite = io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.sealIfRequested(
            artifact = artifactWithProcessedHelpers,
            config = config,
        )

        val outputJarPath = resolveOutputJarPath(config)
        writeBytecodeArtifact(outputJarPath, artifactForWrite)
        val outputJarPathString = outputJarPath.toString()
        emit(buildRunSummaryEvent(
            executedPassCount = passExecution.executedPassCount,
            totalTransformedClasses = passExecution.totalTransformedClasses,
            totalTransformedMembers = passExecution.totalTransformedMembers,
            totalPlannedRenames = passExecution.totalPlannedRenames,
            outputJarPath = outputJarPathString,
        ))
        emit(buildDoneEvent(outputJarPathString))
        EngineRunResult(events = emptyList())
    }
}

internal fun resolveOutputJarPath(config: ObfuscationConfig): Path = Path.of(config.outputJarPath).toAbsolutePath().normalize()

private const val EMBEDDED_HELPER_TARGET = "io/github/hht0rro/javashroud/transforms/protection/*"
private const val JNI_MICROKERNEL_LOADER_ID = "jni-microkernel-loader"

private val helperBasicClassPassIds = setOf(
    "strip-compile-debug-info",
    "member-hide",
    "static-init-perturbation",
    "anti-decompiler-structure",
)

private val helperBasicMemberPassIds = setOf(
    "rename-fields",
)

private val helperBasicPassIds = helperBasicClassPassIds + helperBasicMemberPassIds

private val nativeHelperHardeningPassIds = listOf(
    "strip-compile-debug-info",
    "member-hide",
)

private fun applyEnabledBasicPassesToHelpers(
    config: ObfuscationConfig,
    artifactContext: PassContext,
    registeredPasses: List<RegisteredPass>,
): io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact {
    val enabledPassIds = registeredPasses
        .asSequence()
        .filter { it.spec.enabled }
        .map { it.spec.id }
        .toSet()
    val helperPasses = registeredPasses.filter { registeredPass: RegisteredPass ->
        registeredPass.spec.enabled && registeredPass.spec.id in helperBasicPassIds
    }
    val helperPassIds = helperPasses.mapTo(mutableSetOf()) { it.spec.id }
    val automaticHelperPasses = if (JNI_MICROKERNEL_LOADER_ID in enabledPassIds) {
        nativeHelperHardeningPassIds
            .filterNot { passId -> passId in helperPassIds }
            .map { passId ->
                RegisteredPass(
                    spec = PassSpec(id = passId, enabled = true, params = emptyMap()),
                    executable = requireExecutablePass(passId),
                )
            }
    } else {
        emptyList()
    }
    val allHelperPasses = helperPasses + automaticHelperPasses
    val hasHelperClasses = artifactContext.artifact.classArtifacts.any {
        it.summary.internalName.startsWith("io/github/hht0rro/javashroud/transforms/protection/")
    }
    if (!hasHelperClasses) {
        return artifactContext.artifact
    }

    if (allHelperPasses.isEmpty()) {
        return artifactContext.artifact
    }

    val helperConfig = config.copy(
        ruleSet = RuleSet(rules = allHelperPasses.flatMap { registeredPass: RegisteredPass -> helperRulesForPass(registeredPass.spec.id) }),
        passes = allHelperPasses.map { registeredPass: RegisteredPass -> registeredPass.spec },
    )
    val helperContext = artifactContext.copy(config = helperConfig, events = emptyList())
    return executeRegisteredPasses(
        initialContext = helperContext,
        registeredPasses = allHelperPasses,
    ).context.artifact
}

private fun helperRulesForPass(passId: String): List<RuleSpec> {
    val target = if (passId in helperBasicMemberPassIds) {
        "$EMBEDDED_HELPER_TARGET#*:*"
    } else {
        EMBEDDED_HELPER_TARGET
    }
    return listOf(RuleSpec(target = target, action = passId))
}

private fun planningFailureMessage(
    planningResult: io.github.hht0rro.javashroud.transforms.protection.PlanningResult,
): String {
    val errors = planningResult.diagnostics
        .filter { it.level == "error" }
        .map { it.message }
        .distinct()
    return if (errors.isEmpty()) {
        "Pass ordering planner rejected the configuration."
    } else {
        errors.joinToString(separator = " | ")
    }
}

private val knownBrokenPasses: Map<String, String> = mapOf()

private fun buildKnownBrokenPassWarnings(enabledPassIds: List<String>): List<EngineEvent> {
    val warnings = mutableListOf<EngineEvent>()
    for ((passId, issue) in knownBrokenPasses) {
        if (passId in enabledPassIds) {
            warnings.add(
                EngineEvent(
                    level = "warn",
                    type = "warn",
                    message = "Pass '$passId' has a known runtime issue: $issue. The output JAR may fail to run.",
                    progress = null,
                    outPath = null,
                )
            )
        }
    }
    return warnings
}
