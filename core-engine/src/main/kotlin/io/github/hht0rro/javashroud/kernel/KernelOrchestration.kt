package io.github.hht0rro.javashroud.kernel

import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.analysis.effectiveRuleSetForPass
import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.config.rejectRemovedAkenV4Parameters
import io.github.hht0rro.javashroud.analysis.loadBytecodeArtifact
import io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.maintenance.RuntimeGarbageCollector
import io.github.hht0rro.javashroud.passes.RegisteredPass
import io.github.hht0rro.javashroud.passes.buildRegisteredPasses
import io.github.hht0rro.javashroud.passes.requireExecutablePass
import io.github.hht0rro.javashroud.transforms.protection.buildVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.CandidateProductionBuildEvidence
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.currentVbc4BuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.hardening.HardenedArtifactFinalizer
import io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat
import io.github.hht0rro.javashroud.transforms.protection.hardening.ReleaseArtifactScan
import io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap
import java.nio.file.Files
import java.nio.file.Path

data class KernelPreparation(
    val artifact: BytecodeArtifact,
    val summaryEvent: EngineEvent,
    val initialContext: PassContext,
)

fun prepareKernelRun(config: ObfuscationConfig, artifact: BytecodeArtifact): KernelPreparation {
    validateSelectedOnlyPassSelectionsAgainstArtifact(config = config, artifact = artifact)
    val summary = artifact.analysisSummary
    return KernelPreparation(
        artifact = artifact,
        summaryEvent = buildSummaryEvent(config = config, summary = summary),
        initialContext = PassContext(config = config, artifact = artifact, events = emptyList()),
    )
}

/**
 * Fail closed only when explicit exclusions empty an enabled independent range.
 *
 * A selected-only selection now starts from an all-targets-enabled baseline, so
 * an empty rule list is valid and an unmatched exclusion is harmless. The input
 * artifact is needed to distinguish a genuinely empty module capability from a
 * user range that removed every target the pass could otherwise process.
 */
internal fun validateSelectedOnlyPassSelectionsAgainstArtifact(
    config: ObfuscationConfig,
    artifact: BytecodeArtifact,
) {
    val enabledPassIds = config.passes.asSequence()
        .filter { it.enabled }
        .map { it.id }
        .toSet()
    val modulesById = buildEngineSchemaPayload().modules.associateBy { it.id }
    val classSummaries = artifact.analysisSummary.classSummaries

    config.passSelections
        .asSequence()
        .filter { selection ->
            selection.passId in enabledPassIds &&
                selection.mode == PassSelectionMode.SELECTED_ONLY &&
                selection.rules.any { it.action == "exclude" }
        }
        .forEach { selection ->
            val module = modulesById[selection.passId] ?: return@forEach
            val baselineConfig = config.copy(
                passSelections = config.passSelections.map { candidate ->
                    if (candidate.passId == selection.passId) candidate.copy(rules = emptyList()) else candidate
                },
            )
            val baselineMatches = buildRuleMatches(
                effectiveRuleSetForPass(config = baselineConfig, passId = selection.passId),
                classSummaries,
            )
            val effectiveMatches = buildRuleMatches(
                effectiveRuleSetForPass(config = config, passId = selection.passId),
                classSummaries,
            )
            val baselineHasTargets = hasProcessableTargets(
                artifact = artifact,
                ruleMatches = baselineMatches,
                passId = selection.passId,
                targetKinds = module.targeting.targetKinds,
            )
            val effectiveHasTargets = hasProcessableTargets(
                artifact = artifact,
                ruleMatches = effectiveMatches,
                passId = selection.passId,
                targetKinds = module.targeting.targetKinds,
            )
            if (baselineHasTargets && !effectiveHasTargets) {
                throw IllegalArgumentException(
                    "Pass '${selection.passId}' independent scope excludes every processable class or method " +
                        "in the loaded artifact.",
                )
            }
        }
}

private fun hasProcessableTargets(
    artifact: BytecodeArtifact,
    ruleMatches: List<io.github.hht0rro.javashroud.model.analysis.RuleMatch>,
    passId: String,
    targetKinds: List<String>,
): Boolean {
    if ("class" in targetKinds && eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, passId).isNotEmpty()) {
        return true
    }
    return "method" in targetKinds && eligibleMembersForAction(artifact.classArtifacts, ruleMatches, passId)
        .any { member -> member.kind == MemberKind.METHOD }
}

internal fun executeKernelRun(
    config: ObfuscationConfig,
    configPath: Path,
    emit: (EngineEvent) -> Unit = {},
    vbc4BuildContextOverride: Vbc4BuildContext? = null,
): EngineRunResult {
    rejectRemovedAkenV4Parameters(config.passes)
    val bootstrapEvents = buildBootstrapEvents(configPath)
    bootstrapEvents.forEach(emit)
    val preparation = prepareKernelRun(config = config, artifact = loadBytecodeArtifact(config))
    emit(preparation.summaryEvent)
    val registeredPasses = buildRegisteredPasses(config)
    val enabledPassIds = config.passes.filter { it.enabled }.map { it.id }
    val planningPassParams: Map<String, Map<String, Any?>> = config.passes
        .filter { it.enabled }
        .associate { passSpec: PassSpec ->
            passSpec.id to passSpec.params.mapValues { (_, value) -> value as Any? }
        }
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
        passParams = planningPassParams,
    )
    if (!planningResult.accepted) {
        if (planningResult.resolverProfileActive) {
            val failureMessage = planningFailureMessage(planningResult)
            emit(
                EngineEvent(
                    level = "error",
                    type = "error",
                    message = failureMessage,
                    progress = null,
                    outPath = null,
                ),
            )
            throw IllegalArgumentException(failureMessage)
        }
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
            vbc4BuildContextOverride = vbc4BuildContextOverride,
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
        vbc4BuildContextOverride = vbc4BuildContextOverride,
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
    vbc4BuildContextOverride: Vbc4BuildContext? = null,
): EngineRunResult {
    val passMap = registeredPasses.associateBy { it.spec.id }
    val reorderedPasses = planningResult.orderedPasses.mapNotNull { passMap[it] }
    return executeWithOrderedPasses(
        config = config,
        preparation = preparation,
        reorderedPasses = reorderedPasses,
        emit = emit,
        vbc4BuildContextOverride = vbc4BuildContextOverride,
    )
}

internal fun executeWithOrderedPasses(
    config: ObfuscationConfig,
    preparation: KernelPreparation,
    reorderedPasses: List<RegisteredPass>,
    emit: (EngineEvent) -> Unit = {},
    vbc4BuildContextOverride: Vbc4BuildContext? = null,
): EngineRunResult {
    val outputJarPath = resolveOutputJarPath(config)
    Files.deleteIfExists(CandidateProductionBuildEvidence.evidencePath(outputJarPath))
    val ownsVbc4BuildContext = vbc4BuildContextOverride == null
    val vbc4BuildContext = vbc4BuildContextOverride ?: buildVbc4BuildContext(config, preparation.artifact)
    return try {
        withVbc4BuildContext(vbc4BuildContext) {
            val knownBrokenPassWarnings = buildKnownBrokenPassWarnings(reorderedPasses.filter { it.spec.enabled }.map { it.spec.id })
            knownBrokenPassWarnings.forEach(emit)
            val passExecution = executeRegisteredPasses(
                initialContext = preparation.initialContext,
                registeredPasses = reorderedPasses,
                emit = emit,
            )
            val executedPassIds = reorderedPasses.filter { it.spec.enabled }.map { it.spec.id }
            val artifactWithoutFixedGeneratedNames = io.github.hht0rro.javashroud.transforms.rename
                .removeFixedGeneratedNames(passExecution.context.artifact)
                .artifact
            val artifactWithHelpers = io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment.injectRequiredHelpers(
                artifact = artifactWithoutFixedGeneratedNames,
                executedPassIds = executedPassIds,
            )
            io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(
                artifact = artifactWithHelpers,
                seed = vbc4BuildContext.nativeSeed,
            )
            io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.reserveAkenStringPagePreSealRoutesIfNeeded(
                artifact = artifactWithHelpers,
                seed = vbc4BuildContext.nativeSeed,
            )
            io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(
                artifact = artifactWithHelpers,
                seed = vbc4BuildContext.nativeSeed,
            )
            io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.reserveAkenNativeChunkPreSealRoutesIfNeeded(
                artifact = artifactWithHelpers,
                seed = vbc4BuildContext.nativeSeed,
            )
            val artifactWithAkenPages = io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                artifact = artifactWithHelpers,
                seed = vbc4BuildContext.nativeSeed,
            )
            val artifactWithNative = io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment.bundleNativeLibrariesIfAvailable(
                artifact = artifactWithAkenPages,
                executedPassIds = executedPassIds,
                config = config,
                emit = emit,
            )
            val artifactWithProcessedHelpers = applyEnabledBasicPassesToHelpers(
                config = config,
                artifactContext = passExecution.context.copy(artifact = artifactWithNative),
                registeredPasses = reorderedPasses,
            )
            val sealedArtifact = io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing.sealIfRequested(
                artifact = artifactWithProcessedHelpers,
                config = config,
            )
            val artifactForWrite = HardenedArtifactFinalizer.finalizeForWrite(sealedArtifact, config)
            writeBytecodeArtifact(outputJarPath, artifactForWrite)
            val artifactDigest = SignedDebugMap.sha256(outputJarPath)
            currentVbc4BuildContextOrNull()?.signedDebugMapDraftOrNull()?.let { draft ->
                if (draft.methodMappings.isNotEmpty() || draft.fieldMappings.isNotEmpty()) {
                    SignedDebugMap.write(outputJarPath, draft, artifactDigest)
                }
            }
            val enabledPasses = reorderedPasses.filter { it.spec.enabled }.map { it.spec.id }
            val nativeBytes = artifactForWrite.jarEntries.map { it.bytes }.filter { bytes ->
                bytes.size >= 4 && ((bytes[0] == 0x4D.toByte() && bytes[1] == 0x5A.toByte()) ||
                    (bytes[0] == 0x7F.toByte() && bytes[1] == 0x45.toByte()))
            }
            val inputJarBytes = try {
                Files.size(Path.of(config.inputJarPath))
            } catch (_: Exception) {
                -1L
            }
            val scanReport = ReleaseArtifactScan.scan(
                outputJarPath = outputJarPath,
                artifact = artifactForWrite,
                profile = config.protectionProfile,
                enabledPasses = enabledPasses,
                nativeBytes = nativeBytes,
                inputJarBytes = inputJarBytes,
            )
            ReleaseArtifactScan.writeReport(outputJarPath, scanReport)
            if (config.protectionProfile.requiresReleaseScan) {
                scanReport.requirePass()
            }
            currentVbc4BuildContextOrNull()?.productionBuildEvidence?.writeAfterFinalJar(
                artifact = artifactForWrite,
                outputJarPath = outputJarPath,
            )
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
    } finally {
        if (ownsVbc4BuildContext) vbc4BuildContext.wipe()
        RuntimeGarbageCollector.collect(apply = true)
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
