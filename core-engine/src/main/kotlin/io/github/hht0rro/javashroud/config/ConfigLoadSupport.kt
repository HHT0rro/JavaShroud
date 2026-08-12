package io.github.hht0rro.javashroud.config

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.compatibility.hardConflictPairs
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.schema.requiredPassIdsFor
import io.github.hht0rro.javashroud.model.schema.requiresAnyPassIdsFor
import java.nio.file.Path
import kotlin.io.path.absolutePathString

fun loadValidatedConfig(configPath: Path): ObfuscationConfig {
    ensureReadableFile(configPath)
    return validateConfig(parseConfig(configPath), configPath)
}

fun validateConfig(config: ObfuscationConfig, configPath: Path): ObfuscationConfig {
    if (config.inputJarPath.isBlank()) {
        throw IllegalArgumentException("Config validation failed: inputJarPath is blank, path=${configPath.absolutePathString()}")
    }

    if (config.outputJarPath.isBlank()) {
        throw IllegalArgumentException("Config validation failed: outputJarPath is blank, path=${configPath.absolutePathString()}")
    }

    if (config.passes.isEmpty()) {
        throw IllegalArgumentException("Config validation failed: passes is empty, path=${configPath.absolutePathString()}")
    }

    val executablePasses = config.passes.filterNot { it.id == PASS_ORDERING_PLANNER_ID }
    val enabledIds = executablePasses.filter { it.enabled }.map { it.id }
    val duplicateIds = enabledIds.groupBy { it }.filter { it.value.size > 1 }.keys
    if (duplicateIds.isNotEmpty()) {
        throw IllegalArgumentException(
            "Config validation failed: duplicate pass IDs found: ${duplicateIds.joinToString(", ")}, path=${configPath.absolutePathString()}"
        )
    }

    val inputJarPath = Path.of(config.inputJarPath).toAbsolutePath().normalize()
    val outputJarPath = Path.of(config.outputJarPath).toAbsolutePath().normalize()
    ensureReadableFile(inputJarPath)

    if (executablePasses.isEmpty()) {
        throw IllegalArgumentException("Config validation failed: passes is empty, path=${configPath.absolutePathString()}")
    }

    val normalizedPasses = normalizePassDependencies(executablePasses)
    validateRequiredPassDependencies(normalizedPasses, configPath)
    validatePassCompatibility(normalizedPasses, configPath, config.allowIncomplete)
    validateRequiresAnyPassDependencies(normalizedPasses, configPath)
    validateOptInPasses(normalizedPasses, configPath, config.allowOptInPasses)
    validateRedundantPasses(normalizedPasses, configPath, config.allowRedundantPasses)

    return config.copy(
        passes = normalizedPasses,
        inputJarPath = inputJarPath.absolutePathString(),
        outputJarPath = outputJarPath.absolutePathString(),
    )
}

/**
 * Auto-inject missing required dependency passes.
 *
 * Static and parameter-selected requiredPassIds are inserted into the
 * configuration before downstream validation. This allows users to specify only
 * the pass they want without manually including all required dependencies.
 */
private const val PASS_ORDERING_PLANNER_ID = "pass-ordering-planner"

private fun normalizePassDependencies(passes: List<PassSpec>): List<PassSpec> {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toMutableSet()
    val result = passes.toMutableList()
    val schema = buildEngineSchemaPayload()
    val modulesById = schema.modules.associateBy { it.id }

    var changed = true
    while (changed) {
        changed = false
        for (passSpec in result.toList()) {
            if (!passSpec.enabled) continue
            val module = modulesById[passSpec.id] ?: continue
            for (requiredId in module.requiredPassIdsFor(passSpec.params)) {
                if (requiredId !in enabledIds) {
                    result.add(PassSpec(id = requiredId, enabled = true, params = emptyMap()))
                    enabledIds += requiredId
                    changed = true
                }
            }
        }
    }
    return result
}

private fun validatePassCompatibility(passes: List<PassSpec>, configPath: Path, allowIncomplete: Boolean = false) {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()

    for ((a, b) in hardConflictPairs) {
        if (a in enabledIds && b in enabledIds) {
            throw IllegalArgumentException(
                "Config validation failed: incompatible passes '$a' and '$b' cannot be enabled together, " +
                    "path=${configPath.absolutePathString()}"
            )
        }
    }
}

private fun validateRequiredPassDependencies(passes: List<PassSpec>, configPath: Path) {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()
    val modulesById = buildEngineSchemaPayload().modules.associateBy { it.id }
    val missingDependencies = passes
        .filter { passSpec -> passSpec.enabled }
        .mapNotNull { passSpec ->
            val module = modulesById[passSpec.id] ?: return@mapNotNull null
            val missingRequiredPassIds = module.requiredPassIdsFor(passSpec.params).filterNot(enabledIds::contains)
            if (missingRequiredPassIds.isEmpty()) {
                null
            } else {
                module.id to missingRequiredPassIds
            }
        }
        .sortedBy { (passId, _) -> passId }

    if (missingDependencies.isNotEmpty()) {
        val dependencySummary = missingDependencies.joinToString("; ") { (passId, requiredPassIds) ->
            "$passId requires ${requiredPassIds.sorted()}"
        }
        throw IllegalArgumentException(
            "Config validation failed: missing required passes: $dependencySummary, " +
                "path=${configPath.absolutePathString()}"
        )
    }
}

private fun validateRequiresAnyPassDependencies(passes: List<PassSpec>, configPath: Path) {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()
    val modulesById = buildEngineSchemaPayload().modules.associateBy { it.id }
    val missingAnyDependencies = passes
        .filter { passSpec -> passSpec.enabled }
        .mapNotNull { passSpec ->
            val module = modulesById[passSpec.id] ?: return@mapNotNull null
            val requiredAnyPassIds = module.requiresAnyPassIdsFor(passSpec.params)
            if (requiredAnyPassIds.isEmpty() || requiredAnyPassIds.any(enabledIds::contains)) null else module to requiredAnyPassIds
        }
        .sortedBy { (module, _) -> module.id }

    if (missingAnyDependencies.isNotEmpty()) {
        val dependencySummary = missingAnyDependencies.joinToString("; ") { (module, requiredAnyPassIds) ->
            "${module.id} requires any of ${requiredAnyPassIds.sorted()}"
        }
        throw IllegalArgumentException(
            "Config validation failed: missing companion passes: $dependencySummary, " +
                "path=${configPath.absolutePathString()}"
        )
    }
}

/**
 * Reject opt-in passes unless explicitly allowed.
 * Opt-in passes require explicit user consent because they may change runtime
 * behavior, have significant performance impact, or require specific runtime support.
 */
private fun validateOptInPasses(passes: List<PassSpec>, configPath: Path, allowOptInPasses: Boolean = false) {
    if (allowOptInPasses) return

    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()
    val schema = buildEngineSchemaPayload()
    val optInModuleIds = schema.modules.filter { it.requiresOptIn }.map { it.id }.toSet()

    val usedOptIn = enabledIds.intersect(optInModuleIds)
    if (usedOptIn.isNotEmpty()) {
        throw IllegalArgumentException(
            "Config validation failed: passes $usedOptIn require explicit opt-in. " +
                "These passes may change runtime behavior, have significant performance impact, " +
                "or require specific runtime support. Set \"allowOptInPasses\": true to use them. " +
                "path=${configPath.absolutePathString()}"
        )
    }
}
