package io.github.hht0rro.javashroud.annotations

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun applyAnnotationDirectives(
    config: ObfuscationConfig,
    directives: List<AnnotationDirective>,
): ObfuscationConfig {
    if (directives.isEmpty()) return config

    val schema = buildEngineSchemaPayload()
    val modulesById = schema.modules.associateBy { it.id }
    directives.forEach { directive -> validateAnnotationDirective(directive, modulesById) }

    val enabledDirectivePassIds = directives.filter { it.enabled }.map { it.passId }.toSet()
    val configuredPassesById = config.passes.associateBy { it.id }
    val explicitlyEnabledPassIds = config.passes.filter { it.enabled }.map { it.id }.toSet()
    val annotationOnlyPassIds = enabledDirectivePassIds - explicitlyEnabledPassIds

    val annotationOnlyOptInPassIds = annotationOnlyPassIds
        .filter { passId -> modulesById.getValue(passId).requiresOptIn }
        .toSet()
    if (annotationOnlyOptInPassIds.isNotEmpty() && !config.allowOptInPasses) {
        throw IllegalArgumentException(
            "Config validation failed: annotations requested opt-in passes ${annotationOnlyOptInPassIds.sorted()}. " +
                "Set allowOptInPasses=true and allowAnnotationPasses=true to enable them from annotations.",
        )
    }

    if (annotationOnlyPassIds.isNotEmpty() && !config.allowAnnotationPasses) {
        throw IllegalArgumentException(
            "Config validation failed: annotations requested passes ${annotationOnlyPassIds.sorted()} but allowAnnotationPasses is false. " +
                "Set allowAnnotationPasses=true to let JavaShroud annotations enable passes.",
        )
    }

    val annotationRules = directives
        .filter { it.enabled }
        .map { RuleSpec(target = it.target, action = it.passId) }
        .distinct()
    val annotationParamsByPass = directives
        .filter { it.enabled }
        .groupBy { it.passId }
        .mapValues { (_, passDirectives) -> passDirectives.flatMap { it.options.entries }.associate { it.key to it.value } }

    val mergedPasses = mergeAnnotationPasses(
        configuredPasses = config.passes,
        configuredPassesById = configuredPassesById,
        annotationOnlyPassIds = annotationOnlyPassIds,
        annotationParamsByPass = annotationParamsByPass,
        modulesById = modulesById,
    )

    return config.copy(
        passes = mergedPasses,
        ruleSet = RuleSet(config.ruleSet.rules + annotationRules),
    )
}

private fun mergeAnnotationPasses(
    configuredPasses: List<PassSpec>,
    configuredPassesById: Map<String, PassSpec>,
    annotationOnlyPassIds: Set<String>,
    annotationParamsByPass: Map<String, Map<String, String>>,
    modulesById: Map<String, ModuleDefinition>,
): List<PassSpec> {
    val mergedExisting = configuredPasses.map { pass ->
        val annotationParams = annotationParamsByPass[pass.id].orEmpty()
        if (annotationParams.isEmpty()) {
            pass
        } else {
            pass.copy(params = annotationParams.toJsonParams(modulesById.getValue(pass.id)) + pass.params)
        }
    }
    val annotationPasses = annotationOnlyPassIds
        .filterNot(configuredPassesById::containsKey)
        .sorted()
        .map { passId ->
            PassSpec(
                id = passId,
                enabled = true,
                params = annotationParamsByPass[passId].orEmpty().toJsonParams(modulesById.getValue(passId)),
            )
        }
    return mergedExisting + annotationPasses
}

private fun validateAnnotationDirective(directive: AnnotationDirective, modulesById: Map<String, ModuleDefinition>) {
    val module = modulesById[directive.passId]
        ?: throw IllegalArgumentException("Config validation failed: unknown JavaShroud annotation pass id '${directive.passId}' at ${directive.target}")
    val paramsByKey = module.params.associateBy { it.key }
    directive.options.forEach { (key, value) ->
        val param = paramsByKey[key]
            ?: throw IllegalArgumentException(
                "Config validation failed: JavaShroud annotation option '$key' is not supported by pass '${directive.passId}' at ${directive.target}",
            )
        if (param.options != null && value !in param.options) {
            throw IllegalArgumentException(
                "Config validation failed: JavaShroud annotation option '$key' for pass '${directive.passId}' has unsupported value '$value'. " +
                    "Supported values: ${param.options.joinToString(", ")} at ${directive.target}",
            )
        }
    }
}

private fun Map<String, String>.toJsonParams(module: ModuleDefinition): Map<String, JsonNode> {
    val paramsByKey = module.params.associateBy { it.key }
    return mapValues { (key, value) -> stringToJsonNode(value, paramsByKey.getValue(key)) }
}

private fun stringToJsonNode(value: String, schema: ParamSchema): JsonNode = when (schema.type) {
    "boolean" -> JsonNodeFactory.instance.booleanNode(value.toBooleanStrictOrNull() ?: value.toBoolean())
    "number" -> value.toLongOrNull()?.let(JsonNodeFactory.instance::numberNode)
        ?: value.toDoubleOrNull()?.let(JsonNodeFactory.instance::numberNode)
        ?: throw IllegalArgumentException("Config validation failed: JavaShroud annotation option '${schema.key}' expects number, value='$value'")
    else -> JsonNodeFactory.instance.textNode(value)
}