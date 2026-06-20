package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition

internal fun moduleDefinitionIndex(definitions: List<ModuleDefinition>): Map<String, ModuleDefinition> =
    definitions.associateBy { definition: ModuleDefinition -> definition.id }

internal fun assembledModule(
    definitions: Map<String, ModuleDefinition>,
    id: String,
    transform: ModuleTransform,
): ObfuscationModule = ObfuscationModule(
    definition = definitions.getValue(id),
    transform = transform,
)

internal fun assembledModuleSet(
    definitions: List<ModuleDefinition>,
    bindings: List<ModuleBinding>,
): List<ObfuscationModule> {
    val definitionIndex = moduleDefinitionIndex(definitions)
    return bindings.map { binding: ModuleBinding ->
        assembledModule(
            definitions = definitionIndex,
            id = binding.id,
            transform = binding.transform,
        )
    }
}

internal data class ModuleBinding(
    val id: String,
    val transform: ModuleTransform,
)
