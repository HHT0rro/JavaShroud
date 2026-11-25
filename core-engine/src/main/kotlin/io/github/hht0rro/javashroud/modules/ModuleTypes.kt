package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.transforms.TransformResult

fun interface ModuleTransform {
    fun apply(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult
}

data class ObfuscationModule(
    val definition: ModuleDefinition,
    val transform: ModuleTransform,
)




