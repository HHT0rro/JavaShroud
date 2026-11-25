package io.github.hht0rro.javashroud.model.transforms

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact

data class TransformResult(
    val artifact: BytecodeArtifact,
    val transformedClassCount: Int,
    val transformedMemberCount: Int,
)