package io.github.hht0rro.javashroud.kernel

import io.github.hht0rro.javashroud.analysis.inspectJarClasses
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.model.protocol.JarInspectionPayload
import java.nio.file.Path

data class EngineRunResult(
    val events: List<EngineEvent>,
)

class EngineKernel {
    fun inspectJar(inputJar: Path): JarInspectionPayload = inspectJarClasses(inputJar)

    fun run(config: ObfuscationConfig, configPath: Path, emit: (EngineEvent) -> Unit = {}): EngineRunResult =
        executeKernelRun(config = config, configPath = configPath, emit = emit)
}