package io.github.hht0rro.javashroud.config

import io.github.hht0rro.javashroud.compatibility.softConflictPairs
import io.github.hht0rro.javashroud.model.config.PassSpec
import java.nio.file.Path
import kotlin.io.path.absolutePathString

internal fun validateRedundantPasses(passes: List<PassSpec>, configPath: Path, allowRedundantPasses: Boolean) {
    if (allowRedundantPasses) return

    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()

    for ((a, b) in softConflictPairs) {
        if (a in enabledIds && b in enabledIds) {
            throw IllegalArgumentException(
                "Config validation failed: redundant passes '$a' and '$b' should not be enabled together unless allowRedundantPasses=true, path=${configPath.absolutePathString()}"
            )
        }
    }
}
