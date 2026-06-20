package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.passes.PassContext

data class RegisteredPass(
    val spec: PassSpec,
    val executable: ExecutablePass,
) {
    fun apply(context: PassContext): PassContext = applyRegisteredPass(
        spec = spec,
        executable = executable,
        context = context,
    )
}
