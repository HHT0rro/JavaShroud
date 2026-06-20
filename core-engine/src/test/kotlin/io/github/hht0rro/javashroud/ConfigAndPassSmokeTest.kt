package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.passes.buildRegisteredPasses
import kotlin.test.Test
import kotlin.test.assertFailsWith

class ConfigAndPassSmokeTest {
    @Test
    fun buildRegisteredPasses_rejects_unknown_pass_id() {
        val config = testConfig(
            passes = listOf(PassSpec(id = "missing-pass", enabled = true, params = emptyMap())),
        )

        assertFailsWith<IllegalArgumentException> {
            buildRegisteredPasses(config)
        }
    }
}
