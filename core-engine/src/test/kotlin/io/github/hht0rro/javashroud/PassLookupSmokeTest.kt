package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.passes.requireExecutablePass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PassLookupSmokeTest {
    @Test
    fun requireExecutablePass_returns_registered_pass() {
        val executable = requireExecutablePass("strip-compile-debug-info")
        assertEquals("strip-compile-debug-info", executable.descriptor.id)
        assertEquals("strip-compile-debug-info", executable.module.definition.id)
    }

    @Test
    fun requireExecutablePass_rejects_unknown_pass_with_available_ids() {
        val error = assertFailsWith<IllegalArgumentException> {
            requireExecutablePass("missing-pass")
        }

        assertTrue(error.message?.contains("Unknown pass id=missing-pass") == true)
        assertTrue(error.message?.contains("strip-compile-debug-info") == true)
    }
}
