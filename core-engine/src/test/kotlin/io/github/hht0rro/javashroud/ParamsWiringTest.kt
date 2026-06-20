package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.modules.buildModuleRegistry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ParamsWiringTest {
    @Test
    fun retained_parameterized_passes_expose_implemented_params() {
        val registry = buildModuleRegistry()

        val controlFlow = assertNotNull(registry["control-flow-obfuscation"])
        assertEquals(
            listOf("density", "dispatchMode", "algebraicFamily"),
            controlFlow.definition.params.map { it.key },
        )

        val flattening = assertNotNull(registry["control-flow-flattening"])
        assertEquals(
            listOf("density", "handlerComplexity", "pattern"),
            flattening.definition.params.map { it.key },
        )

        val stringEncryption = assertNotNull(registry["string-encryption"])
        assertEquals(
            listOf("scope", "lengthThreshold", "seed"),
            stringEncryption.definition.params.map { it.key },
        )

        val methodVirtualization = assertNotNull(registry["method-virtualization"])
        assertTrue(methodVirtualization.definition.params.any { it.key == "methodSelection" })
        assertTrue(methodVirtualization.definition.params.any { it.key == "strictVirtualization" })
    }
}
