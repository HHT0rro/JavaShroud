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
            listOf("branchInjection", "handlerSplit", "density", "dispatchMode", "algebraicFamily"),
            controlFlow.definition.params.map { it.key },
        )

        val flattening = assertNotNull(registry["control-flow-flattening"])
        assertEquals(
            listOf("density", "handlerComplexity", "pattern"),
            flattening.definition.params.map { it.key },
        )

        val stringEncryption = assertNotNull(registry["string-encryption"])
        assertEquals(
            listOf("decoderBackend", "strength", "payloadCodec", "scope", "lengthThreshold", "seed"),
            stringEncryption.definition.params.map { it.key },
        )
        assertEquals(
            "auto",
            stringEncryption.definition.params.single { it.key == "payloadCodec" }.defaultValue?.asText(),
            "payloadCodec defaults to auto so strength selects the resolver codec",
        )

        val methodVirtualization = assertNotNull(registry["method-virtualization"])
        assertTrue(methodVirtualization.definition.params.any { it.key == "methodSelection" })
        assertTrue(methodVirtualization.definition.params.none { it.key == "strictVirtualization" })
        assertEquals(0, methodVirtualization.definition.params.single { it.key == "maxInstructions" }.defaultValue?.asInt())
        assertEquals(0, methodVirtualization.definition.params.single { it.key == "maxBroadVirtualizedMethods" }.defaultValue?.asInt())
    }
}
