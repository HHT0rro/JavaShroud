package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class QpBridgeJava8CompatibilityTest {
    @Test
    fun embedded_helper_stays_java8_compatible_without_generic_target_oracle() {
        val resource = "/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.class"
        val helperBytes = requireNotNull(QpBridge::class.java.getResourceAsStream(resource)).use { it.readBytes() }
        val reader = ClassReader(helperBytes)
        assertEquals(Opcodes.V1_8, reader.readShort(6).toInt())
        assertFalse(QpBridge::class.java.declaredMethods.any { method ->
            method.name == "createRunnableLambda" ||
                method.name == "createSamLambda" ||
                method.name == "resolveVmMethodHandle"
        })
        val helperText = helperBytes.toString(Charsets.ISO_8859_1)
        assertFalse(helperText.contains("privateLookupIn"))
        assertFalse(helperText.contains("resolveMethodHandle"))
        assertFalse(helperText.contains("createSamLambda"))
    }
}
