package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode

/** W1/W4 gate: Java helper bytecode contains no generated, linearly recomposable key shares. */
class RootKeyLiteralTest {
    @Test
    fun helper_source_and_bytecode_have_no_share_injection_path() {
        val helperBytes = checkNotNull(
            javaClass.classLoader.getResourceAsStream(
                "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class"
            )
        ).use { it.readBytes() }
        val node = ClassNode()
        ClassReader(helperBytes).accept(node, ClassReader.SKIP_FRAMES)
        assertFalse(node.methods.any { it.name.startsWith("jsRrkS") }, "helper must not contain generated key-share methods")

        val deployment = Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/EmbeddedHelperDeployment.kt"))
        val helper = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        assertFalse(deployment.contains("emitShareMethod"), "deployment must not emit byte-array share literals")
        assertFalse(deployment.contains("emitPartitionKeyDispatch"), "deployment must not emit Java key reconstruction code")
        assertTrue(deployment.contains("BootMaterialEnvelope.encode"), "deployment must emit the encrypted boot material envelope")
        assertTrue(helper.contains("nativeInstallBootMaterial") && helper.contains("nativeIsBootMaterialReady") && helper.contains("nativeAbortBootMaterial"), "helper must use the one-shot native boot ABI with explicit failure wiping")
    }

    private fun resolveSource(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val direct = current.resolve(relative)
            if (Files.exists(direct)) return direct
            val nested = current.resolve("core-engine").resolve(relative)
            if (Files.exists(nested)) return nested
            current = current.parent ?: error("Unable to locate $relative")
        }
    }
}
