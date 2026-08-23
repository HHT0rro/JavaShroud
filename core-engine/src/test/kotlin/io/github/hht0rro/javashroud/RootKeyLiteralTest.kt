package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode

/**
 * AKEN v4 gate: Java helper bytecode contains no generated, linearly
 * recomposable key shares, and deployment no longer emits a boot-root producer.
 */
class RootKeyLiteralTest {
    @Test
    fun helper_source_and_bytecode_have_no_share_injection_or_legacy_boot_producer() {
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
        val coupling = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/CrossClassCouplingHelper.java"))
        val crypto = Files.readString(resolveSource("src/main/rust/crates/jsrt-crypto/src/lib.rs"))
        assertFalse(deployment.contains("emitShareMethod"), "deployment must not emit byte-array share literals")
        assertFalse(deployment.contains("emitPartitionKeyDispatch"), "deployment must not emit Java key reconstruction code")
        assertFalse(deployment.contains("BootMaterialEnvelope"), "AKEN deployment must not emit a JSBM boot-material producer")
        assertFalse(deployment.contains("BootKekSidecar"), "AKEN deployment must not emit a JSBK sidecar producer")
        assertTrue(
            helper.contains("nativeOpenAkenString") &&
                helper.contains("nativeReadAkenClassPage") &&
                helper.contains("nativeConsumeAkenNativeChunk"),
            "helper must expose purpose-split AKEN page routes",
        )
        assertFalse(coupling.contains("reconstructKey"), "AKEN compatibility helper must not recover a page key")
        assertFalse(coupling.contains("nativeReconstructKey"), "AKEN compatibility helper must not expose a key-returning native ABI")
        assertFalse(coupling.contains("CopyOnWriteArrayList"), "AKEN compatibility helper must not retain a global fragment registry")
        assertTrue(coupling.contains("requireBoundNative"), "AKEN compatibility helper must fail closed through the bound native route")
        assertFalse(crypto.contains("js_aes256_expand_lanes"), "bound AES terminal must not materialize a full round-key array")
        assertTrue(crypto.contains("aes256_gcm_decrypt"), "Rust AES-GCM opener must remain the only decrypt terminal")
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
