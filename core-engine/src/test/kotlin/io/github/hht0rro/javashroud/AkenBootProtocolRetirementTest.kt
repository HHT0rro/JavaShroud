package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenBootProtocolRetirementTest {
    @Test
    fun build_context_does_not_cache_or_expose_legacy_boot_authority() {
        val fields = Vbc4BuildContext::class.java.declaredFields.map { it.name }.toSet()
        val methods = Vbc4BuildContext::class.java.declaredMethods.map { it.name }.toSet()

        assertFalse("bootSecretSnapshot" in fields, "AKEN build context must not cache a boot secret")
        assertFalse("bootSidecarBindingSnapshot" in fields, "AKEN build context must not cache a sidecar binding")
        assertFalse("copyBootSecretForBuild" in methods, "AKEN build context must not expose boot secret copies")
        assertFalse("copyBootSidecarBindingForBuild" in methods, "AKEN build context must not expose sidecar copies")
    }

    @Test
    fun legacy_boot_build_producers_are_removed_and_deployment_only_discards_stale_resources() {
        val root = workspaceRoot()
        val protectionRoot = root.resolve("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection")
        assertFalse(Files.exists(protectionRoot.resolve("BootMaterialEnvelope.kt")), "AKEN v4 must not retain the JSBM producer")
        assertFalse(Files.exists(protectionRoot.resolve("BootKekSidecar.kt")), "AKEN v4 must not retain the JSBK producer")

        val deployment = Files.readString(protectionRoot.resolve("EmbeddedHelperDeployment.kt"))
        assertFalse(deployment.contains("BootMaterialEnvelope"), "helper deployment must not construct legacy boot envelopes")
        assertFalse(deployment.contains("BootKekSidecar"), "helper deployment must not construct legacy boot sidecars")
        assertTrue(deployment.contains("legacyBootResourcePaths"), "helper deployment must continue dropping stale legacy boot resources")
    }

    private fun workspaceRoot(): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            if (Files.isDirectory(current.resolve("core-engine").resolve("src"))) return current
            if (current.fileName?.toString() == "core-engine" && Files.isDirectory(current.resolve("src"))) {
                return current.parent ?: error("Unable to locate workspace root")
            }
            current = current.parent ?: error("Unable to locate workspace root")
        }
    }
}
