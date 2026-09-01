package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SelfDecryptBoundaryHardeningTest {
    @Test
    fun current_format_boundary_is_the_typed_unified_native_route() {
        val kernelHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java")
        val ffi = source("src/main/rust/crates/qp-ffi/src/lib.rs")
        val bootstrap = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBootstrap.java")

        for (entry in listOf(
            "nativeExecuteVmPage",
            "nativeOpenStringPage",
            "nativeInitializeDefense",
            "nativeProbeDefense",
            "nativeTransformDefense",
            "nativeInvokeSite",
        )) {
            assertTrue(entry in kernelHelper, "Current JNI helper must declare $entry")
            assertTrue(entry in ffi, "Rust FFI must register $entry")
        }
        assertTrue("expectDefenseForProtectedPath" in kernelHelper, "Protected-data gates must be armable before initialize")
        assertTrue("authorizeProtectedData" in kernelHelper, "Protected-data access must re-run armed defense probes")
        assertTrue("native-extract-digest-mismatch" in kernelHelper, "Extracted native bytes must match the locator digest")
        assertTrue("native-loaded-digest-mismatch" in kernelHelper, "Loaded native temp file must be re-hashed after System.load")
        val defenseHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpGuard.java")
        assertTrue("authorizeProtectedData" in defenseHelper, "Defense helper must expose a protected-data probe gate")
        assertTrue("data-access" in defenseHelper, "Protected-data authorization must use a live probe point")
        val defenseInject = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/UnifiedDefenseTransforms.kt")
        assertTrue("expectDefenseForProtectedPath" in defenseInject, "os-anti injection must arm protected-data gates")
        assertTrue("RegisterNatives" in ffi, "Current runtime must use typed RegisterNatives registration")
        assertTrue("QpBridge.linkTargetSite" in bootstrap, "indy token resolution must use the opaque native site linker")
        assertFalse("resolveHandle" in bootstrap, "indy bootstrap must not expose a Java target-handle oracle")
        assertFalse("Class.forName" in bootstrap, "indy bootstrap must not resolve plaintext target owners")
        assertFalse("javax.crypto" in bootstrap, "indy bootstrap must not carry a Java crypto oracle")
        assertFalse("SecretKeySpec" in bootstrap, "indy bootstrap must not assemble token keys in Java")
        assertFalse("hkdfSha256" in bootstrap, "indy bootstrap must not derive token keys in Java")
        assertFalse("jsn_k14" in ffi, "Retired native bridge identifiers must not survive")
        assertFalse(Files.exists(resolveSource("src/main/native/js_vm_core.c")))
    }

    private fun source(relative: String): String = Files.readString(resolveSource(relative))

    private fun resolveSource(relative: String): Path {
        val direct = Path.of(relative)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relative)
    }
}
