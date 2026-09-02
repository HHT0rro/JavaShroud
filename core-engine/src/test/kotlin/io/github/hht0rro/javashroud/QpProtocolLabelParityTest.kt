package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpProtocolLabelParityTest {
    @Test
    fun current_kotlin_serializer_and_rust_kernel_use_identical_native_magic() {
        val serializer = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpSerializer.kt")
        val rustVm = source("src/main/rust/crates/qp-vm/src/lib.rs")
        assertTrue("derivedVmMagic" in serializer)
        assertTrue("derived_vm_magic" in rustVm || "fn qp_magic" in rustVm)
        assertTrue("pub const QP_AUTH_TAG_SIZE: usize = 32;" in rustVm)
        val production = serializer + "\n" + rustVm
        listOf("VBCX", "inner-crypto-public-v1").forEach { stale ->
            assertFalse(stale in production, "Current production sources must not retain stale protocol label '$stale'")
        }
        assertFalse(Files.exists(resolve("src/main/native/js_vm_core.c")))
    }

    @Test
    fun native_mac_trailer_is_exactly_32_bytes_without_bucket_marker() {
        val serializer = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpSerializer.kt")
        val rustVm = source("src/main/rust/crates/qp-vm/src/lib.rs")
        assertTrue(
            serializer.contains("out.write(frameHmac(payload, cryptoSeed, nonce))"),
            "Kotlin serializer must append the 32-byte HMAC directly",
        )
        assertTrue(rustVm.contains("QP_AUTH_TAG_SIZE: usize = 32"))
        listOf(
            "data[len - 1] == 32",
            "data[len-1] == 32",
            "len - pos == 33",
            "len-pos == 33",
            "out.write(32)",
        ).forEach { bucketMarker ->
            assertFalse(bucketMarker in serializer, "Native VM MAC layout must not expose bucket marker '$bucketMarker'")
        }
    }

    @Test
    fun retired_emit_lexemes_are_absent_from_current_wire_sources() {
        val sources = listOf(
            source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/qp/QpWireFormat.kt"),
            source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpSerializer.kt"),
            source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpCatalogEmitter.kt"),
            source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/qp/QpNameSchedule.kt"),
            source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpNativeCompilerRequest.kt"),
            source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBootstrap.java"),
            source("src/main/rust/crates/qp-crypto/src/types.rs"),
            source("src/main/rust/crates/qp-vm/src/lib.rs"),
            source("src/main/rust/crates/qp-page/src/lib.rs"),
            source("src/main/rust/crates/qp-ffi/src/relocation.rs"),
        ).joinToString("\n")
        listOf(
            "MAGIC: String = \"JSR1\"",
            "*b\"JSR1\"",
            "QP_CURRENT_MAGIC = \"VBC5\"",
            "*b\"VBC5\"",
            "new byte[] {'I', 'T', 'K', '1'}",
            "nativeInstallAken",
            "nativeOpenAken",
            "nativeExecuteAken",
            "private const val CATALOG_INDEX = \"META-INF/jsrt",
            "preSealResourceRoot = \"META-INF/jsrt\"",
        ).forEach { stale ->
            assertFalse(stale in sources, "current wire sources must not emit retired lexeme '$stale'")
        }
        assertTrue("derivedFrameMagic" in sources || "derived_frame_magic" in sources)
        assertTrue("derivedVmMagic" in sources || "qp_magic" in sources)
        assertTrue("qpResourceDir" in sources)
    }

    @Test
    fun nested_vm_and_interpreter_e2e_require_bytecode_verifier() {
        val nested = source("src/test/kotlin/io/github/hht0rro/javashroud/NestedVmExecutionTest.kt")
        val interpreter = source("src/test/kotlin/io/github/hht0rro/javashroud/VmInterpreterExecutionTest.kt")
        assertTrue("-Xverify:all" in nested, "Nested VM e2e must run java -Xverify:all")
        assertTrue("-Xverify:all" in interpreter, "VM interpreter e2e must run java -Xverify:all")
        assertTrue("(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;" in nested)
        assertFalse("(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;" in nested)
    }

    @Test
    fun runtime_product_gates_keep_locator_rewrite_and_public_string_open() {
        val rewriter = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/hardening/QpTargetRewriter.kt")
        val rotation = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeDefenseTransforms.kt")
        val sealing = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt")
        val virtualization = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt")
        val bridge = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java")
        assertTrue("protocolVersion = ProtectionFormat.CURRENT" in rewriter)
        assertTrue("protocolVersion = ProtectionFormat.CURRENT" in rotation)
        assertFalse("protocolVersion = 3" in rewriter)
        assertFalse("protocolVersion = 3" in rotation)
        assertTrue("qpResourceDir() + \"/native.locator\"" in sealing)
        assertTrue("qpResourceDir() + \"/native.bindings.locator\"" in sealing)
        assertTrue("if (name.startsWith(\"a_bsm\"))" in virtualization)
        assertTrue("public static String openQpString" in bridge)
    }

    private fun source(relativePath: String): String = Files.readString(resolve(relativePath))

    private fun resolve(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
