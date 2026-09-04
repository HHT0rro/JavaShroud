package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat
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
        listOf(ascii("56424358"), "inner-crypto-public-v1").forEach { stale ->
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
    fun current_wire_sources_use_only_derived_qp_labels() {
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
        val retiredFrame = ascii(ProtectionFormat.RETIRED_FRAME_MAGIC_HEX)
        val retiredVm = ascii(ProtectionFormat.RETIRED_VM_MAGIC_HEX)
        listOf(
            "MAGIC: String = \"$retiredFrame\"",
            "*b\"$retiredFrame\"",
            "QP_CURRENT_MAGIC = \"$retiredVm\"",
            "*b\"$retiredVm\"",
            "new byte[] {'I', 'T', 'K', '1'}",
            ascii("6e6174697665496e7374616c6c416b656e"),
            ascii("6e61746976654f70656e416b656e"),
            ascii("6e617469766545786563757465416b656e"),
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
        val bootstrap = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBootstrap.java")
        val ffi = source("src/main/rust/crates/qp-ffi/src/lib.rs")
        assertTrue("protocolVersion = ProtectionFormat.CURRENT" in rewriter)
        assertTrue("protocolVersion = ProtectionFormat.CURRENT" in rotation)
        assertFalse("protocolVersion = 3" in rewriter)
        assertFalse("protocolVersion = 3" in rotation)
        assertTrue("private static final int VERSION = ${ProtectionFormat.CURRENT};" in bootstrap)
        assertTrue("const TARGET_TOKEN_VERSION: u8 = ${ProtectionFormat.CURRENT};" in ffi)
        assertFalse("b\\j.m\\0" in ffi, "native must not read the retired method-binding mailbox")
        assertTrue("qpResourceDir() + \"/native.locator\"" in sealing)
        assertTrue("qpResourceDir() + \"/native.bindings.locator\"" in sealing)
        assertTrue("if (name.startsWith(\"a_bsm\"))" in virtualization)
        assertTrue("public static String openQpString" in bridge)
    }

    private fun source(relativePath: String): String = Files.readString(resolve(relativePath))

    private fun ascii(hex: String): String = ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }.toString(Charsets.US_ASCII)

    private fun resolve(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
