package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge
import io.github.hht0rro.javashroud.transforms.protection.QpResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.QP_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.QP_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.QpBuildContext
import java.util.Arrays
import io.github.hht0rro.javashroud.transforms.protection.requireQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.withQpBuildContext
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AttackRegressionTest {
    @Test
    fun all_runtime_resource_kinds_reject_header_body_length_and_tag_tampering() = withQpBuildContext(fixedContext(1)) {
        for (kind in RuntimeResourceKind.entries) {
            val encoded = QpResourceCodec.encode(
                bytes = "attack-regression-${kind.name}-resource".toByteArray(Charsets.UTF_8),
                kind = kind,
                seed = 0x1234_5678 xor kind.id,
                variantId = 3 + kind.id,
                layerCount = 2,
            )

            val offsets = listOf(5, 6, 7, 8, 24, 28, 32, 40, encoded.size - 32, encoded.lastIndex)
            for (offset in offsets) {
                val tampered = encoded.copyOf()
                tampered[offset] = (tampered[offset].toInt() xor 0x5A).toByte()
                assertEquals(null, QpResourceCodec.decode(tampered), "${kind.name} tampering offset $offset must fail closed")
            }
        }
    }

    @Test
    fun copied_runtime_resource_with_wrong_layout_context_fails_closed() {
        val encoded = withQpBuildContext(fixedContext(2)) {
            QpResourceCodec.encode(
                bytes = "layout-bound-vm-resource".toByteArray(Charsets.UTF_8),
                kind = RuntimeResourceKind.VmBytecode,
                seed = 0x2468_1357,
                variantId = 4,
                layerCount = 3,
            )
        }

        assertNotEquals(
            encoded.toList(),
            withQpBuildContext(fixedContext(3)) {
                QpResourceCodec.encode(
                    bytes = "layout-bound-vm-resource".toByteArray(Charsets.UTF_8),
                    kind = RuntimeResourceKind.VmBytecode,
                    seed = 0x2468_1357,
                    variantId = 4,
                    layerCount = 3,
                ).toList()
            },
            "different context must produce different authenticated resource bytes",
        )
        assertEquals(null, withQpBuildContext(fixedContext(3)) { QpResourceCodec.decode(encoded) }, "wrong layout/runtime key must fail closed")
    }

    @Test
    fun rust_runtime_keeps_fail_closed_attack_gates_without_c_sources() {
        assertFalse(Files.exists(Path.of("src/main/native")), "C native runtime must be deleted")
        val vm = Files.readString(Path.of("src/main/rust/crates/qp-vm/src/lib.rs"))
        val ffi = Files.readString(Path.of("src/main/rust/crates/qp-ffi/src/lib.rs"))
        assertTrue(vm.contains("AuthenticationFailed") || vm.contains("parse_authenticated"), "Rust VM must authenticate before execute")
        assertTrue(ffi.contains("Qp VM page route is unavailable") || ffi.contains("TypedPageRouter"), "Rust JNI must fail closed")
    }

    private fun fixedContext(seed: Int, runtimeResourceKey: ByteArray? = null): QpBuildContext {
        val masterKey = ByteArray(QP_MASTER_KEY_SIZE) { index -> (seed * 19 + index * 7).toByte() }
        val nativeSeed = seed.toLong() * 0x1234_5679L
        val jarLayoutDigest = ByteArray(QP_LAYOUT_DIGEST_SIZE) { index -> (seed * 23 + index * 11).toByte() }
        return if (runtimeResourceKey == null) {
            QpBuildContext(
                masterKey = masterKey,
                nativeSeed = nativeSeed,
                jarLayoutDigest = jarLayoutDigest,
            )
        } else {
            QpBuildContext(
                masterKey = masterKey,
                nativeSeed = nativeSeed,
                jarLayoutDigest = jarLayoutDigest,
                runtimeResourceKey = runtimeResourceKey,
            )
        }
    }
}
