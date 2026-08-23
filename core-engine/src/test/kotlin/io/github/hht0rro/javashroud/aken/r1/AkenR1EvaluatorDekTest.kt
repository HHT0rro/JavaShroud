package io.github.hht0rro.javashroud.aken.r1

import io.github.hht0rro.javashroud.transforms.protection.aken.r1.AkenR1EvaluatorDek
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenR1EvaluatorDekTest {
    @Test
    fun rust_eval7_golden_vector_round_trips_and_rejects_tampering() {
        val dek = ByteArray(32) { 0x40 }
        val fingerprint = ByteArray(32) { 0x22 }
        val wrapped = AkenR1EvaluatorDek.wrap(dek, fingerprint)
        assertEquals(EVAL7_GOLDEN.size, wrapped.size)
        assertContentEquals(EVAL7_GOLDEN, wrapped)
        assertContentEquals(dek, AkenR1EvaluatorDek.recover(wrapped, fingerprint))
        val tampered = wrapped.copyOf()
        tampered[AkenR1EvaluatorDek.MAGIC.length + 4] = (tampered[AkenR1EvaluatorDek.MAGIC.length + 4].toInt() xor 1).toByte()
        assertFailsWith<IllegalArgumentException> {
            AkenR1EvaluatorDek.recover(tampered, fingerprint)
        }
    }

    @Test
    fun rust_evaluator_plan_uses_the_eval7_contract() {
        fun rust(relative: String): String {
            val path = java.nio.file.Path.of("src/main/rust/crates/jsrt-page/src").resolve(relative).let { candidate ->
                if (Files.exists(candidate)) candidate else java.nio.file.Path.of("core-engine").resolve(candidate)
            }
            return Files.readString(path)
        }
        val lib = rust("lib.rs")
        val bound = rust("bound.rs")
        assertTrue(lib.contains("AKEN-R1/Eval7/v1"))
        assertTrue(lib.contains("JavaShroud/AKEN-R1/EvaluatorShare/v1"))
        assertTrue(lib.contains("JavaShroud/AKEN-R1/EvaluatorShareTag/v1"))
        assertTrue(bound.contains("bound-page-lane-mask"))
        assertTrue(bound.contains("bound-page-lane-tag"))
        assertTrue(bound.contains("bound-page-plan-tag"))
    }

    private companion object {
        val EVAL7_GOLDEN: ByteArray = hex(
            "414b454e2d52312f4576616c372f76318700d86cb091f115e5ced14cfe8ba752227aa801fb6da5bd069a8aade06887f445c89a03b10690dbe06e1bdfd47873249ce42cee4484d4dcb82843ab320f17a9ba13fc6a7d30ba21ce03a11b4e2d0d8e8c7cbe1297483a5edd9cfd0da1d7044d09ee4bbe22162ecf6f38a15dfa262f3b8f03a8461d58ec7a9b618775ae54da4e8b9663fd46521913efd1bbe2bb2b364a690ec76f8426fdcc7548b5f9affb1ab311225c576e1a772b1174ecca83a7ef624854ff1c81fdab99a6218dea7a313000abc18a5136b9db581a7eddbde6346fabdcfbea887062b1506b66cb2d486e24adb26a117abce7bd8b",
        )

        fun hex(value: String): ByteArray {
            val clean = value.filterNot(Char::isWhitespace)
            return ByteArray(clean.length / 2) { index ->
                clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
