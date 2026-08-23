package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks the de-identified VBC4 parser diagnostics to the current stage
 * boundaries without exercising or exposing protected artifact material.
 */
class NativeParserDiagnosticsTest {
    @Test
    fun exception_stage_uses_distinct_structural_diagnostics() {
        val source = readNativeSource()
        val stageStart = source.indexOf("parse_stage = 6;")
        val paddingStart = source.indexOf("/* Authenticated size-jitter padding", stageStart)
        assertTrue(stageStart >= 0, "VBC4 exception parser stage must remain present")
        assertTrue(paddingStart > stageStart, "exception parser stage must end before padding parsing")

        val stage = source.substring(stageStart, paddingStart)
        assertTrue(stage.contains("parse_detail = 0;"), "stage 6 must reset its diagnostic detail")
        assertFalse(stage.contains("parse_detail = 5063;"), "stage 6 must not reuse the instruction-block detail")
        assertFalse(stage.contains("parse_detail = 600;"), "stage 6 must not publish an undifferentiated detail code")
        assertFalse(stage.contains("parse_detail = 6006;"), "stage 6 detail taxonomy must remain bounded")
        assertFalse(stage.contains("parse_detail = 6007;"), "stage 6 detail taxonomy must remain bounded")

        val codes = listOf("6001", "6002", "6003", "6004", "6005")
        val positions = codes.map { code ->
            stage.indexOf("parse_detail = $code;").also {
                assertTrue(it >= 0, "stage 6 must expose diagnostic detail $code")
            }
        }
        assertTrue(positions.zipWithNext().all { (left, right) -> left < right }, "stage 6 detail codes must follow parser order")
        assertTrue(stage.contains("if (!js_vm_read_u4(data, len, &pos, &exc_plain_sz)) JS_VM_PARSE_FAIL;"))
        assertTrue(stage.contains("js_vbc4_zstd_decompress_owned"))
        assertTrue(stage.contains("expected_token"))
        assertTrue(stage.contains("js_vm_last_exception_count = p->exception_count"))
        assertTrue(stage.contains("js_vm_last_exception_index = i"))
        assertTrue(stage.contains("js_vm_last_exception_fields_read = 4"))
        assertTrue(stage.contains("js_vm_last_exception_pos = exc_pos"))
        assertTrue(stage.contains("js_vm_last_exception_token_match = 1"))
        assertTrue(stage.contains("JS_VM_PARSE_FAIL"), "all exception failures must retain fail-closed cleanup")
    }

    @Test
    fun row_dialect_mismatch_diagnostics_are_deidentified_and_fail_closed() {
        val source = readNativeSource()
        val coreHeader = readNativeHeader()
        val jni = readJniSource()
        listOf(
            "js_vm_last_exception_count",
            "js_vm_last_exception_index",
            "js_vm_last_exception_fields_read",
            "js_vm_last_exception_pos",
            "js_vm_last_exception_token_match",
        ).forEach { field ->
            assertTrue(source.contains(field), "native parser must record de-identified $field")
            assertTrue(coreHeader.contains(field), "native header must declare de-identified $field")
        }
        listOf(
            "js_vm_last_row_dialect_block",
            "js_vm_last_row_dialect_count",
            "js_vm_last_row_dialect_observed",
            "js_vm_last_row_dialect_expected",
        ).forEach { field ->
            assertTrue(source.contains(field), "native parser must record de-identified $field")
            assertTrue(coreHeader.contains(field), "native header must declare de-identified $field")
            assertTrue(jni.contains(field), "JNI failure diagnostics must publish de-identified $field")
        }
        assertTrue(source.contains("if (row_dialect != expected_dialect) JS_VM_PARSE_FAIL;"))
        assertTrue(jni.contains("row_observed=%d row_expected=%d"))
        assertTrue(jni.contains("char reason[2048]"), "JNI diagnostics buffer must retain the complete bounded field set")
        listOf(
            "exception_count=%d",
            "exception_index=%d",
            "exception_fields=%d",
            "exception_pos=%d",
            "exception_token=%d",
        ).forEach { field ->
            assertTrue(jni.contains(field), "JNI failure diagnostics must publish de-identified $field")
        }
        val reasonFormat = jni.substringAfter("AKEN VM page frame is invalid:").substringBefore("js_aken_bridge_unavailable")
        listOf("build_seed", "nonce", "DEK", "plaintext", "expected_token", "encoded_token").forEach { secret ->
            assertFalse(reasonFormat.contains(secret), "row diagnostic must not expose $secret")
        }
    }

    private fun readNativeSource(): String {
        val candidates = listOf(
            Path.of("src/main/native/js_vm_core.c"),
            Path.of("core-engine/src/main/native/js_vm_core.c"),
        )
        return candidates.firstOrNull { Files.exists(it) }?.let(Files::readString)
            ?: error("js_vm_core.c is required for parser diagnostic contract testing")
    }

    private fun readNativeHeader(): String = listOf(
        Path.of("src/main/native/js_vm_core.h"),
        Path.of("core-engine/src/main/native/js_vm_core.h"),
    ).firstOrNull { Files.exists(it) }?.let(Files::readString)
        ?: error("js_vm_core.h is required for parser diagnostic contract testing")

    private fun readJniSource(): String = listOf(
        Path.of("src/main/native/js_jni_runtime.c"),
        Path.of("core-engine/src/main/native/js_jni_runtime.c"),
    ).firstOrNull { Files.exists(it) }?.let(Files::readString)
        ?: error("js_jni_runtime.c is required for parser diagnostic contract testing")
}
