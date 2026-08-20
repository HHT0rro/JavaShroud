package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import java.nio.file.Files
import java.nio.file.Path

class NativeDivergenceVerificationTest {

    @Test
    fun native_source_compiles_exactly_one_parser_and_operand_family_per_profile() {
        val source = Files.readString(Path.of(NATIVE_INTERPRETER_CODEGEN_SOURCE))
        assertTrue(source.contains("#if JS_NATIVE_PARSER_PROFILE != 0"))
        assertTrue(source.contains("#if JS_NATIVE_PARSER_PROFILE == 2"))
        assertTrue(source.contains("js_vbc4_read_native_row"))
        assertTrue(source.contains("#if JS_NATIVE_OPERAND_PROFILE == 0"))
        assertTrue(source.contains("#elif JS_NATIVE_OPERAND_PROFILE == 1"))
        assertTrue(source.contains("#elif JS_NATIVE_OPERAND_PROFILE == 2"))
        val operandAccessor = source.substringAfter("JS_PROTECTED static jint js_vm_profile_fetch_operand").substringBefore("JS_PROTECTED jint js_vm_resident_exception_mask")
        assertFalse(operandAccessor.contains("if (profile =="), "Operand family must no longer be selected by a runtime profile branch")

        val generatedProfiles = (0..2).flatMap { parser ->
            (0..2).map { operand ->
                val context = Vbc4BuildContext(
                    masterKey = ByteArray(32) { it.toByte() },
                    nativeSeed = 0x1234_5678L,
                    jarLayoutDigest = ByteArray(32) { (it * 3).toByte() },
                    nativeVmProfile = NativeVmBuildProfile(parser, operand),
                )
                NativeRecompilationTransforms.generateDiversifiedSecrets(7L, java.util.Random(7L), context)
            }
        }
        assertTrue(generatedProfiles.withIndex().all { (index, secrets) ->
            val parser = index / 3
            val operand = index % 3
            secrets.contains("#define JS_NATIVE_PARSER_PROFILE $parser") &&
                secrets.contains("#define JS_NATIVE_OPERAND_PROFILE $operand")
        }, "All 3x3 build-local profile combinations must generate explicit compile-time macros")
    }

    @Test
    fun diversifiedSecrets_differ_across_10_seeds() {
        val outputs = (0 until 10).map { seed ->
            val rng = java.util.Random(seed.toLong())
            NativeRecompilationTransforms.generateDiversifiedSecrets(seed.toLong(), rng, io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext())
        }
        for (i in outputs.indices) {
            for (j in i + 1 until outputs.size) {
                assertNotEquals(outputs[i], outputs[j], "Seeds  and  should produce different secrets")
            }
        }
    }

    @Test
    fun antiReverseGuards_differ_across_seeds() {
        val outputs = (0 until 5).map { seed ->
            val rng = java.util.Random(seed.toLong())
            NativeRecompilationTransforms.generateAntiReverseGuards(rng)
        }
        for (i in outputs.indices) {
            for (j in i + 1 until outputs.size) {
                assertNotEquals(outputs[i], outputs[j], "Guards for seeds  and  should differ")
            }
        }
    }

    @Test
    fun sourceDiversification_produces_unique_junk_functions() {
        val source = "#include <jni.h>\nstatic int main_func(void) { return 0; }\n"
        val outputs = (0 until 5).map { seed ->
            val rng = java.util.Random(seed.toLong())
            NativeRecompilationTransforms.applySourceDiversification(source, rng)
        }
        for (i in outputs.indices) {
            for (j in i + 1 until outputs.size) {
                assertNotEquals(outputs[i], outputs[j], "Diversified source for seeds  and  should differ")
            }
        }
    }

    @Test
    fun nativeInterpreterCodegen_reorders_dispatch_handlers_across_build_seeds() {
        val source = Files.readString(Path.of(NATIVE_INTERPRETER_CODEGEN_SOURCE))
        val outputs = listOf(0L, 1L, 2L, 3L, 4L, 5L).map { seed ->
            NativeRecompilationTransforms.applyNativeInterpreterCodegen(source, java.util.Random(seed))
        }

        assertTrue(outputs.all { it.contains("VBC4_INTERPRETER_CODEGEN") }, "Interpreter codegen must mark every generated dispatch layout")
        assertTrue(outputs.all { output ->
            output.contains("js_vm_profile_case_salt(js_vm_dispatch_profile") &&
                output.contains("js_vm_profile_case_matches(js_vm_dispatch_profile")
        }, "Interpreter codegen must preserve profile-aware salt and case matching in every generated dispatch shape")
        assertTrue(outputs.any { it.contains("js_vm_handler_variant_") }, "Interpreter codegen must inject per-build handler variants")
        assertTrue(outputs.any { it.contains("VBC4_HANDLER_RELOCATION") }, "Interpreter codegen must inject per-build handler relocation trampolines")
        assertTrue(outputs.flatMap(::dispatchRelocationShapes).toSet().size > 1,
            "Interpreter codegen must diversify handler relocation gate shapes across build seeds")
        assertTrue(
            outputs.any { it.contains("js_vm_dispatch_shape_token") || it.contains("js_vm_dispatch_phase") },
            "Interpreter codegen must emit non-baseline dispatch macro shapes across build seeds",
        )
        assertTrue(
            outputs.map(::dispatchCaseOrder).toSet().size > 1,
            "Different build seeds must produce different native dispatch handler ordering",
        )
        assertTrue(
            outputs.map(::dispatchRelocationSignature).toSet().size > 1,
            "Different build seeds must produce different native handler relocation layouts",
        )
    }

    @Test
    fun nativeInterpreterCodegen_preserves_handler_tail_after_nested_break() {
        val source = """
            #define JS_VM_DISPATCH(insn) if (0)
            #define JS_VM_CASE(x) } if (1) {
            #define JS_VM_BREAK do { break; } while (0)
                    JS_VM_DISPATCH(insn) {
                        JS_VM_CASE(JS_VM_SPECIAL)
                            if (guard) { ok = 0; JS_VM_BREAK; }
                            js_vm_preserve_after_nested_break();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_A)
                            js_vm_preserve_a();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_B)
                            js_vm_preserve_b();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_C)
                            js_vm_preserve_c();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_D)
                            js_vm_preserve_d();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_E)
                            js_vm_preserve_e();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_F)
                            js_vm_preserve_f();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_G)
                            js_vm_preserve_g();
                            JS_VM_BREAK;
                        JS_VM_DEFAULT
                    }
        """.trimIndent()

        val output = NativeRecompilationTransforms.applyNativeInterpreterCodegen(source, java.util.Random(17L))

        assertTrue(output.contains("js_vm_preserve_after_nested_break();"), "A nested early break must not truncate its handler tail")
        assertTrue(output.contains("if (guard) { ok = 0; JS_VM_BREAK; }"), "The nested break branch itself must remain intact")
        assertTrue(output.contains("js_vm_preserve_a();") && output.contains("js_vm_preserve_g();"), "Every top-level handler must survive reordering")
        assertTrue(output.lines().size >= source.lines().size, "Codegen must not discard source lines after nested breaks")
    }


    @Test
    fun nativeInterpreterCodegen_places_relocation_after_alias_case_headers() {
        val source = """
            #define JS_VM_DISPATCH(insn) if (0)
            #define JS_VM_CASE(x) } if (1) {
            #define JS_VM_BREAK do { break; } while (0)
            #define JS_VM_DEFAULT } if (0) {
                    JS_VM_DISPATCH(insn) {
                        JS_VM_CASE(JS_VM_INVOKESTATIC)
                        JS_VM_CASE(JS_VM_INVOKEVIRTUAL)
                        JS_VM_CASE(JS_VM_INVOKESPECIAL)
                        JS_VM_CASE(JS_VM_INVOKEINTERFACE)
                            js_vm_alias_group_body();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_A)
                            js_vm_a();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_B)
                            js_vm_b();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_C)
                            js_vm_c();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_D)
                            js_vm_d();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_E)
                            js_vm_e();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_F)
                            js_vm_f();
                            JS_VM_BREAK;
                        JS_VM_CASE(JS_VM_G)
                            js_vm_g();
                            JS_VM_BREAK;
                        JS_VM_DEFAULT
                    }
        """.trimIndent()

        val output = NativeRecompilationTransforms.applyNativeInterpreterCodegen(source, java.util.Random(29L))
        val aliasRunThenGate = Regex(
            """JS_VM_CASE\(JS_VM_INVOKESTATIC\)\s*
\s*JS_VM_CASE\(JS_VM_INVOKEVIRTUAL\)\s*
\s*JS_VM_CASE\(JS_VM_INVOKESPECIAL\)\s*
\s*JS_VM_CASE\(JS_VM_INVOKEINTERFACE\)\s*
\s*/\* VBC4_HANDLER_RELOCATION""",
        )

        assertTrue(
            aliasRunThenGate.containsMatchIn(output),
            "Relocation labels must be emitted after every alias case header to remain valid C11 under Zig",
        )
        assertTrue(
            output.contains("js_vm_alias_group_body();"),
            "Alias-group handler body must remain reachable after relocation insertion",
        )
    }

}

private const val NATIVE_INTERPRETER_CODEGEN_SOURCE = "src/main/native/js_vm_core.c"

private fun dispatchCaseOrder(source: String): List<String> {
    val start = source.indexOf("        JS_VM_DISPATCH(insn) {")
    val end = source.indexOf("            JS_VM_DEFAULT", start)
    require(start >= 0 && end > start) { "dispatch region not found" }
    return Regex("""JS_VM_CASE\(([^)]+)\)""").findAll(source.substring(start, end)).map { it.groupValues[1] }.toList()
}

private fun dispatchRelocationSignature(source: String): List<String> {
    val start = source.indexOf("        JS_VM_DISPATCH(insn) {")
    val end = source.indexOf("            JS_VM_DEFAULT", start)
    require(start >= 0 && end > start) { "dispatch region not found" }
    return Regex("""VBC4_HANDLER_RELOCATION index=([0-9]+) shape=([0-9]+) token=0x([0-9A-F]+)u""")
        .findAll(source.substring(start, end))
        .map { it.groupValues[1] + ":" + it.groupValues[2] + ":" + it.groupValues[3] }
        .toList()
}

private fun dispatchRelocationShapes(source: String): List<String> {
    val start = source.indexOf("        JS_VM_DISPATCH(insn) {")
    val end = source.indexOf("            JS_VM_DEFAULT", start)
    require(start >= 0 && end > start) { "dispatch region not found" }
    return Regex("""VBC4_HANDLER_RELOCATION index=[0-9]+ shape=([0-9]+) token=0x[0-9A-F]+u""")
        .findAll(source.substring(start, end))
        .map { it.groupValues[1] }
        .toList()
}
