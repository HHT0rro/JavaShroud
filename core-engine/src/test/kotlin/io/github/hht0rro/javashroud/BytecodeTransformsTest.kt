package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.addSyntheticFlags
import io.github.hht0rro.javashroud.bytecode.remapClasses
import io.github.hht0rro.javashroud.bytecode.stripCompileDebug
import io.github.hht0rro.javashroud.bytecode.stripLineNumbers
import io.github.hht0rro.javashroud.bytecode.stripSourceDebug
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BytecodeTransformsTest {

    @Test
    fun stripSourceDebug_removes_source_info() {
        val original = buildMinimalClass(source = "Foo.java", debug = "SMAP")
        val result = stripSourceDebug(original)
        val info = readClassSourceInfo(result)
        assertNull(info.source)
        assertNull(info.debug)
    }

    @Test
    fun stripCompileDebug_removes_source_line_numbers_and_local_variables() {
        val original = buildClassWithDebugInfo()
        val result = stripCompileDebug(original)
        val info = readDebugInfo(result)
        assertNull(info.source)
        assertTrue(info.lineNumbers.isEmpty(), "Expected no line numbers")
        assertTrue(info.localVariables.isEmpty(), "Expected no local variables")
    }

    @Test
    fun stripLineNumbers_removes_line_numbers_for_selected_methods() {
        val original = buildClassWithDebugInfo()
        val result = stripLineNumbers(original, setOf("run:()V"))
        val info = readDebugInfo(result)
        assertTrue(info.lineNumbers.isEmpty(), "Expected no line numbers for selected method")
    }

    @Test
    fun stripLineNumbers_preserves_line_numbers_for_unselected_methods() {
        val original = buildClassWithDebugInfo()
        val result = stripLineNumbers(original, setOf("other:()V"))
        val info = readDebugInfo(result)
        assertTrue(info.lineNumbers.isNotEmpty(), "Expected line numbers preserved for unselected method")
    }

    @Test
    fun addSyntheticFlags_sets_flag_on_matched_method() {
        val original = buildMinimalClass(source = null, debug = null)
        val result = addSyntheticFlags(original, setOf("METHOD:run:()V"))
        val access = readMethodAccess(result, "run", "()V")
        assertTrue(access and Opcodes.ACC_SYNTHETIC != 0, "Expected ACC_SYNTHETIC on matched method")
    }

    @Test
    fun addSyntheticFlags_sets_flag_on_matched_field() {
        val original = buildMinimalClass(source = null, debug = null)
        val result = addSyntheticFlags(original, setOf("FIELD:value:I"))
        val access = readFieldAccess(result, "value", "I")
        assertTrue(access and Opcodes.ACC_SYNTHETIC != 0, "Expected ACC_SYNTHETIC on matched field")
    }

    @Test
    fun addSyntheticFlags_does_not_set_flag_on_unmatched_members() {
        val original = buildMinimalClass(source = null, debug = null)
        val result = addSyntheticFlags(original, setOf("METHOD:other:()V"))
        val methodAccess = readMethodAccess(result, "run", "()V")
        assertEquals(0, methodAccess and Opcodes.ACC_SYNTHETIC, "Expected no ACC_SYNTHETIC on unmatched method")
        val fieldAccess = readFieldAccess(result, "value", "I")
        assertEquals(0, fieldAccess and Opcodes.ACC_SYNTHETIC, "Expected no ACC_SYNTHETIC on unmatched field")
    }

    @Test
    fun remapClasses_updates_package_resource_path_string_constants() {
        val original = buildResourceLookupClass("/com/example/resources/file-a.txt")
        val result = remapClasses(original, mapOf(
            "com/example/ResourceLookup" to "x/y/ResourceLookup",
        ))

        val constants = readStringConstants(result)
        assertTrue("/x/y/resources/file-a.txt" in constants, "Package-scoped resource path must follow package rename")
        assertTrue("/com/example/resources/file-a.txt" !in constants, "Old package resource path must not remain in bytecode constants")
    }

    private fun buildMinimalClass(source: String?, debug: String?): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/test/Foo", null, "java/lang/Object", null)
        if (source != null) {
            writer.visitSource(source, debug)
        }
        writer.visitField(Opcodes.ACC_PRIVATE, "value", "I", null, null).visitEnd()
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null)
        mv.visitCode()
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(1, 1)
        mv.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildResourceLookupClass(resourcePath: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/ResourceLookup", null, "java/lang/Object", null)
        val methodVisitor = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "path", "()Ljava/lang/String;", null, null)
        methodVisitor.visitCode()
        methodVisitor.visitLdcInsn(resourcePath)
        methodVisitor.visitInsn(Opcodes.ARETURN)
        methodVisitor.visitMaxs(1, 0)
        methodVisitor.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildClassWithDebugInfo(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/test/Foo", null, "java/lang/Object", null)
        writer.visitSource("Foo.java", null)
        val methodVisitor = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null)
        methodVisitor.visitCode()
        val startLabel = Label()
        val endLabel = Label()
        methodVisitor.visitLabel(startLabel)
        methodVisitor.visitInsn(Opcodes.RETURN)
        methodVisitor.visitLabel(endLabel)
        methodVisitor.visitLineNumber(42, startLabel)
        methodVisitor.visitLocalVariable("this", "Lcom/test/Foo;", null, startLabel, endLabel, 0)
        methodVisitor.visitMaxs(1, 1)
        methodVisitor.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private data class SourceInfo(val source: String?, val debug: String?)

    private fun readClassSourceInfo(bytes: ByteArray): SourceInfo {
        var capturedSource: String? = null
        var capturedDebug: String? = null
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitSource(source: String?, debug: String?) {
                capturedSource = source
                capturedDebug = debug
            }
        }, 0)
        return SourceInfo(capturedSource, capturedDebug)
    }

    private data class DebugInfo(
        val source: String?,
        val lineNumbers: List<Int>,
        val localVariables: List<String>,
    )

    private fun readDebugInfo(bytes: ByteArray): DebugInfo {
        var source: String? = null
        val lineNumbers = mutableListOf<Int>()
        val localVariables = mutableListOf<String>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitSource(s: String?, debug: String?) {
                source = s
            }

            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
                val parent = super.visitMethod(access, name, descriptor, signature, exceptions)
                return object : MethodVisitor(Opcodes.ASM9, parent) {
                    override fun visitLineNumber(line: Int, start: Label?) {
                        lineNumbers += line
                    }

                    override fun visitLocalVariable(name: String?, descriptor: String?, signature: String?, start: Label?, end: Label?, index: Int) {
                        if (name != null) localVariables += name
                    }
                }
            }
        }, 0)
        return DebugInfo(source, lineNumbers, localVariables)
    }

    private fun readMethodAccess(bytes: ByteArray, targetName: String, targetDesc: String): Int {
        var capturedAccess = 0
        val writer = ClassWriter(0)
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
                if (name == targetName && descriptor == targetDesc) {
                    capturedAccess = access
                }
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }
        }, 0)
        return capturedAccess
    }

    private fun readStringConstants(bytes: ByteArray): Set<String> {
        val constants = linkedSetOf<String>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
                val parent = super.visitMethod(access, name, descriptor, signature, exceptions)
                return object : MethodVisitor(Opcodes.ASM9, parent) {
                    override fun visitLdcInsn(value: Any?) {
                        if (value is String) constants += value
                        super.visitLdcInsn(value)
                    }
                }
            }
        }, 0)
        return constants
    }

    private fun readFieldAccess(bytes: ByteArray, targetName: String, targetDesc: String): Int {
        var capturedAccess = 0
        val writer = ClassWriter(0)
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visitField(access: Int, name: String?, descriptor: String?, signature: String?, value: Any?): org.objectweb.asm.FieldVisitor? {
                if (name == targetName && descriptor == targetDesc) {
                    capturedAccess = access
                }
                return super.visitField(access, name, descriptor, signature, value)
            }
        }, 0)
        return capturedAccess
    }
}