package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.StringEncryptionConfig
import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

class StringEncryptionAnnotatedScopeTest {
    @Test
    fun annotated_scope_encrypts_only_methods_marked_with_shroud_encrypt() {
        val classBytes = buildAnnotatedScopeFixture()
        val encrypted = withVbc4BuildContext(defaultVbc4BuildContext()) {
            encryptClassStrings(
                classBytes = classBytes,
                config = StringEncryptionConfig(scope = "annotated", seed = 42),
            )
        }

        assertFalse(encrypted.contentEquals(classBytes), "annotated scope should still modify the marked method")

        val ldcByMethod = linkedMapOf<String, MutableList<String>>()
        ClassReader(encrypted).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<out String>?,
            ): MethodVisitor {
                val key = "$name$descriptor"
                val bucket = mutableListOf<String>()
                ldcByMethod[key] = bucket
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitLdcInsn(value: Any?) {
                        if (value is String) bucket += value
                    }
                }
            }
        }, 0)

        val annotatedStrings = ldcByMethod["annotated()V"].orEmpty()
        val plainStrings = ldcByMethod["plain()V"].orEmpty()

        assertTrue(annotatedStrings.none { it == "ANNOTATED_SECRET" }, "annotated method literal should be removed")
        assertTrue(plainStrings.any { it == "PLAIN_TEXT" }, "plain method literal should stay in bytecode")
    }

    private fun buildAnnotatedScopeFixture(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "AnnotatedScopeFixture", null, "java/lang/Object", null)

        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val annotated = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "annotated", "()V", null, null)
        annotated.visitAnnotation("Lio/github/hht0rro/javashroud/bytecode/ShroudEncrypt;", false).visitEnd()
        annotated.visitCode()
        annotated.visitLdcInsn("ANNOTATED_SECRET")
        annotated.visitInsn(Opcodes.POP)
        annotated.visitInsn(Opcodes.RETURN)
        annotated.visitMaxs(1, 0)
        annotated.visitEnd()

        val plain = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "plain", "()V", null, null)
        plain.visitCode()
        plain.visitLdcInsn("PLAIN_TEXT")
        plain.visitInsn(Opcodes.POP)
        plain.visitInsn(Opcodes.RETURN)
        plain.visitMaxs(1, 0)
        plain.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }
}
