package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.bytecode.remapClasses
import kotlin.test.Test
import kotlin.test.assertEquals
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

class ApkAccessWideningTest {
    @Test
    fun samePackageProtectedConstructorRemainsCallableAfterTheOtherClassMoves() {
        val caller = "fixture/KeptCaller"
        val callee = "fixture/MovingTarget"
        val target = ClassWriter(ClassWriter.COMPUTE_MAXS)
        target.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, callee, null, "java/lang/Object", null)
        target.visitField(0, "packageValue", "I", null, null).visitEnd()
        target.visitField(Opcodes.ACC_PROTECTED, "protectedValue", "I", null, null).visitEnd()
        target.visitField(Opcodes.ACC_PROTECTED, "unreferenced", "I", null, null).visitEnd()
        target.visitMethod(Opcodes.ACC_PROTECTED, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitIntInsn(Opcodes.BIPUSH, 7)
            visitFieldInsn(Opcodes.PUTFIELD, callee, "packageValue", "I")
            visitVarInsn(Opcodes.ALOAD, 0)
            visitIntInsn(Opcodes.BIPUSH, 11)
            visitFieldInsn(Opcodes.PUTFIELD, callee, "protectedValue", "I")
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        target.visitMethod(Opcodes.ACC_PRIVATE, "privateHelper", "()V", null, null).apply {
            visitCode()
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        target.visitEnd()
        val entry = ClassWriter(ClassWriter.COMPUTE_MAXS)
        entry.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, caller, null, "java/lang/Object", null)
        entry.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "make", "()Ljava/lang/Object;", null, null).apply {
            visitCode()
            visitTypeInsn(Opcodes.NEW, callee)
            visitInsn(Opcodes.DUP)
            visitMethodInsn(Opcodes.INVOKESPECIAL, callee, "<init>", "()V", false)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        entry.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read", "()I", null, null).apply {
            visitCode()
            visitTypeInsn(Opcodes.NEW, callee)
            visitInsn(Opcodes.DUP)
            visitMethodInsn(Opcodes.INVOKESPECIAL, callee, "<init>", "()V", false)
            visitInsn(Opcodes.DUP)
            visitFieldInsn(Opcodes.GETFIELD, callee, "packageValue", "I")
            visitInsn(Opcodes.SWAP)
            visitFieldInsn(Opcodes.GETFIELD, callee, "protectedValue", "I")
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        entry.visitEnd()
        val input = listOf("$caller.class" to entry.toByteArray(), "$callee.class" to target.toByteArray())
        for (kept in listOf(setOf(caller), setOf(callee))) {
            val result = ApkAccessWidening.widen(input, kept)
            val mapping = (setOf(caller, callee) - kept).associateWith { "moved/${it.substringAfterLast('/')}" }
            val output = result.classes.associate { (name, bytes) ->
                val owner = name.removeSuffix(".class")
                (mapping[owner] ?: owner) to remapClasses(bytes, mapping)
            }
            val loader = object : ClassLoader(null) {
                override fun findClass(name: String): Class<*> {
                    val bytes = output[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
                    return defineClass(name, bytes, 0, bytes.size)
                }
            }
            val renamedCaller = (mapping[caller] ?: caller).replace('/', '.')
            val value = loader.loadClass(renamedCaller).getMethod("make").invoke(null)
            assertEquals((mapping[callee] ?: callee).replace('/', '.'), value.javaClass.name)
            assertEquals(18, loader.loadClass(renamedCaller).getMethod("read").invoke(null))
            val node = ClassNode()
            ClassReader(output.getValue(mapping[callee] ?: callee)).accept(node, 0)
            assertEquals(Opcodes.ACC_PRIVATE, node.methods.single { it.name == "privateHelper" }.access)
            assertEquals(Opcodes.ACC_PROTECTED, node.fields.single { it.name == "unreferenced" }.access)
        }
    }
}
