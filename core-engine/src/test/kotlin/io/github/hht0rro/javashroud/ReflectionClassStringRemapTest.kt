package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.remapClasses
import kotlin.test.Test
import kotlin.test.assertEquals
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode

class ReflectionClassStringRemapTest {
    @Test
    fun structuredOwnerNamesKeepLongestMatchAndLeaveOrdinaryStringsAlone() {
        val mapping = linkedMapOf(
            "fixture/Owner" to "renamed/Short",
            "fixture/Owner#Nested" to "renamed/Hash",
            "fixture/Owner::Nested" to "renamed/Colon",
            "fixture/Owner/m_Nested" to "renamed/Member",
        )
        val literals = listOf(
            "fixture.Owner#run()V", "fixture.Owner::run", "fixture.Owner.m_run",
            "fixture.Owner#Nested#run", "fixture.Owner::Nested::run", "fixture.Owner.m_Nested.m_run",
            "fixture.Unmapped#run", "message fixture.Owner#run", "fixture.Ownerless#run",
            "fixture.Owner", "fixture/Owner.class",
        )
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "fixture/StringHolder", null, "java/lang/Object", null)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "literals", "()V", null, null)
        method.visitCode()
        for (literal in literals) {
            method.visitLdcInsn(literal)
            method.visitInsn(Opcodes.POP)
        }
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        val node = ClassNode()
        ClassReader(remapClasses(writer.toByteArray(), mapping)).accept(node, 0)
        val result = node.methods.single().instructions.filterIsInstance<LdcInsnNode>().map { it.cst }
        assertEquals(listOf(
            "renamed.Short#run()V", "renamed.Short::run", "renamed.Short.m_run",
            "renamed.Hash#run", "renamed.Colon::run", "renamed.Member.m_run",
            "fixture.Unmapped#run", "message fixture.Owner#run", "fixture.Ownerless#run",
            "renamed.Short", "renamed/Short.class",
        ), result)
    }
}
