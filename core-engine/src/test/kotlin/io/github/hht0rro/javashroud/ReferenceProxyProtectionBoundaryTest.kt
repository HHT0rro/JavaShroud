package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.createReferenceProxies
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

class ReferenceProxyProtectionBoundaryTest {
    @Test
    fun ordinary_static_calls_are_proxied_while_protection_calls_remain_direct() {
        val owner = "fixture/ReferenceProxyBoundaryHost"
        val transformed = createReferenceProxies(fixtureClass(owner))
        val classNode = ClassNode()
        ClassReader(transformed).accept(classNode, ClassReader.SKIP_FRAMES)

        val caller = classNode.methods.single { method -> method.name == "callBoth" }
        val callerInvocations = caller.instructions.toArray().filterIsInstance<MethodInsnNode>()
        val proxies = classNode.methods.filter { method -> method.name.startsWith("a_px") }

        assertTrue(
            callerInvocations.any { invocation ->
                invocation.opcode == Opcodes.INVOKESTATIC &&
                    invocation.owner == owner &&
                    invocation.name.startsWith("a_px") &&
                    invocation.desc == "()V"
            },
            "ordinary application static calls must still be routed through a generated proxy",
        )
        assertFalse(
            callerInvocations.any { invocation ->
                invocation.owner == APPLICATION_HELPER_OWNER && invocation.name == "work"
            },
            "the original ordinary application call must be replaced by its proxy",
        )
        assertTrue(
            callerInvocations.any { invocation ->
                invocation.opcode == Opcodes.INVOKESTATIC &&
                    invocation.owner == PROTECTION_HELPER_OWNER &&
                    invocation.name == "requireHealthyKernel" &&
                    invocation.desc == "()V"
            },
            "JavaShroud protection calls must remain direct",
        )

        assertEquals(1, proxies.size, "only the ordinary application target should receive a proxy")
        val proxyInvocations = proxies.single().instructions.toArray().filterIsInstance<MethodInsnNode>()
        assertTrue(
            proxyInvocations.any { invocation ->
                invocation.owner == APPLICATION_HELPER_OWNER && invocation.name == "work"
            },
            "the generated proxy must forward to the ordinary application target",
        )
        assertFalse(
            proxyInvocations.any { invocation -> invocation.owner.startsWith(PROTECTION_OWNER_PREFIX) },
            "no a_px proxy may forward to a JavaShroud protection owner",
        )
    }

    private fun fixtureClass(owner: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null)

        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }

        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "callBoth", "()V", null, null).apply {
            visitCode()
            visitMethodInsn(Opcodes.INVOKESTATIC, APPLICATION_HELPER_OWNER, "work", "()V", false)
            visitMethodInsn(Opcodes.INVOKESTATIC, PROTECTION_HELPER_OWNER, "requireHealthyKernel", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        writer.visitEnd()
        return writer.toByteArray()
    }

    private companion object {
        const val APPLICATION_HELPER_OWNER = "fixture/ApplicationHelper"
        const val PROTECTION_OWNER_PREFIX = "io/github/hht0rro/javashroud/transforms/protection/"
        const val PROTECTION_HELPER_OWNER = "${PROTECTION_OWNER_PREFIX}JniMicrokernelHelper"
    }
}
