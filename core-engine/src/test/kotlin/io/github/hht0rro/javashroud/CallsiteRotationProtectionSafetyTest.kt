package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyCallsiteRotationProtection
import kotlin.test.Test
import kotlin.test.assertEquals
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.MethodInsnNode

class CallsiteRotationProtectionSafetyTest {
    @Test
    fun callsite_rotation_does_not_rewrite_array_virtual_calls_with_invalid_receiver_descriptor() {
        val internalName = "sample/ArrayVirtualCallHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildArrayVirtualCallHost(internalName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "copy", "([Ljava/lang/String;)[Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                ),
            ),
        )

        val result = applyCallsiteRotationProtection(
            artifact = artifact,
            ruleMatches = listOf(ruleMatchFor(internalName)),
            params = mapOf("seed" to 1),
        )

        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex[internalName]!!.bytes).accept(node, ClassReader.SKIP_FRAMES)
        val instructions = node.methods.single { it.name == "copy" }.instructions.toArray()
        assertEquals(0, instructions.filterIsInstance<InvokeDynamicInsnNode>().count(), "Array receiver virtual calls must not become invokedynamic with L[array; descriptors")
        assertEquals(1, instructions.filterIsInstance<MethodInsnNode>().count { it.owner.startsWith("[") && it.name == "clone" })
    }

    private fun buildArrayVirtualCallHost(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "copy", "([Ljava/lang/String;)[Ljava/lang/String;", null, null)
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "[Ljava/lang/String;", "clone", "()Ljava/lang/Object;", false)
        method.visitTypeInsn(Opcodes.CHECKCAST, "[Ljava/lang/String;")
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(1, 1)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun ruleMatchFor(internalName: String): RuleMatch = RuleMatch(
        rule = RuleSpec(target = internalName, action = "callsite-rotation-protection"),
        selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
        matchedClassNames = listOf(internalName),
        matchedMembers = emptyList(),
    )
}
