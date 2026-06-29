package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyExceptionSemanticVirtualization
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

class ExceptionSemanticVirtualizationTest {
    @Test
    fun exception_virtualization_rewrites_eligible_method_to_state_dispatcher() {
        val internalName = "sample/ExceptionVirtHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildHost(internalName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "add", "(II)I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                ),
            ),
        )

        val result = applyExceptionSemanticVirtualization(
            artifact = artifact,
            ruleMatches = listOf(RuleMatch(
                rule = RuleSpec(target = internalName, action = "exception-semantic-virtualization"),
                selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
                matchedClassNames = listOf(internalName),
                matchedMembers = emptyList(),
            )),
            params = mapOf("virtualizationLevel" to "aggressive", "seed" to 37),
        )

        assertEquals(1, result.transformedMemberCount)
        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex[internalName]!!.bytes).accept(node, ClassReader.SKIP_FRAMES)
        assertTrue(node.methods.any { it.name.startsWith("\$jsv\$add\$") }, "Original body must move into a synthetic state handler")
        val add = node.methods.single { it.name == "add" }
        val calls = add.instructions.toArray().filterIsInstance<MethodInsnNode>()
        assertTrue(calls.any { it.name == "<init>" && it.desc == "(I)V" }, "Dispatcher must throw state-carrying flow-control exceptions")
        assertTrue(calls.any { it.owner == internalName && it.name.startsWith("\$jsv\$add\$") }, "Dispatcher must invoke the state handler")
    }

    private fun buildHost(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "add", "(II)I", null, null)
        method.visitCode()
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitVarInsn(Opcodes.ILOAD, 1)
        method.visitInsn(Opcodes.IADD)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(2, 2)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
}
