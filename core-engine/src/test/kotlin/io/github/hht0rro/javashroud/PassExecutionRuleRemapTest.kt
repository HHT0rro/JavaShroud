package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.passes.applyRegisteredPassWithMetrics
import io.github.hht0rro.javashroud.passes.requireExecutablePass
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PassExecutionRuleRemapTest {
    private val mapper = ObjectMapper()

    @Test
    fun class_rename_keeps_original_rules_targeting_method_virtualization() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val config = testConfig(
            allowOptInPasses = true,
            ruleSet = RuleSet(
                listOf(
                    RuleSpec("example/Target", "rename-classes"),
                    RuleSpec("example/Target", "method-virtualization"),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = "example/Target",
                    bytes = targetClassBytes(),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "value", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                ),
            ),
            config = config,
        )
        val initialContext = PassContext(config = config, artifact = artifact, events = emptyList())

        val renamed = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "rename-classes",
                params = mapOf(
                    "dictionaryStyle" to mapper.valueToTree("sequential"),
                    "preservePackageDepth" to mapper.valueToTree(0),
                    "collisionPolicy" to mapper.valueToTree("append-index"),
                ),
            ),
            executable = requireExecutablePass("rename-classes"),
            context = initialContext,
        ).context
        val renamedClassName = renamed.artifact.classArtifacts.single().summary.internalName

        val virtualized = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(0),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(0),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = renamed,
        )
        val classBytes = virtualized.context.artifact.classArtifactIndex.getValue(renamedClassName).bytes

        assertEquals(1, virtualized.transformedMemberCount, "Original method-virtualization rule must survive class renaming")
        assertTrue(methodCallsVmDispatcher(classBytes, "value", "()I"), "Renamed class should still have its selected method lowered to VBC4")
    }

    private fun targetClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/Target", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitIntInsn(Opcodes.BIPUSH, 7)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(1, 0)
        value.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun methodCallsVmDispatcher(classBytes: ByteArray, methodName: String, descriptor: String): Boolean {
        var callsDispatcher = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, methodDescriptor: String, isInterface: Boolean) {
                        if (owner.endsWith("JniMicrokernelHelper") && name.startsWith("executeVmResource")) callsDispatcher = true
                    }
                }
            }
        }, 0)
        return callsDispatcher
    }
}
