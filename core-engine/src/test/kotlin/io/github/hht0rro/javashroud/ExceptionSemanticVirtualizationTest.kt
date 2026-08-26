package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyExceptionSemanticVirtualization
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.VarInsnNode

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

        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyExceptionSemanticVirtualization(
                artifact = artifact,
                ruleMatches = listOf(RuleMatch(
                    rule = RuleSpec(target = internalName, action = "exception-semantic-virtualization"),
                    selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
                    matchedClassNames = listOf(internalName),
                    matchedMembers = emptyList(),
                )),
                params = mapOf("virtualizationLevel" to "aggressive", "seed" to 37),
            )
        }

        assertEquals(1, result.transformedMemberCount)
        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex[internalName]!!.bytes).accept(node, ClassReader.SKIP_FRAMES)
        assertTrue(node.methods.none { it.name.startsWith("\$jsv\$") }, "Continuation must not clone the body into a synthetic handler method")
        val add = node.methods.single { it.name == "add" }
        assertEquals("(II)I", add.desc)
        val calls = add.instructions.toArray().filterIsInstance<MethodInsnNode>()
        assertTrue(calls.any { it.name == "<init>" && it.desc == "(I)V" }, "Dispatcher must throw state-carrying flow-control exceptions")
        assertTrue(calls.none { it.owner == internalName && it.name.startsWith("\$jsv\$") })
        assertTrue(add.tryCatchBlocks.isNotEmpty(), "Catch handler must resume from continuation state")
        val opcodes = add.instructions.toArray().mapNotNull { insn -> insn.opcode.takeIf { it >= 0 } }
        assertTrue(opcodes.contains(Opcodes.IADD), "Original body must remain in the method once")
        assertEquals(1, opcodes.count { it == Opcodes.IADD })
        assertTrue(add.tryCatchBlocks.any { it.type?.contains("FlowControlException") == true || it.handler != null })
    }

    @Test
    fun exception_virtualization_skips_reflection_member_lookup_targets() {
        val targetName = "sample/ReflectiveTarget"
        val observerName = "sample/ReflectiveObserver"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = targetName,
                    bytes = buildHost(targetName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "add", "(II)I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                ),
                testClassArtifact(
                    internalName = observerName,
                    bytes = buildReflectionObserver(observerName, targetName),
                ),
            ),
        )
        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyExceptionSemanticVirtualization(
                artifact = artifact,
                ruleMatches = listOf(RuleMatch(
                    rule = RuleSpec(target = targetName, action = "exception-semantic-virtualization"),
                    selector = TargetSelector(classPattern = targetName, memberPattern = null, memberDescriptorPattern = null),
                    matchedClassNames = listOf(targetName),
                    matchedMembers = emptyList(),
                )),
                params = mapOf("virtualizationLevel" to "aggressive"),
            )
        }
        assertEquals(0, result.transformedMemberCount, "reflectively looked-up classes must remain bytecode-compatible")
    }

    @Test
    fun exception_virtualization_skips_synthetic_lambda_bodies() {
        val internalName = "sample/SyntheticLambdaHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildSyntheticHost(internalName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "lambda\$run\$0", "(II)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC)),
                ),
            ),
        )
        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyExceptionSemanticVirtualization(
                artifact = artifact,
                ruleMatches = listOf(RuleMatch(
                    rule = RuleSpec(target = internalName, action = "exception-semantic-virtualization"),
                    selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
                    matchedClassNames = listOf(internalName),
                    matchedMembers = emptyList(),
                )),
                params = mapOf("virtualizationLevel" to "aggressive"),
            )
        }
        assertEquals(0, result.transformedMemberCount)
    }

    @Test
    fun exception_virtualization_splits_empty_stack_blocks_without_cloning() {
        val internalName = "sample/ExceptionSplitHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildSplitHost(internalName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "run", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                ),
            ),
        )
        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyExceptionSemanticVirtualization(
                artifact = artifact,
                ruleMatches = listOf(RuleMatch(
                    rule = RuleSpec(target = internalName, action = "exception-semantic-virtualization"),
                    selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
                    matchedClassNames = listOf(internalName),
                    matchedMembers = emptyList(),
                )),
                params = mapOf("virtualizationLevel" to "aggressive", "seed" to 11),
            )
        }
        assertEquals(1, result.transformedMemberCount)
        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex[internalName]!!.bytes).accept(node, ClassReader.SKIP_FRAMES)
        assertTrue(node.methods.none { it.name.startsWith("\$jsv\$") })
        val run = node.methods.single { it.name == "run" }
        val stores = run.instructions.toArray().filterIsInstance<VarInsnNode>().count { it.opcode == Opcodes.ISTORE }
        assertTrue(stores >= 1)
        assertEquals(1, run.instructions.toArray().count { it is InsnNode && it.opcode == Opcodes.IRETURN })
        assertTrue(run.tryCatchBlocks.filterIsInstance<TryCatchBlockNode>().isNotEmpty())
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

    private fun buildSyntheticHost(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val method = cw.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "lambda\$run\$0",
            "(II)I",
            null,
            null,
        )
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

    private fun buildReflectionObserver(internalName: String, targetName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "observe", "()V", null, null)
        method.visitCode()
        method.visitLdcInsn(org.objectweb.asm.Type.getObjectType(targetName))
        method.visitLdcInsn("add")
        method.visitInsn(Opcodes.ICONST_2)
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class")
        method.visitInsn(Opcodes.DUP)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;")
        method.visitInsn(Opcodes.AASTORE)
        method.visitInsn(Opcodes.DUP)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;")
        method.visitInsn(Opcodes.AASTORE)
        method.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            false,
        )
        method.visitInsn(Opcodes.POP)
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildSplitHost(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        method.visitCode()
        method.visitInsn(Opcodes.ICONST_2)
        method.visitVarInsn(Opcodes.ISTORE, 0)
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(1, 1)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
}
