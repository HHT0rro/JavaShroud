package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyClassEncryptionLoader
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

class ClassEncryptionLoaderOptimizationTest {
    @Test
    fun class_encryption_loader_delegating_methods_do_not_reinvoke_load_class() {
        val internalName = "sample/LoaderTarget"
        val classBytes = buildLoaderTargetClass(internalName)
        val methods = listOf(
            MemberSummary(MemberKind.METHOD, "classify", "(I)I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "seasonName", "(I)Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            MemberSummary(MemberKind.METHOD, "httpStatus", "(I)Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = internalName, bytes = classBytes, methodSummaries = methods)),
        )

        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyClassEncryptionLoader(
                artifact = artifact,
                ruleMatches = listOf(ruleMatchFor(internalName)),
                params = mapOf("encryptionStrategy" to "aes-128", "keyMode" to "per-class", "seed" to 42),
            )
        }

        val transformed = result.artifact.classArtifactIndex[internalName]
        assertNotNull(transformed)
        val node = ClassNode()
        ClassReader(transformed.bytes).accept(node, 0)

        val helperOwner = "io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper"
        val loadClassCallsByMethod = node.methods.associate { method ->
            method.name to method.instructions.asSequence().filterIsInstance<MethodInsnNode>().count { insn ->
                insn.opcode == Opcodes.INVOKESTATIC && insn.owner == helperOwner && insn.name == "loadClass"
            }
        }

        assertEquals(1, loadClassCallsByMethod["<clinit>"], "generated <clinit> should perform the one loader bootstrap")
        assertEquals(0, loadClassCallsByMethod["classify"], "delegating method should not repeat loadClass")
        assertEquals(0, loadClassCallsByMethod["seasonName"], "delegating method should not repeat loadClass")
        assertEquals(0, loadClassCallsByMethod["httpStatus"], "delegating method should not repeat loadClass")
    }

    private fun buildPackagePrivateInterface(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_ABSTRACT or Opcodes.ACC_INTERFACE, internalName, null, "java/lang/Object", null)
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT, "value", "()I", null, null).visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildInterfaceImplementation(internalName: String, interfaceName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", arrayOf(interfaceName))
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = cw.visitMethod(Opcodes.ACC_PUBLIC, "value", "()I", null, null)
        value.visitCode()
        value.visitIntInsn(Opcodes.BIPUSH, 7)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(1, 1)
        value.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
    private fun buildLoaderTargetClass(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)

        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val classify = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "classify", "(I)I", null, null)
        classify.visitCode()
        classify.visitVarInsn(Opcodes.ILOAD, 0)
        classify.visitInsn(Opcodes.IRETURN)
        classify.visitMaxs(1, 1)
        classify.visitEnd()

        val seasonName = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "seasonName", "(I)Ljava/lang/String;", null, null)
        seasonName.visitCode()
        seasonName.visitLdcInsn("spring")
        seasonName.visitInsn(Opcodes.ARETURN)
        seasonName.visitMaxs(1, 1)
        seasonName.visitEnd()

        val httpStatus = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "httpStatus", "(I)Ljava/lang/String;", null, null)
        httpStatus.visitCode()
        httpStatus.visitLdcInsn("ok")
        httpStatus.visitInsn(Opcodes.ARETURN)
        httpStatus.visitMaxs(1, 1)
        httpStatus.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun ruleMatchFor(internalName: String): RuleMatch = RuleMatch(
        rule = RuleSpec(target = internalName, action = "class-encryption-loader"),
        selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
        matchedClassNames = listOf(internalName),
        matchedMembers = emptyList(),
    )
}
