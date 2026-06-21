package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyMethodBodyDelayedDecryption
import kotlin.test.Test
import kotlin.test.assertEquals
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

class MethodBodyDelayedDecryptionSafetyTest {
    @Test
    fun delayed_decryption_skips_methods_with_non_constructor_invokespecial() {
        val internalName = "sample/DelayedInvokeSpecialHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildInvokeSpecialHost(internalName),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "run", "()I", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "secret", "()I", Opcodes.ACC_PRIVATE),
                    ),
                ),
            ),
        )

        val result = applyMethodBodyDelayedDecryption(
            artifact = artifact,
            ruleMatches = listOf(ruleMatchFor(internalName)),
            params = mapOf("seed" to 11),
        )

        assertEquals(0, result.transformedMemberCount, "Methods containing non-constructor invokespecial must not be moved into hidden wrappers")
        assertEquals(emptyList(), result.artifact.jarEntries.filter { it.name.startsWith("__jmd/") }.map { it.name })
        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex[internalName]!!.bytes).accept(node, ClassReader.SKIP_FRAMES)
        assertEquals(setOf("<init>", "run", "secret"), node.methods.map { it.name }.toSet())
    }

    @Test
    fun delayed_decryption_skips_instance_methods() {
        val internalName = "sample/DelayedInstanceHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildSimpleTarget(internalName),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "ping", "(Ljava/lang/String;)Ljava/lang/String;", Opcodes.ACC_PUBLIC),
                    ),
                ),
            ),
        )

        val result = applyMethodBodyDelayedDecryption(
            artifact = artifact,
            ruleMatches = listOf(ruleMatchFor(internalName)),
            params = mapOf("seed" to 17),
        )

        assertEquals(0, result.transformedMemberCount, "Instance methods must not be moved into delayed-decryption wrappers")
        assertEquals(emptyList(), result.artifact.jarEntries.filter { it.name.startsWith("__jmd/") }.map { it.name })
    }

    @Test
    fun delayed_decryption_skips_runtime_protection_helper_calls() {
        val internalName = "sample/DelayedRuntimeHelperHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildRuntimeProtectionHelperCaller(internalName),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "probe", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
        )

        val result = applyMethodBodyDelayedDecryption(
            artifact = artifact,
            ruleMatches = listOf(ruleMatchFor(internalName)),
            params = mapOf("seed" to 23),
        )

        assertEquals(0, result.transformedMemberCount, "Runtime protection helper calls must stay in loadable class bytecode so sealing can remap them")
        assertEquals(emptyList(), result.artifact.jarEntries.filter { it.name.startsWith("__jmd/") }.map { it.name })
    }

    private fun buildRuntimeProtectionHelperCaller(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val probe = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "probe", "()V", null, null)
        probe.visitCode()
        probe.visitLdcInsn("standard")
        probe.visitLdcInsn("log")
        probe.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "io/github/hht0rro/javashroud/transforms/protection/AntiInstrumentationHelper",
            "checkInstrumentation",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            false,
        )
        probe.visitInsn(Opcodes.RETURN)
        probe.visitMaxs(2, 0)
        probe.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
    private fun buildResourceDefineClassLoader(internalName: String, targetName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/ClassLoader", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;", null, null)
        method.visitCode()
        method.visitLdcInsn(org.objectweb.asm.Type.getObjectType(targetName))
        method.visitLdcInsn("/" + targetName + ".class")
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false)
        method.visitInsn(Opcodes.POP)
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitIntInsn(Opcodes.BIPUSH, 0)
        method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;", false)
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(5, 2)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildSimpleTarget(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val ping = cw.visitMethod(Opcodes.ACC_PUBLIC, "ping", "(Ljava/lang/String;)Ljava/lang/String;", null, null)
        ping.visitCode()
        ping.visitVarInsn(Opcodes.ALOAD, 1)
        ping.visitInsn(Opcodes.ARETURN)
        ping.visitMaxs(1, 2)
        ping.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
    private fun buildInvokeSpecialHost(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val run = cw.visitMethod(Opcodes.ACC_PUBLIC, "run", "()I", null, null)
        run.visitCode()
        run.visitVarInsn(Opcodes.ALOAD, 0)
        run.visitMethodInsn(Opcodes.INVOKESPECIAL, internalName, "secret", "()I", false)
        run.visitInsn(Opcodes.IRETURN)
        run.visitMaxs(1, 1)
        run.visitEnd()
        val secret = cw.visitMethod(Opcodes.ACC_PRIVATE, "secret", "()I", null, null)
        secret.visitCode()
        secret.visitIntInsn(Opcodes.BIPUSH, 42)
        secret.visitInsn(Opcodes.IRETURN)
        secret.visitMaxs(1, 1)
        secret.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun ruleMatchFor(internalName: String): RuleMatch = RuleMatch(
        rule = RuleSpec(target = internalName, action = "method-body-delayed-decryption"),
        selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
        matchedClassNames = listOf(internalName),
        matchedMembers = emptyList(),
    )
}
