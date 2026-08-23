package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.transforms.rename.renameMethods
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import kotlin.test.Test
import kotlin.test.assertEquals

class RenameReflectionEnumerationGuardTest {
    @Test
    fun renameMethods_skips_classes_enumerated_by_getDeclaredMethods() {
        val targetName = "sample/ReflectEnumTarget"
        val inspectorName = "sample/ReflectEnumInspector"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = targetName,
                    bytes = buildTarget(targetName),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                        MemberSummary(MemberKind.METHOD, "mutate", "(I)V", Opcodes.ACC_PUBLIC),
                    ),
                ),
                testClassArtifact(
                    internalName = inspectorName,
                    bytes = buildInspector(inspectorName, targetName),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                        MemberSummary(MemberKind.METHOD, "inspect", "()[Ljava/lang/reflect/Method;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
        )
        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )
        assertEquals(setOf("<init>", "mutate"), readMethodNames(result.artifact.classArtifactIndex.getValue(targetName).bytes))
    }

    private fun buildTarget(internalName: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val mutate = writer.visitMethod(Opcodes.ACC_PUBLIC, "mutate", "(I)V", null, null)
        mutate.visitCode()
        mutate.visitInsn(Opcodes.RETURN)
        mutate.visitMaxs(0, 2)
        mutate.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildInspector(internalName: String, targetName: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val inspect = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "inspect", "()[Ljava/lang/reflect/Method;", null, null)
        inspect.visitCode()
        inspect.visitLdcInsn(Type.getObjectType(targetName))
        inspect.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethods", "()[Ljava/lang/reflect/Method;", false)
        inspect.visitInsn(Opcodes.ARETURN)
        inspect.visitMaxs(1, 0)
        inspect.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun readMethodNames(bytes: ByteArray): Set<String> {
        val names = linkedSetOf<String>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): org.objectweb.asm.MethodVisitor? {
                if (name != null) names += name
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return names
    }
}
