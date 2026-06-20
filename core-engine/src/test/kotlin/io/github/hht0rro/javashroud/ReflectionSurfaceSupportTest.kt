package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.obfuscation.applyCondyIndirection
import io.github.hht0rro.javashroud.transforms.obfuscation.applyControlFlowFlattening
import io.github.hht0rro.javashroud.transforms.obfuscation.applyExceptionDispatchLogic
import io.github.hht0rro.javashroud.transforms.obfuscation.applyReferenceProxy
import io.github.hht0rro.javashroud.transforms.obfuscation.invokeDynamicIndirect
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import kotlin.test.Test
import kotlin.test.assertEquals

class ReflectionSurfaceSupportTest {
    @Test
    fun member_adding_transforms_skip_classes_enumerated_by_reflection_surface_calls() {
        val targetName = "sample/ReflectTarget"
        val inspectorName = "sample/ReflectInspector"
        val targetClass = testClassArtifact(internalName = targetName, bytes = buildReflectTargetClass(targetName))
        val inspectorClass = testClassArtifact(internalName = inspectorName, bytes = buildReflectInspectorClass(inspectorName, targetName))
        val artifact = testAttachedArtifact(classArtifacts = listOf(targetClass, inspectorClass))
        val originalMethodCount = declaredMethodCount(artifact.classArtifactIndex.getValue(targetName).bytes)
        val originalFieldCount = declaredFieldCount(artifact.classArtifactIndex.getValue(targetName).bytes)

        val transforms = listOf(
            ::applyControlFlowFlattening,
            ::invokeDynamicIndirect,
            ::applyReferenceProxy,
            ::applyExceptionDispatchLogic,
            ::applyCondyIndirection,
        )

        for (transform in transforms) {
            val result = transform(artifact, emptyList(), mapOf("seed" to 7, "pattern" to "field-noise", "handlerComplexity" to "field-write"))
            val transformedTarget = result.artifact.classArtifactIndex.getValue(targetName).bytes
            assertEquals(
                originalMethodCount,
                declaredMethodCount(transformedTarget),
                "${transform.name} must not add reflection-visible helper methods to $targetName",
            )
            assertEquals(
                originalFieldCount,
                declaredFieldCount(transformedTarget),
                "${transform.name} must not add reflection-visible helper fields to $targetName",
            )
        }
    }

    private fun buildReflectTargetClass(internalName: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)

        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "probe", "()Ljava/lang/Object;", null, null)
        method.visitCode()
        method.visitLdcInsn("reflection-sensitive-value")
        method.visitInsn(Opcodes.POP)
        method.visitIntInsn(Opcodes.BIPUSH, 7)
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(1, 0)
        method.visitEnd()

        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildReflectInspectorClass(internalName: String, targetName: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)

        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "inspect", "()[Ljava/lang/reflect/Method;", null, null)
        method.visitCode()
        method.visitLdcInsn(Type.getObjectType(targetName))
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethods", "()[Ljava/lang/reflect/Method;", false)
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(1, 0)
        method.visitEnd()

        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun declaredMethodCount(classBytes: ByteArray): Int {
        val node = readClassNode(classBytes)
        return node.methods.size
    }

    private fun declaredFieldCount(classBytes: ByteArray): Int {
        val node = readClassNode(classBytes)
        return node.fields.size
    }

    private fun readClassNode(classBytes: ByteArray): ClassNode {
        val node = ClassNode()
        ClassReader(classBytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return node
    }
}

