package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.transforms.rename.renameMethods
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import java.lang.reflect.Method
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RenameReflectionBridgeTest {
    @Test
    fun renameMethods_keeps_ambiguous_reflection_lookup_callable_through_original_name_bridge() {
        val targetName = "sample/ReflectionBridgeTarget"
        val otherTargetName = "sample/ReflectionBridgeOther"
        val callerName = "sample/ReflectionBridgeCaller"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = targetName,
                    bytes = buildStaticTarget(targetName, "(I)I", delta = 2),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "mutate", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    ),
                ),
                testClassArtifact(
                    internalName = otherTargetName,
                    bytes = buildStaticTarget(otherTargetName, "()I", delta = 1),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "mutate", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    ),
                ),
                testClassArtifact(
                    internalName = callerName,
                    bytes = buildReflectiveCaller(callerName, targetName),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "<init>", "()V", Opcodes.ACC_PUBLIC),
                        MemberSummary(MemberKind.METHOD, "lookup", "()Ljava/lang/reflect/Method;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
        )

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )
        val bytecodeByName = result.artifact.classArtifacts.associate { it.summary.internalName to it.bytes }
        val targetNode = readNode(bytecodeByName.getValue(targetName))
        val renamedTarget = targetNode.methods.single { method ->
            method.desc == "(I)I" && method.name != "mutate"
        }
        assertNotEquals("mutate", renamedTarget.name, "The reflective target body must still be renamed")
        assertTrue(
            targetNode.methods.any { method ->
                method.name == "mutate" &&
                    method.desc == "(I)I" &&
                    method.access and Opcodes.ACC_SYNTHETIC != 0 &&
                    method.access and Opcodes.ACC_BRIDGE != 0
            },
            "Ambiguous reflection lookup names need an original-name bridge",
        )

        val loader = BytecodeMapClassLoader(bytecodeByName)
        val callerClass = loader.loadClass(callerName.replace('/', '.'))
        val lookup = callerClass.declaredMethods.single { method ->
            method.returnType == Method::class.java && method.parameterCount == 0
        }
        assertTrue(lookup.trySetAccessible())
        val reflectedTarget = lookup.invoke(null) as Method
        assertEquals("mutate", reflectedTarget.name, "The dynamic lookup must resolve the preserved bridge")
        assertTrue(reflectedTarget.trySetAccessible())
        assertEquals(9, (reflectedTarget.invoke(null, 7) as Number).toInt())
    }

    private fun buildStaticTarget(internalName: String, descriptor: String, delta: Int): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, internalName, null, "java/lang/Object", null)
        emitDefaultConstructor(writer)
        val method = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "mutate", descriptor, null, null)
        method.visitCode()
        if (descriptor == "(I)I") {
            method.visitVarInsn(Opcodes.ILOAD, 0)
            method.visitIntInsn(Opcodes.BIPUSH, delta)
            method.visitInsn(Opcodes.IADD)
        } else {
            method.visitIntInsn(Opcodes.BIPUSH, delta)
        }
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildReflectiveCaller(internalName: String, targetName: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, internalName, null, "java/lang/Object", null)
        emitDefaultConstructor(writer)
        val lookup = writer.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "lookup",
            "()Ljava/lang/reflect/Method;",
            null,
            arrayOf("java/lang/NoSuchMethodException"),
        )
        lookup.visitCode()
        lookup.visitLdcInsn(Type.getObjectType(targetName))
        lookup.visitLdcInsn("mutate")
        lookup.visitInsn(Opcodes.ICONST_1)
        lookup.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class")
        lookup.visitInsn(Opcodes.DUP)
        lookup.visitInsn(Opcodes.ICONST_0)
        lookup.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;")
        lookup.visitInsn(Opcodes.AASTORE)
        lookup.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            false,
        )
        lookup.visitInsn(Opcodes.ARETURN)
        lookup.visitMaxs(0, 0)
        lookup.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun emitDefaultConstructor(writer: ClassWriter) {
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(0, 0)
        constructor.visitEnd()
    }

    private fun readNode(bytes: ByteArray): ClassNode = ClassNode().also { node ->
        ClassReader(bytes).accept(node, 0)
    }

    private class BytecodeMapClassLoader(
        private val bytecodeByName: Map<String, ByteArray>,
    ) : ClassLoader(RenameReflectionBridgeTest::class.java.classLoader) {
        override fun findClass(name: String): Class<*> {
            val internalName = name.replace('.', '/')
            val bytes = bytecodeByName[internalName] ?: throw ClassNotFoundException(name)
            return defineClass(name, bytes, 0, bytes.size)
        }
    }
}
