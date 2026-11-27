package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.insertAntiDecompilerStructures
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.bytecode.remapClassesStrict
import java.lang.reflect.InvocationTargetException
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FrameNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ClassWriterSupportRegressionTest {
    @Test
    fun class_rename_preserves_application_receiver_type_at_a_frame_merge() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/Caller", null, "java/lang/Object", null)
        val method = writer.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "read",
            "(ZLfixture/Left;Lfixture/Right;)I",
            null,
            null,
        )
        val useRight = Label()
        val merge = Label()
        method.visitCode()
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitJumpInsn(Opcodes.IFEQ, useRight)
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitJumpInsn(Opcodes.GOTO, merge)
        method.visitLabel(useRight)
        method.visitFrame(Opcodes.F_SAME, 0, null, 0, null)
        method.visitVarInsn(Opcodes.ALOAD, 2)
        method.visitLabel(merge)
        method.visitFrame(Opcodes.F_SAME1, 0, null, 1, arrayOf("fixture/Base"))
        method.visitFieldInsn(Opcodes.GETFIELD, "fixture/Base", "value", "I")
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(1, 3)
        method.visitEnd()
        writer.visitEnd()

        val renamed = remapClassesStrict(
            writer.toByteArray(),
            mapOf("fixture/Base" to "renamed/Base", "fixture/Left" to "renamed/Left"),
        )
        val caller = ClassNode()
        ClassReader(renamed).accept(caller, ClassReader.EXPAND_FRAMES)
        val mergedFrame = caller.methods.single().instructions.filterIsInstance<FrameNode>().last()
        assertEquals(listOf("renamed/Base"), mergedFrame.stack)
        assertEquals(listOf(Opcodes.INTEGER, "renamed/Left", "fixture/Right"), mergedFrame.local)
    }

    @Test
    fun common_super_class_preserves_throwable_parent() {
        val writer = computeFramesWriter()
        val resolver = ClassWriter::class.java.getDeclaredMethod(
            "getCommonSuperClass",
            String::class.java,
            String::class.java,
        ).apply { isAccessible = true }

        val common = resolver.invoke(
            writer,
            "java/lang/IllegalArgumentException",
            "java/lang/IllegalStateException",
        ) as String

        assertEquals("java/lang/RuntimeException", common)
    }

    @Test
    fun anti_decompiler_does_not_reintroduce_generic_target_entrypoints_in_embedded_jni_helper() {
        val resourceName = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.class"
        val original = requireNotNull(javaClass.classLoader.getResourceAsStream(resourceName)).use { it.readBytes() }
        val transformed = insertAntiDecompilerStructures(original)

        val loaded = VerifyingClassLoader(javaClass.classLoader).defineAndResolve(transformed)

        assertEquals("io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge", loaded.name)
        assertTrue(loaded.declaredMethods.none { method ->
            method.name == "createRunnableLambda" ||
                method.name == "createSamLambda" ||
                method.name == "resolveVmMethodHandle"
        })
    }

    @Test
    fun anti_decompiler_preserves_shared_multicatch_athrow_frames() {
        val resourceName = "io/github/hht0rro/javashroud/MultiCatchAthrowFixture.class"
        val original = requireNotNull(javaClass.classLoader.getResourceAsStream(resourceName)).use { it.readBytes() }
        val transformed = insertAntiDecompilerStructures(original)

        val loaded = VerifyingClassLoader(javaClass.classLoader).defineAndResolve(transformed)
        val run = loaded.getDeclaredMethod("run", Int::class.javaPrimitiveType)
        val thrown = assertFailsWith<InvocationTargetException> { run.invoke(null, 0) }.targetException

        assertIs<IllegalArgumentException>(thrown)
    }

    private class VerifyingClassLoader(parent: ClassLoader) : ClassLoader(parent) {
        fun defineAndResolve(bytes: ByteArray): Class<*> {
            val defined = defineClass(null, bytes, 0, bytes.size)
            resolveClass(defined)
            return defined
        }
    }
}
