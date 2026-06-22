package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.applyMethodHandleCombinatorChain
import io.github.hht0rro.javashroud.bytecode.applyMutableCallSiteRotation
import io.github.hht0rro.javashroud.bytecode.indirectMethodCalls
import io.github.hht0rro.javashroud.bytecode.remapClasses
import io.github.hht0rro.javashroud.bytecode.remapMethods
import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.naming.MemberRename
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class InvokeDynamicBootstrapRemapTest {

    @Test
    fun invoke_dynamic_indirection_skips_class_loader_boundaries() {
        val original = buildClassLoaderBoundaryCaller()
        val transformed = indirectMethodCalls(original)

        assertContentEquals(original, transformed, "ClassLoader/defineClass/resource-loading boundaries must not be wrapped in indy callsites")
    }

    @Test
    fun invoke_dynamic_indirection_bootstrap_handle_tracks_method_and_class_renames() {
        assertBootstrapHandleTracksRenames(::indirectMethodCalls)
    }

    @Test
    fun methodhandle_combinator_bootstrap_handle_tracks_method_and_class_renames() {
        assertBootstrapHandleTracksRenames { classBytes: ByteArray ->
            applyMethodHandleCombinatorChain(classBytes, seed = 0L)
        }
    }

    @Test
    fun mutable_callsite_bootstrap_handle_tracks_method_and_class_renames() {
        assertBootstrapHandleTracksRenames { classBytes: ByteArray ->
            applyMutableCallSiteRotation(classBytes, seed = 0L)
        }
    }

    private fun assertBootstrapHandleTracksRenames(transform: (ByteArray) -> ByteArray) {
        val original = buildCallerClassWithStaticCalls(callCount = 6)
        val transformed = transform(original)
        val beforeBootstrapHandle = findBootstrapMethodHandle(transformed)
        assertNotNull(beforeBootstrapHandle, "Expected transform to emit an invokedynamic bootstrap method handle")
        val beforeHandle = findBootstrapTargetHandle(transformed)
        assertNotNull(beforeHandle, "Expected transform to emit an invokedynamic bootstrap target handle")
        assertEquals("com/example/Target", beforeHandle.owner)
        assertEquals("work", beforeHandle.name)
        assertEquals("(I)I", beforeHandle.desc)

        val remapped = remapClasses(
            remapMethods(
                transformed,
                mapOf(
                    MemberKey("com/example/Caller", beforeBootstrapHandle.name, beforeBootstrapHandle.desc) to MemberRename(
                        owner = "com/example/Caller",
                        originalName = beforeBootstrapHandle.name,
                        descriptor = beforeBootstrapHandle.desc,
                        renamedName = "renamedBootstrap",
                    ),
                    MemberKey("com/example/Target", "work", "(I)I") to MemberRename(
                        owner = "com/example/Target",
                        originalName = "work",
                        descriptor = "(I)I",
                        renamedName = "m0000",
                    ),
                ),
            ),
            mapOf("com/example/Target" to "obf/C0001"),
        )

        val afterHandle = findBootstrapTargetHandle(remapped)
        assertNotNull(afterHandle, "Expected remapped class to retain an invokedynamic bootstrap handle")
        assertEquals("obf/C0001", afterHandle.owner)
        assertEquals("m0000", afterHandle.name)
        assertEquals("(I)I", afterHandle.desc)

        val afterBootstrapHandle = findBootstrapMethodHandle(remapped)
        assertNotNull(afterBootstrapHandle, "Expected remapped class to retain an invokedynamic bootstrap method handle")
        assertEquals("com/example/Caller", afterBootstrapHandle.owner)
        assertEquals("renamedBootstrap", afterBootstrapHandle.name)
        assertEquals(beforeBootstrapHandle.desc, afterBootstrapHandle.desc)
    }

    private fun findBootstrapTargetHandle(classBytes: ByteArray): Handle? {
        val classNode = ClassNode()
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_FRAMES)
        for (method in classNode.methods) {
            for (insn in method.instructions.toArray()) {
                if (insn is InvokeDynamicInsnNode) {
                    return insn.bsmArgs.filterIsInstance<Handle>().firstOrNull()
                }
            }
        }
        return null
    }

    private fun findBootstrapMethodHandle(classBytes: ByteArray): Handle? {
        val classNode = ClassNode()
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_FRAMES)
        for (method in classNode.methods) {
            for (insn in method.instructions.toArray()) {
                if (insn is InvokeDynamicInsnNode) {
                    return insn.bsm
                }
            }
        }
        return null
    }

    private fun buildCallerClassWithStaticCalls(callCount: Int): ByteArray {
        val classWriter = ClassWriter(ClassWriter.COMPUTE_MAXS)
        classWriter.visit(
            Opcodes.V21,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER,
            "com/example/Caller",
            null,
            "java/lang/Object",
            null,
        )

        val init = classWriter.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val run = classWriter.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()V", null, null)
        run.visitCode()
        repeat(callCount) { index: Int ->
            run.visitIntInsn(Opcodes.BIPUSH, index + 1)
            run.visitMethodInsn(Opcodes.INVOKESTATIC, "com/example/Target", "work", "(I)I", false)
            run.visitInsn(Opcodes.POP)
        }
        run.visitInsn(Opcodes.RETURN)
        run.visitMaxs(1, 0)
        run.visitEnd()

        classWriter.visitEnd()
        return classWriter.toByteArray()
    }

    private fun buildClassLoaderBoundaryCaller(): ByteArray {
        val classWriter = ClassWriter(ClassWriter.COMPUTE_MAXS)
        classWriter.visit(
            Opcodes.V21,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER,
            "com/example/BoundaryLoader",
            null,
            "java/lang/ClassLoader",
            null,
        )

        val init = classWriter.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/ClassLoader", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val run = classWriter.visitMethod(Opcodes.ACC_PUBLIC, "load", "(Ljava/lang/String;[B)Ljava/lang/Class;", null, null)
        run.visitCode()
        run.visitVarInsn(Opcodes.ALOAD, 0)
        run.visitVarInsn(Opcodes.ALOAD, 1)
        run.visitVarInsn(Opcodes.ALOAD, 2)
        run.visitInsn(Opcodes.ICONST_0)
        run.visitVarInsn(Opcodes.ALOAD, 2)
        run.visitInsn(Opcodes.ARRAYLENGTH)
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "com/example/BoundaryLoader", "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;", false)
        run.visitInsn(Opcodes.ARETURN)
        run.visitMaxs(5, 3)
        run.visitEnd()

        classWriter.visitEnd()
        return classWriter.toByteArray()
    }
}
