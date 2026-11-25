package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Junk code injection transform.
 *
 * Inserts dead-code bytecode sequences (ICONST + POP) around real instructions
 * to increase analysis noise for decompilers and static analysis tools.
 * Skips interfaces, abstract classes, and enums.
 *
 * Design inspired by jar-obfuscator JunkCodeVisitor (MIT),
 * re-implemented as JavaShroud-native Kotlin.
 */
fun injectJunkCode(classBytes: ByteArray, junkCount: Int = 3): ByteArray {
    val reader = ClassReader(classBytes)
    val writer = computeFramesWriter(reader)
    val tracker = JunkTracker()
    val visitor = JunkCodeClassVisitor(writer, junkCount, tracker)
    reader.accept(visitor, 0)
    return if (tracker.injectedCount > 0) writer.toByteArray() else classBytes
}

internal class JunkTracker {
    var injectedCount: Int = 0
        private set

    fun recordInjection() {
        injectedCount++
    }
}

private class JunkCodeClassVisitor(
    classWriter: ClassWriter?,
    private val junkCount: Int,
    private val tracker: JunkTracker,
) : ClassVisitor(Opcodes.ASM9, classWriter) {

    private var shouldSkip = false

    override fun visit(
        version: Int,
        access: Int,
        name: String,
        signature: String?,
        superName: String?,
        interfaces: Array<out String>?,
    ) {
        super.visit(version, access, name, signature, superName, interfaces)
        val isAbstract = (access and Opcodes.ACC_ABSTRACT) != 0
        val isInterface = (access and Opcodes.ACC_INTERFACE) != 0
        val isEnum = (access and Opcodes.ACC_ENUM) != 0
        shouldSkip = isAbstract || isInterface || isEnum
    }

    override fun visitMethod(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        exceptions: Array<out String>?,
    ): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        if (shouldSkip || name == "<clinit>" || name == "<init>") {
            return mv
        }
        return JunkCodeMethodVisitor(mv, junkCount, tracker)
    }
}

private class JunkCodeMethodVisitor(
    methodVisitor: MethodVisitor?,
    private val junkCount: Int,
    private val tracker: JunkTracker,
) : MethodVisitor(Opcodes.ASM9, methodVisitor) {

    private val random = java.util.Random()

    private fun injectJunkSequence() {
        repeat(junkCount) {
            val constOpcode = when (random.nextInt(6)) {
                0 -> Opcodes.ICONST_0
                1 -> Opcodes.ICONST_1
                2 -> Opcodes.ICONST_2
                3 -> Opcodes.ICONST_3
                4 -> Opcodes.ICONST_4
                else -> Opcodes.ICONST_5
            }
            mv.visitInsn(constOpcode)
            mv.visitInsn(Opcodes.POP)
            tracker.recordInjection()
        }
    }

    override fun visitCode() {
        super.visitCode()
        injectJunkSequence()
    }

    override fun visitMethodInsn(
        opcode: Int,
        owner: String,
        name: String,
        descriptor: String,
        isInterface: Boolean,
    ) {
        injectJunkSequence()
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
    }

    override fun visitInsn(opcode: Int) {
        if (opcode != Opcodes.RETURN && opcode != Opcodes.ARETURN &&
            opcode != Opcodes.IRETURN && opcode != Opcodes.LRETURN &&
            opcode != Opcodes.FRETURN && opcode != Opcodes.DRETURN &&
            opcode != Opcodes.ATHROW
        ) {
            if (random.nextInt(3) == 0) {
                injectJunkSequence()
            }
        }
        super.visitInsn(opcode)
    }

    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
        if (random.nextInt(2) == 0) {
            injectJunkSequence()
        }
        super.visitFieldInsn(opcode, owner, name, descriptor)
    }
}
