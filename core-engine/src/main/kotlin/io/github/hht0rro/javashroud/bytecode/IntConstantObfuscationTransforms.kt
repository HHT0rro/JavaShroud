package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Integer constant obfuscation transform.
 *
 * Replaces integer constant loads (ICONST, BIPUSH, SIPUSH, LDC int)
 * with obfuscated expressions: add a random delta and compensate it
 * at runtime without relying on XOR masking.
 *
 * Pattern: push(encoded), push(delta), IADD  =>  original value
 * This breaks pattern matching in decompilers.
 *
 * Design inspired by obfuscator-master NumberObfuscationTransformer (MIT),
 * re-implemented as JavaShroud-native Kotlin.
 */
fun obfuscateIntegerConstants(classBytes: ByteArray): ByteArray {
    val reader = ClassReader(classBytes)
    val writer = computeFramesWriter(reader)
    val tracker = IntObfuscationTracker()
    val visitor = IntObfuscationClassVisitor(writer, tracker)
    reader.accept(visitor, 0)
    return if (tracker.obfuscatedCount > 0) writer.toByteArray() else classBytes
}

internal class IntObfuscationTracker {
    var obfuscatedCount: Int = 0
        private set

    fun recordObfuscation() {
        obfuscatedCount++
    }
}

private class IntObfuscationClassVisitor(
    classWriter: ClassWriter?,
    private val tracker: IntObfuscationTracker,
) : ClassVisitor(Opcodes.ASM9, classWriter) {

    override fun visitMethod(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        exceptions: Array<out String>?,
    ): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        return IntObfuscationMethodVisitor(mv, tracker)
    }
}

private class IntObfuscationMethodVisitor(
    methodVisitor: MethodVisitor?,
    private val tracker: IntObfuscationTracker,
) : MethodVisitor(Opcodes.ASM9, methodVisitor) {

    private val random = java.util.Random()

    override fun visitIntInsn(opcode: Int, operand: Int) {
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            if (operand != 0) {
                val key = random.nextInt(Int.MAX_VALUE - 1) + 1
                val encoded = operand - key
                // Push encoded, push delta, IADD => original value
                pushInt(encoded)
                pushInt(key)
                mv.visitInsn(Opcodes.IADD)
                tracker.recordObfuscation()
                return
            }
        }
        super.visitIntInsn(opcode, operand)
    }

    override fun visitLdcInsn(value: Any?) {
        if (value is Int && value != 0) {
            val key = random.nextInt(Int.MAX_VALUE - 1) + 1
            val encoded = value - key
            pushInt(encoded)
            pushInt(key)
            mv.visitInsn(Opcodes.IADD)
            tracker.recordObfuscation()
            return
        }
        super.visitLdcInsn(value)
    }

    private fun pushInt(value: Int) {
        when {
            value >= -1 && value <= 5 -> {
                val opcode = Opcodes.ICONST_0 + value
                mv.visitInsn(opcode)
            }
            value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE -> {
                mv.visitIntInsn(Opcodes.BIPUSH, value)
            }
            value >= Short.MIN_VALUE && value <= Short.MAX_VALUE -> {
                mv.visitIntInsn(Opcodes.SIPUSH, value)
            }
            else -> {
                mv.visitLdcInsn(value)
            }
        }
    }
}
