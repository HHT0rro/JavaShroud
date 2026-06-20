package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.util.Random

/**
 * Opaque predicate insertion transform with parameterized algebraic family
 * and insertion mode.
 */
fun insertOpaquePredicates(
    classBytes: ByteArray,
    frequency: Int = 8,
    config: ControlFlowConfig = ControlFlowConfig(frequency = frequency),
): ByteArray {
    val reader = ClassReader(classBytes)
    val writer = computeFramesWriter(reader)
    val tracker = OpaqueTracker()
    val visitor = OpaquePredicateClassVisitor(writer, tracker, config)
    return try {
        reader.accept(visitor, 0)
        if (tracker.insertedCount > 0) writer.toByteArray() else classBytes
    } catch (_: RuntimeException) {
        classBytes
    }
}

internal class OpaqueTracker {
    var insertedCount: Int = 0
        private set
    fun recordInsertion() { insertedCount++ }
}

private class OpaquePredicateClassVisitor(
    classWriter: ClassWriter?,
    private val tracker: OpaqueTracker,
    private val config: ControlFlowConfig,
) : ClassVisitor(Opcodes.ASM9, classWriter) {

    private var isInterface = false

    override fun visit(version: Int, access: Int, name: String, signature: String?, superName: String?, interfaces: Array<out String>?) {
        super.visit(version, access, name, signature, superName, interfaces)
        isInterface = (access and Opcodes.ACC_INTERFACE) != 0
    }

    override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        if (isInterface || name == "<clinit>") return mv
        return OpaquePredicateMethodVisitor(mv, tracker, config)
    }
}

private class OpaquePredicateMethodVisitor(
    methodVisitor: MethodVisitor?,
    private val tracker: OpaqueTracker,
    private val config: ControlFlowConfig,
) : MethodVisitor(Opcodes.ASM9, methodVisitor) {

    private var insnCount = 0
    private val random = if (config.seed != null) Random(config.seed!!) else Random()

    override fun visitInsn(opcode: Int) {
        if (insnCount % config.frequency == 0 && insnCount > 0) {
            insertOpaquePredicate()
        }
        insnCount++
        super.visitInsn(opcode)
    }

    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
        if (insnCount % (config.frequency - 2).coerceAtLeast(2) == 0) {
            insertOpaquePredicate()
        }
        insnCount++
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
    }

    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
        if (insnCount % (config.frequency + 2) == 0) {
            insertOpaquePredicate()
        }
        insnCount++
        super.visitFieldInsn(opcode, owner, name, descriptor)
    }

    private fun insertOpaquePredicate() {
        val family = resolveAlgebraicFamily(config.algebraicFamily, random)
        val mode = resolveMode(config.mode, random)

        when (mode) {
            "arithmetic-split" -> insertArithmeticSplitPredicate()
            "arithmetic-chain" -> insertArithmeticChainPredicate()
            "lookup-table" -> insertLookupTablePredicate()
            else -> insertStandardPredicate(family)
        }
        tracker.recordInsertion()
    }

    private fun resolveAlgebraicFamily(family: String, rng: Random): String = when (family) {
        "mixed" -> listOf("quadratic-residue", "bitwise-identity", "modular-arithmetic")[rng.nextInt(3)]
        else -> family
    }

    private fun resolveMode(mode: String, rng: Random): String = when (mode) {
        "mixed" -> listOf("arithmetic-split", "arithmetic-chain", "lookup-table")[rng.nextInt(3)]
        else -> mode
    }

    private fun insertStandardPredicate(family: String) {
        val skipLabel = Label()
        val slot = 200 + random.nextInt(50)
        when (family) {
            "quadratic-residue" -> {
                mv.visitInsn(Opcodes.ICONST_5)
                mv.visitVarInsn(Opcodes.ISTORE, slot)
                mv.visitVarInsn(Opcodes.ILOAD, slot)
                mv.visitVarInsn(Opcodes.ILOAD, slot)
                mv.visitInsn(Opcodes.ICONST_1)
                mv.visitInsn(Opcodes.ISUB)
                mv.visitInsn(Opcodes.IMUL)
                mv.visitInsn(Opcodes.ICONST_2)
                mv.visitInsn(Opcodes.IREM)
                mv.visitJumpInsn(Opcodes.IFEQ, skipLabel)
            }
            "bitwise-identity" -> {
                mv.visitInsn(Opcodes.ICONST_1)
                mv.visitInsn(Opcodes.ICONST_0)
                mv.visitInsn(Opcodes.IOR)
                mv.visitJumpInsn(Opcodes.IFNE, skipLabel)
            }
            "modular-arithmetic" -> {
                mv.visitInsn(Opcodes.ICONST_4)
                mv.visitInsn(Opcodes.ICONST_0)
                mv.visitInsn(Opcodes.IAND)
                mv.visitJumpInsn(Opcodes.IFEQ, skipLabel)
            }
        }
        mv.visitInsn(Opcodes.NOP)
        mv.visitLabel(skipLabel)
    }

    private fun insertArithmeticSplitPredicate() {
        val skipLabel = Label()
        val slot = 200 + random.nextInt(50)
        mv.visitInsn(Opcodes.ICONST_3)
        mv.visitVarInsn(Opcodes.ISTORE, slot)
        mv.visitVarInsn(Opcodes.ILOAD, slot)
        mv.visitVarInsn(Opcodes.ILOAD, slot)
        mv.visitInsn(Opcodes.ISUB)
        mv.visitJumpInsn(Opcodes.IFEQ, skipLabel)
        mv.visitInsn(Opcodes.NOP)
        mv.visitLabel(skipLabel)
    }

    private fun insertArithmeticChainPredicate() {
        val skipLabel = Label()
        val slot = 200 + random.nextInt(50)
        // Chain: ((x + 1) - 1) == x
        mv.visitInsn(Opcodes.ICONST_5)
        mv.visitVarInsn(Opcodes.ISTORE, slot)
        mv.visitVarInsn(Opcodes.ILOAD, slot)
        mv.visitInsn(Opcodes.ICONST_1)
        mv.visitInsn(Opcodes.IADD)
        mv.visitInsn(Opcodes.ICONST_1)
        mv.visitInsn(Opcodes.ISUB)
        mv.visitVarInsn(Opcodes.ILOAD, slot)
        mv.visitJumpInsn(Opcodes.IF_ICMPEQ, skipLabel)
        mv.visitInsn(Opcodes.NOP)
        mv.visitLabel(skipLabel)
    }

    private fun insertLookupTablePredicate() {
        val skipLabel = Label()
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitInsn(Opcodes.IMUL)
        mv.visitJumpInsn(Opcodes.IFEQ, skipLabel)
        mv.visitInsn(Opcodes.NOP)
        mv.visitLabel(skipLabel)
    }
}
