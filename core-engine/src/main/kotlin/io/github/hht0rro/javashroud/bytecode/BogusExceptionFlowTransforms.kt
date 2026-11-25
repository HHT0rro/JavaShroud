package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * Bogus exception flow transform with configurable density and handler complexity.
 *
 * Emits dead helper calls in target methods while keeping the actual try-catch
 * inside synthetic helper methods. This preserves the fake exception edges for
 * decompilers without forcing ASM to merge extra handler frames into arbitrary
 * existing method bodies.
 */
fun insertBogusExceptionFlow(
    classBytes: ByteArray,
    config: ControlFlowConfig = ControlFlowConfig(),
): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    val rng = if (config.seed != null) Random(config.seed!!) else Random()
    var changed = false
    var helperSequence = 0
    val originalMethods = classNode.methods.toList()

    if (
        config.handlerComplexity == "field-write" &&
            classNode.fields.none { it.name == "__js_bogus_state" && it.desc == "I" }
    ) {
        classNode.fields.add(
            FieldNode(
                Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
                "__js_bogus_state", "I", null, 0,
            )
        )
    }

    for (method in originalMethods) {
        if (method.name == "<clinit>" || method.name == "<init>") continue
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE or Opcodes.ACC_SYNTHETIC)) != 0) continue
        val insns = method.instructions ?: continue
        val realInsns = insns.toArray().filter { it.opcode != -1 }
        if (realInsns.size < 4) continue
        val insertionPoint = realInsns.first()

        val handlerCount = config.density.coerceIn(1, 10)
        repeat(handlerCount) {
            val helperName = buildBogusHelperName(helperSequence++, rng)
            val handlerHelperName = if (config.handlerComplexity == "method-call") {
                buildBogusHelperName(helperSequence++, rng)
            } else {
                null
            }

            if (handlerHelperName != null) {
                classNode.methods.add(buildBogusHandlerBodyHelper(handlerHelperName))
            }
            classNode.methods.add(
                buildBogusExceptionHelper(
                    className = classNode.name,
                    helperName = helperName,
                    handlerComplexity = config.handlerComplexity,
                    handlerHelperName = handlerHelperName,
                )
            )

            val skipLabel = LabelNode()
            val deadCallBlock = InsnList().apply {
                add(InsnNode(Opcodes.ICONST_0))
                add(JumpInsnNode(Opcodes.IFEQ, skipLabel))
                add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, helperName, "()V", false))
                add(skipLabel)
            }
            insns.insertBefore(insertionPoint, deadCallBlock)
            changed = true
        }
    }

    if (!changed) {
        return classBytes
    }

    return try {
        val writer = computeFramesWriter(reader)
        classNode.accept(writer)
        writer.toByteArray()
    } catch (_: Exception) {
        // ASM COMPUTE_FRAMES can fail (NegativeArraySizeException) on certain
        // bytecode patterns after bogus exception flow insertion. Fall back to
        // the original bytes rather than crashing the entire obfuscation run.
        classBytes
    }
}

private fun buildBogusHandlerBodyHelper(helperName: String): MethodNode = MethodNode(
    Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
    helperName, "()V", null, null,
).apply {
    instructions = InsnList().apply {
        add(InsnNode(Opcodes.NOP))
        add(InsnNode(Opcodes.RETURN))
    }
    maxLocals = 0
    maxStack = 0
}

private fun buildBogusExceptionHelper(
    className: String,
    helperName: String,
    handlerComplexity: String,
    handlerHelperName: String?,
): MethodNode {
    val helper = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        helperName, "()V", null, null,
    )
    val tryStart = LabelNode()
    val tryEnd = LabelNode()
    val handlerEntry = LabelNode()
    val helperInsns = InsnList()
    helperInsns.add(tryStart)
    helperInsns.add(TypeInsnNode(Opcodes.NEW, "java/lang/NullPointerException"))
    helperInsns.add(InsnNode(Opcodes.DUP))
    helperInsns.add(MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/NullPointerException", "<init>", "()V", false))
    helperInsns.add(InsnNode(Opcodes.ATHROW))
    helperInsns.add(tryEnd)
    helperInsns.add(handlerEntry)
    helperInsns.add(VarInsnNode(Opcodes.ASTORE, 0))
    when (handlerComplexity) {
        "field-write" -> {
            helperInsns.add(InsnNode(Opcodes.ICONST_0))
            helperInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, className, "__js_bogus_state", "I"))
        }
        "method-call" -> {
            if (handlerHelperName != null) {
                helperInsns.add(MethodInsnNode(Opcodes.INVOKESTATIC, className, handlerHelperName, "()V", false))
            }
        }
        else -> helperInsns.add(InsnNode(Opcodes.NOP))
    }
    helperInsns.add(VarInsnNode(Opcodes.ALOAD, 0))
    helperInsns.add(InsnNode(Opcodes.ATHROW))

    helper.instructions = helperInsns
    helper.tryCatchBlocks = mutableListOf(
        TryCatchBlockNode(tryStart, tryEnd, handlerEntry, "java/lang/NullPointerException")
    )
    helper.maxLocals = 1
    helper.maxStack = 2
    return helper
}

private fun buildBogusHelperName(sequence: Int, rng: Random): String {
    val mixed = rng.nextLong() xor (sequence.toLong() * -7046029254386353131L)
    return "m_" + java.lang.Long.toUnsignedString(mixed, 36)
}
