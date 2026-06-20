package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode

/**
 * ConstantDynamic constant indirection transform.
 *
 * Replaces LDC string and integer constant instructions with LDC of
 * CONSTANT_Dynamic entries that resolve at runtime through bootstrap
 * methods. Decompilers that lack full CONSTANT_Dynamic support
 * (class file version 55+, JVMS 4.4.10) will crash, produce
 * uncompilable output, or silently drop the constant semantics.
 *
 * Attack model: static decompilation (CFR < 160, Procyon, FernFlower,
 * JADX < 1.5.0 all have limited or broken condy support).
 *
 * Each class gets at most two bootstrap methods (one for String condys,
 * one for int condys), each receiving the original constant as an extra
 * bootstrap argument per JVMS 5.4.3.6.
 */
fun applyCondyConstantIndirection(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if (classNode.version < Opcodes.V11) return classBytes
    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    var hasStringCondy = false
    var hasIntCondy = false

    for (method in classNode.methods) {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        val insns = method.instructions ?: continue

        for (insn in insns.toArray()) {
            if (insn is LdcInsnNode) {
                when (insn.cst) {
                    is String -> hasStringCondy = true
                    is Int -> hasIntCondy = true
                }
            }
        }
    }

    if (!hasStringCondy && !hasIntCondy) return classBytes

    val bsmDesc = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"

    if (hasStringCondy) {
        val bsmMethod = MethodNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "\$_c_str",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;",
            null, null,
        )
        bsmMethod.instructions.add(VarInsnNode(Opcodes.ALOAD, 3))
        bsmMethod.instructions.add(InsnNode(Opcodes.ARETURN))
        classNode.methods.add(bsmMethod)
    }

    if (hasIntCondy) {
        val bsmMethod = MethodNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "\$_c_int",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;I)Ljava/lang/Object;",
            null, null,
        )
        bsmMethod.instructions.add(VarInsnNode(Opcodes.ILOAD, 3))
        bsmMethod.instructions.add(MethodInsnNode(
            Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;",
            false,
        ))
        bsmMethod.instructions.add(InsnNode(Opcodes.ARETURN))
        classNode.methods.add(bsmMethod)
    }

    val strBsmHandle = Handle(
        Opcodes.H_INVOKESTATIC, classNode.name, "\$_c_str",
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;",
        false,
    )
    val intBsmHandle = Handle(
        Opcodes.H_INVOKESTATIC, classNode.name, "\$_c_int",
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;I)Ljava/lang/Object;",
        false,
    )

    for (method in classNode.methods) {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        val insns = method.instructions ?: continue

        for (insn in insns.toArray()) {
            if (insn !is LdcInsnNode) continue
            when (val cst = insn.cst) {
                is String -> {
                    val condy = ConstantDynamic("c", "Ljava/lang/String;", strBsmHandle, cst)
                    insns.set(insn, LdcInsnNode(condy))
                }
                is Int -> {
                    val condy = ConstantDynamic("c", "I", intBsmHandle, cst)
                    insns.set(insn, LdcInsnNode(condy))
                }
            }
        }
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}
