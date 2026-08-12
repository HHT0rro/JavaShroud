package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode

private const val INDY_BOOTSTRAP_DESC = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"

/**
 * Wraps class-local resolver members in MutableCallSite linkage. The first execution resolves the
 * literal, installs a constant target, and all later executions bypass the resolver entirely.
 */
fun indirectConstantResolverCalls(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val reader = ClassReader(classBytes)
    val classNode = ClassNode()
    reader.accept(classNode, 0)
    if (classNode.version < Opcodes.V1_7 || !resolverSupportsInjectedMembers(classNode)) return classBytes

    val isInterface = classNode.access and Opcodes.ACC_INTERFACE != 0
    val random = resolverRandom(seed, classNode.name)
    val replacements = mutableListOf<IndyReplacement>()

    for (method in classNode.methods) {
        if (method.name == "<clinit>" || (method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        for (instruction in method.instructions.toArray()) {
            val call = instruction as? MethodInsnNode ?: continue
            val kind = ResolverCallKind.fromDescriptor(call.desc) ?: continue
            if (call.opcode != Opcodes.INVOKESTATIC || call.owner != classNode.name || !isResolverMemberName(call.name)) continue
            replacements += IndyReplacement(method, call, kind, random.nextLong())
        }
    }
    if (replacements.isEmpty()) return classBytes

    val linkers = replacements.map { it.kind }.toSet().associateWith { kind ->
        IndyLinker(
            kind = kind,
            bootstrapName = resolverUniqueMemberName(classNode, "ib${kind.suffix}", random),
            dispatcherName = resolverUniqueMemberName(classNode, "id${kind.suffix}", random),
        )
    }
    for ((method, call, kind, token) in replacements) {
        val linker = linkers.getValue(kind)
        val replacement = InsnList().apply {
            add(LdcInsnNode(token))
            add(
                InvokeDynamicInsnNode(
                    call.name,
                    "(IJ)${kind.returnDescriptor}",
                    Handle(Opcodes.H_INVOKESTATIC, classNode.name, linker.bootstrapName, INDY_BOOTSTRAP_DESC, isInterface),
                    Handle(Opcodes.H_INVOKESTATIC, call.owner, call.name, call.desc, call.itf),
                    Handle(
                        Opcodes.H_INVOKESTATIC,
                        classNode.name,
                        linker.dispatcherName,
                        kind.dispatcherDescriptor,
                        isInterface,
                    ),
                ),
            )
        }
        method.instructions.insertBefore(call, replacement)
        method.instructions.remove(call)
    }
    for (linker in linkers.values) {
        classNode.methods.add(createFirstResolveDispatcher(isInterface, linker.dispatcherName, linker.kind))
        classNode.methods.add(createFirstResolveBootstrap(isInterface, linker.bootstrapName))
    }

    val writer = computeFramesWriter()
    classNode.accept(writer)
    return writer.toByteArray()
}

private data class IndyReplacement(
    val method: MethodNode,
    val call: MethodInsnNode,
    val kind: ResolverCallKind,
    val token: Long,
)

private data class IndyLinker(
    val kind: ResolverCallKind,
    val bootstrapName: String,
    val dispatcherName: String,
)

private enum class ResolverCallKind(
    val resolverDescriptor: String,
    val returnDescriptor: String,
    val returnType: Type,
    val suffix: String,
) {
    STRING("(I)Ljava/lang/String;", "Ljava/lang/String;", Type.getType("Ljava/lang/String;"), "s"),
    INT("(I)I", "I", Type.INT_TYPE, "i"),
    LONG("(I)J", "J", Type.LONG_TYPE, "j"),
    ;

    val dispatcherDescriptor: String
        get() = "(Ljava/lang/invoke/MutableCallSite;Ljava/lang/invoke/MethodHandle;IJ)$returnDescriptor"

    companion object {
        fun fromDescriptor(descriptor: String): ResolverCallKind? = values().firstOrNull { it.resolverDescriptor == descriptor }
    }
}

private fun createFirstResolveBootstrap(isInterface: Boolean, name: String): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, INDY_BOOTSTRAP_DESC, null, null)
    method.visitCode()
    method.visitTypeInsn(Opcodes.NEW, "java/lang/invoke/MutableCallSite")
    method.visitInsn(Opcodes.DUP)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/invoke/MutableCallSite", "<init>", "(Ljava/lang/invoke/MethodType;)V", false)
    method.visitVarInsn(Opcodes.ASTORE, 5)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "bindTo", "(Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;", false)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "bindTo", "(Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;", false)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "asType", "(Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false)
    method.visitVarInsn(Opcodes.ASTORE, 6)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitVarInsn(Opcodes.ALOAD, 6)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MutableCallSite", "setTarget", "(Ljava/lang/invoke/MethodHandle;)V", false)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitInsn(Opcodes.ARETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun createFirstResolveDispatcher(isInterface: Boolean, name: String, kind: ResolverCallKind): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, kind.dispatcherDescriptor, null, null)
    val valueSlot = 5
    val handleSlot = if (kind == ResolverCallKind.LONG) 7 else 6
    method.visitCode()
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitVarInsn(Opcodes.ILOAD, 2)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "invokeExact", "(I)${kind.returnDescriptor}", false)
    when (kind) {
        ResolverCallKind.STRING -> method.visitVarInsn(Opcodes.ASTORE, valueSlot)
        ResolverCallKind.INT -> method.visitVarInsn(Opcodes.ISTORE, valueSlot)
        ResolverCallKind.LONG -> method.visitVarInsn(Opcodes.LSTORE, valueSlot)
    }

    when (kind) {
        ResolverCallKind.STRING -> {
            method.visitLdcInsn(kind.returnType)
            method.visitVarInsn(Opcodes.ALOAD, valueSlot)
        }
        ResolverCallKind.INT -> {
            method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;")
            method.visitVarInsn(Opcodes.ILOAD, valueSlot)
            method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
        }
        ResolverCallKind.LONG -> {
            method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Long", "TYPE", "Ljava/lang/Class;")
            method.visitVarInsn(Opcodes.LLOAD, valueSlot)
            method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
        }
    }
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/lang/invoke/MethodHandles",
        "constant",
        "(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;",
        false,
    )
    method.visitVarInsn(Opcodes.ASTORE, handleSlot)
    method.visitVarInsn(Opcodes.ALOAD, handleSlot)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ALOAD, 0)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MutableCallSite", "type", "()Ljava/lang/invoke/MethodType;", false)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodType", "parameterList", "()Ljava/util/List;", false)
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/lang/invoke/MethodHandles",
        "dropArguments",
        "(Ljava/lang/invoke/MethodHandle;ILjava/util/List;)Ljava/lang/invoke/MethodHandle;",
        false,
    )
    method.visitVarInsn(Opcodes.ASTORE, handleSlot)
    method.visitVarInsn(Opcodes.ALOAD, 0)
    method.visitVarInsn(Opcodes.ALOAD, handleSlot)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MutableCallSite", "setTarget", "(Ljava/lang/invoke/MethodHandle;)V", false)
    method.visitInsn(Opcodes.ICONST_1)
    method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/invoke/MutableCallSite")
    method.visitInsn(Opcodes.DUP)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ALOAD, 0)
    method.visitInsn(Opcodes.AASTORE)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/invoke/MutableCallSite", "syncAll", "([Ljava/lang/invoke/MutableCallSite;)V", false)
    when (kind) {
        ResolverCallKind.STRING -> {
            method.visitVarInsn(Opcodes.ALOAD, valueSlot)
            method.visitInsn(Opcodes.ARETURN)
        }
        ResolverCallKind.INT -> {
            method.visitVarInsn(Opcodes.ILOAD, valueSlot)
            method.visitInsn(Opcodes.IRETURN)
        }
        ResolverCallKind.LONG -> {
            method.visitVarInsn(Opcodes.LLOAD, valueSlot)
            method.visitInsn(Opcodes.LRETURN)
        }
    }
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}
