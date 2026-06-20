package io.github.hht0rro.javashroud.bytecode

import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.naming.MemberRename
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.MethodRemapper
import org.objectweb.asm.commons.Remapper
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.AnnotationNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode

fun remapMethods(
    classBytes: ByteArray,
    methodRenameMap: Map<MemberKey, MemberRename>,
    bridgeMethodKeys: Set<MemberKey> = emptySet(),
    stringRewriteMap: Map<String, Map<String, String>> = emptyMap(),
    nativeMethodKeys: Set<MemberKey> = emptySet(),
): ByteArray = try {
    val classReader = ClassReader(classBytes)
    val classNode = ClassNode()
    classReader.accept(classNode, 0)
    val owner = classNode.name
    val ownerMethodRenames = methodRenameMap.filterKeys { it.owner == owner }
    val bridgeKeysForOwner = bridgeMethodKeys.filter { it.owner == owner }.toSet()
    val nativeKeysForOwner = nativeMethodKeys.filter { it.owner == owner }.toSet()
 val platformMethodOwners = setOf("java/", "javax/", "jdk/", "sun/", "com/sun/", "kotlin/") 
 fun isPlatformMethodOwner(owner: String): Boolean = platformMethodOwners.any { owner.startsWith(it) } 
    val uniqueRenameBySignature = methodRenameMap.entries
        .groupBy { it.key.name to it.key.descriptor }
        .mapValues { (_, entries) -> entries.map { it.value.renamedName }.distinct().singleOrNull() }

    val remappedBytes = run {
        val remapReader = ClassReader(classBytes)
        val classWriter = ClassWriter(remapReader, 0)
        val remapper = createRemapper(
            mapMethodName = { currentOwner: String, name: String, descriptor: String ->
                methodRenameMap[MemberKey(currentOwner, name, descriptor)]?.renamedName
 ?: if (isPlatformMethodOwner(currentOwner)) name else uniqueRenameBySignature[name to descriptor] 
                    ?: name
            },
        )
        val classVisitor = MethodDeclarationAwareRemapper(classWriter, remapper, owner, nativeKeysForOwner)
        remapReader.accept(classVisitor, 0)
        classWriter.toByteArray()
    }

    val bridgedBytes = if (bridgeKeysForOwner.isEmpty() && nativeKeysForOwner.isEmpty()) {
        remappedBytes
    } else {
        addMethodRenameBridges(remappedBytes, ownerMethodRenames, bridgeKeysForOwner, nativeKeysForOwner)
    }
    val annotationSyncedBytes = rewriteAnnotationElementNames(bridgedBytes, annotationElementRenameMap(methodRenameMap))
    rewriteReflectionNameStrings(annotationSyncedBytes, methodStringRewriteMap = stringRewriteMap)
} catch (_: Exception) {
    classBytes
}

fun remapFields(
    classBytes: ByteArray,
    fieldRenameMap: Map<MemberKey, MemberRename>,
    stringRewriteMap: Map<String, String> = emptyMap(),
): ByteArray = try {
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(classReader, 0)
    val classVisitor = ClassRemapper(classWriter, createRemapper(
        mapFieldName = { owner: String, name: String, descriptor: String ->
            fieldRenameMap[MemberKey(owner, name, descriptor)]?.renamedName ?: name
        },
    ))
    classReader.accept(classVisitor, 0)
    rewriteReflectionNameStrings(classWriter.toByteArray(), fieldStringRewriteMap = stringRewriteMap)
} catch (_: Exception) {
    classBytes
}

private fun annotationElementRenameMap(methodRenameMap: Map<MemberKey, MemberRename>): Map<String, Map<String, String>> {
    if (methodRenameMap.isEmpty()) return emptyMap()
    return methodRenameMap.values
        .filter { rename -> rename.descriptor.startsWith("()") }
        .groupBy { rename -> "L${rename.owner};" }
        .mapValues { (_, renames) -> renames.associate { rename -> rename.originalName to rename.renamedName } }
        .filterValues { it.isNotEmpty() }
}

private fun rewriteAnnotationElementNames(
    classBytes: ByteArray,
    annotationElementRenameMap: Map<String, Map<String, String>>,
): ByteArray {
    if (annotationElementRenameMap.isEmpty()) return classBytes
    val node = ClassNode()
    ClassReader(classBytes).accept(node, 0)
    var changed = rewriteAnnotationLists(node.visibleAnnotations, node.invisibleAnnotations, node.visibleTypeAnnotations, node.invisibleTypeAnnotations, renameMap = annotationElementRenameMap)
    for (field in node.fields) {
        changed = rewriteAnnotationLists(field.visibleAnnotations, field.invisibleAnnotations, field.visibleTypeAnnotations, field.invisibleTypeAnnotations, renameMap = annotationElementRenameMap) || changed
    }
    for (method in node.methods) {
        changed = rewriteAnnotationLists(method.visibleAnnotations, method.invisibleAnnotations, method.visibleTypeAnnotations, method.invisibleTypeAnnotations, renameMap = annotationElementRenameMap) || changed
        changed = rewriteParameterAnnotations(method.visibleParameterAnnotations, annotationElementRenameMap) || changed
        changed = rewriteParameterAnnotations(method.invisibleParameterAnnotations, annotationElementRenameMap) || changed
        changed = rewriteAnnotationList(method.visibleLocalVariableAnnotations, annotationElementRenameMap) || changed
        changed = rewriteAnnotationList(method.invisibleLocalVariableAnnotations, annotationElementRenameMap) || changed
        for (tryCatchBlock in method.tryCatchBlocks.orEmpty()) {
            changed = rewriteAnnotationLists(tryCatchBlock.visibleTypeAnnotations, tryCatchBlock.invisibleTypeAnnotations, renameMap = annotationElementRenameMap) || changed
        }
        changed = rewriteAnnotationValue(method.annotationDefault, annotationElementRenameMap).changed || changed
    }
    if (!changed) return classBytes
    val writer = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
    node.accept(writer)
    return writer.toByteArray()
}

private fun rewriteAnnotationLists(vararg lists: List<AnnotationNode>?, renameMap: Map<String, Map<String, String>>): Boolean {
    var changed = false
    for (list in lists) changed = rewriteAnnotationList(list, renameMap) || changed
    return changed
}

private fun rewriteParameterAnnotations(parameterAnnotations: Array<List<AnnotationNode>>?, renameMap: Map<String, Map<String, String>>): Boolean {
    var changed = false
    for (list in parameterAnnotations.orEmpty()) changed = rewriteAnnotationList(list, renameMap) || changed
    return changed
}

private fun rewriteAnnotationList(annotations: List<AnnotationNode>?, renameMap: Map<String, Map<String, String>>): Boolean {
    var changed = false
    for (annotation in annotations.orEmpty()) changed = rewriteAnnotationNode(annotation, renameMap) || changed
    return changed
}

private data class AnnotationValueRewrite(val value: Any?, val changed: Boolean)

private fun rewriteAnnotationNode(annotation: AnnotationNode, renameMap: Map<String, Map<String, String>>): Boolean {
    var changed = false
    val elementRenames = renameMap[annotation.desc].orEmpty()
    val values = annotation.values ?: return false
    var index = 0
    while (index + 1 < values.size) {
        val name = values[index] as? String
        val renamed = if (name == null) null else elementRenames[name]
        if (renamed != null) {
            values[index] = renamed
            changed = true
        }
        val rewrittenValue = rewriteAnnotationValue(values[index + 1], renameMap)
        if (rewrittenValue.changed) {
            values[index + 1] = rewrittenValue.value
            changed = true
        }
        index += 2
    }
    return changed
}

private fun rewriteAnnotationValue(value: Any?, renameMap: Map<String, Map<String, String>>): AnnotationValueRewrite {
    return when (value) {
        is AnnotationNode -> AnnotationValueRewrite(value, rewriteAnnotationNode(value, renameMap))
        is List<*> -> {
            var changed = false
            val rewritten = value.map { item ->
                val result = rewriteAnnotationValue(item, renameMap)
                changed = result.changed || changed
                result.value
            }
            AnnotationValueRewrite(if (changed) rewritten else value, changed)
        }
        else -> AnnotationValueRewrite(value, false)
    }
}

private fun rewriteReflectionNameStrings(
    classBytes: ByteArray,
    fieldStringRewriteMap: Map<String, String> = emptyMap(),
    methodStringRewriteMap: Map<String, Map<String, String>> = emptyMap(),
): ByteArray {
    if (fieldStringRewriteMap.isEmpty() && methodStringRewriteMap.isEmpty()) return classBytes
    val node = ClassNode()
    ClassReader(classBytes).accept(node, 0)
    var changed = false
    for (method in node.methods) {
        for (instruction in method.instructions) {
            val call = instruction as? MethodInsnNode ?: continue
            if (call.owner != "java/lang/Class") continue
            val fieldRewriteMap = fieldReflectionRewriteMap(call, fieldStringRewriteMap)
            val methodRewriteMap = methodReflectionRewriteMap(call, methodStringRewriteMap)
            val rewriteNames = fieldRewriteMap.keys + methodRewriteMap.keys
            if (rewriteNames.isEmpty()) continue
            val nameConstant = reflectionNameConstantInstruction(call, rewriteNames) ?: continue
            val originalName = nameConstant.cst as? String ?: continue
            val renamedName = when {
                methodRewriteMap.isNotEmpty() -> methodReflectionRename(call, originalName, methodRewriteMap)
                fieldRewriteMap.isNotEmpty() -> fieldRewriteMap[originalName]
                else -> null
            } ?: continue
            nameConstant.cst = renamedName
            changed = true
        }
    }
    if (!changed) return classBytes
    val writer = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
    node.accept(writer)
    return writer.toByteArray()
}

private fun fieldReflectionRewriteMap(
    call: MethodInsnNode,
    fieldStringRewriteMap: Map<String, String>,
): Map<String, String> = when {
    fieldStringRewriteMap.isNotEmpty() &&
        (call.name == "getField" || call.name == "getDeclaredField") &&
        call.desc == "(Ljava/lang/String;)Ljava/lang/reflect/Field;" -> fieldStringRewriteMap
    else -> emptyMap()
}

private fun methodReflectionRewriteMap(
    call: MethodInsnNode,
    methodStringRewriteMap: Map<String, Map<String, String>>,
): Map<String, Map<String, String>> = when {
    methodStringRewriteMap.isNotEmpty() &&
        (call.name == "getMethod" || call.name == "getDeclaredMethod") &&
        call.desc.startsWith("(Ljava/lang/String;") -> methodStringRewriteMap
    else -> emptyMap()
}

private fun reflectionNameConstantInstruction(call: MethodInsnNode, rewriteNames: Set<String>): LdcInsnNode? {
    val immediate = previousMeaningfulInstruction(call) as? LdcInsnNode
    if ((immediate?.cst as? String) in rewriteNames) return immediate
    var current = call.previous
    var scanned = 0
    while (current != null && scanned < 48) {
        if (current.opcode >= 0) scanned++
        val ldc = current as? LdcInsnNode
        val value = ldc?.cst as? String
        if (value != null && value in rewriteNames) return ldc
        current = current.previous
    }
    return null
}

private fun methodReflectionRename(
    call: MethodInsnNode,
    originalName: String,
    rewriteMap: Map<String, Map<String, String>>,
): String? {
    val byParameters = rewriteMap[originalName] ?: return null
    val parameterDescriptor = methodReflectionParameterDescriptor(call)
    if (parameterDescriptor != null) return byParameters[parameterDescriptor]
    return byParameters.values.distinct().singleOrNull()
}

private fun methodReflectionParameterDescriptor(call: MethodInsnNode): String? {
    if (call.desc == "(Ljava/lang/String;)Ljava/lang/reflect/Method;") return "()"
    if (!call.desc.startsWith("(Ljava/lang/String;[Ljava/lang/Class;)")) return null
    if (previousMeaningfulInstruction(call)?.opcode == Opcodes.ACONST_NULL) return "()"
    val arrayAllocation = findClassArrayAllocationBefore(call) ?: return null
    return when (constantArraySize(arrayAllocation)) {
        0 -> "()"
        else -> null
    }
}

private fun findClassArrayAllocationBefore(call: MethodInsnNode): AbstractInsnNode? {
    var current = call.previous
    var scanned = 0
    while (current != null && scanned < 16) {
        if (current.opcode >= 0) scanned++
        if (current is TypeInsnNode && current.opcode == Opcodes.ANEWARRAY && current.desc == "java/lang/Class") {
            return previousMeaningfulInstruction(current)
        }
        current = current.previous
    }
    return null
}

private fun constantArraySize(instruction: AbstractInsnNode): Int? = when (instruction.opcode) {
    Opcodes.ICONST_0 -> 0
    Opcodes.ICONST_1 -> 1
    Opcodes.ICONST_2 -> 2
    Opcodes.ICONST_3 -> 3
    Opcodes.ICONST_4 -> 4
    Opcodes.ICONST_5 -> 5
    Opcodes.BIPUSH, Opcodes.SIPUSH -> (instruction as? IntInsnNode)?.operand
    else -> null
}

private fun previousMeaningfulInstruction(instruction: AbstractInsnNode): AbstractInsnNode? {
    var current = instruction.previous
    while (current != null && current.opcode < 0) {
        current = current.previous
    }
    return current
}

private fun addMethodRenameBridges(
    classBytes: ByteArray,
    ownerMethodRenames: Map<MemberKey, MemberRename>,
    bridgeKeysForOwner: Set<MemberKey>,
    nativeKeysForOwner: Set<MemberKey>,
): ByteArray {
    val node = ClassNode()
    ClassReader(classBytes).accept(node, 0)
    val existing = node.methods.map { MemberKey(node.name, it.name, it.desc) }.toMutableSet()
    val abiBridges = bridgeKeysForOwner
        .mapNotNull { key -> ownerMethodRenames[key]?.takeIf { MemberKey(key.owner, it.renamedName, key.descriptor) in existing } }
    val nativeWrappers = nativeKeysForOwner
        .mapNotNull { key -> ownerMethodRenames[key]?.takeIf { MemberKey(key.owner, it.originalName, key.descriptor) in existing } }
    if (abiBridges.isEmpty() && nativeWrappers.isEmpty()) return classBytes

    for (rename in abiBridges) {
        val bridgeKey = MemberKey(rename.owner, rename.originalName, rename.descriptor)
        if (!existing.add(bridgeKey)) continue
        node.methods.add(buildBridgeMethod(node, rename, rename.originalName, rename.renamedName))
    }
    for (rename in nativeWrappers) {
        val wrapperKey = MemberKey(rename.owner, rename.renamedName, rename.descriptor)
        if (!existing.add(wrapperKey)) continue
        node.methods.add(buildBridgeMethod(node, rename, rename.renamedName, rename.originalName))
    }

    val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
    node.accept(writer)
    return writer.toByteArray()
}

private fun buildBridgeMethod(node: ClassNode, rename: MemberRename, bridgeName: String, targetName: String): MethodNode {
    val target = node.methods.firstOrNull { it.name == targetName && it.desc == rename.descriptor }
    val originalAccess = target?.access ?: Opcodes.ACC_PUBLIC
    val access = (originalAccess and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PROTECTED or Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNCHRONIZED or Opcodes.ACC_STRICT)) or Opcodes.ACC_SYNTHETIC or Opcodes.ACC_BRIDGE
    val method = MethodNode(Opcodes.ASM9, access, bridgeName, rename.descriptor, target?.signature, target?.exceptions?.toTypedArray())
    val isStatic = access and Opcodes.ACC_STATIC != 0
    var localIndex = 0
    if (!isStatic) {
        method.instructions.add(VarInsnNode(Opcodes.ALOAD, 0))
        localIndex = 1
    }
    for (argumentType in Type.getArgumentTypes(rename.descriptor)) {
        method.instructions.add(VarInsnNode(argumentType.getOpcode(Opcodes.ILOAD), localIndex))
        localIndex += argumentType.size
    }
    val invokeOpcode = when {
        isStatic -> Opcodes.INVOKESTATIC
        originalAccess and Opcodes.ACC_PRIVATE != 0 -> Opcodes.INVOKESPECIAL
        else -> Opcodes.INVOKEVIRTUAL
    }
    method.instructions.add(MethodInsnNode(invokeOpcode, rename.owner, targetName, rename.descriptor, false))
    method.instructions.add(InsnNode(Type.getReturnType(rename.descriptor).getOpcode(Opcodes.IRETURN)))
    method.maxLocals = localIndex
    method.maxStack = 0
    return method
}


private class MethodDeclarationAwareRemapper(
    classVisitor: ClassVisitor,
    private val remapper: Remapper,
    private val owner: String,
    private val nativeMethodKeys: Set<MemberKey>,
) : ClassVisitor(Opcodes.ASM9, classVisitor) {
    override fun visitMethod(
        access: Int,
        name: String?,
        descriptor: String?,
        signature: String?,
        exceptions: Array<out String>?,
    ): MethodVisitor? {
        if (name == null || descriptor == null) {
            return super.visitMethod(access, name, descriptor, signature, exceptions)
        }
        val key = MemberKey(owner, name, descriptor)
        val mappedName = if (key in nativeMethodKeys) name else remapper.mapMethodName(owner, name, descriptor)
        val mappedDescriptor = remapper.mapMethodDesc(descriptor)
        val mappedSignature = remapper.mapSignature(signature, false)
        val mappedExceptions = exceptions?.map { remapper.mapType(it) }?.toTypedArray()
        val methodVisitor = super.visitMethod(access, mappedName, mappedDescriptor, mappedSignature, mappedExceptions)
        return methodVisitor?.let { MethodRemapper(it, remapper) }
    }
}
