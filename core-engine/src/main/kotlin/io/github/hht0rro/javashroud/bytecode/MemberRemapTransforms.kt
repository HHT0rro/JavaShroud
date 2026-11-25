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
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.AnalyzerException
import org.objectweb.asm.tree.analysis.SourceInterpreter
import org.objectweb.asm.tree.analysis.SourceValue

/**
 * In-artifact per-class declaration facts the method-reference signature
 * fallback needs: the direct supertypes and the (name, descriptor) pairs this
 * class declares. Owners absent from this index (framework classes, external
 * libraries, kept classes excluded from the rename scope) never receive a
 * fallback rename.
 */
class MethodFamilyIndexEntry(
    val superName: String?,
    val interfaceNames: List<String>,
    val ownMethods: Set<Pair<String, String>>,
)

fun remapMethods(
    classBytes: ByteArray,
    methodRenameMap: Map<MemberKey, MemberRename>,
    bridgeMethodKeys: Set<MemberKey> = emptySet(),
    stringRewriteMap: Map<String, Map<String, String>> = emptyMap(),
    nativeMethodKeys: Set<MemberKey> = emptySet(),
    methodFamilies: Map<String, MethodFamilyIndexEntry> = emptyMap(),
): ByteArray = try {
    val classReader = ClassReader(classBytes)
    val classNode = ClassNode()
    classReader.accept(classNode, 0)
    val owner = classNode.name
    val ownerMethodRenames = methodRenameMap.filterKeys { it.owner == owner }
    val bridgeKeysForOwner = bridgeMethodKeys.filter { it.owner == owner }.toSet()
    val nativeKeysForOwner = nativeMethodKeys.filter { it.owner == owner }.toSet()
    val uniqueRenameBySignature = methodRenameMap.entries
        .groupBy { it.key.name to it.key.descriptor }
        .mapValues { (_, entries) -> entries.map { it.value.renamedName }.distinct().singleOrNull() }

    // A signature that any in-artifact declarer keeps under its original name
    // (kept member, native binding, enum owner, protected override family)
    // must never be rewritten at any reference site: resolution could land on
    // the unrenamed declaration.
    val fallbackBlockedSignatures = buildSet {
        for ((familyOwner, entry) in methodFamilies) {
            for ((name, descriptor) in entry.ownMethods) {
                if (MemberKey(familyOwner, name, descriptor) !in methodRenameMap) add(name + descriptor)
            }
        }
    }

    /**
     * Renamed name for a reference whose owner does not itself declare the
     * member, resolved through the in-artifact supertype chain. Mirrors JVM
     * virtual/interface dispatch: the reference may only follow the rename when
     * an in-artifact ancestor declares the signature and the signature was
     * renamed for every in-artifact declarer. References that resolve through
     * external ancestors (framework classes) keep their original name.
     */
    fun inheritedFallbackName(currentOwner: String, name: String, descriptor: String): String? {
        if (methodFamilies.isEmpty() || currentOwner !in methodFamilies) return null
        val signature = name + descriptor
        if (signature in fallbackBlockedSignatures) return null
        val visited = mutableSetOf(currentOwner)
        val pending = ArrayDeque<String>()
        fun enqueue(supertype: String?) {
            if (supertype != null && supertype != "java/lang/Object" && visited.add(supertype)) pending.add(supertype)
        }
        methodFamilies[currentOwner]?.let { entry ->
            enqueue(entry.superName)
            entry.interfaceNames.forEach(::enqueue)
        }
        while (pending.isNotEmpty()) {
            val ancestor = pending.removeFirst()
            val entry = methodFamilies[ancestor] ?: continue
            if ((name to descriptor) in entry.ownMethods) {
                return uniqueRenameBySignature[name to descriptor]
            }
            enqueue(entry.superName)
            entry.interfaceNames.forEach(::enqueue)
        }
        return null
    }

    val remappedBytes = run {
        val remapReader = ClassReader(classBytes)
        val classWriter = ClassWriter(remapReader, 0)
        val remapper = createRemapper(
            mapMethodName = { currentOwner: String, name: String, descriptor: String ->
                methodRenameMap[MemberKey(currentOwner, name, descriptor)]?.renamedName
                    ?: inheritedFallbackName(currentOwner, name, descriptor)
                    ?: name
            },
        )
        val classVisitor = MethodDeclarationAwareRemapper(classWriter, remapper, owner, nativeKeysForOwner, methodRenameMap)
        remapReader.accept(classVisitor, 0)
        classWriter.toByteArray()
    }

    val bridgedBytes = if (bridgeKeysForOwner.isEmpty() && nativeKeysForOwner.isEmpty()) {
        remappedBytes
    } else {
        addMethodRenameBridges(remappedBytes, ownerMethodRenames, bridgeKeysForOwner, nativeKeysForOwner)
    }
    val annotationSyncedBytes = rewriteAnnotationElementNames(bridgedBytes, annotationElementRenameMap(methodRenameMap))
    rewriteReflectionNameStrings(annotationSyncedBytes, methodStringRewriteMap = stringRewriteMap, methodRenames = methodRenameMap)
} catch (_: Exception) {
    classBytes
}

fun remapFields(
    classBytes: ByteArray,
    fieldRenameMap: Map<MemberKey, MemberRename>,
    stringRewriteMap: Map<String, Map<String, String>> = emptyMap(),
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
    fieldStringRewriteMap: Map<String, Map<String, String>> = emptyMap(),
    methodStringRewriteMap: Map<String, Map<String, String>> = emptyMap(),
    methodRenames: Map<MemberKey, MemberRename> = emptyMap(),
): ByteArray {
    if (fieldStringRewriteMap.isEmpty() && methodStringRewriteMap.isEmpty()) return classBytes
    val node = ClassNode()
    ClassReader(classBytes).accept(node, 0)
    var changed = false
    for (method in node.methods) {
        val sources by lazy { ReflectionSources(node.name, method) }
        for ((index, instruction) in method.instructions.toArray().withIndex()) {
            val call = instruction as? MethodInsnNode ?: continue
            if (call.owner != "java/lang/Class") continue
            val methodRewriteMap = methodReflectionRewriteMap(call, methodStringRewriteMap)
            if (methodRewriteMap.isNotEmpty()) {
                val frame = sources.frames?.get(index) ?: continue
                val receiverIndex = frame.stackSize - 3 // receiver, String, Class[]
                if (receiverIndex < 0) continue
                val nameConstant = frame.getStack(receiverIndex + 1).insns.singleOrNull() as? LdcInsnNode ?: continue
                val originalName = nameConstant.cst as? String ?: continue
                val parameters = sources.parameterDescriptor(frame.getStack(receiverIndex + 2))
                val candidate = methodReflectionRename(originalName, parameters, methodRewriteMap) ?: continue
                val receiverSources = frame.getStack(receiverIndex).insns
                val classLiterals = receiverSources.mapNotNull { (it as? LdcInsnNode)?.cst as? Type }
                // A known owner must participate in the actual rename. In particular, an unrelated
                // application method with the same name cannot rename a JDK or Android lookup.
                val renamed = if (classLiterals.isEmpty()) candidate else {
                    val owner = classLiterals.singleOrNull()?.takeIf { receiverSources.size == 1 && it.sort == Type.OBJECT }
                        ?.internalName ?: continue
                    methodRenames.values.asSequence()
                        .filter { it.owner == owner && it.originalName == originalName }
                        .filter { parameters == null || it.descriptor.substringBefore(')') + ")" == parameters }
                        .map { it.renamedName }.distinct().singleOrNull() ?: continue
                }
                if (sources.isDirectName(nameConstant, call)) {
                    nameConstant.cst = renamed
                } else {
                    // A copied or shared literal may still be needed by other calls. Replace only
                    // this operand, preserving the Class[] and the stack shape at every frame.
                    val replacement = InsnList().apply {
                        add(InsnNode(Opcodes.SWAP))
                        add(InsnNode(Opcodes.POP))
                        add(LdcInsnNode(renamed))
                        add(InsnNode(Opcodes.SWAP))
                    }
                    method.instructions.insertBefore(call, replacement)
                }
                changed = true
                continue
            }
            val fieldRewriteMap = fieldReflectionRewriteMap(call, fieldStringRewriteMap)
            if (fieldRewriteMap.isEmpty()) continue
            val nameConstant = reflectionNameConstantInstruction(call, fieldRewriteMap.keys) ?: continue
            val originalName = nameConstant.cst as? String ?: continue
            val renamedName = fieldRewriteMap[originalName] ?: continue
            nameConstant.cst = renamedName
            changed = true
        }
    }
    if (!changed) return classBytes
    // Both the LDC edit and the per-call operand replacement preserve control flow and frame types.
    // Keep the input frames so writing this class does not need its dependencies.
    val writer = ClassWriter(0)
    node.accept(writer)
    return writer.toByteArray()
}

private class ReflectionSources(owner: String, method: MethodNode) {
    private val copiedLiterals = HashSet<AbstractInsnNode>()
    private val originalIndices = method.instructions.toArray().withIndex().associate { it.value to it.index }
    private val interpreter = object : SourceInterpreter(Opcodes.ASM9) {
        override fun copyOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue {
            value.insns.filterTo(copiedLiterals) { it is LdcInsnNode && it.cst is String }
            return value
        }

        override fun unaryOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue =
            if (insn.opcode == Opcodes.CHECKCAST) value else super.unaryOperation(insn, value)
    }
    val frames = try {
        Analyzer(interpreter).analyze(owner, method)
    } catch (_: AnalyzerException) {
        null
    }

    fun parameterDescriptor(array: SourceValue): String? {
        val source = array.insns.singleOrNull() ?: return null
        if (source.opcode == Opcodes.ACONST_NULL) return "()"
        if (source !is TypeInsnNode || source.opcode != Opcodes.ANEWARRAY || source.desc != "java/lang/Class") return null
        val frame = originalIndices[source]?.let { frames?.get(it) } ?: return null
        val size = frame.getStack(frame.stackSize - 1).insns.singleOrNull() ?: return null
        return "()".takeIf { constantArraySize(size) == 0 }
    }

    fun isDirectName(literal: LdcInsnNode, call: MethodInsnNode): Boolean {
        if (literal in copiedLiterals) return false
        var next = literal.next
        while (next != null && next !== call) {
            if (next.type in controlFlowTypes || next.opcode in Opcodes.IRETURN..Opcodes.RETURN || next.opcode == Opcodes.ATHROW) return false
            next = next.next
        }
        return next === call
    }

    private companion object {
        val controlFlowTypes = setOf(AbstractInsnNode.LABEL, AbstractInsnNode.JUMP_INSN, AbstractInsnNode.LOOKUPSWITCH_INSN, AbstractInsnNode.TABLESWITCH_INSN)
    }
}

private fun fieldReflectionRewriteMap(
    call: MethodInsnNode,
    fieldStringRewriteMap: Map<String, Map<String, String>>,
): Map<String, String> = when {
    fieldStringRewriteMap.isNotEmpty() &&
        (call.name == "getField" || call.name == "getDeclaredField") &&
        call.desc == "(Ljava/lang/String;)Ljava/lang/reflect/Field;" ->
        reflectionTargetOwner(call)?.let(fieldStringRewriteMap::get).orEmpty()
    else -> emptyMap()
}

private fun reflectionTargetOwner(call: MethodInsnNode): String? {
    var current = call.previous
    var scanned = 0
    while (current != null && scanned < 48) {
        if (current.opcode >= 0) scanned++
        val type = (current as? LdcInsnNode)?.cst as? Type
        if (type != null && type.sort == Type.OBJECT) return type.internalName
        current = current.previous
    }
    return null
}

private fun methodReflectionRewriteMap(
    call: MethodInsnNode,
    methodStringRewriteMap: Map<String, Map<String, String>>,
): Map<String, Map<String, String>> = when {
    methodStringRewriteMap.isNotEmpty() &&
        (call.name == "getMethod" || call.name == "getDeclaredMethod") &&
        call.desc == "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;" -> methodStringRewriteMap
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
    originalName: String,
    parameterDescriptor: String?,
    rewriteMap: Map<String, Map<String, String>>,
): String? {
    val byParameters = rewriteMap[originalName] ?: return null
    if (parameterDescriptor != null) return byParameters[parameterDescriptor]
    return byParameters.values.distinct().singleOrNull()
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

    val writer = computeFramesWriter(ClassReader(classBytes))
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
    val isInterface = node.access and Opcodes.ACC_INTERFACE != 0
    val invokeOpcode = when {
        isStatic -> Opcodes.INVOKESTATIC
        originalAccess and Opcodes.ACC_PRIVATE != 0 -> Opcodes.INVOKESPECIAL
        isInterface -> Opcodes.INVOKEINTERFACE
        else -> Opcodes.INVOKEVIRTUAL
    }
    method.instructions.add(MethodInsnNode(invokeOpcode, rename.owner, targetName, rename.descriptor, isInterface))
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
    private val methodRenameMap: Map<MemberKey, MemberRename>,
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
        // Declarations are renamed through the exact owner-keyed map only. A
        // signature fallback must never touch a declaration: kept members,
        // native bindings and override-protected methods keep their names even
        // when an unrelated artifact class with the same signature was renamed.
        val mappedName = if (key in nativeMethodKeys) name else methodRenameMap[key]?.renamedName ?: name
        val mappedDescriptor = remapper.mapMethodDesc(descriptor)
        val mappedSignature = remapper.mapSignature(signature, false)
        val mappedExceptions = exceptions?.map { remapper.mapType(it) }?.toTypedArray()
        val methodVisitor = super.visitMethod(access, mappedName, mappedDescriptor, mappedSignature, mappedExceptions)
        return methodVisitor?.let { MethodRemapper(it, remapper) }
    }
}
