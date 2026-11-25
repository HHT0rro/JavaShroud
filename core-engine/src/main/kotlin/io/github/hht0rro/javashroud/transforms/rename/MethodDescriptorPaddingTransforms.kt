package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.bytecode.isResolverMemberName
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.transforms.reflectionSurfaceSensitiveClassNames
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IincInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.logging.Logger

private val methodDescriptorPaddingLogger = Logger.getLogger("io.github.hht0rro.javashroud.transforms.rename.MethodDescriptorPadding")

/**
 * Descriptor padding and parameter packing for the rename-methods pass.
 *
 * The pass deliberately limits itself to in-artifact static direct calls. This
 * keeps descriptor changes out of virtual, reflective, JNI, and bootstrap
 * boundaries while still covering the in-artifact direct-call shape.
 * Unsupported candidates remain unchanged.
 */
internal data class MethodDescriptorPaddingResult(
    val artifact: BytecodeArtifact,
    val descriptors: Map<MemberKey, String>,
    val transformedMemberCount: Int,
)

internal fun applyMethodDescriptorPadding(
    artifact: BytecodeArtifact,
    matchedMembers: List<MatchedMember>,
    params: Map<String, Any>,
): MethodDescriptorPaddingResult {
    val paddingMode = (params["descriptorPadding"] as? String) ?: "off"
    val packingMode = (params["parameterPacking"] as? String) ?: "off"
    require(paddingMode in DESCRIPTOR_PADDING_MODES) {
        "rename-methods descriptorPadding '$paddingMode' is not supported; supported values: ${DESCRIPTOR_PADDING_MODES.joinToString(", ")}"
    }
    require(packingMode in PARAMETER_PACKING_MODES) {
        "rename-methods parameterPacking '$packingMode' is not supported; supported values: ${PARAMETER_PACKING_MODES.joinToString(", ")}"
    }
    if (paddingMode == "off" && packingMode == "off") {
        return MethodDescriptorPaddingResult(artifact, emptyMap(), 0)
    }

    val nodes = artifact.classArtifacts.associate { classArtifact ->
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, 0)
        classArtifact.summary.internalName to node
    }
    val selected = matchedMembers
        .map { MemberKey(it.owner, it.name, it.descriptor) }
        .toSet()
    val unsupportedHandleTargets = collectHandleTargets(nodes.values)
    val reflectionSensitiveOwners = reflectionSurfaceSensitiveClassNames(artifact)
    val reflectionSensitiveTargets = collectReflectionSensitiveMethodTargets(nodes.values)
    val entryPoints = artifact.classArtifacts
        .flatMap { classArtifact ->
            classArtifact.summary.methodSummaries
                .filter { it.name == "main" && it.descriptor == "([Ljava/lang/String;)V" }
                .map { MemberKey(classArtifact.summary.internalName, it.name, it.descriptor) }
        }
        .toSet()

    val skipped = linkedMapOf<String, Int>()
    fun skip(reason: String) {
        skipped[reason] = (skipped[reason] ?: 0) + 1
    }

    val rawPlans = linkedMapOf<MemberKey, MethodPaddingPlan>()
    for ((owner, node) in nodes) {
        for (method in node.methods) {
            val key = MemberKey(owner, method.name, method.desc)
            if (key !in selected) continue
            val skipReason = when {
                isResolverMemberName(method.name) -> "generated resolver ABI"
                key in entryPoints -> "entry point"
                key in unsupportedHandleTargets -> "MethodHandle or condy bootstrap target"
                key in reflectionSensitiveTargets -> "reflection target"
                owner in reflectionSensitiveOwners -> "reflection-sensitive owner"
                !isEligibleStaticTarget(method) -> "not a private static direct-call target"
                else -> null
            }
            if (skipReason != null) {
                skip(skipReason)
                continue
            }
            val arguments = Type.getArgumentTypes(method.desc)
            val contextType = contextTypeFor(paddingMode, key, params["seed"])
            val expandedDescriptor = if (contextType == null) {
                method.desc
            } else {
                Type.getMethodDescriptor(Type.getReturnType(method.desc), *(arguments + contextType))
            }
            val finalDescriptor = if (packingMode == "object-array") {
                Type.getMethodDescriptor(Type.getReturnType(method.desc), Type.getType("[Ljava/lang/Object;"))
            } else {
                expandedDescriptor
            }
            if (finalDescriptor == method.desc) continue
            rawPlans[key] = MethodPaddingPlan(
                key = key,
                originalArgumentTypes = arguments,
                expandedArgumentTypes = if (contextType == null) arguments else arguments + contextType,
                finalDescriptor = finalDescriptor,
                contextType = contextType,
                contextValue = contextValueFor(key, contextType, params["seed"]),
                objectArray = packingMode == "object-array",
            )
        }
    }
    val plans = retainNonCollidingPlans(nodes, rawPlans)
    if (skipped.isNotEmpty()) {
        methodDescriptorPaddingLogger.warning(
            "Method descriptor padding skipped ${skipped.values.sum()} selected methods: " +
                skipped.entries.joinToString { (reason, count) -> "$reason=$count" },
        )
    }
    if (plans.isEmpty()) return MethodDescriptorPaddingResult(artifact, emptyMap(), 0)

    nodes.forEach { (owner, node) ->
        for (method in node.methods) {
            val plan = plans[MemberKey(owner, method.name, method.desc)] ?: continue
            if (plan.objectArray) {
                lowerMethodParametersToObjectArray(method, plan)
            } else {
                clearDescriptorMetadata(method)
                method.desc = plan.finalDescriptor
                method.maxLocals = maxOf(method.maxLocals, argumentSlotCount(plan.expandedArgumentTypes))
            }
        }
    }
    nodes.values.forEach { node ->
        for (method in node.methods) {
            rewriteDirectCallsites(method, plans)
        }
    }

    var changedClasses = 0
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        val node = nodes.getValue(classArtifact.summary.internalName)
        val writer = computeFramesWriter(ClassReader(classArtifact.bytes))
        node.accept(writer)
        val bytes = writer.toByteArray()
        if (bytes.contentEquals(classArtifact.bytes)) classArtifact else {
            changedClasses++
            reanalyzedClassArtifact(classArtifact, bytes)
        }
    }
    if (changedClasses == 0) return MethodDescriptorPaddingResult(artifact, emptyMap(), 0)
    val updatedArtifact = updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = changedClasses,
        transformedMemberCount = plans.size,
    ).artifact
    return MethodDescriptorPaddingResult(
        artifact = updatedArtifact,
        descriptors = plans.mapValues { (_, plan) -> plan.finalDescriptor },
        transformedMemberCount = plans.size,
    )
}

private data class MethodPaddingPlan(
    val key: MemberKey,
    val originalArgumentTypes: Array<Type>,
    val expandedArgumentTypes: Array<Type>,
    val finalDescriptor: String,
    val contextType: Type?,
    val contextValue: Any?,
    val objectArray: Boolean,
)

private val DESCRIPTOR_PADDING_MODES = setOf("off", "fixed", "random")
private val PARAMETER_PACKING_MODES = setOf("off", "object-array")

private fun isEligibleStaticTarget(method: MethodNode): Boolean =
    method.name != "<init>" && method.name != "<clinit>" &&
        method.access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC) == (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC) &&
        method.access and (Opcodes.ACC_NATIVE or Opcodes.ACC_ABSTRACT) == 0

private fun collectHandleTargets(nodes: Collection<ClassNode>): Set<MemberKey> = buildSet {
    fun addHandle(handle: Handle) {
        if (handle.tag in setOf(Opcodes.H_INVOKESTATIC, Opcodes.H_INVOKEVIRTUAL, Opcodes.H_INVOKESPECIAL, Opcodes.H_NEWINVOKESPECIAL, Opcodes.H_INVOKEINTERFACE)) {
            add(MemberKey(handle.owner, handle.name, handle.desc))
        }
    }
    fun collect(value: Any?) {
        when (value) {
            is Handle -> addHandle(value)
            is ConstantDynamic -> {
                addHandle(value.bootstrapMethod)
                repeat(value.bootstrapMethodArgumentCount) { index ->
                    collect(value.getBootstrapMethodArgument(index))
                }
            }
        }
    }
    nodes.forEach { node ->
        node.methods.forEach { method ->
            method.instructions.forEach { instruction ->
                when (instruction) {
                    is LdcInsnNode -> collect(instruction.cst)
                    is InvokeDynamicInsnNode -> {
                        addHandle(instruction.bsm)
                        instruction.bsmArgs.forEach(::collect)
                    }
                }
            }
        }
    }
}

private fun collectReflectionSensitiveMethodTargets(nodes: Collection<ClassNode>): Set<MemberKey> {
    val reflectiveNames = buildSet {
        nodes.forEach { node ->
            node.methods.forEach { method ->
                val hasMethodLookup = method.instructions.any { instruction ->
                    instruction is MethodInsnNode &&
                        instruction.owner == "java/lang/Class" &&
                        instruction.name in setOf("getMethod", "getDeclaredMethod")
                }
                if (hasMethodLookup) {
                    method.instructions.filterIsInstance<LdcInsnNode>()
                        .mapNotNull { instruction -> instruction.cst as? String }
                        .forEach(::add)
                }
            }
        }
    }
    if (reflectiveNames.isEmpty()) return emptySet()
    return buildSet {
        nodes.forEach { node ->
            node.methods
                .filter { method -> method.name in reflectiveNames }
                .forEach { method -> add(MemberKey(node.name, method.name, method.desc)) }
        }
    }
}

private fun retainNonCollidingPlans(
    nodes: Map<String, ClassNode>,
    rawPlans: Map<MemberKey, MethodPaddingPlan>,
): Map<MemberKey, MethodPaddingPlan> {
    if (rawPlans.isEmpty()) return emptyMap()

    fun finalKey(plan: MethodPaddingPlan): MemberKey = MemberKey(plan.key.owner, plan.key.name, plan.finalDescriptor)

    val declaredKeys = nodes.flatMapTo(linkedSetOf<MemberKey>()) { (owner, node) ->
        node.methods.map { method -> MemberKey(owner, method.name, method.desc) }
    }
    val duplicateFinalKeys = rawPlans.values
        .groupBy(::finalKey)
        .filterValues { plans -> plans.size > 1 }
        .keys
    val retained = linkedMapOf<MemberKey, MethodPaddingPlan>()
    rawPlans.forEach { (key, plan) ->
        if (finalKey(plan) !in duplicateFinalKeys) retained[key] = plan
    }

    var removedPlan: Boolean
    do {
        removedPlan = false
        retained.toMap().forEach { (key, plan) ->
            val finalKey = finalKey(plan)
            if (finalKey !in declaredKeys || finalKey == key) return@forEach
            val vacatingPlan = retained[finalKey]
            if (vacatingPlan != null && vacatingPlan.finalDescriptor != finalKey.descriptor) return@forEach
            retained.remove(key)
            removedPlan = true
        }
    } while (removedPlan)

    return retained
}

private fun contextTypeFor(mode: String, key: MemberKey, rawSeed: Any?): Type? = when (mode) {
    "fixed" -> Type.LONG_TYPE
    "random" -> if ((stableSeed(key, rawSeed) and 1L) == 0L) Type.INT_TYPE else Type.LONG_TYPE
    else -> null
}

private fun contextValueFor(key: MemberKey, type: Type?, rawSeed: Any?): Any? = when (type) {
    Type.INT_TYPE -> stableSeed(key, rawSeed).toInt()
    Type.LONG_TYPE -> stableSeed(key, rawSeed)
    else -> null
}

private fun stableSeed(key: MemberKey, rawSeed: Any?): Long {
    val base = when (rawSeed) {
        is Number -> rawSeed.toLong()
        else -> 0x4a53_4852L
    }
    return base xor key.owner.hashCode().toLong().rotateLeft(17) xor key.name.hashCode().toLong().rotateLeft(7) xor key.descriptor.hashCode().toLong()
}

private fun lowerMethodParametersToObjectArray(method: MethodNode, plan: MethodPaddingPlan) {
    shiftMethodLocals(method, 1)
    val prologue = InsnList()
    var local = 1
    plan.expandedArgumentTypes.forEachIndexed { index, type ->
        prologue.add(VarInsnNode(Opcodes.ALOAD, 0))
        prologue.add(pushInt(index))
        prologue.add(InsnNode(Opcodes.AALOAD))
        prologue.add(unbox(type))
        prologue.add(VarInsnNode(type.getOpcode(Opcodes.ISTORE), local))
        local += type.size
    }
    method.instructions.insert(prologue)
    clearDescriptorMetadata(method)
    method.desc = plan.finalDescriptor
    method.maxLocals = maxOf(method.maxLocals, local)
}

private fun clearDescriptorMetadata(method: MethodNode) {
    method.signature = null
    method.parameters = null
    method.visibleParameterAnnotations = null
    method.invisibleParameterAnnotations = null
    method.visibleAnnotableParameterCount = 0
    method.invisibleAnnotableParameterCount = 0
    method.visibleTypeAnnotations = null
    method.invisibleTypeAnnotations = null
    method.visibleLocalVariableAnnotations = null
    method.invisibleLocalVariableAnnotations = null
}

private fun shiftMethodLocals(method: MethodNode, offset: Int) {
    method.instructions.forEach { instruction ->
        when (instruction) {
            is VarInsnNode -> instruction.`var` += offset
            is IincInsnNode -> instruction.`var` += offset
        }
    }
    method.localVariables?.forEach { local -> local.index += offset }
    method.maxLocals += offset
}

private fun rewriteDirectCallsites(method: MethodNode, plans: Map<MemberKey, MethodPaddingPlan>) {
    method.instructions.toArray().forEach { instruction ->
        val call = instruction as? MethodInsnNode ?: return@forEach
        if (call.opcode != Opcodes.INVOKESTATIC) return@forEach
        val plan = plans[MemberKey(call.owner, call.name, call.desc)] ?: return@forEach
        val adapter = if (plan.objectArray) buildObjectArrayAdapter(method, plan) else InsnList().apply {
            plan.contextValue?.let { add(LdcInsnNode(it)) }
        }
        method.instructions.insertBefore(call, adapter)
        call.desc = plan.finalDescriptor
    }
}

private fun buildObjectArrayAdapter(method: MethodNode, plan: MethodPaddingPlan): InsnList {
    val locals = IntArray(plan.originalArgumentTypes.size)
    var nextLocal = method.maxLocals
    plan.originalArgumentTypes.forEachIndexed { index, type ->
        locals[index] = nextLocal
        nextLocal += type.size
    }
    method.maxLocals = nextLocal
    return InsnList().apply {
        for (index in plan.originalArgumentTypes.indices.reversed()) {
            val type = plan.originalArgumentTypes[index]
            add(VarInsnNode(type.getOpcode(Opcodes.ISTORE), locals[index]))
        }
        val count = plan.originalArgumentTypes.size + if (plan.contextType == null) 0 else 1
        add(pushInt(count))
        add(TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"))
        plan.originalArgumentTypes.forEachIndexed { index, type ->
            add(InsnNode(Opcodes.DUP))
            add(pushInt(index))
            add(VarInsnNode(type.getOpcode(Opcodes.ILOAD), locals[index]))
            add(box(type))
            add(InsnNode(Opcodes.AASTORE))
        }
        if (plan.contextType != null) {
            add(InsnNode(Opcodes.DUP))
            add(pushInt(plan.originalArgumentTypes.size))
            add(LdcInsnNode(plan.contextValue))
            add(box(plan.contextType))
            add(InsnNode(Opcodes.AASTORE))
        }
    }
}

private fun box(type: Type): InsnList = InsnList().apply {
    when (type.sort) {
        Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false))
        Type.LONG -> add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false))
        Type.FLOAT -> add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false))
        Type.DOUBLE -> add(MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false))
    }
}

private fun unbox(type: Type): InsnList = InsnList().apply {
    when (type.sort) {
        Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> {
            add(TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"))
            add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false))
        }
        Type.LONG -> {
            add(TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"))
            add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false))
        }
        Type.FLOAT -> {
            add(TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"))
            add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false))
        }
        Type.DOUBLE -> {
            add(TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"))
            add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false))
        }
        Type.ARRAY -> add(TypeInsnNode(Opcodes.CHECKCAST, type.descriptor))
        Type.OBJECT -> add(TypeInsnNode(Opcodes.CHECKCAST, type.internalName))
    }
}

private fun pushInt(value: Int): AbstractInsnNode = when (value) {
    -1 -> InsnNode(Opcodes.ICONST_M1)
    0 -> InsnNode(Opcodes.ICONST_0)
    1 -> InsnNode(Opcodes.ICONST_1)
    2 -> InsnNode(Opcodes.ICONST_2)
    3 -> InsnNode(Opcodes.ICONST_3)
    4 -> InsnNode(Opcodes.ICONST_4)
    5 -> InsnNode(Opcodes.ICONST_5)
    in Byte.MIN_VALUE..Byte.MAX_VALUE -> IntInsnNode(Opcodes.BIPUSH, value)
    in Short.MIN_VALUE..Short.MAX_VALUE -> IntInsnNode(Opcodes.SIPUSH, value)
    else -> LdcInsnNode(value)
}

private fun argumentSlotCount(types: Array<Type>): Int = types.sumOf(Type::getSize)
