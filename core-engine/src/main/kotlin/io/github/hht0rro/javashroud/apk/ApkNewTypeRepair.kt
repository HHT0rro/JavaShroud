package io.github.hht0rro.javashroud.apk

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.AnalyzerException
import org.objectweb.asm.tree.analysis.SourceInterpreter
import org.objectweb.asm.tree.analysis.SourceValue

/**
 * Repairs the dex2jar `new`-type degradation before the kernel sees the
 * merged classes.
 *
 * When a dex invokes a SUPERCLASS constructor directly on a freshly allocated
 * instance (`new-instance Sub` + `invoke-direct Super.<init>`), dex2jar emits
 * a classfile whose `new` instruction is typed to the CONSTRUCTOR owner
 * (`new Super`) instead of the allocated class. Every statically typed use of
 * the value then carries the wrong type, and after the d8 round trip ART's
 * verifier hard-rejects the class ("register has type Super but expected Sub"
 * / "returning 'Super'" / "cannot access").
 *
 * The input DEX supplies allocated types. When dex2jar changes the order or count
 * of allocations with the same constructor owner, tracked field receivers can
 * disambiguate which source type belongs to a converted allocation. If the
 * evidence still conflicts, the repair does not guess between siblings.
 * Without a matching source site, a fallback uses the first statically typed use:
 *  - a field store (putstatic/putfield, T = the field's declared type),
 *  - a reference return (areturn, T = the method's declared return type),
 *  - a zero-argument invoke receiver (T = the call's owner),
 *  - the last argument of an invoke (T = the last parameter's declared type),
 *  - a local store slot whose FIRST reload is immediately followed by any of
 *    the above (the ubiquitous `new; dup; ctor; astore_N; aload_N; use`
 *    constructor-field-initialization shape).
 *
 * Because the ORIGINAL dex verified the real allocated class H against the
 * declared use type T, H is assignable to T; rewriting the allocation to T
 * therefore only ever widens the local's static type to a legal ancestor of
 * H, so frame merges stay valid. A rewrite is only accepted when T is a
 * non-interface class and the artifact hierarchy confirms T extends S (the
 * superclass constructor invocation `S.<init>` stays legal on a T instance).
 * All other shapes — including values that flow into interface-typed
 * arguments such as `Proxy` handlers, where the real allocated class is not
 * recoverable from the classfile — are left untouched.
 */
internal object ApkNewTypeRepair {

    data class RepairOutcome(
        val classes: List<Pair<String, ByteArray>>,
        val repairedSites: Int,
        val repairedClassCount: Int,
        /** Sites recovered from the authoritative dex index (exact allocated type). */
        val dexRecoveredSites: Int,
        /** Sites recovered from the classfile's declared use type (heuristic fallback). */
        val heuristicRecoveredSites: Int,
    )

    private data class ClassFacts(val superName: String?, val isInterface: Boolean)

    fun repair(
        mergedClasses: List<Pair<String, ByteArray>>,
        dexSites: Map<String, Map<String, List<ApkDexNewInstanceIndex.Site>>> = emptyMap(),
    ): RepairOutcome {
        val classFacts = buildMap<String, ClassFacts> {
            for ((_, bytes) in mergedClasses) {
                val node = ClassNode()
                runCatching {
                    ClassReader(bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
                }.onSuccess {
                    put(node.name, ClassFacts(superName = node.superName, isInterface = node.access and Opcodes.ACC_INTERFACE != 0))
                }
            }
        }
        var repairedSites = 0
        var repairedClassCount = 0
        var dexRecoveredSites = 0
        var heuristicRecoveredSites = 0
        val classes = mergedClasses.map { (name, bytes) ->
            val outcome = repairClass(bytes, dexSites, classFacts) ?: return@map name to bytes
            repairedSites += outcome.sites
            repairedClassCount += 1
            dexRecoveredSites += outcome.dexRecovered
            heuristicRecoveredSites += outcome.heuristicRecovered
            name to outcome.bytes
        }
        return RepairOutcome(
            classes = classes,
            repairedSites = repairedSites,
            repairedClassCount = repairedClassCount,
            dexRecoveredSites = dexRecoveredSites,
            heuristicRecoveredSites = heuristicRecoveredSites,
        )
    }

    private data class ClassRepairOutcome(
        val bytes: ByteArray,
        val sites: Int,
        val dexRecovered: Int,
        val heuristicRecovered: Int,
    )

    /** true when [supertype] appears in the artifact-known superclass chain of [subtype]. */
    private fun extendsArtifact(subtype: String, supertype: String, classFacts: Map<String, ClassFacts>): Boolean {
        if (subtype == supertype) return true
        var cursor: String? = classFacts[subtype]?.superName
        var hops = 0
        while (cursor != null && hops < 128) {
            if (cursor == supertype) return true
            cursor = classFacts[cursor]?.superName
            hops++
        }
        return false
    }

    private fun isInstantiableClassType(internalName: String, classFacts: Map<String, ClassFacts>): Boolean {
        if (internalName.startsWith("[")) return false
        val facts = classFacts[internalName] ?: return false // external types cannot be hierarchy-checked
        return !facts.isInterface
    }

    /** Rewrites the degraded `new` sites; null when nothing changed. */
    private fun repairClass(
        classBytes: ByteArray,
        dexSites: Map<String, Map<String, List<ApkDexNewInstanceIndex.Site>>>,
        classFacts: Map<String, ClassFacts>,
    ): ClassRepairOutcome? {
        return try {
            val node = ClassNode()
            ClassReader(classBytes).accept(node, 0)
            val dexMethodSitesByClass = dexSites[node.name]
            var repairedSites = 0
            var dexRecovered = 0
            var heuristicRecovered = 0
            for (method in node.methods) {
                val insns = method.instructions ?: continue
                val dexMethodSites = dexMethodSitesByClass?.get(method.name + method.desc).orEmpty()
                // Pair each `new S` with the next unpaired `invokespecial
                // S.<init>()V` after it, in code order. javac/dex2jar emit them
                // in that order, but argument computations may sit between
                // them, so adjacency cannot be required.
                val unpairedNewByOwner = LinkedHashMap<String, MutableList<TypeInsnNode>>()
                val pairedCtor = HashMap<TypeInsnNode, MethodInsnNode>()
                for (instruction in insns) {
                    when {
                        instruction is TypeInsnNode && instruction.opcode == Opcodes.NEW && instruction.desc.isNotEmpty() ->
                            unpairedNewByOwner.getOrPut(instruction.desc) { mutableListOf() }.add(instruction)
                        instruction is MethodInsnNode && instruction.opcode == Opcodes.INVOKESPECIAL &&
                            instruction.name == "<init>" -> {
                            val pending = unpairedNewByOwner[instruction.owner]
                            if (!pending.isNullOrEmpty()) {
                                pairedCtor[pending.removeAt(0)] = instruction
                            }
                        }
                    }
                }
                val byConstructorOwner = insns.filterIsInstance<TypeInsnNode>()
                    .filter { it in pairedCtor }.groupBy { it.desc }
                val dexByConstructorOwner = dexMethodSites.groupBy { it.constructorOwner }
                val fieldOwners by lazy { allocationFieldOwners(node.name, method) }
                val matchingDexTypes = mutableMapOf<TypeInsnNode, String>()
                val uncertainAllocations = mutableSetOf<TypeInsnNode>()
                for ((owner, allocations) in byConstructorOwner) {
                    val sites = dexByConstructorOwner[owner].orEmpty().map { it.allocatedType }
                    if (sites.isEmpty()) continue
                    if (sites.distinct().size <= 1) {
                        allocations.take(sites.size).zip(sites).forEach { (site, type) -> matchingDexTypes[site] = type }
                        continue
                    }
                    val constraints = allocations.associateWith { fieldOwners[it].orEmpty() }
                    fun permits(site: TypeInsnNode, type: String) = constraints.getValue(site).all { extendsArtifact(type, it, classFacts) }
                    if (allocations.size == sites.size && allocations.zip(sites).all { (site, type) -> permits(site, type) }) {
                        allocations.zip(sites).forEach { (site, type) -> matchingDexTypes[site] = type }
                        continue
                    }

                    // dex2jar may reorder blocks or remove redundant NEWs, so an ordinal disagreement
                    // cannot justify choosing between sibling types. Constrain by actual field receivers.
                    val remaining = sites.toMutableList()
                    val pending = allocations.toMutableList()
                    var progress: Boolean
                    do {
                        progress = false
                        val iterator = pending.iterator()
                        while (iterator.hasNext()) {
                            val site = iterator.next()
                            if (constraints.getValue(site).isEmpty()) continue
                            val type = remaining.asSequence().filter { permits(site, it) }.distinct().singleOrNull() ?: continue
                            matchingDexTypes[site] = type
                            remaining.remove(type)
                            iterator.remove()
                            progress = true
                        }
                    } while (progress)
                    val uniform = remaining.distinct().singleOrNull()
                    if (uniform != null && pending.size <= remaining.size && pending.all { permits(it, uniform) }) {
                        pending.forEach { matchingDexTypes[it] = uniform }
                    } else {
                        uncertainAllocations += pending
                    }
                }
                for (instruction in insns) {
                    val newInsn = instruction as? TypeInsnNode ?: continue
                    if (newInsn.opcode != Opcodes.NEW) continue
                    val constructedType = newInsn.desc
                    val ctor = pairedCtor[newInsn] ?: continue
                    val dexType = matchingDexTypes[newInsn]
                    if (dexType != null) {
                        if (dexType != constructedType && isInstantiableClassType(dexType, classFacts) &&
                            extendsArtifact(dexType, constructedType, classFacts)) {
                            newInsn.desc = dexType
                            repairedSites += 1
                            dexRecovered += 1
                        }
                        continue
                    }
                    if (newInsn in uncertainAllocations) continue

                    // Heuristic fallback: declared use type in the classfile.
                    val use = nextMeaningful(ctor) ?: continue
                    val targetType = declaredUseType(use, method.desc) ?: continue
                    if (targetType == constructedType) continue
                    if (!isInstantiableClassType(targetType, classFacts)) continue
                    if (!extendsArtifact(targetType, constructedType, classFacts)) continue
                    newInsn.desc = targetType
                    repairedSites += 1
                    heuristicRecovered += 1
                }
            }
            if (repairedSites == 0) return null
            val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
            node.accept(writer)
            ClassRepairOutcome(writer.toByteArray(), repairedSites, dexRecovered, heuristicRecovered)
        } catch (_: Exception) {
            null
        }
    }

    private fun allocationFieldOwners(owner: String, method: MethodNode): Map<TypeInsnNode, Set<String>> {
        val interpreter = object : SourceInterpreter(Opcodes.ASM9) {
            override fun copyOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue = value
        }
        val frames = try {
            Analyzer(interpreter).analyze(owner, method)
        } catch (_: AnalyzerException) {
            return emptyMap()
        }
        val owners = mutableMapOf<TypeInsnNode, MutableSet<String>>()
        for ((index, insn) in method.instructions.toArray().withIndex()) {
            if (insn !is FieldInsnNode) continue
            val fromTop = when (insn.opcode) {
                Opcodes.PUTFIELD -> 2 // ASM frames contain one value per operand, including double and long.
                Opcodes.GETFIELD -> 1
                else -> continue
            }
            val frame = frames[index] ?: continue
            if (frame.stackSize < fromTop) continue
            val source = frame.getStack(frame.stackSize - fromTop).insns.singleOrNull() as? TypeInsnNode ?: continue
            if (source.opcode == Opcodes.NEW) owners.getOrPut(source) { mutableSetOf() } += insn.owner
        }
        return owners
    }

    /** Declared reference type when the use pins one; null otherwise. */
    private fun declaredUseType(use: AbstractInsnNode, methodDescriptor: String): String? = when (use) {
        is FieldInsnNode -> when (use.opcode) {
            // The constructed value is the TOP operand: for PUTSTATIC/PUTFIELD
            // it is the value being stored (T = the field's declared type);
            // for GETFIELD it is the receiver (T = the field's owner).
            Opcodes.PUTSTATIC, Opcodes.PUTFIELD -> referenceType(use.desc)
            Opcodes.GETFIELD -> use.owner
            else -> null
        }
        is InsnNode -> when (use.opcode) {
            Opcodes.ARETURN -> {
                val returnType = Type.getReturnType(methodDescriptor)
                if (returnType.sort == Type.OBJECT) returnType.internalName else null
            }
            else -> null
        }
        is MethodInsnNode -> {
            // The constructed value is the TOP operand of the immediately
            // following invoke: either its LAST argument, or (for a no-arg
            // descriptor) its receiver.
            val argumentTypes = Type.getArgumentTypes(use.desc)
            when {
                argumentTypes.isNotEmpty() && argumentTypes.last().sort == Type.OBJECT ->
                    argumentTypes.last().internalName
                argumentTypes.isEmpty() && use.owner.isNotEmpty() -> use.owner
                else -> null
            }
        }
        is VarInsnNode -> when (use.opcode) {
            // ASM normalizes astore_N/astore to ASTORE with the slot in `var`.
            Opcodes.ASTORE -> firstReloadUseType(use, methodDescriptor)
            else -> null
        }
        else -> null
    }

    /**
     * The `new; dup; ctor; astore_N; aload_N; use` chain: resolves the first
     * RELOAD of the stored slot (skipping everything that does not touch it)
     * and returns the declared type that reload's immediate use pins. Any
     * redefinition of the slot first yields null.
     */
    private fun firstReloadUseType(astore: VarInsnNode, methodDescriptor: String): String? {
        val slot = astore.`var`
        var current: AbstractInsnNode? = astore.next
        while (current != null) {
            val variable = current as? VarInsnNode
            if (variable != null && variable.`var` == slot) {
                return when (variable.opcode) {
                    // ASM normalizes aload_N/aload to ALOAD with the slot in `var`.
                    Opcodes.ALOAD -> {
                        val reloadUse = nextMeaningful(variable) ?: return null
                        directUseType(reloadUse, methodDescriptor)
                    }
                    else -> null // slot overwritten before it was read
                }
            }
            current = current.next
        }
        return null
    }

    /** Like [declaredUseType] but without local-slot chaining (one level only). */
    private fun directUseType(use: AbstractInsnNode, methodDescriptor: String?): String? = when (use) {
        is FieldInsnNode -> when (use.opcode) {
            Opcodes.PUTSTATIC, Opcodes.PUTFIELD -> referenceType(use.desc)
            Opcodes.GETFIELD -> use.owner
            else -> null
        }
        is InsnNode -> when (use.opcode) {
            Opcodes.ARETURN -> {
                val descriptor = methodDescriptor ?: return null
                val returnType = Type.getReturnType(descriptor)
                if (returnType.sort == Type.OBJECT) returnType.internalName else null
            }
            else -> null
        }
        is MethodInsnNode -> {
            val argumentTypes = Type.getArgumentTypes(use.desc)
            when {
                argumentTypes.isNotEmpty() && argumentTypes.last().sort == Type.OBJECT ->
                    argumentTypes.last().internalName
                argumentTypes.isEmpty() && use.owner.isNotEmpty() -> use.owner
                else -> null
            }
        }
        else -> null
    }

    private fun referenceType(descriptor: String): String? {
        val type = Type.getType(descriptor)
        return if (type.sort == Type.OBJECT) type.internalName else null
    }

    private fun nextMeaningful(instruction: AbstractInsnNode): AbstractInsnNode? {
        var current = instruction.next
        while (current != null && current.opcode < 0) {
            current = current.next
        }
        return current
    }
}
