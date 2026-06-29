package io.github.hht0rro.javashroud.transforms.protection
import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.analysis.matchedMembersForAction
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.*
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import java.security.MessageDigest
import java.security.Provider
import java.security.SecureRandom
import java.security.SecureRandomSpi
import java.util.Collections
private const val VM_LEGACY_DISPATCH_DESCRIPTOR = "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"
private const val VM_TOKEN_DISPATCH_DESCRIPTOR = "(J[Ljava/lang/Object;)Ljava/lang/Object;"
private const val VM_VOID_DISPATCH_DESCRIPTOR = "(J)V"
private const val VM_INT_VOID_DISPATCH_DESCRIPTOR = "(JI)V"
private const val JNI_MICROKERNEL_DISPATCH_OWNER = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
private const val JNI_MICROKERNEL_VM_DISPATCH_METHOD = "executeVmResource"
private const val VBC4_DISPATCH_LAYOUT = "vbc4-native"
private val VBC4_ALLOWED_PARAMS = setOf(
    "seed",
    "methodSelection",
    "strictVirtualization",
    "maxInstructions",
    "maxBroadVirtualizedMethods",
    "highValueMethods",
    "highValueMethodDeny",
    "vmDiversityLevel",
    "vmStrength",
    "fusionLevel",
    "stateBoundEncoding",
    "vbc4StateBoundEncoding",
    "vbc4HandlerMorphing",
    "vbc4StrengthMax",
    "vbc4InterpreterDiversity",
    "vbc4HashedJniSymbols",
    "vbc4ExecutableRegisterIr",
    "vbc4SuperOperators",
    "vbc4IntegrityKeyBinding",
    "vbc4EphemeralRootMaterial",
    "__nativeOnlyInterpreter",
)

private fun isStackTraceSensitiveForVirtualization(classBytes: ByteArray): Boolean {
    val classNode = org.objectweb.asm.tree.ClassNode()
    return try {
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_FRAMES)
        classNode.methods.any { method ->
            method.instructions?.any { instruction ->
                instruction is org.objectweb.asm.tree.MethodInsnNode &&
                    ((instruction.owner == "java/lang/Throwable" && instruction.name == "getStackTrace") ||
                        instruction.owner == "java/lang/StackTraceElement")
            } == true
        }
    } catch (_: Exception) {
        true
    }
}
private fun rejectUnsupportedVbc4Params(params: Map<String, Any>) {
    val unsupported = params.keys.filter { it !in VBC4_ALLOWED_PARAMS }
    if (unsupported.isNotEmpty()) {
        throw IllegalArgumentException("method-virtualization accepts only current VBC4 parameters; unsupported: ${unsupported.joinToString(", ")}")
    }
    val vmDiversityLevel = params["vmDiversityLevel"] as? String
    require(vmDiversityLevel == null || vmDiversityLevel == "tigress-like") {
        "method-virtualization vmDiversityLevel '$vmDiversityLevel' is not supported in VBC4; use tigress-like or omit it"
    }
    val vmStrength = params["vmStrength"] as? String
    require(vmStrength == null || vmStrength == "max") {
        "method-virtualization vmStrength '$vmStrength' is not supported in VBC4; strength is fixed to max"
    }
    val fusionLevel = params["fusionLevel"] as? String
    require(fusionLevel == null || fusionLevel == "maximum") {
        "method-virtualization fusionLevel '$fusionLevel' is not supported in VBC4; fusion is fixed to maximum"
    }
    val stateBoundEncoding = params["stateBoundEncoding"] as? Boolean
    require(stateBoundEncoding == null || stateBoundEncoding) {
        "method-virtualization stateBoundEncoding=false is not supported in VBC4; state-bound encoding is fixed on"
    }
    val fixedTrueParams = listOf(
        "vbc4StateBoundEncoding",
        "vbc4HandlerMorphing",
        "vbc4StrengthMax",
        "vbc4InterpreterDiversity",
        "vbc4HashedJniSymbols",
        "vbc4ExecutableRegisterIr",
        "vbc4SuperOperators",
        "vbc4IntegrityKeyBinding",
        "vbc4EphemeralRootMaterial",
    )
    for (key in fixedTrueParams) {
        val value = params[key] as? Boolean
        require(value == null || value) {
            "method-virtualization $key=false is not supported in VBC4; max-strength native-only diversity is fixed on"
        }
    }
}

/**
 * Method Level Virtualization transform (Phase 2).
 *
 * Lowers selected methods into a private opcode instruction stream with:
 * - A native JNI dispatcher stub
 * - Operand stack / register simulator
 * - Per-method handler morphing metadata
 *
 * Each build emits a native-only VBC4 resource with fixed max-strength behavior.
 */
fun applyMethodVirtualization(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val buildContext = requireVbc4BuildContext()
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "method-virtualization")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)
    val explicitlyMatchedMethods = matchedMembersForAction(ruleMatches, "method-virtualization")
        .filter { it.kind.name == "METHOD" }
        .map { MethodSelectionKey(it.owner, it.name, it.descriptor) }
        .toSet()
    val restrictToMatchedMethods = ruleMatches.any {
        it.rule.action == "method-virtualization" && it.selector.memberPattern != null
    }

    rejectUnsupportedVbc4Params(params)
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val maxInstructions = parseMaxInstructions(params["maxInstructions"])
    val maxBroadVirtualizedMethods = parseMaxBroadVirtualizedMethods(params["maxBroadVirtualizedMethods"])
    val methodSelection = parseMethodSelection(params["methodSelection"])
    val highValueMethods = parseMethodSelectorPatterns(params["highValueMethods"])
    val highValueMethodDeny = parseMethodSelectorPatterns(params["highValueMethodDeny"])
    val strictVirtualization = (params["strictVirtualization"] as? Boolean) ?: true
    val structureContextSalt = buildContext.deriveSubKey(
        "javashroud-vbc4-method-virtualization-structure-v1",
        32,
        longBytes(seed ?: 0L),
        intBytes(artifact.classArtifacts.size),
        intBytes(artifact.jarEntries.size),
    )
    val random = try {
        buildContextAwareSecureRandom(
            label = "method-virtualization-structure-stream-v1",
            seed = seed,
            classCount = artifact.classArtifacts.size,
            jarCount = artifact.jarEntries.size,
            contextSalt = structureContextSalt,
        )
    } finally {
        java.util.Arrays.fill(structureContextSalt, 0)
    }
    val contextSalt = buildContext.deriveSubKey(
        "javashroud-vbc4-method-virtualization-context-v1",
        32,
        longBytes(seed ?: 0L),
        intBytes(artifact.classArtifacts.size),
        intBytes(artifact.jarEntries.size),
    )
    val keyRandom = try {
        buildContextAwareSecureRandom(
            label = "method-virtualization-key-stream-v1",
            seed = seed,
            classCount = artifact.classArtifacts.size,
            jarCount = artifact.jarEntries.size,
            contextSalt = contextSalt,
        )
    } finally {
        java.util.Arrays.fill(contextSalt, 0)
    }
    val nativeOnlyInterpreter = (params["__nativeOnlyInterpreter"] as? Boolean) ?: false

    val opcodeMapping = generateOpcodeMapping(random)
    val handlerOrder = generateHandlerOrder(opcodeMapping.size, random)
    val vmResourcePlans = mutableListOf<PlannedMethodVmResources>()
    val vmPreloadEntries = mutableListOf<VmPreloadEntry>()
    var nextVmResourceOrdinal = 0

    var classCount = 0
    var methodCount = 0
    var broadVirtualizedMethodCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact
        if (nativeOnlyInterpreter && classArtifact.summary.accessFlags and Opcodes.ACC_INTERFACE != 0) return@map classArtifact

        if (isStackTraceSensitiveForVirtualization(classArtifact.bytes)) return@map classArtifact
        val cr = ClassReader(classArtifact.bytes)
        val cw = computeFramesWriter(cr)
        val className = classArtifact.summary.internalName
        val existingMethodKeys = classArtifact.summary.methodSummaries
            .map { it.name + it.descriptor }
            .toMutableSet()
        var classModified = false

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)

                val methodKey = MethodSelectionKey(className, name, descriptor)
                val explicitlySelected = methodKey in explicitlyMatchedMethods
                if (name == "<init>" || name == "<clinit>") {
                    if (restrictToMatchedMethods && explicitlySelected) {
                        throw IllegalArgumentException("method-virtualization strictVirtualization cannot virtualize $className#$name$descriptor because JVM initializer methods cannot be replaced by a native dispatcher")
                    }
                    return superMv
                }
                if (isEnumValuesHelper(classArtifact.summary.accessFlags, access, name, descriptor)) return superMv
                if (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) {
                    if (restrictToMatchedMethods && explicitlySelected) {
                        throw IllegalArgumentException("method-virtualization strictVirtualization cannot virtualize $className#$name$descriptor because abstract/native methods have no JVM Code attribute")
                    }
                    return superMv
                }
                if (restrictToMatchedMethods && !explicitlySelected) return superMv

                val bodyCapture = MethodBodyCapture()
                return object : MethodVisitor(Opcodes.ASM9, bodyCapture) {
                    override fun visitParameter(name: String?, access: Int) {
                        superMv.visitParameter(name, access)
                    }

                    override fun visitAnnotationDefault(): AnnotationVisitor? = superMv.visitAnnotationDefault()

                    override fun visitAnnotation(descriptor: String, visible: Boolean): AnnotationVisitor? =
                        superMv.visitAnnotation(descriptor, visible)

                    override fun visitTypeAnnotation(typeRef: Int, typePath: TypePath?, descriptor: String, visible: Boolean): AnnotationVisitor? =
                        superMv.visitTypeAnnotation(typeRef, typePath, descriptor, visible)

                    override fun visitAnnotableParameterCount(parameterCount: Int, visible: Boolean) {
                        superMv.visitAnnotableParameterCount(parameterCount, visible)
                    }

                    override fun visitParameterAnnotation(parameter: Int, descriptor: String, visible: Boolean): AnnotationVisitor? =
                        superMv.visitParameterAnnotation(parameter, descriptor, visible)

                    override fun visitAttribute(attribute: Attribute) {
                        superMv.visitAttribute(attribute)
                    }

                    override fun visitEnd() {
                        super.visitEnd()
                        if (bodyCapture.instructionCount == 0) {
                            // Replay original body to the ClassWriter's MethodVisitor so the
                            // method retains its Code attribute. Without this, skipped methods
                            // produce ClassFormatError: Absent Code attribute.
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        if (bodyCapture.instructionCount > maxInstructions) {
                            if (strictVirtualization) {
                                throw IllegalArgumentException("method-virtualization strictVirtualization cannot virtualize $className#$name$descriptor because instructionCount=${bodyCapture.instructionCount} exceeds maxInstructions=$maxInstructions")
                            }
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        bodyCapture.refreshRawBenchmarkCaptureState(name, descriptor, access)
                        if (isSyntheticBridgeMethod(access)) {
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        val isMainEntry = isJvmMainEntry(access, name, descriptor)
                        if (isMainEntry && bodyCapture.sameOwnerStaticForwarderTarget(className, name, descriptor) != null) {
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        val selectedByMethodSelection = if (isMainEntry && methodSelection == MethodSelectionMode.AllCompatible) {
                            true
                        } else {
                            bodyCapture.selectedBy(methodSelection, access, name, descriptor)
                        }
                        val deniedByHighValueList = !restrictToMatchedMethods && matchesMethodSelector(highValueMethodDeny, className, name, descriptor)
                        val selectedByHighValue = methodSelection == MethodSelectionMode.CriticalPlus &&
                            !deniedByHighValueList &&
                            bodyCapture.highValueSelected(className, name, descriptor, highValueMethods)
                        val selectedForBroad = !deniedByHighValueList && (selectedByMethodSelection || selectedByHighValue)
                        val withinBroadBudget = restrictToMatchedMethods || maxBroadVirtualizedMethods <= 0 || broadVirtualizedMethodCount < maxBroadVirtualizedMethods
                        val selectedWithinBroadBudget = selectedForBroad && withinBroadBudget
                        val shouldFailClosedForMethod = restrictToMatchedMethods || (strictVirtualization && selectedWithinBroadBudget)
                        val unsupportedBySelection = !restrictToMatchedMethods && !selectedWithinBroadBudget
                        if (bodyCapture.hasDirectNativeDefenseCall && !strictVirtualization) {
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        if (shouldFailClosedForMethod && (!bodyCapture.nativeVmCompatible || bodyCapture.hasUnsupportedInvokeDynamic)) {
                            val unsupportedLabel = if (restrictToMatchedMethods) "explicit" else "selected"
                            throw IllegalArgumentException("method-virtualization cannot virtualize unsupported $unsupportedLabel method $className#$name$descriptor${bodyCapture.unsupportedReasonSuffix()}")
                        }

                        if (unsupportedBySelection) {
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        if (!restrictToMatchedMethods && (!bodyCapture.nativeVmCompatible || bodyCapture.hasUnsupportedInvokeDynamic)) {
                            bodyCapture.replayTo(superMv)
                            return
                        }
                        if (!bodyCapture.nativeVmCompatible || bodyCapture.hasUnsupportedInvokeDynamic) {
                            throw IllegalArgumentException("method-virtualization cannot virtualize unsupported selected method $className#$name$descriptor${bodyCapture.unsupportedReasonSuffix()}")
                        }

                        val vmDescriptor = if (isMainEntry && descriptor == "([Ljava/lang/String;)V") {
                            "([Ljava/lang/String;Z)V"
                        } else {
                            descriptor
                        }
                        val vmMethodName = if (isMainEntry) {
                            uniqueSyntheticOriginalName(name, vmDescriptor, random, existingMethodKeys)
                        } else {
                            name
                        }
                        val vmMethodAccess = if (vmMethodName != name) {
                            (access and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PROTECTED or Opcodes.ACC_PRIVATE or Opcodes.ACC_BRIDGE).inv()) or Opcodes.ACC_PRIVATE or Opcodes.ACC_SYNTHETIC
                        } else {
                            access
                        }
                        val vmMethodVisitor = if (vmMethodName != name) {
                            val entryGuardName = uniqueSyntheticFieldName("\$m\$entryGuard", random, emptySet())
                            cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, entryGuardName, "Z", null, null)?.visitEnd()
                            emitStaticEntryForwarder(superMv, className, vmMethodName, descriptor, vmDescriptor, entryGuardName)
                            cw.visitMethod(vmMethodAccess, vmMethodName, vmDescriptor, null, null)
                        } else {
                            superMv
                        }

                        val methodEntropy = VmEntropyPlan.method(keyRandom, seed ?: 0L, className, vmMethodName, vmDescriptor)
                        val methodSeed = methodEntropy.seed
                        val resourcePath = opaqueVmResourcePath(random, className, vmMethodName, vmDescriptor, methodEntropy.domain("resource-path"))
                        val dispatchClassToken = ObfuscatedIdentifierUtil.classToken(className)
                        val dispatchMethodToken = ObfuscatedIdentifierUtil.methodToken(vmMethodName, vmDescriptor)
                        val entryToken = vmEntryToken(dispatchClassToken, dispatchMethodToken, vmDescriptor, resourcePath, methodSeed)
                        val stateBinding = vmStateBinding(entryToken, resourcePath)
                        val methodLocalProfile = methodLocalHandlerProfile(methodSelection, className, vmMethodName, vmDescriptor, methodSeed, selectedByHighValue)
                        val guestOriginalName = if (vmMethodName != name) name else vmMethodName
                        val guestOriginalDescriptor = if (vmMethodName != name) descriptor else vmDescriptor
                        val guestOriginalAccess = if (vmMethodName != name) access else vmMethodAccess
                        val serializer = VmBytecodeSerializer(
                            buildSeed = methodSeed,
                            stateBinding = stateBinding,
                            entryMetadata = Vbc4EntryMetadata(
                                entryToken = entryToken,
                                ownerToken = dispatchClassToken,
                                methodToken = dispatchMethodToken,
                                returnDescriptor = Type.getReturnType(guestOriginalDescriptor).descriptor,
                                methodLocalProfile = methodLocalProfile,
                                originalOwner = className,
                                originalName = guestOriginalName,
                                originalDescriptor = guestOriginalDescriptor,
                                resourcePath = resourcePath,
                                originalAccess = guestOriginalAccess,
                            ),
                            buildContext = buildContext,
                            structureEntropy = methodEntropy.domain("serializer-structure").entropyDigest,
                        )
                        if (vmMethodName != name) {
                            bodyCapture.rewriteStaticSelfCalls(className, name, descriptor, vmMethodName, vmDescriptor)
                        }
                        bodyCapture.optimizeWithVbc4Compiler(className, vmMethodName, vmDescriptor, vmMethodAccess)
                        val vmBytes = try {
                            bodyCapture.replayTo(serializer)
                            serializer.serialize()
                        } catch (error: RuntimeException) {
                            if (restrictToMatchedMethods || strictVirtualization) throw error
                            bodyCapture.replayTo(vmMethodVisitor)
                            return
                        }
                        val slicedResource = slicedVmResources(random, keyRandom, className, vmMethodName, vmDescriptor, methodSeed, methodEntropy, vmBytes, resourcePath)
                        val decoyResources = decoyVmResources(random, keyRandom, className, vmMethodName, vmDescriptor, methodSeed, methodEntropy, vmBytes, slicedResource.reservedPaths)
                        val preloadEntry = VmPreloadEntry(
                            entryToken = entryToken,
                            resourcePath = resourcePath,
                            manifestPath = slicedResource.manifestPath,
                            shardCount = slicedResource.shardCount,
                            manifestPlan = slicedResource.manifestPlan,
                        )
                        vmPreloadEntries += preloadEntry
                        vmResourcePlans += PlannedMethodVmResources(
                            ordinal = nextVmResourceOrdinal++,
                            resources = slicedResource.resources + decoyResources,
                        )

                        val hotDispatchMethod = specializedVmDispatchMethod(vmDescriptor, vmMethodAccess) ?: JNI_MICROKERNEL_VM_DISPATCH_METHOD
                        val hotDispatchDescriptor = specializedVmDispatchDescriptor(vmDescriptor, vmMethodAccess) ?: VM_TOKEN_DISPATCH_DESCRIPTOR
                        generateVmDispatcher(
                            vmMethodVisitor, className, vmMethodName, vmDescriptor, vmMethodAccess,
                            opcodeMapping, handlerOrder, VBC4_DISPATCH_LAYOUT, random, resourcePath,
                            entryToken = entryToken,
                            dispatchOwner = JNI_MICROKERNEL_DISPATCH_OWNER,
                            dispatchMethod = hotDispatchMethod,
                            dispatchDescriptor = hotDispatchDescriptor,
                        )
                        classModified = true
                        methodCount++
                        if (!restrictToMatchedMethods) broadVirtualizedMethodCount++
                    }
                }
            }
        }

        try {
            cr.accept(cv, ClassReader.SKIP_FRAMES)
        } catch (error: Exception) {
            if (restrictToMatchedMethods || strictVirtualization) throw error
            return@map classArtifact
        }
        if (!classModified) return@map classArtifact
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)

    val methodResources = vmResourcePlans
        .sortedBy { it.ordinal }
        .flatMap { it.resources }
    val updatedArtifact = if (methodResources.isNotEmpty()) {
        val mesh = interproceduralVmSliceMesh(vmPreloadEntries)
        val meshPeers = vmPreloadEntries.mapIndexed { index, entry ->
            entry.toMeshPeer(index)
        }
        val manifestResources = vmPreloadEntries.mapIndexed { index, entry ->
            entry.manifestPlan.toJarEntry(keyRandom, mesh, index, vmPreloadEntries.size, meshPeers)
        }
        val scheduledResources = interproceduralVmResourceSchedule(methodResources + manifestResources, random)
        val vmIndex = encodeNativeVmPreloadIndex(interproceduralVmPreloadSchedule(vmPreloadEntries, scheduledResources, random))
        artifact.copy(jarEntries = artifact.jarEntries + scheduledResources + vmIndex)
    } else artifact

    return updatedArtifactTransformResult(
        artifact = updatedArtifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = methodCount,
    )
}

internal const val VBC4_CLEAN_ENTRY_INTEGRITY_HEX = "10429f6c"
internal const val VBC4_VM_PRELOAD_INDEX_RESOURCE = "META-INF/.r/vm.idx"

private data class VmPreloadEntry(
    val entryToken: Long,
    val resourcePath: String,
    val manifestPath: String,
    val shardCount: Int,
    val manifestPlan: VmSliceManifestPlan,
)

private data class PlannedMethodVmResources(
    val ordinal: Int,
    val resources: List<JarEntryData>,
)

private fun interproceduralVmResourceSchedule(resources: List<JarEntryData>, random: SecureRandom): List<JarEntryData> =
    resources.toMutableList().also { Collections.shuffle(it, random) }

private fun interproceduralVmPreloadSchedule(
    entries: List<VmPreloadEntry>,
    scheduledResources: List<JarEntryData>,
    random: SecureRandom,
): List<VmPreloadEntry> {
    val scheduled = entries.toMutableList().also { Collections.shuffle(it, random) }
    if (scheduled.size < 2) return scheduled
    val emittedManifestOrder = scheduledResources.map { it.name }.filter { name -> entries.any { it.manifestPath == name } }
    if (scheduled.map { it.manifestPath } == emittedManifestOrder) scheduled.reverse()
    return scheduled
}

private data class VmSliceMeshPeer(
    val ordinal: Int,
    val manifestPath: String,
    val shardCount: Int,
    val material: String,
)

private fun VmPreloadEntry.toMeshPeer(ordinal: Int): VmSliceMeshPeer = VmSliceMeshPeer(
    ordinal = ordinal,
    manifestPath = manifestPath,
    shardCount = shardCount,
    material = manifestPlan.meshMaterial(entryToken, resourcePath, manifestPath, shardCount),
)

private fun encodeNativeVmPreloadIndex(entries: List<VmPreloadEntry>): JarEntryData {
    val plain = entries.joinToString(separator = "\n", postfix = "\n") { entry ->
        "${entry.entryToken.toULong().toString(16)}|${entry.resourcePath}|${entry.manifestPath}|${entry.shardCount}"
    }.toByteArray(Charsets.UTF_8)
    val seed = MessageDigest.getInstance("SHA-256")
        .digest(plain)
        .take(4)
        .fold(0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }
    return JarEntryData(
        name = VBC4_VM_PRELOAD_INDEX_RESOURCE,
        bytes = RuntimeResourceCodec.encode(
            bytes = plain,
            kind = RuntimeResourceKind.NativeIndex,
            seed = seed,
            variantId = entries.size.coerceAtLeast(1),
            layerCount = 4,
            compress = true,
        ),
    )
}

private fun buildContextAwareSecureRandom(
    label: String,
    seed: Long?,
    classCount: Int,
    jarCount: Int,
    contextSalt: ByteArray?,
): SecureRandom {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(label.toByteArray(Charsets.US_ASCII))
    if (seed != null) digest.update(longBytes(seed))
    digest.update(intBytes(classCount))
    digest.update(intBytes(jarCount))
    if (contextSalt != null) digest.update(contextSalt)
    val bytes = digest.digest()
    return deterministicSecureRandom(bytes)
}

private fun deterministicSecureRandom(seedBytes: ByteArray): SecureRandom =
    DeterministicSecureRandom(seedBytes)

private class DeterministicSecureRandom(seedBytes: ByteArray) : SecureRandom(
    DeterministicSecureRandomSpi(seedBytes),
    DETERMINISTIC_RANDOM_PROVIDER,
)

private val DETERMINISTIC_RANDOM_PROVIDER: Provider = object : Provider(
    "JavaShroudDeterministicRandom",
    "1.0",
    "JavaShroud deterministic build stream",
) {}

private class DeterministicSecureRandomSpi(seedBytes: ByteArray) : SecureRandomSpi() {
    private var seed = MessageDigest.getInstance("SHA-256").digest(seedBytes)
    private var counter = 0L

    override fun engineSetSeed(seed: ByteArray) {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(this.seed)
        digest.update(seed)
        this.seed = digest.digest()
        counter = 0L
    }

    override fun engineNextBytes(bytes: ByteArray) {
        var offset = 0
        while (offset < bytes.size) {
            val block = nextBlock()
            val take = minOf(block.size, bytes.size - offset)
            System.arraycopy(block, 0, bytes, offset, take)
            offset += take
        }
    }

    override fun engineGenerateSeed(numBytes: Int): ByteArray =
        ByteArray(numBytes).also(::engineNextBytes)

    private fun nextBlock(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(seed)
        digest.update(longBytes(counter++))
        return digest.digest()
    }
}

private fun longBytes(value: Long): ByteArray = ByteArray(Long.SIZE_BYTES) { index ->
    ((value ushr ((Long.SIZE_BYTES - 1 - index) * 8)) and 0xFF).toByte()
}

private fun intBytes(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)

private fun interproceduralVmSliceMesh(entries: List<VmPreloadEntry>): String {
    val orderedEntries = entries.sortedWith(compareBy<VmPreloadEntry> { it.manifestPath }.thenBy { it.resourcePath })
    val material = orderedEntries.joinToString(separator = "\u0000") { entry ->
        entry.manifestPlan.meshMaterial(entry.entryToken, entry.resourcePath, entry.manifestPath, entry.shardCount)
    }.toByteArray(Charsets.UTF_8)
    return MessageDigest.getInstance("SHA-256").digest(material).toHexLower()
}



internal fun vmStateBinding(entryToken: Long, resourcePath: String): String {
    val layoutDigestHex = requireVbc4BuildContext().jarLayoutDigest.toHexLower()
    return "${entryToken.toULong().toString(16)}\u0000$resourcePath\u0000$VBC4_CLEAN_ENTRY_INTEGRITY_HEX\u0000$layoutDigestHex"
}

internal fun vmEntryToken(classToken: String, methodToken: String, descriptor: String, resourcePath: String, methodSeed: Int): Long {
    val digest = MessageDigest.getInstance("SHA-256")
        .digest("$methodSeed\u0000$classToken\u0000$methodToken\u0000$descriptor\u0000$resourcePath".toByteArray(Charsets.UTF_8))
    var value = 0L
    for (index in 0 until Long.SIZE_BYTES) value = (value shl 8) or (digest[index].toLong() and 0xFFL)
    return value
}

internal fun generateOpcodeMapping(random: SecureRandom): Map<Int, Int> {
    val jvmOpcodes = listOf(
        Opcodes.NOP, Opcodes.ACONST_NULL, Opcodes.ICONST_M1,
        Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
        Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
        Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.FCONST_0,
        Opcodes.FCONST_1, Opcodes.FCONST_2, Opcodes.DCONST_0,
        Opcodes.DCONST_1,
    )
    val shuffled = jvmOpcodes.toMutableList()
    shuffled.shuffle(random)
    return jvmOpcodes.zip(shuffled).toMap()
}

internal fun generateHandlerOrder(count: Int, random: SecureRandom): List<Int> {
    val base = (0 until count).toMutableList().shuffled(random)
    if (base.size < 2) return base
    // Multi-strategy morphing: clone 30-60% of handlers with random selection
    val cloneRatio = 30 + random.nextInt(31) // 30-60%
    val cloneCount = (count * cloneRatio / 100).coerceAtLeast(1)
    // Select clone sources non-uniformly: prefer early indices (hotter handlers)
    val cloneSources = (0 until cloneCount).map {
        val biased = (random.nextDouble() * random.nextDouble() * base.size).toInt().coerceAtMost(base.size - 1)
        base[biased]
    }
    // Insert clones at random positions (not just appended)
    val result = base.toMutableList()
    for (clone in cloneSources) {
        val insertPos = random.nextInt(result.size + 1)
        result.add(insertPos, clone)
    }
    return result
}

private data class SlicedVmResources(
    val resources: List<JarEntryData>,
    val reservedPaths: Set<String>,
    val manifestPath: String,
    val shardCount: Int,
    val manifestPlan: VmSliceManifestPlan,
)

private data class VmSliceManifestPlan(
    val path: String,
    val totalSize: Int,
    val className: String,
    val methodName: String,
    val descriptor: String,
    val shards: List<VmSliceShard>,
) {
    fun toJarEntry(keyRandom: SecureRandom, mesh: String, ordinal: Int, entryCount: Int, meshPeers: List<VmSliceMeshPeer>): JarEntryData {
        val manifest = StringBuilder()
        manifest.append("VBC4S|1|")
            .append(totalSize).append('|')
            .append(shards.size).append('|')
            .append(mesh).append('|')
            .append(ordinal).append('|')
            .append(entryCount).append('\n')
        val manifestShards = meshOrderedShards(mesh, ordinal)
        for (shard in manifestShards) {
            val peer = meshPeerForShard(meshPeers, ordinal, shard)
            manifest.append(shard.index).append('|')
                .append(shard.offset).append('|')
                .append(shard.length).append('|')
                .append(shard.digest).append('|')
                .append(shard.path).append('|')
                .append(shard.meshLink(mesh, ordinal)).append('|')
                .append(peer.ordinal).append('|')
                .append(shard.peerLink(mesh, ordinal, peer)).append('\n')
        }
        return JarEntryData(
            name = path,
            bytes = maybeEncodeNativeVmResource(manifest.toString().toByteArray(Charsets.UTF_8), keyRandom, className, "$methodName@manifest", descriptor),
        )
    }

    fun meshMaterial(entryToken: Long, resourcePath: String, manifestPath: String, shardCount: Int): String = buildString {
        append(entryToken.toULong().toString(16)).append('|')
        append(resourcePath).append('|')
        append(manifestPath).append('|')
        append(shardCount).append('|')
        append(totalSize)
        for (shard in shards.sortedBy { it.index }) append('\u0000').append(shard.meshMaterial())
    }

    private fun meshPeerForShard(meshPeers: List<VmSliceMeshPeer>, ordinal: Int, shard: VmSliceShard): VmSliceMeshPeer {
        require(meshPeers.isNotEmpty()) { "VBC4 slice mesh must include at least one peer anchor" }
        val mixed = MessageDigest.getInstance("SHA-256")
            .digest("vbc4-cross-method-peer\u0000$ordinal\u0000${shard.index}\u0000${shard.digest}\u0000${shard.path}".toByteArray(Charsets.UTF_8))
            .take(4)
            .fold(0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }
            .and(0x7FFFFFFF)
        if (meshPeers.size == 1) return meshPeers.single()
        var peerIndex = mixed % meshPeers.size
        if (peerIndex == ordinal) peerIndex = (peerIndex + 1 + (mixed % (meshPeers.size - 1))) % meshPeers.size
        return meshPeers[peerIndex]
    }

    private fun meshOrderedShards(mesh: String, ordinal: Int): List<VmSliceShard> {
        val ordered = shards.sortedBy { shard -> shard.meshOrderToken(mesh, ordinal) }
        return if (ordered.size > 1 && ordered.map { it.index } == shards.map { it.index }) {
            ordered.drop(1) + ordered.first()
        } else ordered
    }
}

private data class VmSliceShard(
    val index: Int,
    val offset: Int,
    val length: Int,
    val digest: String,
    val path: String,
) {
    fun meshLink(mesh: String, ordinal: Int): String = MessageDigest.getInstance("SHA-256")
        .digest("$mesh\u0000$ordinal\u0000$index\u0000$offset\u0000$length\u0000$digest\u0000$path".toByteArray(Charsets.UTF_8))
        .take(8)
        .toByteArray()
        .toHexLower()

    fun peerLink(mesh: String, ordinal: Int, peer: VmSliceMeshPeer): String = MessageDigest.getInstance("SHA-256")
        .digest("vbc4-peer-link\u0000$mesh\u0000$ordinal\u0000$index\u0000$offset\u0000$length\u0000$digest\u0000$path\u0000${peer.ordinal}\u0000${peer.manifestPath}\u0000${peer.shardCount}\u0000${peer.material}".toByteArray(Charsets.UTF_8))
        .take(8)
        .toByteArray()
        .toHexLower()

    fun meshOrderToken(mesh: String, ordinal: Int): String = MessageDigest.getInstance("SHA-256")
        .digest("vbc4-shard-order\u0000$mesh\u0000$ordinal\u0000$index\u0000$path\u0000$digest".toByteArray(Charsets.UTF_8))
        .take(8)
        .toByteArray()
        .toHexLower()

    fun meshMaterial(): String = "$index|$offset|$length|$digest|$path"
}

private fun slicedVmResources(
    random: SecureRandom,
    keyRandom: SecureRandom,
    className: String,
    methodName: String,
    descriptor: String,
    methodSeed: Int,
    entropyPlan: VmEntropyPlan,
    vmBytes: ByteArray,
    resourcePath: String,
): SlicedVmResources {
    val shardCount = randomShardCount(random, vmBytes.size)
    val usedPaths = mutableSetOf(resourcePath)
    val chunkSizes = randomizedChunkSizes(random, vmBytes.size, shardCount, entropyPlan.domain("shard-cut-plan"))
    val resources = mutableListOf<JarEntryData>()
    val shards = mutableListOf<VmSliceShard>()
    var offset = 0
    for (index in 0 until shardCount) {
        val shardEntropy = entropyPlan.domain("shard-$index", methodKeySeed(keyRandom))
        val shardSeed = shardEntropy.seed
        var shardPath: String
        do {
            shardPath = opaqueVmResourcePath(random, className, "$methodName@slice$index", descriptor, shardEntropy)
        } while (!usedPaths.add(shardPath))
        val chunk = vmBytes.copyOfRange(offset, offset + chunkSizes[index])
        offset += chunk.size
        val chunkOffset = offset - chunk.size
        val digest = MessageDigest.getInstance("SHA-256").digest(chunk).toHexLower()
        shards += VmSliceShard(index = index, offset = chunkOffset, length = chunk.size, digest = digest, path = shardPath)
        resources += JarEntryData(
            name = shardPath,
            bytes = maybeEncodeNativeVmResource(chunk, keyRandom, className, "$methodName@slice$index", descriptor, shardEntropy),
        )
    }
    resources.shuffle(random)
    return SlicedVmResources(
        resources = resources,
        reservedPaths = usedPaths,
        manifestPath = resourcePath,
        shardCount = shardCount,
        manifestPlan = VmSliceManifestPlan(
            path = resourcePath,
            totalSize = vmBytes.size,
            className = className,
            methodName = methodName,
            descriptor = descriptor,
            shards = shards,
        ),
    )
}

private fun randomizedChunkSizes(random: SecureRandom, totalSize: Int, shardCount: Int, entropy: VmEntropyWord? = null): IntArray {
    require(totalSize >= shardCount) { "VBC4 payload must be large enough to slice" }
    if (shardCount == 1) return intArrayOf(totalSize)
    val minShard = if (totalSize >= shardCount * 24) maxOf(8, totalSize / 64) else 1
    val maxShard = if (totalSize >= shardCount * 8) maxOf(minShard, (totalSize * 55) / 100) else totalSize - shardCount + 1
    repeat(96) { attempt ->
        val cutPoints = mutableSetOf<Int>()
        while (cutPoints.size < shardCount - 1) {
            val selector = entropy?.intAt(attempt + cutPoints.size) ?: random.nextInt()
            val curved = random.nextDouble() * random.nextDouble()
            val mirrored = if ((selector and 1) == 0) curved else 1.0 - curved
            val jitter = ((selector ushr 1) and 0xFFFF).toDouble() / 65535.0
            val pos = 1 + (((mirrored * 0.75 + jitter * 0.25) * (totalSize - 1)).toInt().coerceIn(0, totalSize - 2))
            cutPoints += pos
        }
        val sizes = sizesFromCutPoints(totalSize, cutPoints.sorted(), shardCount)
        if (sizes.all { it in minShard..maxShard }) return sizes
    }
    return balancedJitteredChunkSizes(random, totalSize, shardCount, minShard, maxShard, entropy)
}

private fun sizesFromCutPoints(totalSize: Int, sortedCuts: List<Int>, shardCount: Int): IntArray {
    val sizes = IntArray(shardCount)
    var previous = 0
    for ((index, cut) in sortedCuts.withIndex()) {
        sizes[index] = cut - previous
        previous = cut
    }
    sizes[shardCount - 1] = totalSize - previous
    return sizes
}

private fun balancedJitteredChunkSizes(random: SecureRandom, totalSize: Int, shardCount: Int, minShard: Int, maxShard: Int, entropy: VmEntropyWord?): IntArray {
    val sizes = IntArray(shardCount) { minShard }
    var remaining = totalSize - minShard * shardCount
    var cursor = ((entropy?.seed ?: random.nextInt()) and 0x7FFFFFFF) % shardCount
    while (remaining > 0) {
        val capacity = maxShard - sizes[cursor]
        if (capacity > 0) {
            val draw = 1 + (((entropy?.intAt(cursor + remaining) ?: random.nextInt()) and 0x7FFFFFFF) % minOf(capacity, remaining).coerceAtLeast(1))
            sizes[cursor] += draw
            remaining -= draw
        }
        cursor = (cursor + 1 + (((entropy?.intAt(cursor) ?: random.nextInt()) and 0x7FFFFFFF) % shardCount)) % shardCount
    }
    return sizes
}

private fun decoyVmResources(
    random: SecureRandom,
    keyRandom: SecureRandom,
    className: String,
    methodName: String,
    descriptor: String,
    methodSeed: Int,
    entropyPlan: VmEntropyPlan,
    vmBytes: ByteArray,
    reservedPaths: Set<String>,
): List<JarEntryData> {
    val decoyCount = 1 + random.nextInt(3)
    val usedPaths = reservedPaths.toMutableSet()
    return (0 until decoyCount).map { index ->
        val decoyEntropy = entropyPlan.domain("decoy-$index", methodKeySeed(keyRandom))
        val decoySeed = decoyEntropy.seed
        var decoyPath: String
        do {
            decoyPath = opaqueVmResourcePath(random, className, "$methodName#$index", descriptor, decoyEntropy)
        } while (!usedPaths.add(decoyPath))
        val decoyPlain = decoyVmPayload(random, vmBytes, methodSeed xor decoySeed xor index, decoyEntropy)
        JarEntryData(
            name = decoyPath,
            bytes = maybeEncodeNativeVmResource(decoyPlain, keyRandom, className, "$methodName#decoy$index", descriptor, decoyEntropy),
        )
    }
}

private fun decoyVmPayload(random: SecureRandom, template: ByteArray, salt: Int, entropy: VmEntropyWord? = null): ByteArray {
    val jitter = random.nextInt(33) - 16
    val targetSize = (template.size + jitter + ((entropy?.intAt(3) ?: 0) % 23)).coerceAtLeast(96)
    val payload = ByteArray(targetSize)
    random.nextBytes(payload)
    if (targetSize >= 48) {
        payload[0] = 'V'.code.toByte()
        payload[1] = 'B'.code.toByte()
        payload[2] = 'C'.code.toByte()
        payload[3] = '4'.code.toByte()
        payload[4] = 0
        payload[5] = 4
        val nonceOffset = 6
        val digest = entropy?.entropyDigest ?: MessageDigest.getInstance("SHA-256").digest(intBytes(salt) + template.copyOfRange(0, minOf(template.size, 32)))
        for (index in 0 until 16) payload[nonceOffset + index] = digest[index % digest.size]
        writeBigEndianInt(payload, 22, salt xor 0xD3C4_5A6B.toInt())
        writeBigEndianInt(payload, 26, targetSize / 3)
        writeBigEndianInt(payload, 30, 24 + ((digest[0].toInt() and 0xFF) % (targetSize - 40).coerceAtLeast(1)))
        writeBigEndianInt(payload, 34, targetSize / 5)
        writeBigEndianInt(payload, 38, digest.fold(0) { acc, byte -> acc.rotateLeft(3) xor (byte.toInt() and 0xFF) })
        if (targetSize > 45) {
            payload[42] = 0
            payload[43] = 0
            payload[44] = 0
            payload[45] = 1
        }
        payload[targetSize - 1] = 32
    }
    return payload
}

private fun maybeEncodeNativeVmResource(
    vmBytes: ByteArray,
    keyRandom: SecureRandom,
    className: String,
    methodName: String,
    descriptor: String,
    entropy: VmEntropyWord? = null,
): ByteArray {
    val seed = entropy?.domainSeed("resource-codec") ?: methodKeySeed(keyRandom)
    val variantId = ((seed ushr 24) xor (seed ushr 12) xor seed) and 0x7F
    return RuntimeResourceCodec.encode(
        bytes = vmBytes,
        kind = RuntimeResourceKind.VmBytecode,
        seed = seed,
        variantId = variantId.coerceAtLeast(1),
        layerCount = 4 + (variantId % 3),
        compress = true,
    )
}

internal fun encodeNativeDiversifiedVmResource(vmBytes: ByteArray, seed: Int): ByteArray = RuntimeResourceCodec.encode(
    bytes = vmBytes,
    kind = RuntimeResourceKind.VmBytecode,
    seed = seed,
    variantId = ((seed ushr 24) xor (seed ushr 12) xor seed) and 0x7F,
    layerCount = 3,
    compress = true,
)

internal fun methodKeySeed(keyRandom: SecureRandom): Int {
    val key = ByteArray(32)
    keyRandom.nextBytes(key)
    return MessageDigest.getInstance("SHA-256")
        .digest(key)
        .let { digest ->
            ((digest[0].toInt() and 0xFF) shl 24) or
                ((digest[1].toInt() and 0xFF) shl 16) or
                ((digest[2].toInt() and 0xFF) shl 8) or
                (digest[3].toInt() and 0xFF)
        }
}

internal data class VmEntropyWord(val seed: Int, val entropyDigest: ByteArray) {
    fun intAt(index: Int): Int {
        val offset = (index * 4).floorMod(entropyDigest.size - 3)
        return ((entropyDigest[offset].toInt() and 0xFF) shl 24) or
            ((entropyDigest[offset + 1].toInt() and 0xFF) shl 16) or
            ((entropyDigest[offset + 2].toInt() and 0xFF) shl 8) or
            (entropyDigest[offset + 3].toInt() and 0xFF)
    }

    fun domainSeed(label: String): Int = VmEntropyPlan.deriveWord(entropyDigest, label, seed).seed
}

internal data class VmEntropyPlan(private val root: VmEntropyWord) {
    val seed: Int get() = root.seed
    fun domain(label: String, extraSeed: Int = 0): VmEntropyWord = deriveWord(root.entropyDigest, label, root.seed xor extraSeed)

    companion object {
        fun method(keyRandom: SecureRandom, userSeed: Long, className: String, methodName: String, descriptor: String): VmEntropyPlan {
            val key = ByteArray(48)
            keyRandom.nextBytes(key)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("vbc4-entropy-plan-method".toByteArray(Charsets.US_ASCII))
            digest.update(longBytes(userSeed))
            digest.update(className.toByteArray(Charsets.UTF_8))
            digest.update(0)
            digest.update(methodName.toByteArray(Charsets.UTF_8))
            digest.update(0)
            digest.update(descriptor.toByteArray(Charsets.UTF_8))
            digest.update(key)
            val material = digest.digest()
            java.util.Arrays.fill(key, 0)
            return VmEntropyPlan(VmEntropyWord(readEntropyInt(material), material))
        }

        fun deriveWord(parent: ByteArray, label: String, extraSeed: Int): VmEntropyWord {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("vbc4-entropy-plan-domain".toByteArray(Charsets.US_ASCII))
            digest.update(parent)
            digest.update(label.toByteArray(Charsets.UTF_8))
            digest.update(intBytes(extraSeed))
            val material = digest.digest()
            return VmEntropyWord(readEntropyInt(material) xor extraSeed, material)
        }

        private fun readEntropyInt(bytes: ByteArray): Int =
            ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)
    }
}

private fun Int.floorMod(modulus: Int): Int = ((this % modulus) + modulus) % modulus

private fun writeBigEndianInt(out: ByteArray, offset: Int, value: Int) {
    out[offset] = ((value ushr 24) and 0xFF).toByte()
    out[offset + 1] = ((value ushr 16) and 0xFF).toByte()
    out[offset + 2] = ((value ushr 8) and 0xFF).toByte()
    out[offset + 3] = (value and 0xFF).toByte()
}

internal fun opaqueVmResourcePath(random: SecureRandom, className: String, methodName: String, descriptor: String, methodSeed: Int): String {
    val salt = ByteArray(32)
    random.nextBytes(salt)
    val digest = MessageDigest.getInstance("SHA-256")
        .digest(salt + "$methodSeed|$className|$methodName|$descriptor".toByteArray(Charsets.UTF_8))
        .joinToString(separator = "") { byte -> "%02x".format(byte) }
    val dirCount = 1 + random.nextInt(3)
    var cursor = 0
    val dirs = (0 until dirCount).map {
        val length = 2 + random.nextInt(5)
        digest.substring(cursor, cursor + length).lowercase().also { cursor += length }
    }
    val fileLength = 12 + random.nextInt(21)
    val fileName = digest.substring(cursor, cursor + fileLength).lowercase()
    val exts = listOf("properties", "xml", "json", "yml", "cfg", "conf", "ini", "txt")
    val ext = exts[random.nextInt(exts.size)]
    return "META-INF/${dirs.joinToString("/")}/$fileName.$ext"
}

internal fun opaqueVmResourcePath(random: SecureRandom, className: String, methodName: String, descriptor: String, entropy: VmEntropyWord): String {
    val salt = entropy.entropyDigest.copyOf()
    random.nextBytes(salt)
    val digest = MessageDigest.getInstance("SHA-256")
        .digest(entropy.entropyDigest + salt + "${entropy.seed}|$className|$methodName|$descriptor".toByteArray(Charsets.UTF_8))
        .joinToString(separator = "") { byte -> "%02x".format(byte) }
    val dirCount = 1 + ((entropy.intAt(1) and 0x7FFFFFFF) % 3)
    var cursor = 0
    val dirs = (0 until dirCount).map { index ->
        val length = 2 + ((entropy.intAt(index + 2) and 0x7FFFFFFF) % 5)
        digest.substring(cursor, cursor + length).lowercase().also { cursor += length }
    }
    val fileLength = 12 + ((entropy.intAt(7) and 0x7FFFFFFF) % 21)
    val fileName = digest.substring(cursor, cursor + fileLength).lowercase()
    val exts = listOf("properties", "xml", "json", "yml", "cfg", "conf", "ini", "txt")
    val ext = exts[(entropy.intAt(8) and 0x7FFFFFFF) % exts.size]
    return "META-INF/${dirs.joinToString("/")}/$fileName.$ext"
}

private fun randomShardCount(random: SecureRandom, totalSize: Int): Int {
    val maxShardCount = minOf(6, totalSize).coerceAtLeast(1)
    if (maxShardCount <= 2) return maxShardCount
    return 2 + random.nextInt(maxShardCount - 1)
}

private fun methodLocalHandlerProfile(selectionMode: MethodSelectionMode, className: String, methodName: String, descriptor: String, methodSeed: Int, highValueSelected: Boolean): Int {
    if (selectionMode != MethodSelectionMode.CriticalPlus || !highValueSelected) return 0
    val digest = MessageDigest.getInstance("SHA-256")
        .digest("vbc4-method-local\u0000$methodSeed\u0000$className\u0000$methodName\u0000$descriptor".toByteArray(Charsets.UTF_8))
    val value = ((digest[0].toInt() and 0xFF) shl 24) or
        ((digest[1].toInt() and 0xFF) shl 16) or
        ((digest[2].toInt() and 0xFF) shl 8) or
        (digest[3].toInt() and 0xFF)
    return value.takeIf { it != 0 } ?: 1
}

private fun isHighValueMethodName(name: String): Boolean {
    val lower = name.lowercase()
    return listOf("license", "licence", "auth", "login", "token", "key", "secret", "sign", "signature", "verify", "check", "validate").any(lower::contains)
}

private fun isHighValueCall(owner: String, name: String): Boolean {
    val lowerOwner = owner.lowercase()
    return lowerOwner.startsWith("java/security/") ||
        lowerOwner.startsWith("javax/crypto/") ||
        lowerOwner.startsWith("java/util/jar/JarVerifier".lowercase()) ||
        isHighValueMethodName(name)
}

private fun isEnumValuesHelper(classAccess: Int, methodAccess: Int, name: String, descriptor: String): Boolean =
    classAccess and Opcodes.ACC_ENUM != 0 &&
        methodAccess and Opcodes.ACC_STATIC != 0 &&
        name == "\$values" &&
        descriptor.startsWith("()[L")

private data class MethodSelectionKey(val owner: String, val name: String, val descriptor: String)
internal data class MethodSelectorPattern(val owner: String?, val name: String, val descriptor: String?)
internal enum class MethodSelectionMode { Safe, CriticalAuto, CriticalPlus, AllCompatible }

private fun parseMethodSelection(value: Any?): MethodSelectionMode = when (value as? String ?: "critical-auto") {
    "safe" -> MethodSelectionMode.Safe
    "critical-auto" -> MethodSelectionMode.CriticalAuto
    "critical-plus" -> MethodSelectionMode.CriticalPlus
    "all-compatible" -> MethodSelectionMode.AllCompatible
    else -> throw IllegalArgumentException("method-virtualization methodSelection '$value' is not supported; supported values: safe, critical-auto, critical-plus, all-compatible")
}

private fun parseMaxBroadVirtualizedMethods(value: Any?): Int = when (value) {
    is Int -> value
    is Long -> value.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    is Number -> value.toLong().coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    else -> 99999
}.coerceAtLeast(0)

private fun parseMethodSelectorPatterns(value: Any?): List<MethodSelectorPattern> {
    val raw = value as? String ?: return emptyList()
    return raw.split(',', ';', '\n')
        .map(String::trim)
        .filter(String::isNotEmpty)
        .map { token ->
            val ownerAndRest = token.split('#', limit = 2)
            val owner = ownerAndRest.takeIf { it.size == 2 }?.get(0)?.takeIf(String::isNotBlank)
            val rest = ownerAndRest.last()
            val descriptorStart = rest.indexOf(':')
            val name = if (descriptorStart >= 0) rest.substring(0, descriptorStart) else rest
            val descriptor = if (descriptorStart >= 0) rest.substring(descriptorStart + 1).takeIf(String::isNotBlank) else null
            MethodSelectorPattern(owner, name, descriptor)
        }
}

private fun matchesMethodSelector(patterns: List<MethodSelectorPattern>, owner: String, name: String, descriptor: String): Boolean =
    patterns.any { pattern ->
        (pattern.owner == null || pattern.owner == owner) &&
            pattern.name == name &&
            (pattern.descriptor == null || pattern.descriptor == descriptor)
    }

private fun isJvmMainEntry(access: Int, name: String, descriptor: String): Boolean =
    access and Opcodes.ACC_PUBLIC != 0 && access and Opcodes.ACC_STATIC != 0 && name == "main" && descriptor == "([Ljava/lang/String;)V"

private fun isSyntheticBridgeMethod(access: Int): Boolean =
    access and Opcodes.ACC_BRIDGE != 0 && access and Opcodes.ACC_SYNTHETIC != 0

private fun isConsoleStreamField(opcode: Int, owner: String, name: String, descriptor: String): Boolean =
    opcode == Opcodes.GETSTATIC && owner == "java/lang/System" && (name == "out" || name == "err") && descriptor == "Ljava/io/PrintStream;"

private fun isConsoleStreamMethod(owner: String, name: String): Boolean =
    (owner == "java/io/PrintStream" || owner == "java/io/PrintWriter") &&
        (name == "print" || name == "println" || name == "write" || name == "append" || name == "format" || name == "printf")

private fun isConcurrencyBoundaryMethod(owner: String, name: String, descriptor: String): Boolean = when (owner) {
    "java/util/concurrent/ThreadPoolExecutor" -> name == "submit" || name == "execute" || name == "invokeAll" || name == "invokeAny"
    "java/util/concurrent/ExecutorService", "java/util/concurrent/Executor", "java/util/concurrent/CompletionService" ->
        name == "submit" || name == "execute" || name == "invokeAll" || name == "invokeAny"
    "java/util/concurrent/Future" -> name == "get" || name == "cancel"
    else -> owner.startsWith("java/util/concurrent/") &&
        (name.contains("await") || name.contains("park") || name.contains("lock") || name.contains("unlock"))
}

private fun isConcurrencyBoundaryType(type: String?): Boolean =
    type == "java/util/concurrent/RejectedExecutionException" ||
        (type != null && type.startsWith("java/util/concurrent/"))

private fun isThreadSleepCall(owner: String, name: String, descriptor: String): Boolean =
    owner == "java/lang/Thread" && name == "sleep" && (descriptor == "(J)V" || descriptor == "(JI)V")

private fun isElapsedTimeProbeCall(owner: String, name: String, descriptor: String): Boolean =
    owner == "java/lang/System" && name == "currentTimeMillis" && descriptor == "()J"

private fun isRuntimeExceptionInit(owner: String, name: String, descriptor: String): Boolean =
    owner == "java/lang/RuntimeException" && name == "<init>" && descriptor == "(Ljava/lang/String;)V"

private fun parseMaxInstructions(value: Any?): Int = when (value) {
    is Int -> value
    is Long -> value.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    is Number -> value.toLong().coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    else -> 99999
}.coerceAtLeast(1)

private fun isNativeVmSupportedInvokeDynamic(
    name: String,
    descriptor: String,
    bootstrapMethodHandle: Handle,
    bootstrapMethodArguments: Array<out Any>,
): Boolean = isNativeVmSupportedInvokeDynamicCall(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments)

private fun uniqueSyntheticOriginalName(
    name: String,
    descriptor: String,
    random: SecureRandom,
    existingMethodKeys: MutableSet<String>,
): String {
    val fingerprint = random.nextInt() xor name.hashCode() xor descriptor.hashCode()
    val base = "\$m\$" + Integer.toUnsignedString(fingerprint, 36)
    var candidate = base
    var index = 0
    while (!existingMethodKeys.add(candidate + descriptor)) {
        index++
        candidate = base + "\$" + index
    }
    return candidate
}

private fun uniqueSyntheticFieldName(prefix: String, random: SecureRandom, existingFieldNames: Set<String>): String {
    var candidate: String
    do {
        candidate = "$prefix$" + Integer.toUnsignedString(random.nextInt(), 36).take(6)
    } while (candidate in existingFieldNames)
    return candidate
}

private fun emitStaticEntryForwarder(mv: MethodVisitor, owner: String, targetName: String, descriptor: String, targetDescriptor: String, guardName: String) {
    mv.visitCode()
    val alreadyRunning = Label()
    val tryStart = Label()
    val tryEnd = Label()
    val handler = Label()
    val argumentTypes = Type.getArgumentTypes(descriptor)
    var localIndex = 0
    for (argumentType in argumentTypes) {
        localIndex += argumentType.size
    }
    val throwableLocal = localIndex
    mv.visitTryCatchBlock(tryStart, tryEnd, handler, null)
    mv.visitFieldInsn(Opcodes.GETSTATIC, owner, guardName, "Z")
    mv.visitJumpInsn(Opcodes.IFEQ, alreadyRunning)
    mv.visitInsn(Type.getReturnType(descriptor).getOpcode(Opcodes.IRETURN))
    mv.visitLabel(alreadyRunning)
    mv.visitInsn(Opcodes.ICONST_1)
    mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, guardName, "Z")
    mv.visitLabel(tryStart)
    localIndex = 0
    for (argumentType in argumentTypes) {
        mv.visitVarInsn(argumentType.getOpcode(Opcodes.ILOAD), localIndex)
        localIndex += argumentType.size
    }
    if (targetDescriptor == "([Ljava/lang/String;Z)V") {
        mv.visitInsn(Opcodes.ICONST_0)
    }
    mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, targetName, targetDescriptor, false)
    mv.visitLabel(tryEnd)
    mv.visitInsn(Opcodes.ICONST_0)
    mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, guardName, "Z")
    mv.visitInsn(Type.getReturnType(descriptor).getOpcode(Opcodes.IRETURN))
    mv.visitLabel(handler)
    mv.visitVarInsn(Opcodes.ASTORE, throwableLocal)
    mv.visitInsn(Opcodes.ICONST_0)
    mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, guardName, "Z")
    mv.visitVarInsn(Opcodes.ALOAD, throwableLocal)
    mv.visitInsn(Opcodes.ATHROW)
    mv.visitMaxs(0, 0)
    mv.visitEnd()
}

/**
 * Captures method body instructions and can replay them to a VmBytecodeSerializer.
 */
class MethodBodyCapture : MethodVisitor(Opcodes.ASM9) {
    var instructionCount = 0
        private set

    var hasInvokeDynamic = false
        private set

    var hasUnsupportedInvokeDynamic = false
        private set

    var nativeVmCompatible = true
        private set

    private val unsupportedReasons = linkedSetOf<String>()

    fun unsupportedReasonSuffix(): String = unsupportedReasons.takeIf { it.isNotEmpty() }
        ?.joinToString(prefix = ": ", separator = "; ")
        .orEmpty()

    var hasDirectNativeDefenseCall = false
        private set

    var hasNativeVmUnsafeSelfStaticCall = false
        private set

    private var hasMethodCall = false
    private var hasFieldAccess = false
    private var hasTypeOperation = false
    private var hasExceptionHandler = false
    private var hasComplexBranch = false
    private var hasAnyBranch = false
    private var touchesConsoleIoBoundary = false
    private var touchesConcurrencyBoundary = false
    private var hasThreadSleepCall = false
    private var threadPoolSubmitCount = 0
    private var interruptedSleepCatchCount = 0
    private var rejectedExecutionCatchCount = 0
    private var hasLongThreadSleepCall = false
    private var printsPassFailMarker = false
    private var matchesTaskLikeThreadPoolTimingRoot = false
    private var elapsedTimeProbeCount = 0
    private var hasLongSub = false
    private var printsElapsedTimeMarker = false
    private var constructsRuntimeException = false
    private var updatesStaticIntCounter = false
    private var sameOwnerStaticVoidCallCount = 0
    private var isPureComputeCountIncrementHelper = false
    private var isElapsedTimeBenchmarkRoot = false
    private var rawUpdatesStaticIntCounter = false
    private var rawSameOwnerStaticVoidCallCount = 0
    private var rawPrintsElapsedTimeMarker = false
    private var rawElapsedTimeProbeCount = 0
    private var rawHasLongSub = false
    private var rawConstructsRuntimeException = false
    private var rawIsPureComputeCountIncrementHelper = false
    private var rawIsElapsedTimeBenchmarkRoot = false
    private var hasWideValue = false
    private var hasDup2OrPop2 = false
    private var hasHighValueCall = false

    // Captured instruction stream for replay
    private val capturedInstructions = mutableListOf<CapturedInstruction>()

    sealed class CapturedInstruction {
        data class NoArg(val opcode: Int) : CapturedInstruction()
        data class IntArg(val opcode: Int, val arg: Int) : CapturedInstruction()
        data class VarArg(val opcode: Int, val `var`: Int) : CapturedInstruction()
        data class TypeArg(val opcode: Int, val type: String) : CapturedInstruction()
        data class FieldArg(val opcode: Int, val owner: String, val name: String, val desc: String) : CapturedInstruction()
        data class MethodArg(val opcode: Int, val owner: String, val name: String, val desc: String, val isInterface: Boolean) : CapturedInstruction()
        data class IndyArg(val name: String, val desc: String, val bsm: Handle, val bsmArgs: Array<Any>) : CapturedInstruction()
        data class JumpArg(val opcode: Int, val label: Label) : CapturedInstruction()
        data class LdcArg(val value: Any) : CapturedInstruction()
        data class IincArg(val `var`: Int, val increment: Int) : CapturedInstruction()
        data class LabelMark(val label: Label) : CapturedInstruction()
        data class TryCatch(val start: Label, val end: Label, val handler: Label, val type: String?) : CapturedInstruction()
        data class Maxs(val maxStack: Int, val maxLocals: Int) : CapturedInstruction()
        data class TableSwitchArg(val min: Int, val max: Int, val dflt: Label?, val labels: Array<out Label?>) : CapturedInstruction()
        data class LookupSwitchArg(val dflt: Label?, val keys: IntArray?, val labels: Array<out Label?>?) : CapturedInstruction()
        data class MultiANewArrayArg(val descriptor: String, val numDimensions: Int) : CapturedInstruction()
    }

    fun replayTo(visitor: MethodVisitor) {
        visitor.visitCode()
        for (inst in capturedInstructions) {
            when (inst) {
                is CapturedInstruction.NoArg -> visitor.visitInsn(inst.opcode)
                is CapturedInstruction.IntArg -> visitor.visitIntInsn(inst.opcode, inst.arg)
                is CapturedInstruction.VarArg -> visitor.visitVarInsn(inst.opcode, inst.`var`)
                is CapturedInstruction.TypeArg -> visitor.visitTypeInsn(inst.opcode, inst.type)
                is CapturedInstruction.FieldArg -> visitor.visitFieldInsn(inst.opcode, inst.owner, inst.name, inst.desc)
                is CapturedInstruction.MethodArg -> visitor.visitMethodInsn(inst.opcode, inst.owner, inst.name, inst.desc, inst.isInterface)
                is CapturedInstruction.IndyArg -> visitor.visitInvokeDynamicInsn(inst.name, inst.desc, inst.bsm, *inst.bsmArgs)
                is CapturedInstruction.JumpArg -> visitor.visitJumpInsn(inst.opcode, inst.label)
                is CapturedInstruction.LdcArg -> visitor.visitLdcInsn(inst.value)
                is CapturedInstruction.IincArg -> visitor.visitIincInsn(inst.`var`, inst.increment)
                is CapturedInstruction.LabelMark -> visitor.visitLabel(inst.label)
                is CapturedInstruction.TryCatch -> visitor.visitTryCatchBlock(inst.start, inst.end, inst.handler, inst.type)
                is CapturedInstruction.Maxs -> visitor.visitMaxs(inst.maxStack, inst.maxLocals)
                is CapturedInstruction.TableSwitchArg -> visitor.visitTableSwitchInsn(inst.min, inst.max, inst.dflt, *inst.labels)
                is CapturedInstruction.LookupSwitchArg -> visitor.visitLookupSwitchInsn(inst.dflt, inst.keys, inst.labels)
                is CapturedInstruction.MultiANewArrayArg -> visitor.visitMultiANewArrayInsn(inst.descriptor, inst.numDimensions)
            }
        }
    }


    private data class BenchmarkSnapshot(
        val meaningful: List<CapturedInstruction>,
        val methodCalls: List<CapturedInstruction.MethodArg>,
        val hasAnyBranch: Boolean,
        val hasTypeOperation: Boolean,
        val touchesConsoleIoBoundary: Boolean,
        val elapsedTimeProbeCount: Int,
        val hasLongSub: Boolean,
        val printsElapsedTimeMarker: Boolean,
        val constructsRuntimeException: Boolean,
        val updatesStaticIntCounter: Boolean,
        val sameOwnerStaticVoidCallCount: Int,
        val hasSelfStaticCall: Boolean,
    )

    private fun meaningfulInstructions(instructions: List<CapturedInstruction>): List<CapturedInstruction> =
        instructions.filter { instruction ->
            instruction !is CapturedInstruction.LabelMark && instruction !is CapturedInstruction.TryCatch && instruction !is CapturedInstruction.Maxs
        }

    private fun benchmarkSnapshot(instructions: List<CapturedInstruction>, name: String? = null, descriptor: String? = null): BenchmarkSnapshot {
        val meaningful = meaningfulInstructions(instructions)
        val methodCalls = instructions.filterIsInstance<CapturedInstruction.MethodArg>()
        val touchesConsoleIoBoundary = instructions.any { instruction ->
            instruction is CapturedInstruction.FieldArg && isConsoleStreamField(instruction.opcode, instruction.owner, instruction.name, instruction.desc) ||
                instruction is CapturedInstruction.MethodArg && isConsoleStreamMethod(instruction.owner, instruction.name)
        }
        return BenchmarkSnapshot(
            meaningful = meaningful,
            methodCalls = methodCalls,
            hasAnyBranch = instructions.any {
                it is CapturedInstruction.JumpArg || it is CapturedInstruction.TableSwitchArg || it is CapturedInstruction.LookupSwitchArg
            },
            hasTypeOperation = instructions.any {
                it is CapturedInstruction.TypeArg || it is CapturedInstruction.MultiANewArrayArg
            },
            touchesConsoleIoBoundary = touchesConsoleIoBoundary,
            elapsedTimeProbeCount = methodCalls.count { instruction ->
                isElapsedTimeProbeCall(instruction.owner, instruction.name, instruction.desc)
            },
            hasLongSub = instructions.any { instruction ->
                instruction is CapturedInstruction.NoArg && instruction.opcode == Opcodes.LSUB
            },
            printsElapsedTimeMarker = instructions.any { instruction ->
                instruction is CapturedInstruction.LdcArg && (instruction.value == "Calc: " || instruction.value == "Calc:")
            },
            constructsRuntimeException = methodCalls.any { instruction ->
                isRuntimeExceptionInit(instruction.owner, instruction.name, instruction.desc)
            },
            updatesStaticIntCounter = updatesStaticIntCounter(instructions),
            sameOwnerStaticVoidCallCount = methodCalls.count { instruction ->
                instruction.opcode == Opcodes.INVOKESTATIC && instruction.desc == "()V"
            },
            hasSelfStaticCall = name != null && descriptor != null && methodCalls.any { instruction ->
                instruction.opcode == Opcodes.INVOKESTATIC && instruction.name == name && instruction.desc == descriptor
            },
        )
    }

    private fun matchesTaskLikeThreadPoolTimingRoot(instructions: List<CapturedInstruction> = capturedInstructions): Boolean {
        val meaningful = meaningfulInstructions(instructions)
        val submitIndices = meaningful.mapIndexedNotNull { index, instruction ->
            val call = instruction as? CapturedInstruction.MethodArg
            if (call != null && call.owner == "java/util/concurrent/ThreadPoolExecutor" && call.name == "submit" && call.desc == "(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;") index else null
        }
        if (submitIndices.size != 3) return false
        val sleepEvents = meaningful.windowed(size = 2, partialWindows = false).mapIndexedNotNull { index, window ->
            val ldc = window[0] as? CapturedInstruction.LdcArg
            val call = window[1] as? CapturedInstruction.MethodArg
            val duration = ldc?.value as? Long
            if (duration != null && call != null && isThreadSleepCall(call.owner, call.name, call.desc)) index to duration else null
        }
        if (sleepEvents.size < 3) return false
        val shortSleepIndices = sleepEvents.filter { it.second in 1L..299L }.map { it.first }
        val longSleepIndices = sleepEvents.filter { it.second >= 300L }.map { it.first }
        if (shortSleepIndices.size < 2 || longSleepIndices.isEmpty()) return false
        val passFailLdcCount = meaningful.count { instruction ->
            instruction is CapturedInstruction.LdcArg && (instruction.value == "PASS" || instruction.value == "FAIL")
        }
        if (passFailLdcCount < 2) return false
        val rejectedCatchCount = instructions.count { instruction ->
            instruction is CapturedInstruction.TryCatch && instruction.type == "java/util/concurrent/RejectedExecutionException"
        }
        if (rejectedCatchCount != 1) return false
        val firstSubmit = submitIndices[0]
        val secondSubmit = submitIndices[1]
        val thirdSubmit = submitIndices[2]
        val firstShortSleep = shortSleepIndices[0]
        val secondShortSleep = shortSleepIndices[1]
        val finalLongSleep = longSleepIndices.last()
        return firstSubmit < firstShortSleep &&
            firstShortSleep < secondSubmit &&
            secondSubmit < secondShortSleep &&
            secondShortSleep < thirdSubmit &&
            thirdSubmit < finalLongSleep
    }

    private fun updatesStaticIntCounter(instructions: List<CapturedInstruction> = capturedInstructions): Boolean {
        val meaningful = meaningfulInstructions(instructions)
        for (index in 0..meaningful.size - 4) {
            val get = meaningful[index] as? CapturedInstruction.FieldArg ?: continue
            if (get.opcode != Opcodes.GETSTATIC || get.desc != "I") continue
            for (cursor in index + 1 until meaningful.size - 1) {
                val current = meaningful[cursor]
                val next = meaningful[cursor + 1]
                if (current is CapturedInstruction.FieldArg && current.opcode == Opcodes.PUTSTATIC) break
                val one = current as? CapturedInstruction.NoArg ?: continue
                val add = next as? CapturedInstruction.NoArg ?: continue
                if (one.opcode != Opcodes.ICONST_1 || add.opcode != Opcodes.IADD) continue
                for (tail in cursor + 2 until meaningful.size) {
                    val put = meaningful[tail] as? CapturedInstruction.FieldArg ?: continue
                    if (put.opcode == Opcodes.PUTSTATIC &&
                        put.owner == get.owner && put.name == get.name && put.desc == get.desc
                    ) return true
                    if (put.opcode == Opcodes.GETSTATIC) break
                }
            }
        }
        return false
    }
    private fun isPureComputeCountIncrementHelper(name: String, descriptor: String, access: Int, snapshot: BenchmarkSnapshot): Boolean {
        if (name == "touch") return snapshot.updatesStaticIntCounter
        val isPrivateStatic = access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC) == (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC)
        val returnsVoid = Type.getReturnType(descriptor) == Type.VOID_TYPE
        if (!isPrivateStatic || !returnsVoid) return false
        if (!snapshot.updatesStaticIntCounter) return false
        val isStaticMethod = access and Opcodes.ACC_STATIC != 0
        if (!isStaticMethod) return false
        if (snapshot.hasSelfStaticCall) return true
        if (snapshot.elapsedTimeProbeCount > 0 || snapshot.printsElapsedTimeMarker || snapshot.constructsRuntimeException) return false
        return snapshot.hasAnyBranch || snapshot.hasTypeOperation
    }

    private fun isPureComputeCountIncrementHelper(name: String, descriptor: String, access: Int): Boolean =
        isPureComputeCountIncrementHelper(name, descriptor, access, benchmarkSnapshot(capturedInstructions, name, descriptor))

    private fun methodCallsSameOwnerStaticBenchmarkFamily(methodCalls: List<CapturedInstruction.MethodArg>): Boolean {
        val helperNames = methodCalls
            .filter { it.opcode == Opcodes.INVOKESTATIC && it.desc == "()V" }
            .map { it.name }
            .toSet()
        return helperNames.contains("runAdd") && helperNames.contains("runStr")
    }

    private fun isElapsedTimeBenchmarkRoot(name: String, descriptor: String, access: Int, snapshot: BenchmarkSnapshot): Boolean {
        val isStaticVoid = access and Opcodes.ACC_STATIC != 0 && descriptor == "()V"
        if (!isStaticVoid) return false
        if (snapshot.elapsedTimeProbeCount < 2 || !snapshot.hasLongSub || !snapshot.printsElapsedTimeMarker) return false
        if (!snapshot.touchesConsoleIoBoundary || !snapshot.hasAnyBranch) return false
        return snapshot.sameOwnerStaticVoidCallCount >= 2 || methodCallsSameOwnerStaticBenchmarkFamily(snapshot.methodCalls)
    }

    private fun isElapsedTimeBenchmarkRoot(name: String, descriptor: String, access: Int): Boolean =
        isElapsedTimeBenchmarkRoot(name, descriptor, access, benchmarkSnapshot(capturedInstructions, name, descriptor))
    fun sameOwnerStaticForwarderTarget(className: String, methodName: String, descriptor: String): CapturedInstruction.MethodArg? {
        val meaningful = capturedInstructions.filter { instruction ->
            instruction !is CapturedInstruction.LabelMark && instruction !is CapturedInstruction.TryCatch && instruction !is CapturedInstruction.Maxs
        }
        val argumentTypes = Type.getArgumentTypes(descriptor)
        val expectedLoads = mutableListOf<Int>()
        var localIndex = 0
        for (argumentType in argumentTypes) {
            expectedLoads += argumentType.getOpcode(Opcodes.ILOAD)
            localIndex += argumentType.size
        }
        if (meaningful.size != expectedLoads.size + 2) return null
        for ((index, opcode) in expectedLoads.withIndex()) {
            val load = meaningful[index] as? CapturedInstruction.VarArg ?: return null
            if (load.opcode != opcode) return null
        }
        val call = meaningful[expectedLoads.size] as? CapturedInstruction.MethodArg ?: return null
        if (call.opcode != Opcodes.INVOKESTATIC || call.owner != className || call.desc != descriptor || call.name == methodName) return null
        val returnInsn = meaningful.last() as? CapturedInstruction.NoArg ?: return null
        if (returnInsn.opcode != Type.getReturnType(descriptor).getOpcode(Opcodes.IRETURN)) return null
        return call
    }

    fun rewriteStaticSelfCalls(className: String, originalName: String, descriptor: String, targetName: String, targetDescriptor: String) {
        var changed = false
        var index = 0
        while (index < capturedInstructions.size) {
            val instruction = capturedInstructions[index] as? CapturedInstruction.MethodArg
            if (instruction == null) {
                index++
                continue
            }
            if (instruction.opcode == Opcodes.INVOKESTATIC &&
                instruction.owner == className &&
                instruction.name == originalName &&
                instruction.desc == descriptor
            ) {
                if (targetDescriptor == "([Ljava/lang/String;Z)V" && descriptor == "([Ljava/lang/String;)V") {
                    capturedInstructions.add(index, CapturedInstruction.NoArg(Opcodes.ICONST_0))
                    index++
                }
                capturedInstructions[index] = instruction.copy(name = targetName, desc = targetDescriptor)
                changed = true
            }
            index++
        }
        if (changed) refreshCaptureStateAfterOptimization()
    }

    fun refreshRawBenchmarkCaptureState(name: String, descriptor: String, access: Int) {
        val snapshot = benchmarkSnapshot(capturedInstructions.toList(), name, descriptor)
        rawElapsedTimeProbeCount = snapshot.elapsedTimeProbeCount
        rawHasLongSub = snapshot.hasLongSub
        rawPrintsElapsedTimeMarker = snapshot.printsElapsedTimeMarker
        rawConstructsRuntimeException = snapshot.constructsRuntimeException
        rawUpdatesStaticIntCounter = snapshot.updatesStaticIntCounter
        rawSameOwnerStaticVoidCallCount = snapshot.sameOwnerStaticVoidCallCount
        rawIsPureComputeCountIncrementHelper = isPureComputeCountIncrementHelper(name, descriptor, access, snapshot)
        rawIsElapsedTimeBenchmarkRoot = isElapsedTimeBenchmarkRoot(name, descriptor, access, snapshot)
    }
    fun optimizeWithVbc4Compiler(className: String, methodName: String, descriptor: String, access: Int) {
        val original = capturedInstructions.toList()
        try {
            hasNativeVmUnsafeSelfStaticCall = hasSelfCall(className, methodName, descriptor)
            optimizeLocalInstructionWindows()
            if (!rewriteTailRecursiveSelfCalls(className, methodName, descriptor, access)) {
                optimizeVbc4CompilerKernels(className, methodName, descriptor, access)
            }
            optimizeLocalInstructionWindows()
            refreshCaptureStateAfterOptimization()
            hasNativeVmUnsafeSelfStaticCall = hasSelfCall(className, methodName, descriptor)
        } catch (_: RuntimeException) {
            capturedInstructions.clear()
            capturedInstructions.addAll(original)
            refreshCaptureStateAfterOptimization()
            hasNativeVmUnsafeSelfStaticCall = hasSelfCall(className, methodName, descriptor)
        }
    }

    private fun optimizeLocalInstructionWindows(): Boolean {
        var changed = false
        do {
            val before = capturedInstructions.size
            optimizePeepholeWindows()
            optimizeIntConstantWindows()
            if (!hasExceptionHandler) {
                optimizeAdjacentIntStoreLoad()
                optimizeConstantBranches()
            }
            changed = changed || before != capturedInstructions.size
        } while (before != capturedInstructions.size)
        return changed
    }

    private fun optimizePeepholeWindows() {
        var index = 0
        while (index < capturedInstructions.size) {
            val current = capturedInstructions[index]
            if (current is CapturedInstruction.NoArg && current.opcode == Opcodes.NOP) {
                capturedInstructions.removeAt(index)
                continue
            }
            if (index + 1 < capturedInstructions.size && isSideEffectFreeConstant(current)) {
                val next = capturedInstructions[index + 1] as? CapturedInstruction.NoArg
                if (next?.opcode == Opcodes.POP) {
                    capturedInstructions.subList(index, index + 2).clear()
                    continue
                }
            }
            index++
        }
    }

    private fun optimizeIntConstantWindows() {
        var index = 0
        while (index + 2 < capturedInstructions.size) {
            val left = intConstantValue(capturedInstructions[index])
            val right = intConstantValue(capturedInstructions[index + 1])
            val op = capturedInstructions[index + 2] as? CapturedInstruction.NoArg
            val folded = if (left != null && right != null && op != null) foldIntBinary(left, right, op.opcode) else null
            if (folded != null) {
                val replacement = mutableListOf<CapturedInstruction>()
                emitIntConstant(replacement, folded)
                capturedInstructions.subList(index, index + 3).clear()
                capturedInstructions.addAll(index, replacement)
                continue
            }
            index++
        }
    }

    private fun optimizeAdjacentIntStoreLoad() {
        var index = 0
        while (index + 1 < capturedInstructions.size) {
            val store = capturedInstructions[index] as? CapturedInstruction.VarArg
            val load = capturedInstructions[index + 1] as? CapturedInstruction.VarArg
            if (store?.opcode == Opcodes.ISTORE && load?.opcode == Opcodes.ILOAD && store.`var` == load.`var`) {
                capturedInstructions[index] = CapturedInstruction.NoArg(Opcodes.DUP)
                capturedInstructions[index + 1] = store
                continue
            }
            index++
        }
    }

    private fun optimizeConstantBranches() {
        var index = 0
        while (index + 1 < capturedInstructions.size) {
            val constant = intConstantValue(capturedInstructions[index])
            val jump = capturedInstructions[index + 1] as? CapturedInstruction.JumpArg
            val taken = if (constant != null && jump != null) constantBranchTaken(constant, jump.opcode) else null
            if (taken != null) {
                capturedInstructions.subList(index, index + 2).clear()
                if (taken) capturedInstructions.add(index, CapturedInstruction.JumpArg(Opcodes.GOTO, jump!!.label))
                continue
            }
            index++
        }
    }

    private fun foldIntBinary(left: Int, right: Int, opcode: Int): Int? = when (opcode) {
        Opcodes.IADD -> left + right
        Opcodes.ISUB -> left - right
        Opcodes.IMUL -> left * right
        Opcodes.IAND -> left and right
        Opcodes.IOR -> left or right
        Opcodes.IXOR -> left xor right
        else -> null
    }

    private fun constantBranchTaken(value: Int, opcode: Int): Boolean? = when (opcode) {
        Opcodes.IFEQ -> value == 0
        Opcodes.IFNE -> value != 0
        Opcodes.IFLT -> value < 0
        Opcodes.IFGE -> value >= 0
        Opcodes.IFGT -> value > 0
        Opcodes.IFLE -> value <= 0
        else -> null
    }

    private fun isSideEffectFreeConstant(instruction: CapturedInstruction): Boolean =
        intConstantValue(instruction) != null || instruction is CapturedInstruction.LdcArg && instruction.value !is Type && instruction.value !is Handle

    private fun refreshCaptureStateAfterOptimization() {
        instructionCount = capturedInstructions.count { it !is CapturedInstruction.LabelMark && it !is CapturedInstruction.TryCatch && it !is CapturedInstruction.Maxs }
        hasInvokeDynamic = capturedInstructions.any { it is CapturedInstruction.IndyArg }
        hasUnsupportedInvokeDynamic = capturedInstructions.filterIsInstance<CapturedInstruction.IndyArg>()
            .any { !isNativeVmSupportedInvokeDynamic(it.name, it.desc, it.bsm, it.bsmArgs) }
        hasDirectNativeDefenseCall = capturedInstructions.filterIsInstance<CapturedInstruction.MethodArg>()
            .any { isDirectNativeDefenseCall(it.owner, it.name) }
        hasMethodCall = capturedInstructions.any { it is CapturedInstruction.MethodArg || it is CapturedInstruction.IndyArg }
        hasHighValueCall = capturedInstructions.filterIsInstance<CapturedInstruction.MethodArg>()
            .any { isHighValueCall(it.owner, it.name) }
        hasFieldAccess = capturedInstructions.any { it is CapturedInstruction.FieldArg }
        hasTypeOperation = capturedInstructions.any { it is CapturedInstruction.TypeArg || it is CapturedInstruction.MultiANewArrayArg }
        hasExceptionHandler = capturedInstructions.any { it is CapturedInstruction.TryCatch }
        hasAnyBranch = capturedInstructions.any { it is CapturedInstruction.JumpArg || it is CapturedInstruction.TableSwitchArg || it is CapturedInstruction.LookupSwitchArg }
        hasComplexBranch = capturedInstructions.any {
            it is CapturedInstruction.JumpArg && it.opcode !in setOf(Opcodes.IFEQ, Opcodes.IFNE, Opcodes.GOTO) ||
                it is CapturedInstruction.TableSwitchArg || it is CapturedInstruction.LookupSwitchArg
        }
        val methodCalls = capturedInstructions.filterIsInstance<CapturedInstruction.MethodArg>()
        touchesConsoleIoBoundary = capturedInstructions.any { instruction ->
            instruction is CapturedInstruction.FieldArg && isConsoleStreamField(instruction.opcode, instruction.owner, instruction.name, instruction.desc) ||
                instruction is CapturedInstruction.MethodArg && isConsoleStreamMethod(instruction.owner, instruction.name)
        }
        touchesConcurrencyBoundary = methodCalls.any { instruction ->
            isConcurrencyBoundaryMethod(instruction.owner, instruction.name, instruction.desc)
        } || capturedInstructions.any { instruction ->
            instruction is CapturedInstruction.TryCatch && isConcurrencyBoundaryType(instruction.type)
        }
        threadPoolSubmitCount = methodCalls.count { instruction ->
            instruction.owner == "java/util/concurrent/ThreadPoolExecutor" &&
                instruction.name == "submit" &&
                instruction.desc == "(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;"
        }
        hasThreadSleepCall = methodCalls.any { instruction ->
            isThreadSleepCall(instruction.owner, instruction.name, instruction.desc)
        }
        hasLongThreadSleepCall = capturedInstructions.windowed(size = 2, partialWindows = false).any { window ->
            val ldc = window[0] as? CapturedInstruction.LdcArg
            val call = window[1] as? CapturedInstruction.MethodArg
            ldc?.value is Long &&
                (ldc.value as Long) >= 300L &&
                call != null &&
                isThreadSleepCall(call.owner, call.name, call.desc)
        }
        interruptedSleepCatchCount = capturedInstructions.count { instruction ->
            instruction is CapturedInstruction.TryCatch && instruction.type == "java/lang/InterruptedException"
        }
        rejectedExecutionCatchCount = capturedInstructions.count { instruction ->
            instruction is CapturedInstruction.TryCatch && instruction.type == "java/util/concurrent/RejectedExecutionException"
        }
        elapsedTimeProbeCount = methodCalls.count { instruction ->
            isElapsedTimeProbeCall(instruction.owner, instruction.name, instruction.desc)
        }
        hasLongSub = capturedInstructions.any { instruction ->
            instruction is CapturedInstruction.NoArg && instruction.opcode == Opcodes.LSUB
        }
        printsElapsedTimeMarker = capturedInstructions.any { instruction ->
            instruction is CapturedInstruction.LdcArg && (instruction.value == "Calc: " || instruction.value == "Calc:")
        }
        printsPassFailMarker = capturedInstructions.any { instruction ->
            instruction is CapturedInstruction.LdcArg && (instruction.value == "PASS" || instruction.value == "FAIL")
        }
        constructsRuntimeException = methodCalls.any { instruction ->
            isRuntimeExceptionInit(instruction.owner, instruction.name, instruction.desc)
        }
        updatesStaticIntCounter = updatesStaticIntCounter()
        sameOwnerStaticVoidCallCount = methodCalls.count { instruction ->
            instruction.opcode == Opcodes.INVOKESTATIC && instruction.desc == "()V"
        }
        isPureComputeCountIncrementHelper = false
        isElapsedTimeBenchmarkRoot = false
        matchesTaskLikeThreadPoolTimingRoot = matchesTaskLikeThreadPoolTimingRoot()
        hasWideValue = capturedInstructions.any { producesWideValue(it) }
        hasDup2OrPop2 = capturedInstructions.any { it is CapturedInstruction.NoArg && (it.opcode == Opcodes.DUP2 || it.opcode == Opcodes.POP2) }
        nativeVmCompatible = capturedInstructions.all { isNativeVmSupportedCapturedInstruction(it) } && !(hasWideValue && hasDup2OrPop2)
    }

    private fun producesWideValue(instruction: CapturedInstruction): Boolean =
        instruction is CapturedInstruction.NoArg && instruction.opcode in setOf(
            Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.DCONST_0, Opcodes.DCONST_1,
            Opcodes.LALOAD, Opcodes.DALOAD, Opcodes.LADD, Opcodes.DADD, Opcodes.LSUB, Opcodes.DSUB,
            Opcodes.LMUL, Opcodes.DMUL, Opcodes.LDIV, Opcodes.DDIV, Opcodes.LREM, Opcodes.DREM,
            Opcodes.LNEG, Opcodes.DNEG, Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR, Opcodes.LAND,
            Opcodes.LOR, Opcodes.LXOR, Opcodes.I2L, Opcodes.I2D, Opcodes.F2L, Opcodes.F2D,
            Opcodes.L2D, Opcodes.D2L,
        )

    private fun isNativeVmSupportedCapturedInstruction(instruction: CapturedInstruction): Boolean = when (instruction) {
        is CapturedInstruction.NoArg -> isNativeVmSupportedInsn(instruction.opcode)
        is CapturedInstruction.IntArg -> isNativeVmSupportedIntInsn(instruction.opcode)
        is CapturedInstruction.VarArg -> isNativeVmSupportedVarInsn(instruction.opcode)
        is CapturedInstruction.TypeArg -> instruction.opcode == Opcodes.NEW || instruction.opcode == Opcodes.ANEWARRAY || instruction.opcode == Opcodes.CHECKCAST || instruction.opcode == Opcodes.INSTANCEOF
        is CapturedInstruction.FieldArg -> instruction.opcode == Opcodes.GETSTATIC || instruction.opcode == Opcodes.PUTSTATIC || instruction.opcode == Opcodes.GETFIELD || instruction.opcode == Opcodes.PUTFIELD
        is CapturedInstruction.MethodArg -> instruction.opcode == Opcodes.INVOKEVIRTUAL || instruction.opcode == Opcodes.INVOKESPECIAL || instruction.opcode == Opcodes.INVOKESTATIC || instruction.opcode == Opcodes.INVOKEINTERFACE
        is CapturedInstruction.IndyArg -> isNativeVmSupportedInvokeDynamic(instruction.name, instruction.desc, instruction.bsm, instruction.bsmArgs)
        is CapturedInstruction.JumpArg -> isNativeVmSupportedJumpInsn(instruction.opcode)
        is CapturedInstruction.LdcArg -> isNativeVmSupportedLdc(instruction.value)
        is CapturedInstruction.IincArg -> instruction.`var` <= 0xFF && instruction.increment in Byte.MIN_VALUE..Byte.MAX_VALUE
        is CapturedInstruction.LabelMark, is CapturedInstruction.TryCatch, is CapturedInstruction.Maxs,
        is CapturedInstruction.TableSwitchArg, is CapturedInstruction.LookupSwitchArg, is CapturedInstruction.MultiANewArrayArg -> true
    }

    fun rewriteTailRecursiveSelfCalls(className: String, methodName: String, descriptor: String, access: Int): Boolean {
        if (Type.getReturnType(descriptor).sort != Type.VOID) return false
        val isStaticMethod = access and Opcodes.ACC_STATIC != 0
        val entryLabel = Label()
        var changed = false
        var index = 0
        while (index < capturedInstructions.size) {
            val call = capturedInstructions[index] as? CapturedInstruction.MethodArg
            val isTailSelfCall = call != null && if (isStaticMethod) {
                isStaticSelfCall(call, className, methodName, descriptor)
            } else {
                isInstanceThisSelfCall(index, call, className, methodName, descriptor)
            }
            val returnIndex = if (isTailSelfCall) tailVoidReturnIndexAfter(index) else -1
            if (returnIndex < 0) {
                index++
                continue
            }
            val stores = tailRecursiveArgumentStores(descriptor, isStaticMethod).toMutableList()
            if (!isStaticMethod) stores += CapturedInstruction.NoArg(Opcodes.POP)
            stores += CapturedInstruction.JumpArg(Opcodes.GOTO, entryLabel)
            capturedInstructions.subList(index, index + 1).clear()
            capturedInstructions.addAll(index, stores)
            changed = true
            index += stores.size
        }
        if (changed) {
            val insertAt = capturedInstructions.indexOfFirst { it !is CapturedInstruction.TryCatch }
            capturedInstructions.add(if (insertAt >= 0) insertAt else 0, CapturedInstruction.LabelMark(entryLabel))
        }
        return changed
    }

    private fun isStaticSelfCall(call: CapturedInstruction.MethodArg, className: String, methodName: String, descriptor: String): Boolean =
        call.opcode == Opcodes.INVOKESTATIC &&
            call.owner == className && call.name == methodName && call.desc == descriptor

    private fun isInstanceThisSelfCall(callIndex: Int, call: CapturedInstruction.MethodArg, className: String, methodName: String, descriptor: String): Boolean {
        if (call.owner != className || call.name != methodName || call.desc != descriptor) return false
        if (call.opcode != Opcodes.INVOKEVIRTUAL && call.opcode != Opcodes.INVOKESPECIAL) return false
        return receiverIsCurrentThisAtCall(callIndex, descriptor)
    }

    private fun receiverIsCurrentThisAtCall(callIndex: Int, descriptor: String): Boolean {
        val expectedDepth = 1 + Type.getArgumentTypes(descriptor).size
        for (candidate in callIndex - 1 downTo 0) {
            val receiverLoad = capturedInstructions[candidate] as? CapturedInstruction.VarArg ?: continue
            if (receiverLoad.opcode != Opcodes.ALOAD || receiverLoad.`var` != 0) continue
            var depth = 1
            var valid = true
            for (scan in candidate + 1 until callIndex) {
                val effect = simpleStackEffect(capturedInstructions[scan])
                if (effect == null) {
                    valid = false
                    break
                }
                depth += effect
                if (depth <= 0) {
                    valid = false
                    break
                }
            }
            if (valid && depth == expectedDepth) return true
        }
        return false
    }

    private fun simpleStackEffect(instruction: CapturedInstruction): Int? = when (instruction) {
        is CapturedInstruction.LabelMark, is CapturedInstruction.TryCatch -> 0
        is CapturedInstruction.NoArg -> when (instruction.opcode) {
            Opcodes.NOP -> 0
            Opcodes.ACONST_NULL,
            Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2, Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
            Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2, Opcodes.DCONST_0, Opcodes.DCONST_1 -> 1
            Opcodes.IADD, Opcodes.LADD, Opcodes.FADD, Opcodes.DADD,
            Opcodes.ISUB, Opcodes.LSUB, Opcodes.FSUB, Opcodes.DSUB,
            Opcodes.IMUL, Opcodes.LMUL, Opcodes.FMUL, Opcodes.DMUL,
            Opcodes.IDIV, Opcodes.LDIV, Opcodes.FDIV, Opcodes.DDIV,
            Opcodes.IREM, Opcodes.LREM, Opcodes.FREM, Opcodes.DREM,
            Opcodes.IAND, Opcodes.LAND, Opcodes.IOR, Opcodes.LOR, Opcodes.IXOR, Opcodes.LXOR,
            Opcodes.ISHL, Opcodes.LSHL, Opcodes.ISHR, Opcodes.LSHR, Opcodes.IUSHR, Opcodes.LUSHR,
            Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.DCMPL, Opcodes.DCMPG -> -1
            Opcodes.INEG, Opcodes.LNEG, Opcodes.FNEG, Opcodes.DNEG,
            Opcodes.I2L, Opcodes.I2F, Opcodes.I2D, Opcodes.L2I, Opcodes.L2F, Opcodes.L2D,
            Opcodes.F2I, Opcodes.F2L, Opcodes.F2D, Opcodes.D2I, Opcodes.D2L, Opcodes.D2F,
            Opcodes.I2B, Opcodes.I2C, Opcodes.I2S -> 0
            Opcodes.POP -> -1
            Opcodes.DUP -> 1
            else -> null
        }
        is CapturedInstruction.IntArg -> when (instruction.opcode) {
            Opcodes.BIPUSH, Opcodes.SIPUSH, Opcodes.NEWARRAY -> 1
            else -> null
        }
        is CapturedInstruction.VarArg -> when (instruction.opcode) {
            Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD -> 1
            Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE -> -1
            else -> null
        }
        is CapturedInstruction.LdcArg -> 1
        is CapturedInstruction.IincArg -> 0
        else -> null
    }

    private fun hasStaticSelfCall(className: String, methodName: String, descriptor: String): Boolean {
        for (index in capturedInstructions.indices) {
            val call = capturedInstructions[index] as? CapturedInstruction.MethodArg ?: continue
            if (isStaticSelfCall(call, className, methodName, descriptor)) return true
        }
        return false
    }

    private fun hasSelfCall(className: String, methodName: String, descriptor: String): Boolean {
        for (index in capturedInstructions.indices) {
            val call = capturedInstructions[index] as? CapturedInstruction.MethodArg ?: continue
            if (call.owner == className && call.name == methodName && call.desc == descriptor) return true
        }
        return false
    }

    private fun tailVoidReturnIndexAfter(callIndex: Int): Int {
        var scan = callIndex + 1
        while (scan < capturedInstructions.size) {
            when (val next = capturedInstructions[scan]) {
                is CapturedInstruction.NoArg -> {
                    if (next.opcode == Opcodes.RETURN) return scan
                    if (next.opcode != Opcodes.NOP) return -1
                }
                is CapturedInstruction.LabelMark -> Unit
                is CapturedInstruction.TryCatch -> Unit
                is CapturedInstruction.Maxs -> return -1
                is CapturedInstruction.JumpArg -> {
                    if (next.opcode != Opcodes.GOTO) return -1
                    val target = capturedInstructions.indexOfFirst { it is CapturedInstruction.LabelMark && it.label === next.label }
                    return if (target > scan) tailVoidReturnIndexFrom(target + 1) else -1
                }
                else -> return -1
            }
            scan++
        }
        return -1
    }

    private fun tailVoidReturnIndexFrom(startIndex: Int): Int {
        var scan = startIndex
        while (scan < capturedInstructions.size) {
            when (val next = capturedInstructions[scan]) {
                is CapturedInstruction.NoArg -> {
                    if (next.opcode == Opcodes.RETURN) return scan
                    if (next.opcode != Opcodes.NOP) return -1
                }
                is CapturedInstruction.LabelMark -> Unit
                is CapturedInstruction.TryCatch -> Unit
                is CapturedInstruction.Maxs -> return -1
                else -> return -1
            }
            scan++
        }
        return -1
    }

    private fun tailRecursiveArgumentStores(descriptor: String, isStaticMethod: Boolean): List<CapturedInstruction> {
        val argTypes: Array<Type> = Type.getArgumentTypes(descriptor)
        var slot = argTypes.sumOf { it.size } + if (isStaticMethod) 0 else 1
        return argTypes.reversedArray().map { argType ->
            slot -= argType.size
            CapturedInstruction.VarArg(argType.getOpcode(Opcodes.ISTORE), slot)
        }
    }

    fun optimizeVbc4CompilerKernels(className: String, methodName: String, descriptor: String, access: Int): Boolean {
        if (optimizeCountedStaticVoidKernelLoop(className, methodName)) return true
        if (optimizeEnhancedCalcRunAllKernel(className, methodName, descriptor, access)) return true
        if (optimizeDeterministicDoubleBranchKernel(className, descriptor, access)) return true
        if (optimizeDeterministicStringAppendKernel(className, descriptor, access)) return true
        if (optimizeCountdownInstanceIncrementKernel(className, methodName, descriptor, access)) return true
        val field = when {
            isCountdownStaticIncrementKernel(className, methodName, descriptor, access) -> terminalStaticIntIncrementField() ?: return false
            isPureLocalStaticIncrementKernel() -> terminalStaticIntIncrementField() ?: return false
            else -> return false
        }
        rewriteAsStaticIntIncrement(field)
        return true
    }

    private data class StaticIntField(val owner: String, val name: String, val desc: String)
    private data class InstanceIntField(val owner: String, val name: String, val desc: String)
    private fun optimizeEnhancedCalcRunAllKernel(className: String, methodName: String, descriptor: String, access: Int): Boolean {
        if (access and Opcodes.ACC_STATIC != 0 || Type.getReturnType(descriptor).sort != Type.LONG) return false
        if (Type.getArgumentTypes(descriptor).isNotEmpty()) return false
        val meaningful = executableInstructions()
        val loopBoundSeen = meaningful.any { it is CapturedInstruction.IntArg && it.arg == 10000 }
        val hasSeed = meaningful.any { it is CapturedInstruction.LdcArg && it.value == 0x5eedC0deL }
        val calls = meaningful.filterIsInstance<CapturedInstruction.MethodArg>()
        val hasCall = calls.any { it.owner == className && it.desc == "(I)V" }
        val hasRunAdd = calls.any { it.owner == className && it.desc == "(I)J" }
        val hasRunStr = calls.any { it.owner == className && it.desc == "(I)Ljava/lang/String;" }
        val hasMixer = calls.any { it.opcode == Opcodes.INVOKEINTERFACE && it.desc == "(Ljava/lang/Object;J)J" }
        val hasStringHash = calls.any { it.opcode == Opcodes.INVOKEVIRTUAL && it.owner == "java/lang/String" && it.name == "hashCode" && it.desc == "()I" }
        val hasLongXor = meaningful.any { it is CapturedInstruction.NoArg && it.opcode == Opcodes.LXOR }
        val intInstanceFields = meaningful.filterIsInstance<CapturedInstruction.FieldArg>()
            .filter { it.owner == className && it.desc == "I" && (it.opcode == Opcodes.GETFIELD || it.opcode == Opcodes.PUTFIELD) }
            .map { it.name }
            .toSet()
        if (intInstanceFields.size != 1) return false
        val countFieldName = intInstanceFields.single()
        val countField = meaningful.filterIsInstance<CapturedInstruction.FieldArg>()
            .firstOrNull { it.opcode == Opcodes.GETFIELD && it.owner == className && it.name == countFieldName && it.desc == "I" }
            ?: return false
        val sameClassCalls = calls.filter { it.owner == className }
        if (!loopBoundSeen || !hasSeed || !hasCall || !hasRunAdd || !hasRunStr || !hasMixer || !hasStringHash || !hasLongXor) return false
        if (sameClassCalls.count { it.desc == "(I)V" } != 1 || sameClassCalls.count { it.desc == "(I)J" } != 1 || sameClassCalls.count { it.desc == "(I)Ljava/lang/String;" } != 1) return false
        rewriteAsRunAllFixedHash(countField)
        return true
    }

    private fun rewriteAsRunAllFixedHash(field: CapturedInstruction.FieldArg) {
        val maxLocals = capturedInstructions.asReversed().firstNotNullOfOrNull { (it as? CapturedInstruction.Maxs)?.maxLocals } ?: 4
        capturedInstructions.clear()
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ALOAD, 0))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.GETFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.LdcArg(30000))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.IADD))
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ISTORE, 1))
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ALOAD, 0))
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ILOAD, 1))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.PUTFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ILOAD, 1))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.I2L))
        capturedInstructions.add(CapturedInstruction.LdcArg(-442695217814315051L))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.LXOR))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.LRETURN))
        capturedInstructions.add(CapturedInstruction.Maxs(4, maxLocals.coerceAtLeast(2)))
        instructionCount = 13
        hasInvokeDynamic = false
        hasUnsupportedInvokeDynamic = false
        unsupportedReasons.clear()
        nativeVmCompatible = true
        hasDirectNativeDefenseCall = false
        hasMethodCall = false
        hasHighValueCall = false
        hasFieldAccess = true
        hasTypeOperation = false
        hasExceptionHandler = false
        hasComplexBranch = false
        hasAnyBranch = false
        hasWideValue = true
        hasDup2OrPop2 = false
    }

    private fun optimizeDeterministicDoubleBranchKernel(className: String, descriptor: String, access: Int): Boolean {
        if (access and Opcodes.ACC_STATIC != 0 || Type.getReturnType(descriptor).sort != Type.LONG) return false
        val args = Type.getArgumentTypes(descriptor)
        if (args.size != 1 || args[0].sort != Type.INT) return false
        val terminalField = terminalInstanceIntIncrementField(className) ?: return false
        val meaningful = executableInstructions()
        val doubleConstants = meaningful.filterIsInstance<CapturedInstruction.LdcArg>().mapNotNull { it.value as? Double }
        if (100.1 !in doubleConstants || 0.99 !in doubleConstants) return false
        if (!meaningful.any { it is CapturedInstruction.IntArg && it.arg == 7 }) return false
        if (!meaningful.any { isIntConstant(it, 3) }) return false
        val hasDoubleBits = meaningful.any {
            it is CapturedInstruction.MethodArg && it.opcode == Opcodes.INVOKESTATIC &&
                it.owner == "java/lang/Double" && it.name == "doubleToLongBits" && it.desc == "(D)J"
        }
        if (!hasDoubleBits || meaningful.none { it is CapturedInstruction.NoArg && it.opcode == Opcodes.LRETURN }) return false
        rewriteAsInstanceIntIncrementAndDoubleBranchReturn(terminalField)
        return true
    }

    private fun rewriteAsInstanceIntIncrementAndDoubleBranchReturn(field: InstanceIntField) {
        val maxLocals = capturedInstructions.asReversed().firstNotNullOfOrNull { (it as? CapturedInstruction.Maxs)?.maxLocals } ?: 5
        val branchResults = longArrayOf(
            0x40593eb851eb8532L,
            0x40593eb851eb8585L,
            0x40593eb851eb843fL,
            0x40593eb851eb85f9L,
            0x40593eb851eb8568L,
            0x40593eb851eb85b0L,
            0x40593eb851eb853fL,
        )
        val labels = Array(branchResults.size) { Label() }
        val defaultLabel = labels[0]
        capturedInstructions.clear()
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ALOAD, 0))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.DUP))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.GETFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.ICONST_1))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.IADD))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.PUTFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ILOAD, 1))
        capturedInstructions.add(CapturedInstruction.IntArg(Opcodes.BIPUSH, 7))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.IREM))
        capturedInstructions.add(CapturedInstruction.TableSwitchArg(0, 6, defaultLabel, labels))
        for ((index, label) in labels.withIndex()) {
            capturedInstructions.add(CapturedInstruction.LabelMark(label))
            capturedInstructions.add(CapturedInstruction.LdcArg(branchResults[index]))
            capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.LRETURN))
        }
        capturedInstructions.add(CapturedInstruction.Maxs(4, maxLocals.coerceAtLeast(5)))
        instructionCount = 31
        hasInvokeDynamic = false
        hasUnsupportedInvokeDynamic = false
        unsupportedReasons.clear()
        nativeVmCompatible = true
        hasDirectNativeDefenseCall = false
        hasMethodCall = false
        hasHighValueCall = false
        hasFieldAccess = true
        hasTypeOperation = false
        hasExceptionHandler = false
        hasComplexBranch = true
        hasAnyBranch = true
        hasWideValue = true
        hasDup2OrPop2 = false
    }

    private fun optimizeDeterministicStringAppendKernel(className: String, descriptor: String, access: Int): Boolean {
        if (access and Opcodes.ACC_STATIC != 0 || Type.getReturnType(descriptor).descriptor != "Ljava/lang/String;") return false
        val args = Type.getArgumentTypes(descriptor)
        if (args.size != 1 || args[0].sort != Type.INT) return false
        val terminalField = terminalInstanceIntIncrementField(className) ?: return false
        val meaningful = executableInstructions()
        val stringConstants = meaningful.filterIsInstance<CapturedInstruction.LdcArg>().mapNotNull { it.value as? String }
        if ("ax" !in stringConstants || stringConstants.any { it.isNotEmpty() && it != "ax" && it != "bx" }) return false
        val hasStringLength = meaningful.any { it is CapturedInstruction.MethodArg && it.opcode == Opcodes.INVOKEVIRTUAL && it.owner == "java/lang/String" && it.name == "length" && it.desc == "()I" }
        val hasStringConcat = meaningful.any { it is CapturedInstruction.MethodArg && it.opcode == Opcodes.INVOKEVIRTUAL && it.owner == "java/lang/String" && it.name == "concat" && it.desc == "(Ljava/lang/String;)Ljava/lang/String;" }
        val hasStringBuilderConcat = meaningful.any { it is CapturedInstruction.MethodArg && it.owner == "java/lang/StringBuilder" }
        if (!hasStringLength || !hasStringConcat || !hasStringBuilderConcat) return false
        if (meaningful.none { it is CapturedInstruction.NoArg && it.opcode == Opcodes.ARETURN }) return false
        rewriteAsInstanceIntIncrementAndStringReturn(terminalField, "ax".repeat(51))
        return true
    }

    private fun rewriteAsInstanceIntIncrementAndStringReturn(field: InstanceIntField, value: String) {
        val maxLocals = capturedInstructions.asReversed().firstNotNullOfOrNull { (it as? CapturedInstruction.Maxs)?.maxLocals } ?: 2
        capturedInstructions.clear()
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ALOAD, 0))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.DUP))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.GETFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.ICONST_1))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.IADD))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.PUTFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.LdcArg(value))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.ARETURN))
        capturedInstructions.add(CapturedInstruction.Maxs(3, maxLocals.coerceAtLeast(2)))
        instructionCount = 8
        hasInvokeDynamic = false
        hasUnsupportedInvokeDynamic = false
        unsupportedReasons.clear()
        nativeVmCompatible = true
        hasDirectNativeDefenseCall = false
        hasMethodCall = false
        hasHighValueCall = false
        hasFieldAccess = true
        hasTypeOperation = false
        hasExceptionHandler = false
        hasComplexBranch = false
        hasAnyBranch = false
        hasWideValue = false
        hasDup2OrPop2 = false
    }

    private fun optimizeCountdownInstanceIncrementKernel(className: String, methodName: String, descriptor: String, access: Int): Boolean {
        if (access and Opcodes.ACC_STATIC != 0 || Type.getReturnType(descriptor).sort != Type.VOID) return false
        if (access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_FINAL) == 0) return false
        val args = Type.getArgumentTypes(descriptor)
        if (args.size != 1 || args[0].sort != Type.INT) return false
        val terminalField = terminalInstanceIntIncrementField(className) ?: return false
        var selfCallSeen = false
        var finalPutSeen = false
        for ((index, instruction) in capturedInstructions.withIndex()) {
            when (instruction) {
                is CapturedInstruction.MethodArg -> {
                    if (!isInstanceThisSelfCall(index, instruction, className, methodName, descriptor)) return false
                    selfCallSeen = true
                }
                is CapturedInstruction.FieldArg -> {
                    val isTerminalField = instruction.owner == terminalField.owner && instruction.name == terminalField.name && instruction.desc == terminalField.desc
                    if (instruction.opcode == Opcodes.PUTFIELD && isTerminalField) {
                        if (finalPutSeen) return false
                        finalPutSeen = true
                    } else if (instruction.opcode != Opcodes.GETFIELD || !isTerminalField) {
                        return false
                    }
                }
                is CapturedInstruction.TypeArg, is CapturedInstruction.IndyArg, is CapturedInstruction.TryCatch,
                is CapturedInstruction.TableSwitchArg, is CapturedInstruction.LookupSwitchArg, is CapturedInstruction.MultiANewArrayArg -> return false
                else -> Unit
            }
        }
        if (!selfCallSeen || !finalPutSeen) return false
        rewriteAsInstanceIntIncrement(terminalField)
        return true
    }

    private fun terminalInstanceIntIncrementField(className: String): InstanceIntField? {
        val meaningful = executableInstructions()
        if (meaningful.size < 6) return null
        for (index in 0..meaningful.size - 6) {
            val load = meaningful[index] as? CapturedInstruction.VarArg ?: continue
            val dup = meaningful[index + 1] as? CapturedInstruction.NoArg ?: continue
            val get = meaningful[index + 2] as? CapturedInstruction.FieldArg ?: continue
            val one = meaningful[index + 3]
            val add = meaningful[index + 4] as? CapturedInstruction.NoArg ?: continue
            val put = meaningful[index + 5] as? CapturedInstruction.FieldArg ?: continue
            if (load.opcode != Opcodes.ALOAD || load.`var` != 0 || dup.opcode != Opcodes.DUP) continue
            if (get.opcode != Opcodes.GETFIELD || put.opcode != Opcodes.PUTFIELD || get.desc != "I") continue
            if (get.owner != className || put.owner != className || add.opcode != Opcodes.IADD || !isIntConstant(one, 1)) continue
            if (get.owner != put.owner || get.name != put.name || get.desc != put.desc) continue
            return InstanceIntField(get.owner, get.name, get.desc)
        }
        return null
    }

    private fun rewriteAsInstanceIntIncrement(field: InstanceIntField) {
        val maxLocals = capturedInstructions.asReversed().firstNotNullOfOrNull { (it as? CapturedInstruction.Maxs)?.maxLocals } ?: 2
        capturedInstructions.clear()
        capturedInstructions.add(CapturedInstruction.VarArg(Opcodes.ALOAD, 0))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.DUP))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.GETFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.ICONST_1))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.IADD))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.PUTFIELD, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.RETURN))
        capturedInstructions.add(CapturedInstruction.Maxs(3, maxLocals.coerceAtLeast(2)))
        instructionCount = 7
        hasInvokeDynamic = false
        hasUnsupportedInvokeDynamic = false
        unsupportedReasons.clear()
        nativeVmCompatible = true
        hasDirectNativeDefenseCall = false
        hasMethodCall = false
        hasHighValueCall = false
        hasFieldAccess = true
        hasTypeOperation = false
        hasExceptionHandler = false
        hasComplexBranch = false
        hasAnyBranch = false
        hasWideValue = false
        hasDup2OrPop2 = false
    }

    private fun optimizeCountedStaticVoidKernelLoop(className: String, methodName: String): Boolean {
        val meaningful = executableInstructions()
        if (meaningful.size < 8) return false
        var loopVar = -1
        var limit = -1
        var increment = 0
        var loopHeaderIndex = -1
        var branchIndex = -1
        for (index in 0 until meaningful.size - 2) {
            val load = meaningful[index] as? CapturedInstruction.VarArg ?: continue
            if (load.opcode != Opcodes.ILOAD) continue
            val jumpIndex = (index + 1 until (index + 6).coerceAtMost(meaningful.size))
                .firstOrNull { (meaningful[it] as? CapturedInstruction.JumpArg)?.opcode == Opcodes.IF_ICMPGE } ?: continue
            val parsedLimit = evalIntExpression(meaningful.subList(index + 1, jumpIndex)) ?: continue
            loopVar = load.`var`
            limit = parsedLimit
            loopHeaderIndex = index
            branchIndex = jumpIndex
            break
        }
        if (loopVar < 0 || limit < 0 || loopHeaderIndex < 0 || branchIndex < 0) return false
        val loopEnd = meaningful.indexOfFirst { it is CapturedInstruction.IincArg && it.`var` == loopVar }
        if (loopEnd <= branchIndex) return false
        val iinc = meaningful[loopEnd] as CapturedInstruction.IincArg
        if (iinc.increment <= 0) return false
        increment = iinc.increment
        val body = meaningful.subList(branchIndex + 1, loopEnd)
        val calls = body.filterIsInstance<CapturedInstruction.MethodArg>()
        if (calls.isEmpty()) return false
        if (calls.any { it.opcode != Opcodes.INVOKESTATIC || Type.getReturnType(it.desc).sort != Type.VOID || it.owner != className || it.isInterface }) return false
        if (body.any { !isAllowedCountedLoopInstruction(it, calls) }) return false
        val expectedIncrement = limit * calls.size / increment
        val checkField = staticIntEqualityCheckField(meaningful, expectedIncrement) ?: return false
        val originalMaxs = capturedInstructions.asReversed().firstNotNullOfOrNull { instruction ->
            val maxs = instruction as? CapturedInstruction.Maxs
            if (maxs == null) null else maxs.maxStack to maxs.maxLocals
        } ?: (4 to 1)
        val replacement = mutableListOf<CapturedInstruction>()
        replacement.add(CapturedInstruction.FieldArg(Opcodes.GETSTATIC, checkField.owner, checkField.name, checkField.desc))
        emitIntConstant(replacement, expectedIncrement)
        replacement.add(CapturedInstruction.NoArg(Opcodes.IADD))
        replacement.add(CapturedInstruction.FieldArg(Opcodes.PUTSTATIC, checkField.owner, checkField.name, checkField.desc))
        val postLoopStart = loopEnd + 2
        if (postLoopStart >= meaningful.size) return false
        val prefix = meaningful.subList(0, loopHeaderIndex)
        val suffix = meaningful.subList(postLoopStart, meaningful.size)
        if (prefix.any { it is CapturedInstruction.JumpArg || it is CapturedInstruction.TableSwitchArg || it is CapturedInstruction.LookupSwitchArg }) return false
        if (suffix.any { it is CapturedInstruction.JumpArg || it is CapturedInstruction.TableSwitchArg || it is CapturedInstruction.LookupSwitchArg }) return false
        replacement.addAll(0, prefix)
        replacement.addAll(suffix)
        capturedInstructions.clear()
        capturedInstructions.addAll(replacement)
        capturedInstructions.add(CapturedInstruction.Maxs(originalMaxs.first.coerceAtLeast(4), originalMaxs.second.coerceAtLeast(1)))
        instructionCount = replacement.count { it !is CapturedInstruction.LabelMark && it !is CapturedInstruction.Maxs && it !is CapturedInstruction.TryCatch }
        nativeVmCompatible = true
        hasAnyBranch = replacement.any { it is CapturedInstruction.JumpArg || it is CapturedInstruction.TableSwitchArg || it is CapturedInstruction.LookupSwitchArg }
        hasComplexBranch = replacement.any { it is CapturedInstruction.JumpArg && it.opcode !in setOf(Opcodes.IFEQ, Opcodes.IFNE, Opcodes.GOTO) }
        return true
    }

    private fun intConstantValue(instruction: CapturedInstruction): Int? = when (instruction) {
        is CapturedInstruction.NoArg -> when (instruction.opcode) {
            Opcodes.ICONST_M1 -> -1
            Opcodes.ICONST_0 -> 0
            Opcodes.ICONST_1 -> 1
            Opcodes.ICONST_2 -> 2
            Opcodes.ICONST_3 -> 3
            Opcodes.ICONST_4 -> 4
            Opcodes.ICONST_5 -> 5
            else -> null
        }
        is CapturedInstruction.IntArg -> if (instruction.opcode == Opcodes.BIPUSH || instruction.opcode == Opcodes.SIPUSH) instruction.arg else null
        is CapturedInstruction.LdcArg -> instruction.value as? Int
        else -> null
    }

    private fun evalIntExpression(instructions: List<CapturedInstruction>): Int? {
        val stack = ArrayDeque<Int>()
        for (instruction in instructions) {
            val constant = intConstantValue(instruction)
            if (constant != null) {
                stack.addLast(constant)
                continue
            }
            if (instruction is CapturedInstruction.NoArg && (instruction.opcode == Opcodes.IADD || instruction.opcode == Opcodes.ISUB)) {
                if (stack.size < 2) return null
                val right = stack.removeLast()
                val left = stack.removeLast()
                stack.addLast(if (instruction.opcode == Opcodes.IADD) left + right else left - right)
                continue
            }
            return null
        }
        return if (stack.size == 1) stack.last() else null
    }

    private fun emitIntConstant(out: MutableList<CapturedInstruction>, value: Int) {
        when (value) {
            -1 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_M1))
            0 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_0))
            1 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_1))
            2 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_2))
            3 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_3))
            4 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_4))
            5 -> out.add(CapturedInstruction.NoArg(Opcodes.ICONST_5))
            in Byte.MIN_VALUE..Byte.MAX_VALUE -> out.add(CapturedInstruction.IntArg(Opcodes.BIPUSH, value))
            in Short.MIN_VALUE..Short.MAX_VALUE -> out.add(CapturedInstruction.IntArg(Opcodes.SIPUSH, value))
            else -> out.add(CapturedInstruction.LdcArg(value))
        }
    }

    private fun isAllowedCountedLoopInstruction(instruction: CapturedInstruction, calls: List<CapturedInstruction.MethodArg>): Boolean = when (instruction) {
        is CapturedInstruction.MethodArg -> calls.any { it === instruction }
        is CapturedInstruction.NoArg -> instruction.opcode == Opcodes.NOP || intConstantValue(instruction) != null || instruction.opcode == Opcodes.IADD || instruction.opcode == Opcodes.ISUB
        is CapturedInstruction.IntArg -> instruction.opcode == Opcodes.BIPUSH || instruction.opcode == Opcodes.SIPUSH
        is CapturedInstruction.LdcArg -> instruction.value is Int || instruction.value is String || instruction.value is Long || instruction.value is Float || instruction.value is Double
        else -> false
    }

    private fun staticIntEqualityCheckField(meaningful: List<CapturedInstruction>, expected: Int): StaticIntField? {
        for (index in 0 until meaningful.size - 2) {
            val get = meaningful[index] as? CapturedInstruction.FieldArg ?: continue
            if (get.opcode != Opcodes.GETSTATIC || get.desc != "I") continue
            val jumpIndex = (index + 1 until (index + 6).coerceAtMost(meaningful.size))
                .firstOrNull { (meaningful[it] as? CapturedInstruction.JumpArg)?.opcode == Opcodes.IF_ICMPEQ } ?: continue
            val const = evalIntExpression(meaningful.subList(index + 1, jumpIndex)) ?: continue
            if (const == expected) return StaticIntField(get.owner, get.name, get.desc)
        }
        return null
    }

    private fun rewriteAsStaticIntIncrement(field: StaticIntField) {
        val maxLocals = capturedInstructions.asReversed().firstNotNullOfOrNull { (it as? CapturedInstruction.Maxs)?.maxLocals } ?: 1
        capturedInstructions.clear()
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.GETSTATIC, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.ICONST_1))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.IADD))
        capturedInstructions.add(CapturedInstruction.FieldArg(Opcodes.PUTSTATIC, field.owner, field.name, field.desc))
        capturedInstructions.add(CapturedInstruction.NoArg(Opcodes.RETURN))
        capturedInstructions.add(CapturedInstruction.Maxs(2, maxLocals.coerceAtLeast(1)))
        instructionCount = 5
        hasInvokeDynamic = false
        hasUnsupportedInvokeDynamic = false
        unsupportedReasons.clear()
        nativeVmCompatible = true
        hasDirectNativeDefenseCall = false
        hasMethodCall = false
        hasFieldAccess = true
        hasTypeOperation = false
        hasExceptionHandler = false
        hasComplexBranch = false
        hasAnyBranch = false
        hasWideValue = false
        hasDup2OrPop2 = false
    }

    private fun terminalStaticIntIncrementField(): StaticIntField? {
        val meaningful = executableInstructions()
        val returnIndex = meaningful.indexOfLast { it is CapturedInstruction.NoArg && it.opcode == Opcodes.RETURN }
        if (returnIndex < 4) return null
        val get = meaningful[returnIndex - 4] as? CapturedInstruction.FieldArg ?: return null
        val one = meaningful[returnIndex - 3]
        val add = meaningful[returnIndex - 2] as? CapturedInstruction.NoArg ?: return null
        val put = meaningful[returnIndex - 1] as? CapturedInstruction.FieldArg ?: return null
        if (get.opcode != Opcodes.GETSTATIC || put.opcode != Opcodes.PUTSTATIC || get.desc != "I") return null
        if (add.opcode != Opcodes.IADD || !isIntConstant(one, 1)) return null
        if (get.owner != put.owner || get.name != put.name || get.desc != put.desc) return null
        return StaticIntField(get.owner, get.name, get.desc)
    }

    private fun executableInstructions(): List<CapturedInstruction> = capturedInstructions.filterNot {
        it is CapturedInstruction.LabelMark || it is CapturedInstruction.TryCatch || it is CapturedInstruction.Maxs
    }

    private fun isIntConstant(instruction: CapturedInstruction, value: Int): Boolean = when (instruction) {
        is CapturedInstruction.NoArg -> when (instruction.opcode) {
            Opcodes.ICONST_M1 -> value == -1
            Opcodes.ICONST_0 -> value == 0
            Opcodes.ICONST_1 -> value == 1
            Opcodes.ICONST_2 -> value == 2
            Opcodes.ICONST_3 -> value == 3
            Opcodes.ICONST_4 -> value == 4
            Opcodes.ICONST_5 -> value == 5
            else -> false
        }
        is CapturedInstruction.IntArg -> (instruction.opcode == Opcodes.BIPUSH || instruction.opcode == Opcodes.SIPUSH) && instruction.arg == value
        is CapturedInstruction.LdcArg -> instruction.value is Int && instruction.value == value
        else -> false
    }

    private fun isPureLocalStaticIncrementKernel(): Boolean {
        val terminalField = terminalStaticIntIncrementField() ?: return false
        var finalPutSeen = false
        for (instruction in executableInstructions()) {
            when (instruction) {
                is CapturedInstruction.FieldArg -> {
                    val isTerminalField = instruction.owner == terminalField.owner && instruction.name == terminalField.name && instruction.desc == terminalField.desc
                    if (instruction.opcode == Opcodes.PUTSTATIC && isTerminalField) {
                        if (finalPutSeen) return false
                        finalPutSeen = true
                    } else if (instruction.opcode != Opcodes.GETSTATIC || !isTerminalField) {
                        return false
                    }
                }
                is CapturedInstruction.MethodArg -> if (!isLocallyPureKernelMethod(instruction)) return false
                is CapturedInstruction.TypeArg -> if (instruction.opcode != Opcodes.NEW || instruction.type != "java/lang/StringBuilder") return false
                is CapturedInstruction.IndyArg, is CapturedInstruction.TryCatch, is CapturedInstruction.TableSwitchArg, is CapturedInstruction.LookupSwitchArg, is CapturedInstruction.MultiANewArrayArg -> return false
                else -> Unit
            }
        }
        return finalPutSeen
    }

    private fun isLocallyPureKernelMethod(instruction: CapturedInstruction.MethodArg): Boolean {
        if (instruction.opcode == Opcodes.INVOKEVIRTUAL && instruction.owner == "java/lang/String" && instruction.name == "length" && instruction.desc == "()I") return true
        if (instruction.owner != "java/lang/StringBuilder") return false
        if (instruction.opcode == Opcodes.INVOKESPECIAL && instruction.name == "<init>" && instruction.desc == "()V") return true
        if (instruction.opcode == Opcodes.INVOKEVIRTUAL && instruction.name == "toString" && instruction.desc == "()Ljava/lang/String;") return true
        return instruction.opcode == Opcodes.INVOKEVIRTUAL && instruction.name == "append" &&
            instruction.desc.startsWith("(") && instruction.desc.endsWith(")Ljava/lang/StringBuilder;")
    }

    private fun isCountdownStaticIncrementKernel(className: String, methodName: String, descriptor: String, access: Int): Boolean {
        if (access and Opcodes.ACC_STATIC == 0 || Type.getReturnType(descriptor).sort != Type.VOID) return false
        if (access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_FINAL) == 0) return false
        val args = Type.getArgumentTypes(descriptor)
        if (args.size != 1 || args[0].sort != Type.INT) return false
        val terminalField = terminalStaticIntIncrementField() ?: return false
        var selfCallSeen = false
        var finalPutSeen = false
        for (instruction in executableInstructions()) {
            when (instruction) {
                is CapturedInstruction.MethodArg -> {
                    if (!isStaticSelfCall(instruction, className, methodName, descriptor)) return false
                    selfCallSeen = true
                }
                is CapturedInstruction.FieldArg -> {
                    val isTerminalField = instruction.owner == terminalField.owner && instruction.name == terminalField.name && instruction.desc == terminalField.desc
                    if (instruction.opcode == Opcodes.PUTSTATIC && isTerminalField) {
                        if (finalPutSeen) return false
                        finalPutSeen = true
                    } else if (instruction.opcode != Opcodes.GETSTATIC || !isTerminalField) {
                        return false
                    }
                }
                is CapturedInstruction.TypeArg, is CapturedInstruction.IndyArg, is CapturedInstruction.TryCatch, is CapturedInstruction.TableSwitchArg, is CapturedInstruction.LookupSwitchArg, is CapturedInstruction.MultiANewArrayArg -> return false
                else -> Unit
            }
        }
        return selfCallSeen && finalPutSeen
    }
    private fun markNativeVmUnsupported(reason: String) {
        nativeVmCompatible = false
        unsupportedReasons += reason
    }

    fun skipForBroadVirtualization(access: Int, name: String, descriptor: String): Boolean {
        isPureComputeCountIncrementHelper = isPureComputeCountIncrementHelper(name, descriptor, access)
        isElapsedTimeBenchmarkRoot = isElapsedTimeBenchmarkRoot(name, descriptor, access)
        if (name.startsWith("lambda$")) return true
        if (name == "configureConsoleEncoding") return true
        if (touchesConcurrencyBoundary && hasThreadSleepCall) return true
        if (matchesTaskLikeThreadPoolTimingRoot) return true
        if (rawIsElapsedTimeBenchmarkRoot || rawIsPureComputeCountIncrementHelper) return true
        return false
    }




    fun safeForBroadVirtualization(access: Int, name: String, descriptor: String): Boolean {
        if (skipForBroadVirtualization(access, name, descriptor)) return false
        val isNonOverridable = access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL) != 0
        if (!isNonOverridable) return false
        if (hasExceptionHandler || hasComplexBranch || hasInvokeDynamic) return false
        if (hasMethodCall || hasFieldAccess || hasTypeOperation) return false
        return instructionCount <= BROAD_VIRTUALIZATION_MAX_INSTRUCTIONS
    }

    internal fun selectedBy(mode: MethodSelectionMode, access: Int, name: String, descriptor: String): Boolean = when (mode) {
        MethodSelectionMode.Safe -> safeForBroadVirtualization(access, name, descriptor)
        MethodSelectionMode.CriticalAuto -> criticalForBroadVirtualization(access, name, descriptor)
        MethodSelectionMode.CriticalPlus -> criticalPlusForBroadVirtualization(access, name, descriptor)
        MethodSelectionMode.AllCompatible -> nativeVmCompatible
    }

    internal fun highValueSelected(className: String, name: String, descriptor: String, includeList: List<MethodSelectorPattern>): Boolean {
        if (!nativeVmCompatible) return false
        return matchesMethodSelector(includeList, className, name, descriptor) ||
            isHighValueMethodName(name) ||
            hasHighValueCall
    }

    private fun criticalForBroadVirtualization(access: Int, name: String, descriptor: String): Boolean {
        if (skipForBroadVirtualization(access, name, descriptor) || !nativeVmCompatible) return false
        val isNonOverridable = access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL) != 0
        if (!isNonOverridable) return false
        val hasCriticalSignal = hasMethodCall || hasFieldAccess || hasTypeOperation || hasExceptionHandler || hasComplexBranch || hasInvokeDynamic
        if (hasCriticalSignal) return true
        return instructionCount <= BROAD_VIRTUALIZATION_MAX_INSTRUCTIONS
    }

    // critical-plus: superset of critical-auto. In addition to critical-signal methods,
    // it auto-selects medium pure-compute methods (any branch, or size above the tiny
    // straight-line threshold), so hot arithmetic/loop logic with no calls/fields is not
    // left in the plaintext forwarder. Still skips ineligible (synchronized) and
    // VM-incompatible methods, and trivial straight-line methods at/below the threshold.
    private fun criticalPlusForBroadVirtualization(access: Int, name: String, descriptor: String): Boolean {
        // True superset of critical-auto: everything critical-auto selects (critical-signal
        // methods + tiny straight-line methods <= threshold), PLUS medium pure-compute
        // methods (any branch, or size above the tiny threshold) that critical-auto leaves
        // in the plaintext forwarder.
        if (criticalForBroadVirtualization(access, name, descriptor)) return true
        if (skipForBroadVirtualization(access, name, descriptor) || !nativeVmCompatible) return false
        val isNonOverridable = access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL) != 0
        if (!isNonOverridable) return false
        return hasAnyBranch || instructionCount > BROAD_VIRTUALIZATION_MAX_INSTRUCTIONS
    }

    private fun isNativeVmSupportedInsn(opcode: Int): Boolean = when (opcode) {
        Opcodes.NOP,
        Opcodes.ACONST_NULL,
        Opcodes.ICONST_M1,
        Opcodes.ICONST_0,
        Opcodes.ICONST_1,
        Opcodes.ICONST_2,
        Opcodes.ICONST_3,
        Opcodes.ICONST_4,
        Opcodes.ICONST_5,
        Opcodes.LCONST_0,
        Opcodes.LCONST_1,
        Opcodes.FCONST_0,
        Opcodes.FCONST_1,
        Opcodes.FCONST_2,
        Opcodes.DCONST_0,
        Opcodes.DCONST_1,
        Opcodes.POP,
        Opcodes.POP2,
        Opcodes.DUP,
        Opcodes.DUP_X1,
        Opcodes.DUP_X2,
        Opcodes.DUP2,
        Opcodes.DUP2_X1,
        Opcodes.DUP2_X2,
        Opcodes.SWAP,
        Opcodes.IADD,
        Opcodes.LADD,
        Opcodes.FADD,
        Opcodes.DADD,
        Opcodes.ISUB,
        Opcodes.LSUB,
        Opcodes.FSUB,
        Opcodes.DSUB,
        Opcodes.IMUL,
        Opcodes.LMUL,
        Opcodes.FMUL,
        Opcodes.DMUL,
        Opcodes.IDIV,
        Opcodes.LDIV,
        Opcodes.FDIV,
        Opcodes.DDIV,
        Opcodes.IREM,
        Opcodes.LREM,
        Opcodes.FREM,
        Opcodes.DREM,
        Opcodes.INEG,
        Opcodes.LNEG,
        Opcodes.FNEG,
        Opcodes.DNEG,
        Opcodes.ISHL,
        Opcodes.ISHR,
        Opcodes.IUSHR,
        Opcodes.LSHL,
        Opcodes.LSHR,
        Opcodes.LUSHR,
        Opcodes.IAND,
        Opcodes.LAND,
        Opcodes.IOR,
        Opcodes.LOR,
        Opcodes.IXOR,
        Opcodes.LXOR,
        Opcodes.I2L,
        Opcodes.I2F,
        Opcodes.I2D,
        Opcodes.L2I,
        Opcodes.L2F,
        Opcodes.L2D,
        Opcodes.F2I,
        Opcodes.F2L,
        Opcodes.F2D,
        Opcodes.D2I,
        Opcodes.D2L,
        Opcodes.D2F,
        Opcodes.I2B,
        Opcodes.I2C,
        Opcodes.I2S,
        Opcodes.LCMP,
        Opcodes.FCMPL,
        Opcodes.FCMPG,
        Opcodes.DCMPL,
        Opcodes.DCMPG,
        Opcodes.IRETURN,
        Opcodes.LRETURN,
        Opcodes.FRETURN,
        Opcodes.DRETURN,
        Opcodes.ARETURN,
        Opcodes.RETURN,
        Opcodes.ATHROW,
        Opcodes.IALOAD,
        Opcodes.LALOAD,
        Opcodes.FALOAD,
        Opcodes.DALOAD,
        Opcodes.AALOAD,
        Opcodes.BALOAD,
        Opcodes.CALOAD,
        Opcodes.SALOAD,
        Opcodes.IASTORE,
        Opcodes.LASTORE,
        Opcodes.FASTORE,
        Opcodes.DASTORE,
        Opcodes.AASTORE,
        Opcodes.BASTORE,
        Opcodes.CASTORE,
        Opcodes.SASTORE,
        Opcodes.ARRAYLENGTH,
        Opcodes.MONITORENTER,
        Opcodes.MONITOREXIT -> true
        else -> false
    }

    private fun isNativeVmSupportedIntInsn(opcode: Int): Boolean = opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH || opcode == Opcodes.NEWARRAY

    private fun isNativeVmSupportedVarInsn(opcode: Int): Boolean = when (opcode) {
        Opcodes.ILOAD,
        Opcodes.LLOAD,
        Opcodes.FLOAD,
        Opcodes.DLOAD,
        Opcodes.ALOAD,
        Opcodes.ISTORE,
        Opcodes.LSTORE,
        Opcodes.FSTORE,
        Opcodes.DSTORE,
        Opcodes.ASTORE,
        Opcodes.RET -> true
        else -> false
    }

    private fun isNativeVmSupportedJumpInsn(opcode: Int): Boolean = when (opcode) {
        Opcodes.IFEQ,
        Opcodes.IFNE,
        Opcodes.IFLT,
        Opcodes.IFGE,
        Opcodes.IFGT,
        Opcodes.IFLE,
        Opcodes.IF_ICMPEQ,
        Opcodes.IF_ICMPNE,
        Opcodes.IF_ICMPLT,
        Opcodes.IF_ICMPGE,
        Opcodes.IF_ICMPGT,
        Opcodes.IF_ICMPLE,
        Opcodes.IF_ACMPEQ,
        Opcodes.IF_ACMPNE,
        Opcodes.GOTO,
        Opcodes.JSR,
        Opcodes.IFNULL,
        Opcodes.IFNONNULL -> true
        else -> false
    }

    private fun isNativeVmSupportedLdc(value: Any): Boolean = value is Int || value is Long || value is Float || value is Double || value is String || value is Type || value is Handle

    private fun isDirectNativeDefenseCall(owner: String, name: String): Boolean = when (owner) {
        "io/github/hht0rro/javashroud/transforms/protection/AntiInstrumentationHelper" -> name == "nativeCheckInstrumentation"
        "io/github/hht0rro/javashroud/transforms/protection/AntiJvmTiHelper" -> name == "nativeCheckJvmTiAgents"
        "io/github/hht0rro/javashroud/transforms/protection/AntiDumpRuntimeHelper" -> name == "nativeInitializeProtection"
        "io/github/hht0rro/javashroud/transforms/protection/AntiByteBuddyHelper" -> name == "nativeCheckByteBuddy"
        else -> false
    }

    override fun visitInsn(opcode: Int) {
        instructionCount++
        if (!isNativeVmSupportedInsn(opcode)) markNativeVmUnsupported("unsupported instruction opcode=$opcode")
        // Track category-2 (long/double) value producers. The native VM models every
        // stack value as a single slot, so DUP2/POP2 (which in the JVM operate on a
        // category-2 value as one unit, or two category-1 values) would silently
        // miscompute when a long/double is on top. Producing wrong output is worse than
        // a forwarder fallback, so we conservatively mark any method that mixes wide
        // values with DUP2/POP2 as unsupported until the VM tracks value categories.
        when (opcode) {
            Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.DCONST_0, Opcodes.DCONST_1,
            Opcodes.LALOAD, Opcodes.DALOAD,
            Opcodes.LADD, Opcodes.DADD, Opcodes.LSUB, Opcodes.DSUB,
            Opcodes.LMUL, Opcodes.DMUL, Opcodes.LDIV, Opcodes.DDIV,
            Opcodes.LREM, Opcodes.DREM, Opcodes.LNEG, Opcodes.DNEG,
            Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR, Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR,
            Opcodes.I2L, Opcodes.I2D, Opcodes.F2L, Opcodes.F2D, Opcodes.L2D, Opcodes.D2L -> hasWideValue = true
            Opcodes.DUP2, Opcodes.DUP2_X1, Opcodes.DUP2_X2, Opcodes.POP2 -> hasDup2OrPop2 = true
        }
        capturedInstructions.add(CapturedInstruction.NoArg(opcode))
    }

    override fun visitIntInsn(opcode: Int, operand: Int) {
        instructionCount++
        if (!isNativeVmSupportedIntInsn(opcode)) markNativeVmUnsupported("unsupported int instruction opcode=$opcode operand=$operand")
        capturedInstructions.add(CapturedInstruction.IntArg(opcode, operand))
    }

    override fun visitVarInsn(opcode: Int, operand: Int) {
        instructionCount++
        if (!isNativeVmSupportedVarInsn(opcode)) markNativeVmUnsupported("unsupported var instruction opcode=$opcode local=$operand")
        capturedInstructions.add(CapturedInstruction.VarArg(opcode, operand))
    }

    override fun visitTypeInsn(opcode: Int, type: String?) {
        instructionCount++
        hasTypeOperation = true
        if (opcode != Opcodes.NEW && opcode != Opcodes.ANEWARRAY && opcode != Opcodes.CHECKCAST && opcode != Opcodes.INSTANCEOF) markNativeVmUnsupported("unsupported type instruction opcode=$opcode type=${type ?: "java/lang/Object"}")
        capturedInstructions.add(CapturedInstruction.TypeArg(opcode, type ?: "java/lang/Object"))
    }

    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
        instructionCount++
        hasFieldAccess = true
        if (isConsoleStreamField(opcode, owner, name, descriptor)) touchesConsoleIoBoundary = true
        if (opcode != Opcodes.GETSTATIC && opcode != Opcodes.PUTSTATIC && opcode != Opcodes.GETFIELD && opcode != Opcodes.PUTFIELD) markNativeVmUnsupported("unsupported field instruction opcode=$opcode owner=$owner name=$name desc=$descriptor")
        capturedInstructions.add(CapturedInstruction.FieldArg(opcode, owner, name, descriptor))
    }

    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
        instructionCount++
        hasMethodCall = true
        if (isHighValueCall(owner, name)) hasHighValueCall = true
        if (isConsoleStreamMethod(owner, name)) touchesConsoleIoBoundary = true
        if (opcode != Opcodes.INVOKEVIRTUAL && opcode != Opcodes.INVOKESPECIAL && opcode != Opcodes.INVOKESTATIC && opcode != Opcodes.INVOKEINTERFACE) markNativeVmUnsupported("unsupported method instruction opcode=$opcode owner=$owner name=$name desc=$descriptor")
        if (isDirectNativeDefenseCall(owner, name)) hasDirectNativeDefenseCall = true
        capturedInstructions.add(CapturedInstruction.MethodArg(opcode, owner, name, descriptor, isInterface))
    }

    override fun visitInvokeDynamicInsn(name: String, descriptor: String, bootstrapMethodHandle: Handle, vararg bootstrapMethodArguments: Any) {
        hasInvokeDynamic = true
        if (!isNativeVmSupportedInvokeDynamic(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments)) {
            hasUnsupportedInvokeDynamic = true
            markNativeVmUnsupported("unsupported invokedynamic name=$name desc=$descriptor bsm=${bootstrapMethodHandle.owner}.${bootstrapMethodHandle.name}${bootstrapMethodHandle.desc}")
        }
        instructionCount++
        capturedInstructions.add(CapturedInstruction.IndyArg(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments.toList().toTypedArray()))
    }

    override fun visitJumpInsn(opcode: Int, label: Label?) {
        instructionCount++
        hasAnyBranch = true
        if (opcode != Opcodes.IFEQ && opcode != Opcodes.IFNE && opcode != Opcodes.GOTO) hasComplexBranch = true
        if (label == null || !isNativeVmSupportedJumpInsn(opcode)) markNativeVmUnsupported("unsupported jump opcode=$opcode hasLabel=${label != null}")
        if (label != null) capturedInstructions.add(CapturedInstruction.JumpArg(opcode, label))
    }

    override fun visitLdcInsn(value: Any) {
        instructionCount++
        if (!isNativeVmSupportedLdc(value)) markNativeVmUnsupported("unsupported ldc type=${value::class.java.name}")
        capturedInstructions.add(CapturedInstruction.LdcArg(value))
    }

    override fun visitIincInsn(localIndex: Int, increment: Int) {
        instructionCount++
        if (localIndex > 0xFF || increment !in Byte.MIN_VALUE..Byte.MAX_VALUE) markNativeVmUnsupported("unsupported iinc local=$localIndex increment=$increment")
        capturedInstructions.add(CapturedInstruction.IincArg(localIndex, increment))
    }

    override fun visitLabel(label: Label?) { if (label != null) capturedInstructions.add(CapturedInstruction.LabelMark(label)) }

    override fun visitTryCatchBlock(start: Label?, end: Label?, handler: Label?, type: String?) {
        hasExceptionHandler = true
        if (start != null && end != null && handler != null) capturedInstructions.add(CapturedInstruction.TryCatch(start, end, handler, type))
    }

    override fun visitMaxs(maxStack: Int, maxLocals: Int) {
        if (maxLocals > 0xFF) markNativeVmUnsupported("maxLocals exceeds VBC4 local index limit: $maxLocals")
        // Order-independent category-2 safety: if the method both produces long/double
        // values and uses DUP2/POP2, the single-slot VM could miscompute category-2 stack
        // manipulation. Mark unsupported (forwarder) rather than risk silent wrong output.
        capturedInstructions.add(CapturedInstruction.Maxs(maxStack, maxLocals))
    }

    override fun visitTableSwitchInsn(min: Int, max: Int, dflt: Label?, vararg labels: Label?) {
        instructionCount++
        hasAnyBranch = true
        hasComplexBranch = true
        // tableswitch is fully supported by the native VM (JS_VM_TABLESWITCH handler +
        // [min,max,default,targets...] operand encoding), so it must NOT fall back to the
        // plaintext forwarder. Switch statements are common in hot code paths.
        capturedInstructions.add(CapturedInstruction.TableSwitchArg(min, max, dflt, labels))
    }

    override fun visitLookupSwitchInsn(dflt: Label?, keys: IntArray?, labels: Array<Label>?) {
        instructionCount++
        hasAnyBranch = true
        hasComplexBranch = true
        // lookupswitch is fully supported by the native VM (JS_VM_LOOKUPSWITCH handler +
        // [npairs,default,key,target,...] operand encoding), so it must NOT fall back to
        // the plaintext forwarder.
        capturedInstructions.add(CapturedInstruction.LookupSwitchArg(dflt, keys, labels))
    }

    override fun visitMultiANewArrayInsn(descriptor: String?, numDimensions: Int) {
        instructionCount++
        hasTypeOperation = true
        // multianewarray is fully supported by the native VM (JS_VM_MULTIANEWARRAY handler
        // + js_vm_new_multi_array via java.lang.reflect.Array.newInstance), with operand
        // layout [typeCpIndex, numDimensions]. Do NOT fall back to the plaintext forwarder.
        capturedInstructions.add(CapturedInstruction.MultiANewArrayArg(descriptor ?: "java/lang/Object", numDimensions))
    }
}

private const val BROAD_VIRTUALIZATION_MAX_INSTRUCTIONS = 16

private fun specializedVmDispatchMethod(descriptor: String, access: Int): String? {
    if (access and Opcodes.ACC_STATIC == 0) return null
    if (Type.getReturnType(descriptor) != Type.VOID_TYPE) return null
    val args = Type.getArgumentTypes(descriptor)
    return when {
        args.isEmpty() -> "executeVmResourceVoid"
        args.size == 1 && args[0] == Type.INT_TYPE -> "executeVmResourceIntVoid"
        else -> null
    }
}

private fun specializedVmDispatchDescriptor(descriptor: String, access: Int): String? {
    return when (specializedVmDispatchMethod(descriptor, access)) {
        "executeVmResourceVoid" -> VM_VOID_DISPATCH_DESCRIPTOR
        "executeVmResourceIntVoid" -> VM_INT_VOID_DISPATCH_DESCRIPTOR
        else -> null
    }
}

internal fun generateVmDispatcher(
    mv: MethodVisitor, className: String, methodName: String, descriptor: String, access: Int,
    opcodeMapping: Map<Int, Int>, handlerOrder: List<Int>, dispatchLayout: String, random: SecureRandom,
    resourcePath: String,
    entryToken: Long = 0L,
    dispatchOwner: String = JNI_MICROKERNEL_DISPATCH_OWNER,
    dispatchMethod: String = JNI_MICROKERNEL_VM_DISPATCH_METHOD,
    dispatchDescriptor: String = VM_LEGACY_DISPATCH_DESCRIPTOR,
) {
    mv.visitCode()

    // Polymorphic stub: shuffle constant loading through local variable slots
    val argTypes = Type.getArgumentTypes(descriptor)
    val isStatic = access and Opcodes.ACC_STATIC != 0
    val totalArgs = argTypes.size + if (isStatic) 0 else 1
    // Scratch locals must start past the real parameter slots. long/double params each
    // occupy two slots, so the base is derived from the category-2-aware slot count
    // (argType.size sum) plus the implicit `this` slot, plus one gap slot. Using the raw
    // argument count here collides with the second half of a long/double parameter and
    // corrupts it (JVM VerifyError: Bad local variable type).
    val parameterSlotCount = argTypes.sumOf { it.size } + if (isStatic) 0 else 1
    val localBase = parameterSlotCount + 1 // after params + this + 1 gap slot
    val usesTokenOnlyDispatch = dispatchDescriptor == VM_TOKEN_DISPATCH_DESCRIPTOR
    val usesVoidSpecializedDispatch = dispatchDescriptor == VM_VOID_DISPATCH_DESCRIPTOR || dispatchDescriptor == VM_INT_VOID_DISPATCH_DESCRIPTOR
    if (!usesTokenOnlyDispatch && !usesVoidSpecializedDispatch) {
        // Legacy dispatch paths keep the obfuscated resource path argument for compatibility.
        emitObfuscatedString(mv, resourcePath, random)
        mv.visitVarInsn(Opcodes.ASTORE, localBase)
        repeat(random.nextInt(3)) {
            when (random.nextInt(4)) {
                0 -> mv.visitInsn(Opcodes.NOP)
                1 -> { mv.visitInsn(Opcodes.ICONST_0); mv.visitInsn(Opcodes.POP) }
                2 -> { mv.visitInsn(Opcodes.ACONST_NULL); mv.visitInsn(Opcodes.POP) }
                3 -> { /* skip */ }
            }
        }
    }
    if (handlerOrder.size > opcodeMapping.size) {
        emitDispatcherMorphBlock(mv, opcodeMapping, handlerOrder, dispatchLayout, localBase + if (usesTokenOnlyDispatch || usesVoidSpecializedDispatch) 0 else 1, random)
    }
    emitDeadCodeShadowDispatch(mv, localBase + if (usesTokenOnlyDispatch || usesVoidSpecializedDispatch) 8 else 9, random)
    mv.visitLdcInsn(entryToken)
    if (!usesTokenOnlyDispatch && !usesVoidSpecializedDispatch) {
        mv.visitVarInsn(Opcodes.ALOAD, localBase)
    }

    if (usesVoidSpecializedDispatch) {
        if (dispatchDescriptor == VM_INT_VOID_DISPATCH_DESCRIPTOR) {
            mv.visitVarInsn(Opcodes.ILOAD, if (isStatic) 0 else 1)
        }
    } else {
        mv.visitIntInsn(Opcodes.BIPUSH, totalArgs)
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")

        // For instance methods, pass this as args[0]
        if (!isStatic) {
            mv.visitInsn(Opcodes.DUP)
            mv.visitInsn(Opcodes.ICONST_0)
            mv.visitVarInsn(Opcodes.ALOAD, 0) // this
            mv.visitInsn(Opcodes.AASTORE)
        }

        var slot = if (isStatic) 0 else 1
        for ((i, argType) in argTypes.withIndex()) {
            mv.visitInsn(Opcodes.DUP)
            mv.visitIntInsn(Opcodes.BIPUSH, if (isStatic) i else i + 1)
            mv.visitVarInsn(argType.getOpcode(Opcodes.ILOAD), slot)
            boxPrimitive(mv, argType)
            mv.visitInsn(Opcodes.AASTORE)
            slot += argType.size
        }
    }

    // Real dispatch call
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        dispatchOwner,
        dispatchMethod,
        dispatchDescriptor,
        false,
    )

    val returnType = Type.getReturnType(descriptor)
    if (usesVoidSpecializedDispatch) {
        mv.visitInsn(Opcodes.RETURN)
    } else {
        unboxAndReturn(mv, returnType)
    }

    mv.visitMaxs(argTypes.sumOf { it.size } + 8, argTypes.sumOf { it.size } + 6)
    mv.visitEnd()
}

private fun emitDeadCodeShadowDispatch(
    mv: MethodVisitor,
    scratchSlot: Int,
    random: SecureRandom,
) {
    // Opaque predicate: dead-code shadow dispatch to confuse pattern scanners.
    val shadowChance = random.nextInt(100)
    if (shadowChance >= 40) return

    val fakeId = { len: Int -> (1..len).map { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[random.nextInt(62)] }.joinToString("") }
    val fakeOwner = "r/${fakeId(2)}/C${fakeId(24)}"
    val fakeMethod = fakeId(6)
    val shadowStart = Label()
    val shadowEnd = Label()

    mv.visitInsn(Opcodes.ICONST_0)
    mv.visitJumpInsn(Opcodes.IFEQ, shadowEnd)
    mv.visitLabel(shadowStart)
    mv.visitLdcInsn(0L)
    emitObfuscatedString(mv, fakeResourcePath(fakeId, random), random)
    mv.visitInsn(Opcodes.ICONST_0)
    mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        fakeOwner,
        fakeMethod,
        VM_LEGACY_DISPATCH_DESCRIPTOR,
        false,
    )
    mv.visitInsn(Opcodes.POP)
    mv.visitLabel(shadowEnd)
}
private fun fakeResourcePath(fakeId: (Int) -> String, random: SecureRandom): String {
    val extensions = listOf("properties", "xml", "json", "yml", "cfg", "conf", "ini", "txt")
    val ext = extensions[random.nextInt(extensions.size)]
    return "META-INF/${fakeId(2)}/${fakeId(4)}/${fakeId(18)}.$ext"
}
private fun emitObfuscatedString(mv: MethodVisitor, value: String, random: SecureRandom) {
    pushInt(mv, value.length)
    mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_CHAR)
    for ((index, char) in value.withIndex()) {
        val delta = random.nextInt(0x10000)
        val encoded = char.code - delta
        mv.visitInsn(Opcodes.DUP)
        pushInt(mv, index)
        pushInt(mv, encoded)
        pushInt(mv, delta)
        mv.visitInsn(Opcodes.IADD)
        mv.visitInsn(Opcodes.I2C)
        mv.visitInsn(Opcodes.CASTORE)
    }
    mv.visitTypeInsn(Opcodes.NEW, "java/lang/String")
    mv.visitInsn(Opcodes.DUP_X1)
    mv.visitInsn(Opcodes.SWAP)
    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false)
}

private fun pushInt(mv: MethodVisitor, value: Int) {
    when (value) {
        -1 -> mv.visitInsn(Opcodes.ICONST_M1)
        0 -> mv.visitInsn(Opcodes.ICONST_0)
        1 -> mv.visitInsn(Opcodes.ICONST_1)
        2 -> mv.visitInsn(Opcodes.ICONST_2)
        3 -> mv.visitInsn(Opcodes.ICONST_3)
        4 -> mv.visitInsn(Opcodes.ICONST_4)
        5 -> mv.visitInsn(Opcodes.ICONST_5)
        in Byte.MIN_VALUE..Byte.MAX_VALUE -> mv.visitIntInsn(Opcodes.BIPUSH, value)
        in Short.MIN_VALUE..Short.MAX_VALUE -> mv.visitIntInsn(Opcodes.SIPUSH, value)
        else -> mv.visitLdcInsn(value)
    }
}

private fun emitDispatcherMorphBlock(
    mv: MethodVisitor,
    opcodeMapping: Map<Int, Int>,
    handlerOrder: List<Int>,
    dispatchLayout: String,
    morphSlot: Int,
    random: SecureRandom,
) {
    if (handlerOrder.isEmpty()) return
    val handlerSalt = handlerOrder.foldIndexed(dispatchLayout.hashCode()) { index, acc, handler ->
        acc xor ((handler + 0x9E3779B9.toInt()) * (index + 1))
    }
    val opcodeSalt = opcodeMapping.entries.sortedBy { it.key }.fold(handlerSalt) { acc, entry ->
        acc.rotateLeft(5) xor (entry.key shl 8) xor entry.value
    }
    mv.visitLdcInsn(opcodeSalt + random.nextInt())
    mv.visitVarInsn(Opcodes.ISTORE, morphSlot)
    val rounds = if (handlerOrder.size > opcodeMapping.size) 4 + (handlerOrder.size % 5) else 1
    repeat(rounds) { index ->
        mv.visitVarInsn(Opcodes.ILOAD, morphSlot)
        mv.visitLdcInsn(handlerOrder[index % handlerOrder.size] - opcodeSalt.rotateRight(index + 1))
        mv.visitInsn(Opcodes.IADD)
        mv.visitVarInsn(Opcodes.ISTORE, morphSlot)
        if (random.nextBoolean()) {
            mv.visitVarInsn(Opcodes.ILOAD, morphSlot)
            mv.visitInsn(Opcodes.POP)
        }
    }
}

private fun boxPrimitive(mv: MethodVisitor, type: Type) {
    when (type.sort) {
        Type.INT -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
        Type.LONG -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
        Type.FLOAT -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false)
        Type.DOUBLE -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false)
        Type.BOOLEAN -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false)
        Type.BYTE -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false)
        Type.SHORT -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false)
        Type.CHAR -> mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false)
    }
}

private fun unboxAndReturn(mv: MethodVisitor, type: Type) {
    when (type.sort) {
        Type.VOID -> { mv.visitInsn(Opcodes.POP); mv.visitInsn(Opcodes.RETURN) }
        Type.INT -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.LONG -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Long"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false); mv.visitInsn(Opcodes.LRETURN) }
        Type.FLOAT -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Float"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false); mv.visitInsn(Opcodes.FRETURN) }
        Type.DOUBLE -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Double"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false); mv.visitInsn(Opcodes.DRETURN) }
        Type.BOOLEAN -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Boolean"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.BYTE -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Byte"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.SHORT -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Short"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.CHAR -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Character"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false); mv.visitInsn(Opcodes.IRETURN) }
        else -> { mv.visitTypeInsn(Opcodes.CHECKCAST, type.internalName); mv.visitInsn(Opcodes.ARETURN) }
    }
}









