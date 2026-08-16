package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import org.objectweb.asm.*
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MultiANewArrayInsnNode
import org.objectweb.asm.tree.TypeInsnNode
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.jar.Manifest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

fun applyClassEncryptionLoader(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "class-encryption-loader")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)
    val dynamicLoaderPackages = collectDynamicLoaderPackages(artifact)
    val manifestEntryPointClosure = manifestEntryPointClassClosure(artifact)
    val encryptionCandidates = expandClassEncryptionRuntimePackageClosure(artifact, matchedClassNames)
        .filterNot { className -> className.substringBeforeLast('/', missingDelimiterValue = "") in dynamicLoaderPackages }
        .filterNot { className -> className in manifestEntryPointClosure }
        .filter { className -> artifact.classArtifactIndex[className]?.let(::isSafeClassEncryptionCandidate) == true }
        .toSet()
    val encryptedClassNames = pruneUnsafePackagePrivateLoaderSplits(artifact, encryptionCandidates)

    // Retain the public configuration validation during the protocol
    // transition. AKEN v4 owns actual page AEAD and does not derive a class
    // root key from either setting.
    val strategy = (params["encryptionStrategy"] as? String) ?: "aes-128"
    val supportedStrategies = setOf("aes-128", "aes-256")
    require(strategy in supportedStrategies) {
        "class-encryption-loader encryptionStrategy '" +
            strategy +
            "' is not supported; supported values: " +
            supportedStrategies.joinToString(", ")
    }
    val keyMode = (params["keyMode"] as? String) ?: "per-class"
    val supportedKeyModes = setOf("per-class", "global")
    require(keyMode in supportedKeyModes) {
        "class-encryption-loader keyMode '" +
            keyMode +
            "' is not supported; supported values: " +
            supportedKeyModes.joinToString(", ")
    }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { configuredSeed ->
        SecureRandom(configuredSeed.toString().toByteArray(Charsets.UTF_8))
    } ?: SecureRandom()
    val buildContext = requireVbc4BuildContext()
    val nameGen = NameGenerator(random)
    val candidateBatches = LinkedHashMap<String, List<AkenClassPageCandidate>>()
    var classCount = 0

    try {
        val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
            if (!encryptedClassNames.contains(classArtifact.summary.internalName)) {
                return@map classArtifact
            }

            val className = classArtifact.summary.internalName
            val classCandidates = createAkenClassPageCandidates(
                classInternalName = className,
                classBytes = classArtifact.bytes,
                random = random,
            )
            try {
                check(candidateBatches.put(className, classCandidates) == null) {
                    "AKEN ClassPage candidates were generated more than once for " + className
                }
            } catch (error: Throwable) {
                classCandidates.forEach { candidate -> candidate.wipe() }
                throw error
            }
            classCount++

            // Interfaces enter the class-local descriptor map so a real class
            // defined by the shared child loader can resolve them through the
            // typed ClassPage bridge. They keep their original bytecode because
            // an interface cannot be proxied by a delegating instance stub.
            if (classArtifact.summary.accessFlags and Opcodes.ACC_INTERFACE != 0) {
                return@map classArtifact
            }

            val stubBytes = generateClassStubVisitor(
                classBytes = classArtifact.bytes,
                binaryClassName = className.replace('/', '.'),
                nameGen = nameGen,
            )
            reanalyzedClassArtifact(classArtifact, stubBytes)
        }

        if (classCount == 0) return unchangedTransformResult(artifact)

        candidateBatches
            .toSortedMap()
            .forEach { (internalName, candidates) ->
                buildContext.registerAkenClassPageCandidatesForClass(
                    internalName = internalName,
                    candidates = candidates,
                )
            }

        return updatedArtifactTransformResult(
            artifact = artifact,
            updatedClassArtifacts = updatedClassArtifacts,
            transformedClassCount = classCount,
            transformedMemberCount = classCount,
        )
    } finally {
        candidateBatches.values.flatten().forEach { candidate -> candidate.wipe() }
    }
}


private const val AKEN_CLASS_PAGE_BUILD_NONCE_SIZE = 32
private val AKEN_CLASS_PAGE_TARGET_SIZES = intArrayOf(512, 1024, 1536, 2048)
private val AKEN_CLASS_PAGE_IDENTITY_DOMAIN =
    "AKEN-v4-class-page-identity-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_CLASS_PAGE_HANDLE_DOMAIN =
    "AKEN-v4-class-page-handle-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_CLASS_PAGE_PROOF_DOMAIN =
    "AKEN-v4-class-page-proof-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_CLASS_PAGE_PATH_DOMAIN =
    "AKEN-v4-class-page-logical-path-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_CLASS_PAGE_PATH_ROOTS = arrayOf(
    "META-INF/.logical/cp",
    "META-INF/.r4/cp",
    "assets/.logical/cp",
)
private val AKEN_CLASS_PAGE_PATH_SUFFIXES = arrayOf(".bin", ".dat", ".p")

/**
 * Partitions one original class definition into independently bound AKEN
 * ClassPages. Every page receives its own identity, handle, proof, layout
 * variant, and target size; no class-wide AES key, manifest record, or
 * resource-path/key-metadata pair is produced.
 */
private fun createAkenClassPageCandidates(
    classInternalName: String,
    classBytes: ByteArray,
    random: SecureRandom,
): List<AkenClassPageCandidate> {
    require(classBytes.isNotEmpty()) { "AKEN ClassPage source bytes must not be empty" }
    val candidates = ArrayList<AkenClassPageCandidate>()
    var offset = 0
    var pageIndex = 0
    try {
        while (offset < classBytes.size) {
            val targetPageSize = AKEN_CLASS_PAGE_TARGET_SIZES[random.nextInt(AKEN_CLASS_PAGE_TARGET_SIZES.size)]
            val pageLength = minOf(targetPageSize, classBytes.size - offset)
            val buildNonce = ByteArray(AKEN_CLASS_PAGE_BUILD_NONCE_SIZE).also(random::nextBytes)
            var logicalIdentity: ByteArray? = null
            var plaintext: ByteArray? = null
            var encodedHandle: ByteArray? = null
            var callSiteProof: ByteArray? = null
            var candidate: AkenClassPageCandidate? = null
            try {
                logicalIdentity = deriveAkenClassPageIdentity(
                    classInternalName = classInternalName,
                    pageIndex = pageIndex,
                    pageOffset = offset,
                    pageLength = pageLength,
                    buildNonce = buildNonce,
                )
                encodedHandle = deriveAkenClassPageHandle(logicalIdentity, buildNonce)
                val logicalBindingPath = akenClassPageLogicalBindingPath(logicalIdentity, encodedHandle)
                callSiteProof = deriveAkenClassPageCallSiteProof(
                    logicalIdentity = logicalIdentity,
                    encodedHandle = encodedHandle,
                    pageIndex = pageIndex,
                    logicalBindingPath = logicalBindingPath,
                )
                plaintext = classBytes.copyOfRange(offset, offset + pageLength)
                candidate = AkenClassPageCandidate.create(
                    logicalIdentity = logicalIdentity,
                    plaintext = plaintext,
                    pageIndex = pageIndex,
                    callSiteProof = callSiteProof,
                    encodedHandle = encodedHandle,
                    logicalBindingPath = logicalBindingPath,
                    targetPageSize = targetPageSize,
                    random = random,
                )
                candidates += candidate
                candidate = null
                offset += pageLength
                pageIndex++
            } finally {
                candidate?.wipe()
                java.util.Arrays.fill(buildNonce, 0)
                logicalIdentity?.let { value -> java.util.Arrays.fill(value, 0) }
                plaintext?.let { value -> java.util.Arrays.fill(value, 0) }
                encodedHandle?.let { value -> java.util.Arrays.fill(value, 0) }
                callSiteProof?.let { value -> java.util.Arrays.fill(value, 0) }
            }
        }
        return candidates
    } catch (error: Throwable) {
        candidates.forEach { candidate -> candidate.wipe() }
        throw error
    }
}

private fun deriveAkenClassPageIdentity(
    classInternalName: String,
    pageIndex: Int,
    pageOffset: Int,
    pageLength: Int,
    buildNonce: ByteArray,
): ByteArray = MessageDigest.getInstance("SHA-256").apply {
    update(AKEN_CLASS_PAGE_IDENTITY_DOMAIN)
    updateAkenClassPageString(classInternalName)
    updateAkenClassPageInt(pageIndex)
    updateAkenClassPageInt(pageOffset)
    updateAkenClassPageInt(pageLength)
    updateAkenClassPageBytes(buildNonce)
}.digest()

private fun deriveAkenClassPageHandle(
    logicalIdentity: ByteArray,
    buildNonce: ByteArray,
): ByteArray {
    val digest = digestAkenClassPageBinding(
        AKEN_CLASS_PAGE_HANDLE_DOMAIN,
        logicalIdentity,
        buildNonce,
    )
    return try {
        digest.copyOf(AkenHandle.ENCODED_HANDLE_SIZE)
    } finally {
        java.util.Arrays.fill(digest, 0)
    }
}

private fun deriveAkenClassPageCallSiteProof(
    logicalIdentity: ByteArray,
    encodedHandle: ByteArray,
    pageIndex: Int,
    logicalBindingPath: String,
): ByteArray {
    val pageBytes = akenClassPageIntBytes(pageIndex)
    val pathBytes = logicalBindingPath.toByteArray(Charsets.UTF_8)
    return try {
        digestAkenClassPageBinding(
            AKEN_CLASS_PAGE_PROOF_DOMAIN,
            logicalIdentity,
            encodedHandle,
            pageBytes,
            pathBytes,
        )
    } finally {
        java.util.Arrays.fill(pageBytes, 0)
        java.util.Arrays.fill(pathBytes, 0)
    }
}

private fun akenClassPageLogicalBindingPath(
    logicalIdentity: ByteArray,
    encodedHandle: ByteArray,
): String {
    val digest = digestAkenClassPageBinding(
        AKEN_CLASS_PAGE_PATH_DOMAIN,
        logicalIdentity,
        encodedHandle,
    )
    return try {
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        val root = AKEN_CLASS_PAGE_PATH_ROOTS[
            (digest[0].toInt() and 0xFF) % AKEN_CLASS_PAGE_PATH_ROOTS.size
        ]
        val prefixLength = 2 + ((digest[1].toInt() and 0xFF) % 3)
        val suffix = AKEN_CLASS_PAGE_PATH_SUFFIXES[
            (digest[2].toInt() and 0xFF) % AKEN_CLASS_PAGE_PATH_SUFFIXES.size
        ]
        root + "/" + token.substring(0, prefixLength) + "/" + token.substring(prefixLength) + suffix
    } finally {
        java.util.Arrays.fill(digest, 0)
    }
}

private fun digestAkenClassPageBinding(domain: ByteArray, vararg values: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").apply {
        update(domain)
        values.forEach { value -> updateAkenClassPageBytes(value) }
    }.digest()

private fun MessageDigest.updateAkenClassPageString(value: String) {
    val bytes = value.toByteArray(Charsets.UTF_8)
    try {
        updateAkenClassPageBytes(bytes)
    } finally {
        java.util.Arrays.fill(bytes, 0)
    }
}

private fun MessageDigest.updateAkenClassPageBytes(value: ByteArray) {
    updateAkenClassPageInt(value.size)
    update(value)
}

private fun MessageDigest.updateAkenClassPageInt(value: Int) {
    val bytes = akenClassPageIntBytes(value)
    try {
        update(bytes)
    } finally {
        java.util.Arrays.fill(bytes, 0)
    }
}

private fun akenClassPageIntBytes(value: Int): ByteArray = byteArrayOf(
    (value ushr 24).toByte(),
    (value ushr 16).toByte(),
    (value ushr 8).toByte(),
    value.toByte(),
)

private fun isSafeClassEncryptionCandidate(classArtifact: ClassArtifact): Boolean {
    val node = ClassNode()
    return runCatching {
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_FRAMES)
        val hasInstanceField = node.fields.orEmpty().any { field -> field.access and Opcodes.ACC_STATIC == 0 }
        val hasInstanceMethod = node.methods.orEmpty().any { method ->
            method.access and (Opcodes.ACC_STATIC or Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) == 0 &&
                method.name != "<init>"
        }
        !hasInstanceField && !hasInstanceMethod
    }.getOrDefault(false)
}

private fun pruneUnsafePackagePrivateLoaderSplits(
    artifact: BytecodeArtifact,
    candidates: Set<String>,
): Set<String> {
    val selected = candidates.toMutableSet()
    var changed: Boolean
    do {
        changed = false
        for (className in selected.toList()) {
            val classArtifact = artifact.classArtifactIndex[className] ?: continue
            val unresolvedDependencies = packagePrivateRuntimeDependencies(classArtifact, artifact.classArtifactIndex)
                .filterNot { dependency -> dependency in selected }
            if (unresolvedDependencies.isNotEmpty()) {
                selected.remove(className)
                changed = true
            }
        }
    } while (changed)
    return selected
}

private fun packagePrivateRuntimeDependencies(
    classArtifact: ClassArtifact,
    index: Map<String, ClassArtifact>,
): Set<String> {
    val node = ClassNode()
    return runCatching {
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_FRAMES)
        val packageName = node.name.substringBeforeLast('/', missingDelimiterValue = "")
        buildSet<String> {
            fun addIfPackagePrivateBoundary(owner: String, name: String? = null, desc: String? = null) {
                if (owner == node.name) return
                if (owner.substringBeforeLast('/', missingDelimiterValue = "") != packageName) return
                val ownerArtifact = index[owner] ?: return
                if (isPackagePrivateRuntimeType(ownerArtifact)) {
                    add(owner)
                    return
                }
                if (name == null || desc == null) return
                val member = ownerArtifact.summary.methodSummaries.firstOrNull { it.name == name && it.descriptor == desc }
                    ?: ownerArtifact.summary.fieldSummaries.firstOrNull { it.name == name && it.descriptor == desc }
                if (member != null && member.accessFlags and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PRIVATE or Opcodes.ACC_PROTECTED) == 0) {
                    add(owner)
                }
            }

            for (method in node.methods) {
                method.instructions?.iterator()?.forEach { insn ->
                    when (insn) {
                        is MethodInsnNode -> addIfPackagePrivateBoundary(insn.owner, insn.name, insn.desc)
                        is FieldInsnNode -> addIfPackagePrivateBoundary(insn.owner, insn.name, insn.desc)
                        is TypeInsnNode -> addIfPackagePrivateBoundary(insn.desc)
                    }
                }
            }
        }
    }.getOrDefault(emptySet())
}
private fun manifestEntryPointClassClosure(artifact: BytecodeArtifact): Set<String> {
    val index = artifact.classArtifactIndex
    val selected = manifestEntryPointClasses(artifact).filterTo(LinkedHashSet<String>()) { className -> className in index }
    val queue = ArrayDeque<String>()
    queue.addAll(selected)
    while (queue.isNotEmpty()) {
        val className = queue.removeFirst()
        val classArtifact = index[className] ?: continue
        for (referenced in referencedApplicationClasses(classArtifact, index.keys)) {
            if (selected.add(referenced)) queue.addLast(referenced)
        }
    }
    return selected
}

private fun referencedApplicationClasses(classArtifact: ClassArtifact, applicationClasses: Set<String>): Set<String> {
    val node = ClassNode()
    return runCatching {
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_FRAMES)
        buildSet<String> {
            addReferencedType(node.superName, applicationClasses)
            node.interfaces.orEmpty().forEach { addReferencedType(it as String, applicationClasses) }
            node.outerClass?.let { addReferencedType(it, applicationClasses) }
            node.nestHostClass?.let { addReferencedType(it, applicationClasses) }
            node.nestMembers.orEmpty().forEach { addReferencedType(it as String, applicationClasses) }
            node.innerClasses.orEmpty().forEach { inner ->
                addReferencedType(inner.name, applicationClasses)
                inner.outerName?.let { addReferencedType(it, applicationClasses) }
            }
            node.fields.orEmpty().forEach { field ->
                addDescriptorTypes(field.desc, applicationClasses)
                field.signature?.let { addSignatureTypeNames(it, applicationClasses) }
            }
            node.methods.orEmpty().forEach { method ->
                addDescriptorTypes(method.desc, applicationClasses)
                method.signature?.let { addSignatureTypeNames(it, applicationClasses) }
                method.exceptions.orEmpty().forEach { addReferencedType(it as String, applicationClasses) }
                method.tryCatchBlocks.orEmpty().forEach { block -> block.type?.let { addReferencedType(it, applicationClasses) } }
                method.instructions?.iterator()?.forEach { insn ->
                    when (insn) {
                        is FieldInsnNode -> {
                            addReferencedType(insn.owner, applicationClasses)
                            addDescriptorTypes(insn.desc, applicationClasses)
                        }
                        is MethodInsnNode -> {
                            addReferencedType(insn.owner, applicationClasses)
                            addDescriptorTypes(insn.desc, applicationClasses)
                        }
                        is TypeInsnNode -> addReferencedType(insn.desc, applicationClasses)
                        is LdcInsnNode -> (insn.cst as? Type)?.let { addType(it, applicationClasses) }
                        is MultiANewArrayInsnNode -> addDescriptorTypes(insn.desc, applicationClasses)
                    }
                }
            }
        }
    }.getOrDefault(emptySet())
}

private fun MutableSet<String>.addDescriptorTypes(descriptor: String, applicationClasses: Set<String>) {
    runCatching { Type.getType(descriptor) }.getOrNull()?.let { addType(it, applicationClasses) }
}

private fun MutableSet<String>.addType(type: Type, applicationClasses: Set<String>) {
    when (type.sort) {
        Type.ARRAY -> addType(type.elementType, applicationClasses)
        Type.OBJECT -> addReferencedType(type.internalName, applicationClasses)
        Type.METHOD -> {
            type.argumentTypes.forEach { addType(it, applicationClasses) }
            addType(type.returnType, applicationClasses)
        }
    }
}

private fun MutableSet<String>.addSignatureTypeNames(signature: String, applicationClasses: Set<String>) {
    for (candidate in applicationClasses) {
        if (signature.contains("L$candidate;")) add(candidate)
    }
}

private fun MutableSet<String>.addReferencedType(internalName: String, applicationClasses: Set<String>) {
    var name = internalName.removePrefix("[").removePrefix("L").removeSuffix(";")
    while (name.startsWith("[")) name = name.removePrefix("[").removePrefix("L").removeSuffix(";")
    if (name in applicationClasses) add(name)
}
private fun manifestEntryPointClasses(artifact: BytecodeArtifact): Set<String> {
    val manifestEntry = artifact.jarEntries.firstOrNull { it.name.equals("META-INF/MANIFEST.MF", ignoreCase = true) }
        ?: return emptySet()
    return runCatching {
        Manifest(manifestEntry.bytes.inputStream()).mainAttributes
            .getValue("Main-Class")
            ?.replace('.', '/')
            ?.let(::setOf)
            ?: emptySet()
    }.getOrDefault(emptySet())
}
private fun collectDynamicLoaderPackages(artifact: BytecodeArtifact): Set<String> {
    val packages = HashSet<String>()
    for (classArtifact in artifact.classArtifacts) {
        val node = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) {
            continue
        }
        for (method in node.methods) {
            if (!method.instructions.asSequence().filterIsInstance<MethodInsnNode>().any { it.name == "defineClass" }) continue
            val instructions = method.instructions.toArray()
            for (index in instructions.indices) {
                val call = instructions[index] as? MethodInsnNode ?: continue
                if (call.owner != "java/lang/ClassLoader" && call.name != "getResourceAsStream") continue
                var scan = index - 1
                while (scan >= 0 && index - scan <= 24) {
                    val value = (instructions[scan] as? LdcInsnNode)?.cst
                    val internalName = when (value) {
                        is Type -> value.takeIf { it.sort == Type.OBJECT }?.internalName
                        is String -> value.removePrefix("/").removeSuffix(".class").takeIf { it.contains('/') }
                        else -> null
                    }
                    if (internalName != null) {
                        packages.add(internalName.substringBeforeLast('/', missingDelimiterValue = ""))
                        break
                    }
                    scan--
                }
            }
        }
    }
    return packages
}
private fun expandClassEncryptionRuntimePackageClosure(

    artifact: BytecodeArtifact,

    initialClassNames: Set<String>,

): Set<String> {

    val index = artifact.classArtifactIndex

    val selected = initialClassNames.toMutableSet()

    var changed: Boolean

    do {

        changed = false

        for (className in selected.toList()) {

            val classArtifact = index[className] ?: continue

            val packageName = className.substringBeforeLast('/', missingDelimiterValue = "")

            val related = sequenceOf(classArtifact.summary.superName)

                .plus(classArtifact.summary.interfaceNames.asSequence())

                .filterNotNull()

            for (candidateName in related) {

                val candidate = index[candidateName] ?: continue

                if (candidateName.substringBeforeLast('/', missingDelimiterValue = "") != packageName) continue

                if (!isPackagePrivateRuntimeType(candidate)) continue

                if (selected.add(candidateName)) changed = true

            }

        }

    } while (changed)

    return selected

}



private fun isPackagePrivateRuntimeType(classArtifact: ClassArtifact): Boolean {

    val access = classArtifact.summary.accessFlags

    return access and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PRIVATE or Opcodes.ACC_PROTECTED) == 0

}

// --- Visitor-based stub generation ---

private const val HELPER_INTERNAL = "io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper"

/**
 * Generate a stub class using the visitor pattern: reads the original class,
 * adds one typed-loader class reference, and replaces method bodies with
 * delegation code. All metadata (InnerClasses, SourceFile, NestHost, etc.) is
 * automatically preserved.
 */
private fun generateClassStubVisitor(
    classBytes: ByteArray,
    binaryClassName: String,
    nameGen: NameGenerator,
): ByteArray {
    val cr = ClassReader(classBytes)
    val cw = object : ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
    }

    val classRefField = nameGen.generateFieldName()
    val initFlagField = nameGen.generateFieldName()
    var className = ""

    val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
        override fun visit(
            version: Int,
            access: Int,
            name: String,
            signature: String?,
            superName: String?,
            interfaces: Array<String>?,
        ) {
            className = name
            super.visit(version, access, name, signature, superName, interfaces)
        }

        override fun visitField(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            value: Any?,
        ): FieldVisitor? = super.visitField(access, name, descriptor, signature, value)

        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<String>?,
        ): MethodVisitor? {
            // Skip the original class initializer; the replacement initializer
            // obtains exactly this class through the strict typed ClassPage API.
            if (name == "<clinit>") return null

            // Preserve construction semantics in the visible stub.
            if (name == "<init>") {
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }

            if (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) {
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }

            val isStatic = access and Opcodes.ACC_STATIC != 0
            val argTypes = Type.getArgumentTypes(descriptor)
            val returnType = Type.getReturnType(descriptor)
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, mv) {
                override fun visitCode() {
                    super.visitCode()

                    val arraySize = 5 + argTypes.size
                    mv.visitIntInsn(Opcodes.BIPUSH, arraySize)
                    mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")

                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_0)
                    mv.visitFieldInsn(Opcodes.GETSTATIC, className, classRefField, "Ljava/lang/Class;")
                    mv.visitInsn(Opcodes.AASTORE)

                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_1)
                    mv.visitLdcInsn(name)
                    mv.visitInsn(Opcodes.AASTORE)

                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_2)
                    mv.visitLdcInsn(descriptor)
                    mv.visitInsn(Opcodes.AASTORE)

                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_3)
                    mv.visitLdcInsn(if (isStatic) 1 else 0)
                    mv.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Integer",
                        "valueOf",
                        "(I)Ljava/lang/Integer;",
                        false,
                    )
                    mv.visitInsn(Opcodes.AASTORE)

                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_4)
                    if (isStatic) mv.visitInsn(Opcodes.ACONST_NULL) else mv.visitVarInsn(Opcodes.ALOAD, 0)
                    mv.visitInsn(Opcodes.AASTORE)

                    var slot = if (isStatic) 0 else 1
                    for ((index, argType) in argTypes.withIndex()) {
                        mv.visitInsn(Opcodes.DUP)
                        mv.visitIntInsn(Opcodes.BIPUSH, 5 + index)
                        loadAndBoxArgument(mv, argType, slot)
                        mv.visitInsn(Opcodes.AASTORE)
                        slot += argType.size
                    }

                    mv.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        HELPER_INTERNAL,
                        "invokeMethod",
                        "([Ljava/lang/Object;)Ljava/lang/Object;",
                        false,
                    )
                    generateReturnConversion(mv, returnType)
                }

                override fun visitInsn(opcode: Int) { }
                override fun visitIntInsn(opcode: Int, operand: Int) { }
                override fun visitVarInsn(opcode: Int, operand: Int) { }
                override fun visitTypeInsn(opcode: Int, type: String?) { }
                override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) { }
                override fun visitMethodInsn(
                    opcode: Int,
                    owner: String,
                    name: String,
                    descriptor: String,
                    isInterface: Boolean,
                ) { }
                override fun visitInvokeDynamicInsn(name: String, descriptor: String, bsm: Handle, vararg bsmArgs: Any) { }
                override fun visitJumpInsn(opcode: Int, label: Label?) { }
                override fun visitLabel(label: Label?) { }
                override fun visitLdcInsn(value: Any) { }
                override fun visitIincInsn(variable: Int, increment: Int) { }
                override fun visitTableSwitchInsn(min: Int, max: Int, dflt: Label?, vararg labels: Label?) { }
                override fun visitLookupSwitchInsn(dflt: Label?, keys: IntArray?, labels: Array<Label>?) { }
                override fun visitMultiANewArrayInsn(descriptor: String?, numDimensions: Int) { }
                override fun visitTryCatchBlock(start: Label?, end: Label?, handler: Label?, type: String?) { }
                override fun visitLocalVariable(
                    name: String,
                    descriptor: String,
                    signature: String?,
                    start: Label?,
                    end: Label?,
                    index: Int,
                ) { }
                override fun visitMaxs(maxStack: Int, maxLocals: Int) {
                    super.visitMaxs(20, 20)
                }
            }
        }
    }

    cr.accept(cv, ClassReader.SKIP_FRAMES)
    return addLoaderFieldsAndInit(
        classBytes = cw.toByteArray(),
        className = className,
        classRefField = classRefField,
        initFlagField = initFlagField,
        binaryClassName = binaryClassName,
    )
}

/**
 * Second pass: add the typed ClassPage loader reference and replacement class
 * initializer to the already-transformed class bytes.
 */
private fun addLoaderFieldsAndInit(
    classBytes: ByteArray,
    className: String,
    classRefField: String,
    initFlagField: String,
    binaryClassName: String,
): ByteArray {
    val cr = ClassReader(classBytes)
    val cw = object : ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
    }

    val mutableFieldAccess = Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC
    val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
        override fun visitField(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            value: Any?,
        ): FieldVisitor? = super.visitField(access, name, descriptor, signature, value)

        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<String>?,
        ): MethodVisitor? {
            if (name == "<clinit>") return null
            return super.visitMethod(access, name, descriptor, signature, exceptions)
        }

        override fun visitEnd() {
            super.visitField(mutableFieldAccess, classRefField, "Ljava/lang/Class;", null, null).visitEnd()
            super.visitField(mutableFieldAccess, initFlagField, "Z", null, null).visitEnd()

            val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
            mv.visitCode()

            mv.visitFieldInsn(Opcodes.GETSTATIC, className, initFlagField, "Z")
            val alreadyInit = Label()
            mv.visitJumpInsn(Opcodes.IFNE, alreadyInit)

            mv.visitInsn(Opcodes.ICONST_1)
            mv.visitFieldInsn(Opcodes.PUTSTATIC, className, initFlagField, "Z")

            mv.visitLdcInsn(binaryClassName)
            mv.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                HELPER_INTERNAL,
                "loadAkenClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                false,
            )
            mv.visitFieldInsn(Opcodes.PUTSTATIC, className, classRefField, "Ljava/lang/Class;")

            mv.visitLabel(alreadyInit)
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(2, 0)
            mv.visitEnd()

            super.visitEnd()
        }
    }

    cr.accept(cv, ClassReader.SKIP_FRAMES)
    return cw.toByteArray()
}

// --- Key generation and encryption ---

private fun classKeyLength(strategy: String): Int = when (strategy) {
    "aes-256" -> 32
    else -> 16
}

private fun generateKeyId(random: SecureRandom): ByteArray = ByteArray(8).also { random.nextBytes(it) }

private fun generateSalt(random: SecureRandom): ByteArray = ByteArray(16).also { random.nextBytes(it) }

/**
 * Derive the per-class AES key from the per-build runtime resource root key via
 * the shared HKDF-SHA256 skeleton. The keyId and salt are the only material
 * stored in the artifact; the key itself is never persisted and is recomputed
 * byte-for-byte at runtime from the same root.
 */
internal fun deriveClassEncryptionKey(
    context: Vbc4BuildContext,
    strategy: String,
    keyId: ByteArray,
    salt: ByteArray,
): ByteArray = context.deriveSubKey(VBC4_DERIVE_LABEL_CLASS_ENCRYPTION, classKeyLength(strategy), keyId, salt)

private fun generateNonce(random: SecureRandom): ByteArray = ByteArray(12).also { random.nextBytes(it) }

private fun encryptBytes(data: ByteArray, strategy: String, key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
    require(strategy == "aes-128" || strategy == "aes-256") { "class-encryption-loader requires AES encryption" }
    require(nonce.size == 12) { "class-encryption-loader AES-GCM nonce must be 12 bytes" }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec = SecretKeySpec(key, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
    cipher.updateAAD(aad)
    return cipher.doFinal(data)
}

private fun buildKeyMetadata(strategy: String, keyId: ByteArray, salt: ByteArray, nonce: ByteArray, aad: ByteArray): String {
    // v2 metadata format: v2:strategy:keyId:salt:nonce:aadHash. No raw
    // symmetric key is written; the runtime re-derives the AES-GCM key from the
    // resident root and refuses metadata/resource tampering through the AEAD tag.
    val sb = StringBuilder()
    sb.append("v2:").append(strategy).append(":")
    sb.append(Base64.getEncoder().encodeToString(keyId)).append(":")
    sb.append(Base64.getEncoder().encodeToString(salt))
    sb.append(":").append(Base64.getEncoder().encodeToString(nonce))
    sb.append(":").append(Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(aad)))
    return sb.toString()
}

private fun classEncryptionAad(className: String, resourcePath: String, strategy: String, keyMode: String): ByteArray =
    "javashroud:class-encryption:v2:$className:$resourcePath:$strategy:$keyMode:sealed-runtime".toByteArray(Charsets.UTF_8)

// --- Argument loading helpers ---

private fun loadAndBoxArgument(mv: MethodVisitor, type: Type, slot: Int) {
    when (type.sort) {
        Type.BOOLEAN -> {
            mv.visitVarInsn(Opcodes.ILOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false)
        }
        Type.BYTE -> {
            mv.visitVarInsn(Opcodes.ILOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false)
        }
        Type.CHAR -> {
            mv.visitVarInsn(Opcodes.ILOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false)
        }
        Type.SHORT -> {
            mv.visitVarInsn(Opcodes.ILOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false)
        }
        Type.INT -> {
            mv.visitVarInsn(Opcodes.ILOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
        }
        Type.LONG -> {
            mv.visitVarInsn(Opcodes.LLOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
        }
        Type.FLOAT -> {
            mv.visitVarInsn(Opcodes.FLOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false)
        }
        Type.DOUBLE -> {
            mv.visitVarInsn(Opcodes.DLOAD, slot)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false)
        }
        else -> mv.visitVarInsn(Opcodes.ALOAD, slot)
    }
}

private fun generateReturnConversion(mv: MethodVisitor, returnType: Type) {
    when (returnType.sort) {
        Type.VOID -> { mv.visitInsn(Opcodes.POP); mv.visitInsn(Opcodes.RETURN) }
        Type.BOOLEAN -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Boolean")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false)
            mv.visitInsn(Opcodes.IRETURN)
        }
        Type.BYTE -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "byteValue", "()B", false)
            mv.visitInsn(Opcodes.IRETURN)
        }
        Type.CHAR -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Character")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false)
            mv.visitInsn(Opcodes.IRETURN)
        }
        Type.SHORT -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "shortValue", "()S", false)
            mv.visitInsn(Opcodes.IRETURN)
        }
        Type.INT -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "intValue", "()I", false)
            mv.visitInsn(Opcodes.IRETURN)
        }
        Type.LONG -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "longValue", "()J", false)
            mv.visitInsn(Opcodes.LRETURN)
        }
        Type.FLOAT -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "floatValue", "()F", false)
            mv.visitInsn(Opcodes.FRETURN)
        }
        Type.DOUBLE -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number")
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "doubleValue", "()D", false)
            mv.visitInsn(Opcodes.DRETURN)
        }
        else -> {
            mv.visitTypeInsn(Opcodes.CHECKCAST, returnType.internalName)
            mv.visitInsn(Opcodes.ARETURN)
        }
    }
}

// --- Name generator ---

class NameGenerator(private val random: SecureRandom) {
    private val chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    fun generateFieldName(): String = generateRandomIdentifier(12)
    fun generateLoaderName(): String = generateRandomIdentifier(16)

    private fun generateRandomIdentifier(length: Int): String {
        val sb = StringBuilder()
        sb.append(chars[random.nextInt(chars.length)])
        repeat(length - 1) {
            sb.append(("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")[random.nextInt(63)])
        }
        return sb.toString()
    }
}
