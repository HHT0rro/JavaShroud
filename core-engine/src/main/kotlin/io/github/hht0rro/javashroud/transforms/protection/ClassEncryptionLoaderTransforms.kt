package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
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

/**
 * Class Encryption Loader transform.
 *
 * Encrypts selected .class bodies and stores them as JAR resource entries.
 * Replaces the original class with a stub that preserves the FULL class
 * structure (superclass, interfaces, fields, metadata) and delegates all
 * method calls to the real class loaded at runtime via a child ClassLoader.
 *
 * Uses visitor-based transform to preserve all metadata (InnerClasses,
 * SourceFile, etc.) automatically.
 */
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

    val strategy = (params["encryptionStrategy"] as? String) ?: "aes-128"
    val supportedStrategies = setOf("aes-128", "aes-256")
    require(strategy in supportedStrategies) { "class-encryption-loader encryptionStrategy '$strategy' is not supported; supported values: ${supportedStrategies.joinToString("", "")}" }
    val keyMode = (params["keyMode"] as? String) ?: "per-class"
    val supportedKeyModes = setOf("per-class", "global")
    require(keyMode in supportedKeyModes) { "class-encryption-loader keyMode '$keyMode' is not supported; supported values: ${supportedKeyModes.joinToString("", "")}" }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)

    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()
    // Per-build root key: every class AES key is HKDF-derived from this root at
    // build time and recomputed (never stored) at runtime. No raw symmetric key
    // is ever written into the artifact.
    val buildContext = requireVbc4BuildContext()
    val globalKeyId = if (keyMode == "global") generateKeyId(random) else null
    val globalSalt = if (keyMode == "global") generateSalt(random) else null
    val globalNonce = if (keyMode == "global") generateNonce(random) else null

    val nameGen = NameGenerator(random)
    val newResources = mutableListOf<JarEntryData>()
    // Central key manifest: maps every encrypted class to its resource path and
    // key metadata. The runtime loader reads this so a single shared classloader
    // can decrypt-and-define ANY encrypted class (including sibling/inner classes
    // discovered through references), keeping them in one loader namespace.
    val manifestLines = mutableListOf<String>()
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!encryptedClassNames.contains(classArtifact.summary.internalName)) {
            return@map classArtifact
        }


        val className = classArtifact.summary.internalName
        val classKeyId = globalKeyId ?: generateKeyId(random)
        val classSalt = globalSalt ?: generateSalt(random)
        val classNonce = globalNonce ?: generateNonce(random)
        val classKey = deriveClassEncryptionKey(buildContext, strategy, classKeyId, classSalt)
        val resourcePath = "__jse/${className}.enc"
        val aad = classEncryptionAad(className, resourcePath, strategy, keyMode)

        // Encrypt the original class bytes
        val encryptedBytes = encryptBytes(classArtifact.bytes, strategy, classKey, classNonce, aad)
        java.util.Arrays.fill(classKey, 0)
        newResources.add(JarEntryData(name = resourcePath, bytes = encryptedBytes))

        val keyMetadata = buildKeyMetadata(strategy, classKeyId, classSalt, classNonce, aad)
        // internalName \t resourcePath \t keyMetadata
        manifestLines.add("$className\t$resourcePath\t$keyMetadata")

        classCount++

        // Interfaces/annotations also enter the manifest so encrypted package siblings
        // resolve them through the shared loader and keep package-private access valid.
        if (classArtifact.summary.accessFlags and Opcodes.ACC_INTERFACE != 0) {
            return@map classArtifact
        }

        // Generate stub using visitor pattern - preserves all metadata
        val stubBytes = generateClassStubVisitor(
            classBytes = classArtifact.bytes,
            resourcePath = resourcePath,
            keyMetadata = keyMetadata,
            random = random,
            nameGen = nameGen,
        )

        reanalyzedClassArtifact(classArtifact, stubBytes)
    }

    if (classCount == 0) return unchangedTransformResult(artifact)

    // Emit the central manifest as a JAR resource consumed by the runtime helper.
    val manifestBytes = manifestLines.joinToString("\n").toByteArray(Charsets.UTF_8)
    newResources.add(JarEntryData(name = "__jse/index.tab", bytes = manifestBytes))

    val updatedArtifact = artifact.copy(
        jarEntries = artifact.jarEntries + newResources,
    )

    return updatedArtifactTransformResult(
        artifact = updatedArtifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = classCount,
    )
}

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
 * adds loader fields, replaces method bodies with delegation code.
 * All metadata (InnerClasses, SourceFile, NestHost, etc.) is automatically preserved.
 */
private fun generateClassStubVisitor(
    classBytes: ByteArray,
    resourcePath: String,
    keyMetadata: String,
    random: SecureRandom,
    nameGen: NameGenerator,
): ByteArray {
    val cr = ClassReader(classBytes)
    val cw = object : ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
    }

    val classRefField = nameGen.generateFieldName()
    val initFlagField = nameGen.generateFieldName()
    val resourceFieldName = nameGen.generateFieldName()
    val keyFieldName = nameGen.generateFieldName()

    var className = ""
    var isInterface = false

    val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
        override fun visit(
            version: Int, access: Int, name: String, signature: String?,
            superName: String?, interfaces: Array<String>?
        ) {
            className = name
            isInterface = access and Opcodes.ACC_INTERFACE != 0
            super.visit(version, access, name, signature, superName, interfaces)
        }

        override fun visitField(
            access: Int, name: String, descriptor: String, signature: String?, value: Any?
        ): FieldVisitor? {
            // Keep all original fields unchanged
            return super.visitField(access, name, descriptor, signature, value)
        }

        override fun visitMethod(
            access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?
        ): MethodVisitor? {
            // Pass through <clinit> - we'll generate our own
            if (name == "<clinit>") {
                // Skip original <clinit>, we add our own at the end
                return null
            }

            // For <init>: pass through to super (preserves original constructor behavior)
            if (name == "<init>") {
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }

            // Skip abstract and native methods
            if (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) {
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }

            // For regular methods: replace body with delegation
            val isStatic = access and Opcodes.ACC_STATIC != 0
            val argTypes = Type.getArgumentTypes(descriptor)
            val returnType = Type.getReturnType(descriptor)

            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, mv) {
                override fun visitCode() {
                    super.visitCode()

                    // Build args array for invokeMethod: [classRef, name, desc, isStatic, this, arg0, ...]
                    val arraySize = 5 + argTypes.size
                    mv.visitIntInsn(Opcodes.BIPUSH, arraySize)
                    mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")

                    // index 0: classRef
                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_0)
                    mv.visitFieldInsn(Opcodes.GETSTATIC, className, classRefField, "Ljava/lang/Class;")
                    mv.visitInsn(Opcodes.AASTORE)

                    // index 1: method name
                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_1)
                    mv.visitLdcInsn(name)
                    mv.visitInsn(Opcodes.AASTORE)

                    // index 2: descriptor
                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_2)
                    mv.visitLdcInsn(descriptor)
                    mv.visitInsn(Opcodes.AASTORE)

                    // index 3: isStatic (boxed)
                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_3)
                    mv.visitLdcInsn(if (isStatic) 1 else 0)
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
                    mv.visitInsn(Opcodes.AASTORE)

                    // index 4: this or null
                    mv.visitInsn(Opcodes.DUP)
                    mv.visitInsn(Opcodes.ICONST_4)
                    if (isStatic) mv.visitInsn(Opcodes.ACONST_NULL) else mv.visitVarInsn(Opcodes.ALOAD, 0)
                    mv.visitInsn(Opcodes.AASTORE)

                    // index 5+: arguments (boxed)
                    var slot = if (isStatic) 0 else 1
                    for ((i, argType) in argTypes.withIndex()) {
                        mv.visitInsn(Opcodes.DUP)
                        mv.visitIntInsn(Opcodes.BIPUSH, 5 + i)
                        loadAndBoxArgument(mv, argType, slot)
                        mv.visitInsn(Opcodes.AASTORE)
                        slot += argType.size
                    }

                    // Call ClassEncryptionLoaderHelper.invokeMethod(Object[])
                    mv.visitMethodInsn(
                        Opcodes.INVOKESTATIC, HELPER_INTERNAL, "invokeMethod",
                        "([Ljava/lang/Object;)Ljava/lang/Object;", false
                    )

                    // Convert and return
                    generateReturnConversion(mv, returnType)
                }

                // Suppress all original instructions
                override fun visitInsn(opcode: Int) { }
                override fun visitIntInsn(opcode: Int, operand: Int) { }
                override fun visitVarInsn(opcode: Int, operand: Int) { }
                override fun visitTypeInsn(opcode: Int, type: String?) { }
                override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) { }
                override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) { }
                override fun visitInvokeDynamicInsn(name: String, descriptor: String, bsm: Handle, vararg bsmArgs: Any) { }
                override fun visitJumpInsn(opcode: Int, label: Label?) { }
                override fun visitLabel(label: Label?) { }
                override fun visitLdcInsn(value: Any) { }
                override fun visitIincInsn(`var`: Int, increment: Int) { }
                override fun visitTableSwitchInsn(min: Int, max: Int, dflt: Label?, vararg labels: Label?) { }
                override fun visitLookupSwitchInsn(dflt: Label?, keys: IntArray?, labels: Array<Label>?) { }
                override fun visitMultiANewArrayInsn(descriptor: String?, numDimensions: Int) { }
                override fun visitTryCatchBlock(start: Label?, end: Label?, handler: Label?, type: String?) { }
                override fun visitLocalVariable(name: String, descriptor: String, signature: String?, start: Label?, end: Label?, index: Int) { }
                override fun visitMaxs(maxStack: Int, maxLocals: Int) { super.visitMaxs(20, 20) }
            }
        }
    }

    cr.accept(cv, ClassReader.SKIP_FRAMES)

    // Now add the loader fields and <clinit> using a second pass
    // This is necessary because we need to know the class name and can't add fields after visitEnd
    // Instead, use a simpler approach: rewrite the bytes
    return addLoaderFieldsAndInit(cw.toByteArray(), className, isInterface, classRefField, initFlagField, resourceFieldName, keyFieldName, resourcePath, keyMetadata)
}

/**
 * Second pass: add loader fields and <clinit> to the already-transformed class bytes.
 */
private fun addLoaderFieldsAndInit(
    classBytes: ByteArray,
    className: String,
    isInterface: Boolean,
    classRefField: String,
    initFlagField: String,
    resourceFieldName: String,
    keyFieldName: String,
    resourcePath: String,
    keyMetadata: String,
): ByteArray {
    val cr = ClassReader(classBytes)
    val cw = object : ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
    }

    val fieldAccess = if (isInterface) {
        Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL
    } else {
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL
    }
    val mutableFieldAccess = Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC

    var clinitInjected = false

    val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
        override fun visitField(access: Int, name: String, descriptor: String, signature: String?, value: Any?): FieldVisitor? {
            return super.visitField(access, name, descriptor, signature, value)
        }

        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
            // Skip the original <clinit> if present
            if (name == "<clinit>") return null
            return super.visitMethod(access, name, descriptor, signature, exceptions)
        }

        override fun visitEnd() {
            // Add loader fields
            super.visitField(fieldAccess, resourceFieldName, "Ljava/lang/String;", null, resourcePath).visitEnd()
            super.visitField(fieldAccess, keyFieldName, "Ljava/lang/String;", null, keyMetadata).visitEnd()
            super.visitField(mutableFieldAccess, classRefField, "Ljava/lang/Class;", null, null).visitEnd()
            super.visitField(mutableFieldAccess, initFlagField, "Z", null, null).visitEnd()

            // Add <clinit>
            val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
            mv.visitCode()

            // if (__init) return
            mv.visitFieldInsn(Opcodes.GETSTATIC, className, initFlagField, "Z")
            val alreadyInit = Label()
            mv.visitJumpInsn(Opcodes.IFNE, alreadyInit)

            // __init = true
            mv.visitInsn(Opcodes.ICONST_1)
            mv.visitFieldInsn(Opcodes.PUTSTATIC, className, initFlagField, "Z")

            // __rC = ClassEncryptionLoaderHelper.loadClass(resourcePath, keyMetadata)
            mv.visitFieldInsn(Opcodes.GETSTATIC, className, resourceFieldName, "Ljava/lang/String;")
            mv.visitFieldInsn(Opcodes.GETSTATIC, className, keyFieldName, "Ljava/lang/String;")
            mv.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER_INTERNAL, "loadClass",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Class;", false
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
