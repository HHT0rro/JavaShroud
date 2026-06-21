package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.*
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Method Body Delayed Decryption transform.
 *
 * Preserves class structure but moves selected method bodies into encrypted
 * resources. On first invocation, the method body is decrypted and executed
 * via a hidden class defined through MethodHandles.Lookup.
 *
 * Approach:
 * 1. Parse class to capture original method bodies.
 * 2. Serialize each method body into a wrapper class, encrypt, and store as __jmd/ resource.
 * 3. Replace method body with a decryption + execution trampoline.
 * 4. Uses deterministic resource paths (hash-based) so Phase 2 (encryption) and
 *    Phase 3 (trampoline) agree on the same path.
 */
fun applyMethodBodyDelayedDecryption(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "method-body-delayed-decryption")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val mode = (params["mode"] as? String) ?: "lazy-decrypt"
    val supportedModes = setOf("lazy-decrypt", "hidden-class-redirect")
    require(mode in supportedModes) { "method-body-delayed-decryption mode '$mode' is not supported; supported values: ${supportedModes.joinToString("", "")}" }
    val strategy = (params["encryptionStrategy"] as? String) ?: "aes-128"
    val supportedStrategies = setOf("aes-128", "aes-256")
    require(strategy in supportedStrategies) { "method-body-delayed-decryption encryptionStrategy '$strategy' is not supported; supported values: ${supportedStrategies.joinToString("", "")}" }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    val newResources = mutableListOf<JarEntryData>()
    var classCount = 0
    var methodCount = 0

    // Phase 1: Parse all matched classes to ClassNode for method body extraction
    val classNodeCache = mutableMapOf<String, ClassNode>()
    for (classArtifact in artifact.classArtifacts) {
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) continue
        val cr = ClassReader(classArtifact.bytes)
        val cn = ClassNode()
        cr.accept(cn, ClassReader.EXPAND_FRAMES)
        classNodeCache[classArtifact.summary.internalName] = cn
    }

    val dynamicallyDefinedClassNames = collectDynamicallyDefinedClassNames(classNodeCache.values)

    // Phase 2: Encrypt method bodies and collect resource paths
    // Key per class, deterministic resource path per method
    val classKeys = mutableMapOf<String, ByteArray>()
    val classIvs = mutableMapOf<String, ByteArray?>()
    val methodResourceMap = mutableMapOf<String, MutableMap<String, String>>() // className -> (methodKey -> resourcePath)

    for ((className, cn) in classNodeCache) {
        if (className in dynamicallyDefinedClassNames) continue
        val key = generateMethodKey(strategy, random)
        val iv = generateMethodIv(random)
        classKeys[className] = key
        classIvs[className] = iv

        val methodMap = mutableMapOf<String, String>()
        for (method in cn.methods) {
            if (!shouldProtectDelayedMethod(cn, method)) continue

            val methodBytes = serializeMethod(cn, method)
            if (methodBytes.isEmpty()) continue

            // Use deterministic resource path based on class + method + descriptor
            val resourcePath = deterministicResourcePath(className, method.name, method.desc)
            val encryptedBytes = encryptBytes(methodBytes, strategy, key, iv)
            newResources.add(JarEntryData(name = resourcePath, bytes = encryptedBytes))

            val methodKey = method.name + method.desc
            methodMap[methodKey] = resourcePath
        }
        methodResourceMap[className] = methodMap
    }

    // Phase 3: Replace method bodies with decryption trampolines
    val updatedClassArtifacts = artifact.classArtifacts.map classMap@{ classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@classMap classArtifact

        val className = classArtifact.summary.internalName
        val methodMap = methodResourceMap[className] ?: return@classMap classArtifact
        val key = classKeys[className] ?: return@classMap classArtifact
        val keyBase64 = Base64.getEncoder().encodeToString(key)
        var classModified = false

        val cr = ClassReader(classArtifact.bytes)
        val cw = object : ClassWriter(cr, ClassWriter.COMPUTE_MAXS) {
            override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
        }

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)

                // Only transform matched methods
                val methodKey = name + descriptor
                val resourcePath = methodMap[methodKey]
                if (resourcePath == null) return superMv
                if (!shouldProtectDelayedMethod(classNodeCache[className] ?: return superMv, name, descriptor)) return superMv

                val isStatic = access and Opcodes.ACC_STATIC != 0
                val argTypes = Type.getArgumentTypes(descriptor)
                val returnType = Type.getReturnType(descriptor)

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitCode() {
                        super.visitCode()

                        // Call MethodBodyDecryptionHelper.invokeEncrypted(
                        //     resourcePath, keyBase64, strategy, isStatic, declaringClass, thisRef, methodArgs[])
                        // where methodArgs is an Object[] of boxed arguments

                        // Push resource path, key, strategy, isStatic, declaringClassName
                        super.visitLdcInsn(resourcePath)
                        super.visitLdcInsn(keyBase64)
                        super.visitLdcInsn(strategy)
                        super.visitLdcInsn(if (isStatic) 1 else 0)
                        super.visitLdcInsn(Type.getObjectType(className))

                        // Push this or null
                        if (isStatic) {
                            super.visitInsn(Opcodes.ACONST_NULL)
                        } else {
                            super.visitVarInsn(Opcodes.ALOAD, 0)
                        }

                        // Build Object[] for method arguments
                        super.visitIntInsn(Opcodes.BIPUSH, argTypes.size)
                        super.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")

                        var slot = if (isStatic) 0 else 1
                        for ((i, argType) in argTypes.withIndex()) {
                            super.visitInsn(Opcodes.DUP)
                            super.visitIntInsn(Opcodes.BIPUSH, i)
                            loadAndBoxArg(superMv, argType, slot)
                            super.visitInsn(Opcodes.AASTORE)
                            slot += argType.size
                        }

                        // Call helper: invokeEncrypted(String, String, String, int, Class, Object, Object[]) -> Object
                        super.visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            MBDD_HELPER_INTERNAL,
                            "invokeEncrypted",
                            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Class;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                            false,
                        )

                        // Handle return value
                        generateReturnConversion(superMv, returnType)

                        classModified = true
                        methodCount++
                    }

                    // Suppress all original method body instructions
                    override fun visitInsn(opcode: Int) { }
                    override fun visitIntInsn(opcode: Int, operand: Int) { }
                    override fun visitVarInsn(opcode: Int, operand: Int) { }
                    override fun visitTypeInsn(opcode: Int, type: String?) { }
                    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) { }
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) { }
                    override fun visitInvokeDynamicInsn(name: String, descriptor: String, bootstrapMethodHandle: Handle, vararg bootstrapMethodArguments: Any) { }
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

        try {
            cr.accept(cv, ClassReader.SKIP_FRAMES)
        } catch (e: Exception) {
            return@classMap classArtifact
        }

        if (!classModified) return@classMap classArtifact
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)

    val updatedArtifact = artifact.copy(jarEntries = artifact.jarEntries + newResources)
    return updatedArtifactTransformResult(
        artifact = updatedArtifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = methodCount,
    )
}

private fun collectDynamicallyDefinedClassNames(classNodes: Collection<ClassNode>): Set<String> {
    val classNames = HashSet<String>()
    for (classNode in classNodes) {
        for (method in classNode.methods) {
            if (!method.instructions.asSequence().filterIsInstance<MethodInsnNode>().any { it.name == "defineClass" }) continue
            val instructions = method.instructions.toArray()
            for (index in instructions.indices) {
                val call = instructions[index] as? MethodInsnNode ?: continue
                if (call.owner != "java/lang/Class" || call.name != "getResourceAsStream") continue
                var scan = index - 1
                while (scan >= 0 && index - scan <= 16) {
                    val ldc = instructions[scan] as? LdcInsnNode
                    val type = ldc?.cst as? Type
                    if (type != null && type.sort == Type.OBJECT) {
                        classNames.add(type.internalName)
                        break
                    }
                    scan--
                }
            }
        }
    }
    return classNames
}
private const val MBDD_HELPER_INTERNAL = "io/github/hht0rro/javashroud/transforms/protection/MethodBodyDecryptionHelper"

private fun shouldProtectDelayedMethod(classNode: ClassNode, name: String, descriptor: String): Boolean {
    val method = classNode.methods.firstOrNull { it.name == name && it.desc == descriptor } ?: return false
    return shouldProtectDelayedMethod(classNode, method)
}

private fun shouldProtectDelayedMethod(classNode: ClassNode, method: MethodNode): Boolean {
    if (method.name == "<init>" || method.name == "<clinit>") return false
    if (method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) return false
    if (method.access and Opcodes.ACC_STATIC == 0) return false
    if (method.access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_SYNTHETIC or Opcodes.ACC_BRIDGE) != 0) return false
    if (method.instructions == null || method.instructions.size() == 0) return false
    if (isClassLoaderType(classNode)) return false
    if (hasClassWideDelayedDecryptionSensitivity(classNode)) return false

    for (instruction in method.instructions) {
        if (instruction is org.objectweb.asm.tree.InvokeDynamicInsnNode) return false
        if (instruction is MethodInsnNode && isRuntimeProtectionHelperCall(instruction)) return false
        if (instruction is MethodInsnNode && isDelayedDecryptionSensitiveCall(classNode, method, instruction)) return false
    }
    return true
}

private fun isRuntimeProtectionHelperCall(call: MethodInsnNode): Boolean =
    call.owner.startsWith("io/github/hht0rro/javashroud/transforms/protection/")

private fun hasClassWideDelayedDecryptionSensitivity(classNode: ClassNode): Boolean {
    for (method in classNode.methods) {
        if (method.instructions == null) continue
        for (instruction in method.instructions) {
            if (instruction is MethodInsnNode && isClassWideDelayedDecryptionSensitiveCall(instruction)) return true
        }
    }
    return false
}

private fun isClassWideDelayedDecryptionSensitiveCall(call: MethodInsnNode): Boolean {
    if (call.owner == "java/lang/Class" && call.name == "getResourceAsStream") return true
    if (call.name == "defineClass") return true
    if (call.owner == "java/lang/Throwable" && call.name == "getStackTrace") return true
    if (call.owner == "java/lang/StackTraceElement") return true
    return false
}

private fun isClassLoaderType(classNode: ClassNode): Boolean {
    if (classNode.name == "java/lang/ClassLoader") return true
    if (classNode.superName == "java/lang/ClassLoader") return true
    return classNode.superName?.endsWith("ClassLoader") == true
}

private fun isDelayedDecryptionSensitiveCall(classNode: ClassNode, method: MethodNode, call: MethodInsnNode): Boolean {
    if (call.opcode == Opcodes.INVOKESPECIAL && call.name != "<init>") return true
    if (call.owner == classNode.name && call.name == method.name && call.desc == method.desc) return true
    if (call.owner == "java/lang/Thread" && call.name == "sleep") return true
    if (call.owner == "java/lang/Throwable" && call.name == "getStackTrace") return true
    if (call.owner == "java/lang/StackTraceElement") return true
    if (call.owner == "java/lang/ClassLoader" || call.name == "defineClass") return true
    if (call.owner == "java/lang/Class" && (call.name.startsWith("getDeclared") || call.name.startsWith("getMethod") || call.name == "newInstance" || call.name == "getResourceAsStream")) return true
    if (call.owner == "java/lang/reflect/Method" && call.name == "invoke") return true
    if (call.owner == "java/lang/reflect/Constructor" && call.name == "newInstance") return true
    return false
}

// --- Resource path ---

/**
 * Generate a deterministic resource path for a method body.
 * Uses a hash of className+method+descriptor to ensure Phase 2 and Phase 3 agree.
 */
private fun deterministicResourcePath(className: String, methodName: String, descriptor: String): String {
    val input = "$className/$methodName$descriptor"
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(input.toByteArray())
    val shortHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash).take(12)
    return "__jmd/${className}/${methodName}_${shortHash}.enc"
}

// --- Serialization ---

/**
 * Serialize a single method from a ClassNode into a wrapper class containing the method.
 * Instance methods are converted to static with the owner type prepended as first parameter
 * so the hidden class only uses findStatic (no virtual dispatch on hidden-class instances).
 */
private fun serializeMethod(classNode: ClassNode, method: MethodNode): ByteArray {
    // Place wrapper class in the declaring class's package so that
    // defineHiddenClass (via privateLookupIn) can access same-package members.
    val pkgPrefix = if (classNode.name.contains('/')) classNode.name.substringBeforeLast('/') + "/" else ""
    val wrapperClassName = pkgPrefix + "\$_method_body_"

    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(
        classNode.version.coerceAtLeast(Opcodes.V11),
        Opcodes.ACC_PUBLIC,
        wrapperClassName,
        null,
        "java/lang/Object",
        null,
    )

    val isInstanceMethod = (method.access and Opcodes.ACC_STATIC) == 0
    val wrapperAccess: Int
    val wrapperDesc: String
    if (isInstanceMethod) {
        // Convert instance method to static: prepend owner type as first param.
        // Slot layout is identical (ALOAD 0 still refers to the instance).
        wrapperAccess = (method.access or Opcodes.ACC_STATIC) and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE).inv()
        val originalType = Type.getMethodType(method.desc)
        val newParamTypes = arrayOf(Type.getObjectType(classNode.name)) + originalType.argumentTypes
        wrapperDesc = Type.getMethodDescriptor(originalType.returnType, *newParamTypes)
    } else {
        wrapperAccess = method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE).inv()
        wrapperDesc = method.desc
    }

    val mv = cw.visitMethod(
        wrapperAccess,
        method.name, wrapperDesc, method.signature, method.exceptions?.toTypedArray(),
    )
    method.accept(mv)
    cw.visitEnd()
    return cw.toByteArray()
}

// --- Encryption ---

private fun generateMethodKey(strategy: String, random: SecureRandom): ByteArray = when (strategy) {
    "aes-256" -> ByteArray(32).also { random.nextBytes(it) }
    else -> ByteArray(16).also { random.nextBytes(it) }
}

private fun generateMethodIv(random: SecureRandom): ByteArray = ByteArray(16).also { random.nextBytes(it) }

private fun encryptBytes(data: ByteArray, strategy: String, key: ByteArray, iv: ByteArray?): ByteArray {
    require(strategy == "aes-128" || strategy == "aes-256") { "method-body-delayed-decryption requires AES encryption" }
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = SecretKeySpec(key, "AES")
    val actualIv = iv ?: ByteArray(16).also { SecureRandom().nextBytes(it) }
    val ivSpec = IvParameterSpec(actualIv)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    return actualIv + cipher.doFinal(data)
}

// --- Argument loading helpers ---

private fun loadArgument(mv: MethodVisitor, type: Type, slot: Int) {
    when (type.sort) {
        Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> mv.visitVarInsn(Opcodes.ILOAD, slot)
        Type.LONG -> mv.visitVarInsn(Opcodes.LLOAD, slot)
        Type.FLOAT -> mv.visitVarInsn(Opcodes.FLOAD, slot)
        Type.DOUBLE -> mv.visitVarInsn(Opcodes.DLOAD, slot)
        else -> mv.visitVarInsn(Opcodes.ALOAD, slot)
    }
}

private fun loadAndBoxArg(mv: MethodVisitor, type: Type, slot: Int) {
    when (type.sort) {
        Type.BOOLEAN -> { mv.visitVarInsn(Opcodes.ILOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false) }
        Type.BYTE -> { mv.visitVarInsn(Opcodes.ILOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false) }
        Type.CHAR -> { mv.visitVarInsn(Opcodes.ILOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false) }
        Type.SHORT -> { mv.visitVarInsn(Opcodes.ILOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false) }
        Type.INT -> { mv.visitVarInsn(Opcodes.ILOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false) }
        Type.LONG -> { mv.visitVarInsn(Opcodes.LLOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false) }
        Type.FLOAT -> { mv.visitVarInsn(Opcodes.FLOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false) }
        Type.DOUBLE -> { mv.visitVarInsn(Opcodes.DLOAD, slot); mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false) }
        else -> mv.visitVarInsn(Opcodes.ALOAD, slot)
    }
}

/**
 * Generate code to convert the Object return value from the helper to the expected type.
 */
private fun generateReturnConversion(mv: MethodVisitor, returnType: Type) {
    when (returnType.sort) {
        Type.VOID -> { mv.visitInsn(Opcodes.POP); mv.visitInsn(Opcodes.RETURN) }
        Type.BOOLEAN -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Boolean"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.BYTE -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "byteValue", "()B", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.CHAR -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Character"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.SHORT -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "shortValue", "()S", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.INT -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "intValue", "()I", false); mv.visitInsn(Opcodes.IRETURN) }
        Type.LONG -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "longValue", "()J", false); mv.visitInsn(Opcodes.LRETURN) }
        Type.FLOAT -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "floatValue", "()F", false); mv.visitInsn(Opcodes.FRETURN) }
        Type.DOUBLE -> { mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Number"); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "doubleValue", "()D", false); mv.visitInsn(Opcodes.DRETURN) }
        else -> { mv.visitTypeInsn(Opcodes.CHECKCAST, returnType.internalName); mv.visitInsn(Opcodes.ARETURN) }
    }
}
