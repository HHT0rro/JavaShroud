package io.github.hht0rro.javashroud.transforms.rename

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import org.objectweb.asm.Opcodes
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodNode
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * A method signature ("name" + descriptor) is dispatch-sensitive across the
 * artifact boundary when any in-artifact class declares an instance method with
 * that signature that overrides or implements a method contributed by an
 * out-of-artifact supertype (external superclass or interface, transitively).
 *
 * Renaming only one side of such a relationship silently breaks virtual / interface
 * dispatch (AbstractMethodError, or the JVM/library calling the original name).
 * Because [buildMethodRenameMap] groups renames globally by (name, descriptor),
 * the safe and consistent unit of exclusion is the signature itself: if any owner
 * of a signature is externally bound, the signature is protected for every owner.
 *
 * In-artifact-only override families (interface declared in the artifact plus its
 * in-artifact implementations) are intentionally left renameable; the global
 * grouping renames every member of such a family to the same name, preserving
 * dispatch.
 */
internal fun externallyBoundMethodSignatures(
    artifact: BytecodeArtifact,
    classLoader: ClassLoader = OverrideBoundaryReflection::class.java.classLoader,
): Set<String> {
    val inArtifact = artifact.classArtifactIndex
    val reflection = OverrideBoundaryReflection(classLoader)
    val blocked = HashSet<String>()

    for (classArtifact in artifact.classArtifacts) {
        val classNode = parseClassNode(classArtifact.bytes)
        val externalSupertypes = collectExternalSupertypes(classArtifact, inArtifact)
        if (externalSupertypes.isEmpty()) {
            continue
        }

        val ownInstanceSignatures = classNode.methods
            .filter { it.access and Opcodes.ACC_STATIC == 0 }
            .map { methodSignature(it.name, it.desc) }
            .toSet()
        if (ownInstanceSignatures.isEmpty()) {
            continue
        }

        var opaqueExternalPresent = false
        val externalSignatures = HashSet<String>()
        for (externalName in externalSupertypes) {
            val resolved = reflection.instanceMethodSignatures(externalName)
            if (resolved == null) {
                opaqueExternalPresent = true
            } else {
                externalSignatures.addAll(resolved)
            }
        }

        if (opaqueExternalPresent) {
            // Cannot introspect the external supertype (e.g. a third-party library
            // not on the engine classpath); conservatively protect every instance
            // method this class declares, matching the historical whole-class guard.
            blocked.addAll(ownInstanceSignatures)
            continue
        }

        for (signature in ownInstanceSignatures) {
            if (signature in externalSignatures) {
                blocked.add(signature)
            }
        }
    }

    return blocked
}

internal fun methodSignature(name: String, descriptor: String): String = "$name$descriptor"

internal fun inArtifactOverrideMethodSignatures(artifact: BytecodeArtifact): Set<String> {
    val inArtifact = artifact.classArtifactIndex
    val blocked = HashSet<String>()
    val methodSignaturesByOwner = artifact.classArtifacts.associate { classArtifact ->
        val signatures = classNodeMethods(classArtifact.bytes)
            .filter { it.access and Opcodes.ACC_STATIC == 0 }
            .map { methodSignature(it.name, it.desc) }
            .toSet()
        classArtifact.summary.internalName to signatures
    }
    for (classArtifact in artifact.classArtifacts) {
        val ownSignatures = methodSignaturesByOwner[classArtifact.summary.internalName].orEmpty()
        if (ownSignatures.isEmpty()) continue
        for (supertype in collectInArtifactSupertypes(classArtifact, inArtifact)) {
            val shared = ownSignatures.intersect(methodSignaturesByOwner[supertype].orEmpty())
            blocked.addAll(shared)
        }
    }
    return blocked
}

internal fun reflectedFieldNames(artifact: BytecodeArtifact): Set<String> {
    val stringConstants = stringConstants(artifact)
    val blocked = HashSet<String>()
    for (classArtifact in artifact.classArtifacts) {
        for (field in classArtifact.summary.fieldSummaries) {
            if (field.name in stringConstants) {
                blocked.add(field.name)
            }
        }
    }
    return blocked
}

private fun parseClassNode(classBytes: ByteArray): ClassNode {
    val node = ClassNode()
    ClassReader(classBytes).accept(node, ClassReader.SKIP_FRAMES)
    return node
}

private fun classNodeMethods(classBytes: ByteArray): List<MethodNode> = parseClassNode(classBytes).methods

private fun reflectedMethodNameSignatures(artifact: BytecodeArtifact): HashSet<String> {
    val stringConstants = stringConstants(artifact)
    val blocked = HashSet<String>()
    for (classArtifact in artifact.classArtifacts) {
        for (method in classNodeMethods(classArtifact.bytes)) {
            if (method.name in stringConstants) {
                blocked.add(methodSignature(method.name, method.desc))
            }
        }
    }
    return blocked
}

private fun stringConstants(artifact: BytecodeArtifact): Set<String> {
    val stringConstants = HashSet<String>()
    for (classArtifact in artifact.classArtifacts) {
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_FRAMES)
        for (method in node.methods) {
            for (instruction in method.instructions) {
                val constant = (instruction as? LdcInsnNode)?.cst as? String ?: continue
                stringConstants.add(constant)
            }
        }
    }
    return stringConstants
}

private fun collectExternalSupertypes(
    classArtifact: ClassArtifact,
    inArtifact: Map<String, ClassArtifact>,
): Set<String> {
    val external = HashSet<String>()
    val visited = HashSet<String>()
    val pending = ArrayDeque<String>()

    fun enqueue(supertypes: Iterable<String?>) {
        for (supertype in supertypes) {
            if (supertype != null && visited.add(supertype)) {
                pending.add(supertype)
            }
        }
    }

    enqueue(listOf(classArtifact.summary.superName) + classArtifact.summary.interfaceNames)
    runCatching {
        val node = parseClassNode(classArtifact.bytes)
        enqueue(listOf(node.superName) + node.interfaces.filterIsInstance<String>())
    }
    while (pending.isNotEmpty()) {
        val supertype = pending.removeFirst()
        val inArtifactSupertype = inArtifact[supertype]
        if (inArtifactSupertype == null) {
            // java/lang/Object still contributes overridable methods (toString, equals...).
            external.add(supertype)
        } else {
            enqueue(listOf(inArtifactSupertype.summary.superName) + inArtifactSupertype.summary.interfaceNames)
            runCatching {
                val node = parseClassNode(inArtifactSupertype.bytes)
                enqueue(listOf(node.superName) + node.interfaces.filterIsInstance<String>())
            }
        }
    }
    return external
}

private fun collectInArtifactSupertypes(
    classArtifact: ClassArtifact,
    inArtifact: Map<String, ClassArtifact>,
): Set<String> {
    val found = HashSet<String>()
    val visited = HashSet<String>()
    val pending = ArrayDeque<String>()

    fun enqueue(supertypes: Iterable<String?>) {
        for (supertype in supertypes) {
            if (supertype != null && visited.add(supertype)) pending.add(supertype)
        }
    }

    enqueue(listOf(classArtifact.summary.superName) + classArtifact.summary.interfaceNames)
    runCatching {
        val node = parseClassNode(classArtifact.bytes)
        enqueue(listOf(node.superName) + node.interfaces.filterIsInstance<String>())
    }
    while (pending.isNotEmpty()) {
        val supertype = pending.removeFirst()
        val inArtifactSupertype = inArtifact[supertype] ?: continue
        found.add(supertype)
        enqueue(listOf(inArtifactSupertype.summary.superName) + inArtifactSupertype.summary.interfaceNames)
        runCatching {
            val node = parseClassNode(inArtifactSupertype.bytes)
            enqueue(listOf(node.superName) + node.interfaces.filterIsInstance<String>())
        }
    }
    return found
}

internal class OverrideBoundaryReflection(private val classLoader: ClassLoader) {
    private val cache = HashMap<String, Set<String>?>()

    /**
     * Public + protected instance method signatures contributed by an external
     * type (including those inherited from its own supertypes), or null when the
     * type cannot be resolved on the engine classpath.
     */
    fun instanceMethodSignatures(internalName: String): Set<String>? = cache.getOrPut(internalName) {
        val knownSignatures = wellKnownExternalInstanceMethodSignatures(internalName)
        val resolved = resolveClass(internalName) ?: return@getOrPut knownSignatures.ifEmpty { null }
        val signatures = HashSet<String>()
        signatures.addAll(knownSignatures)
        collectPublicInstanceMethods(resolved, signatures)
        collectProtectedInstanceMethods(resolved, signatures)
        signatures
    }

    private fun resolveClass(internalName: String): Class<*>? = try {
        Class.forName(internalName.replace('/', '.'), false, classLoader)
    } catch (_: Throwable) {
        null
    }

    private fun collectPublicInstanceMethods(type: Class<*>, signatures: MutableSet<String>) {
        for (method in type.methods) {
            addInstanceMethod(method, signatures)
        }
    }

    private fun collectProtectedInstanceMethods(type: Class<*>, signatures: MutableSet<String>) {
        var current: Class<*>? = type
        while (current != null && current != Any::class.java) {
            for (method in current.declaredMethods) {
                if (Modifier.isProtected(method.modifiers)) {
                    addInstanceMethod(method, signatures)
                }
            }
            current = current.superclass
        }
        for (method in Any::class.java.declaredMethods) {
            if (Modifier.isProtected(method.modifiers)) {
                addInstanceMethod(method, signatures)
            }
        }
    }

    private fun addInstanceMethod(method: Method, signatures: MutableSet<String>) {
        if (Modifier.isStatic(method.modifiers)) {
            return
        }
        signatures.add(methodSignature(method.name, Type.getMethodDescriptor(method)))
    }
}

internal fun wellKnownExternalInstanceMethodSignatures(internalName: String): Set<String> = when (internalName) {
    "java/lang/Runnable" -> setOf(methodSignature("run", "()V"))
    "java/util/Comparator" -> setOf(methodSignature("compare", "(Ljava/lang/Object;Ljava/lang/Object;)I"))
    "java/lang/ClassLoader" -> setOf(
        methodSignature("findClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
        methodSignature("getResource", "(Ljava/lang/String;)Ljava/net/URL;"),
        methodSignature("getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;"),
        methodSignature("loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
        methodSignature("loadClass", "(Ljava/lang/String;Z)Ljava/lang/Class;"),
    )
    "java/util/concurrent/Callable" -> setOf(methodSignature("call", "()Ljava/lang/Object;"))
    "java/util/function/Supplier" -> setOf(methodSignature("get", "()Ljava/lang/Object;"))
    "java/util/function/Consumer" -> setOf(methodSignature("accept", "(Ljava/lang/Object;)V"))
    "java/util/function/Function" -> setOf(methodSignature("apply", "(Ljava/lang/Object;)Ljava/lang/Object;"))
    "java/util/function/Predicate" -> setOf(methodSignature("test", "(Ljava/lang/Object;)Z"))
    "java/awt/event/ActionListener" -> setOf(methodSignature("actionPerformed", "(Ljava/awt/event/ActionEvent;)V"))
    "java/awt/event/KeyListener" -> setOf(
        methodSignature("keyTyped", "(Ljava/awt/event/KeyEvent;)V"),
        methodSignature("keyPressed", "(Ljava/awt/event/KeyEvent;)V"),
        methodSignature("keyReleased", "(Ljava/awt/event/KeyEvent;)V"),
    )
    "java/awt/event/MouseListener" -> setOf(
        methodSignature("mouseClicked", "(Ljava/awt/event/MouseEvent;)V"),
        methodSignature("mousePressed", "(Ljava/awt/event/MouseEvent;)V"),
        methodSignature("mouseReleased", "(Ljava/awt/event/MouseEvent;)V"),
        methodSignature("mouseEntered", "(Ljava/awt/event/MouseEvent;)V"),
        methodSignature("mouseExited", "(Ljava/awt/event/MouseEvent;)V"),
    )
    "java/awt/event/MouseMotionListener" -> setOf(
        methodSignature("mouseDragged", "(Ljava/awt/event/MouseEvent;)V"),
        methodSignature("mouseMoved", "(Ljava/awt/event/MouseEvent;)V"),
    )
    "java/awt/event/WindowListener" -> setOf(
        methodSignature("windowOpened", "(Ljava/awt/event/WindowEvent;)V"),
        methodSignature("windowClosing", "(Ljava/awt/event/WindowEvent;)V"),
        methodSignature("windowClosed", "(Ljava/awt/event/WindowEvent;)V"),
        methodSignature("windowIconified", "(Ljava/awt/event/WindowEvent;)V"),
        methodSignature("windowDeiconified", "(Ljava/awt/event/WindowEvent;)V"),
        methodSignature("windowActivated", "(Ljava/awt/event/WindowEvent;)V"),
        methodSignature("windowDeactivated", "(Ljava/awt/event/WindowEvent;)V"),
    )
    "javax/swing/event/ChangeListener" -> setOf(methodSignature("stateChanged", "(Ljavax/swing/event/ChangeEvent;)V"))
    "javax/swing/event/ListSelectionListener" -> setOf(methodSignature("valueChanged", "(Ljavax/swing/event/ListSelectionEvent;)V"))
    "javax/swing/event/DocumentListener" -> setOf(
        methodSignature("insertUpdate", "(Ljavax/swing/event/DocumentEvent;)V"),
        methodSignature("removeUpdate", "(Ljavax/swing/event/DocumentEvent;)V"),
        methodSignature("changedUpdate", "(Ljavax/swing/event/DocumentEvent;)V"),
    )
    else -> emptySet()
}


