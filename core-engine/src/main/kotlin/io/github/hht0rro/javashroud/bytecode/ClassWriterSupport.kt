package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter

/**
 * Creates a [ClassWriter] that recomputes stack map frames from scratch.
 *
 * The default [ClassWriter.getCommonSuperClass] implementation is accurate for
 * JDK and engine-visible types, but it fails when an application type is not on
 * the engine classpath. Preserve the accurate result whenever possible and only
 * fall back after type resolution fails.
 */
internal fun computeFramesWriter(reader: ClassReader): ClassWriter =
    object : ClassWriter(reader, ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String =
            resolveCommonSuperClass(type1, type2) { super.getCommonSuperClass(type1, type2) }
    }

/**
 * Creates a [ClassWriter] that recomputes stack map frames from scratch
 * (no [ClassReader] copy variant).
 */
internal fun computeFramesWriter(): ClassWriter =
    object : ClassWriter(ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String =
            resolveCommonSuperClass(type1, type2) { super.getCommonSuperClass(type1, type2) }
    }

private inline fun resolveCommonSuperClass(
    type1: String,
    type2: String,
    defaultResolver: () -> String,
): String = try {
    // Let ASM use its normal hierarchy resolution first. This keeps precise
    // exception parents such as java/lang/Throwable in shared handlers.
    defaultResolver()
} catch (failure: RuntimeException) {
    // ASM reports missing types as TypeNotPresentException. Do not turn an
    // unrelated transform bug into an Object frame merely because it happens
    // to be a RuntimeException.
    if (!isTypeResolutionFailure(failure)) throw failure
    resolveVisibleCommonSuperClass(type1, type2)
} catch (_: LinkageError) {
    // Class loading can fail with a linkage error when a dependency is absent
    // or incompatible. These are resolution failures, not fatal VM errors such
    // as OutOfMemoryError, which intentionally remain uncaught.
    resolveVisibleCommonSuperClass(type1, type2)
}

private fun isTypeResolutionFailure(failure: RuntimeException): Boolean {
    var current: Throwable? = failure
    while (current != null) {
        if (current is TypeNotPresentException || current is ClassNotFoundException || current is SecurityException) {
            return true
        }
        current = current.cause
    }
    return false
}

private fun resolveVisibleCommonSuperClass(type1: String, type2: String): String {
    val loaders = linkedSetOf(
        Thread.currentThread().contextClassLoader,
        ClassWriter::class.java.classLoader,
    )
    for (loader in loaders) {
        val first = loadInternalType(type1, loader) ?: continue
        val second = loadInternalType(type2, loader) ?: continue
        if (first.isAssignableFrom(second)) return type1
        if (second.isAssignableFrom(first)) return type2
        if (first.isInterface || second.isInterface || first.isArray || second.isArray) {
            return "java/lang/Object"
        }

        var cursor = first.superclass
        while (cursor != null && !cursor.isAssignableFrom(second)) cursor = cursor.superclass
        return cursor?.name?.replace('.', '/') ?: "java/lang/Object"
    }
    return "java/lang/Object"
}

private fun loadInternalType(internalName: String, loader: ClassLoader?): Class<*>? = try {
    val binaryName = if (internalName.startsWith("[")) internalName.replace('/', '.') else internalName.replace('/', '.')
    Class.forName(binaryName, false, loader)
} catch (_: ClassNotFoundException) {
    null
} catch (_: LinkageError) {
    null
}

/**
 * Creates a [ClassWriter] that only recomputes maxStack and maxLocals.
 *
 * Use this instead of [computeFramesWriter] for aggressive transforms
 * that produce intentionally malformed StackMapTable frames.
 */
internal fun computeMaxsWriter(): ClassWriter = ClassWriter(ClassWriter.COMPUTE_MAXS)
