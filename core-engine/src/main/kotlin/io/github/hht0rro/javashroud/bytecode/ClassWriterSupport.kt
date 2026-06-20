package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter

/**
 * Creates a [ClassWriter] that recomputes stack map frames from scratch.
 *
 * The default [ClassWriter.getCommonSuperClass] implementation uses
 * [Class.forName], which fails when referenced types are not on the
 * engine classpath.  The override below falls back to
 * `java/lang/Object` so frame computation never throws.
 */
internal fun computeFramesWriter(reader: ClassReader): ClassWriter =
    object : ClassWriter(reader, ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
    }

/**
 * Creates a [ClassWriter] that recomputes stack map frames from scratch
 * (no [ClassReader] copy variant).
 */
internal fun computeFramesWriter(): ClassWriter =
    object : ClassWriter(ClassWriter.COMPUTE_FRAMES) {
        override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
    }

/**
 * Creates a [ClassWriter] that only recomputes maxStack and maxLocals.
 *
 * Use this instead of [computeFramesWriter] for aggressive transforms
 * that produce intentionally malformed StackMapTable frames.
 */
internal fun computeMaxsWriter(): ClassWriter = ClassWriter(ClassWriter.COMPUTE_MAXS)
