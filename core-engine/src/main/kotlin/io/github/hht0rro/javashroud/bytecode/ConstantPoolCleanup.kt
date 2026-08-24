package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter

/**
 * Rewrites [classBytes] through a fresh ClassReader/ClassWriter cycle so the
 * output constant pool contains only entries actually reachable from the final
 * bytecode and class metadata.
 *
 * Call this after any transform that removes attributes (SourceFile,
 * LineNumberTable, etc.) or rewrites type references, to eliminate dead
 * constant pool entries that would otherwise leak original names.
 */
fun stripDeadConstantPoolEntries(classBytes: ByteArray): ByteArray {
    val reader = ClassReader(classBytes)
    // Do not seed the writer from the input reader.  ClassWriter(reader, ...)
    // intentionally copies the complete original constant pool, including
    // Utf8 entries that became unreachable after SourceFile/parameter-debug
    // stripping.  A fresh writer retains the emitted graph only, which is the
    // release gate needed to prevent removed debug names leaking in bytes.
    val writer = ClassWriter(0)
    reader.accept(writer, 0)
    return writer.toByteArray()
}
