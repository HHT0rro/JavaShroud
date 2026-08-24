package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.Attribute
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Production classfile attribute whitelist. Debug names are dropped.
 * Runtime-required attributes (nests, records, modules, bootstrap, signatures)
 * are kept so Java 8/21 semantics survive.
 */
internal object ClassfileAttributeWhitelist {
    val KEPT_CUSTOM_ATTRIBUTES: Set<String> = emptySet()

    fun apply(classBytes: ByteArray): ByteArray {
        val reader = ClassReader(classBytes)
        // This is the last classfile rewrite in the current-format pipeline.
        // Recompute StackMapTable here so branch-producing transforms that
        // intentionally operate on a frame-free tree cannot emit a verifier-
        // invalid Java 8+ class.  The helper preserves precise common-super
        // resolution when application classes are not on the engine classpath.
        val writer = computeFramesWriter(reader)
        reader.accept(object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visitSource(source: String?, debug: String?) {}

            override fun visitAttribute(attribute: Attribute) {
                if (attribute.type in KEPT_CUSTOM_ATTRIBUTES) super.visitAttribute(attribute)
            }

            override fun visitField(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                value: Any?,
            ): FieldVisitor {
                val parent = super.visitField(access, name, descriptor, signature, value)
                return object : FieldVisitor(Opcodes.ASM9, parent) {
                    override fun visitAttribute(attribute: Attribute) {
                        if (attribute.type in KEPT_CUSTOM_ATTRIBUTES) super.visitAttribute(attribute)
                    }
                }
            }

            override fun visitMethod(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                exceptions: Array<out String>?,
            ): MethodVisitor {
                val parent = super.visitMethod(access, name, descriptor, signature, exceptions)
                return object : MethodVisitor(Opcodes.ASM9, parent) {
                    override fun visitParameter(name: String?, access: Int) {}
                    override fun visitAttribute(attribute: Attribute) {
                        if (attribute.type in KEPT_CUSTOM_ATTRIBUTES) super.visitAttribute(attribute)
                    }
                }
            }
        // Preserve the input control-flow graph while the COMPUTE_FRAMES
        // writer rebuilds StackMapTable for the final Java 8+ artifact.  Using
        // SKIP_FRAMES here silently emitted verifier-invalid classes whenever
        // an earlier pass inserted a branch.
        }, ClassReader.SKIP_DEBUG)
        return stripDeadConstantPoolEntries(writer.toByteArray())
    }
}
