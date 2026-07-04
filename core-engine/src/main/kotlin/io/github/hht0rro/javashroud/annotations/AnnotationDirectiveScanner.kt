package io.github.hht0rro.javashroud.annotations

import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import org.objectweb.asm.AnnotationVisitor
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

internal fun collectAnnotationDirectives(classArtifacts: List<ClassArtifact>): List<AnnotationDirective> =
    classArtifacts.flatMap { classArtifact -> collectAnnotationDirectives(classArtifact.bytes) }

internal fun collectAnnotationDirectives(classBytes: ByteArray): List<AnnotationDirective> {
    val collector = JavaShroudAnnotationCollector()
    ClassReader(classBytes).accept(collector, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
    return collector.directives
}

private class JavaShroudAnnotationCollector : ClassVisitor(Opcodes.ASM9) {
    val directives = mutableListOf<AnnotationDirective>()
    private var className: String = ""

    override fun visit(version: Int, access: Int, name: String?, signature: String?, superName: String?, interfaces: Array<out String>?) {
        className = name.orEmpty()
    }

    override fun visitAnnotation(descriptor: String?, visible: Boolean): AnnotationVisitor? =
        directiveAnnotationVisitor(descriptor, AnnotationTargetKind.CLASS, className)

    override fun visitField(access: Int, name: String?, descriptor: String?, signature: String?, value: Any?): FieldVisitor =
        object : FieldVisitor(Opcodes.ASM9) {
            override fun visitAnnotation(annotationDescriptor: String?, visible: Boolean): AnnotationVisitor? =
                directiveAnnotationVisitor(
                    descriptor = annotationDescriptor,
                    targetKind = AnnotationTargetKind.FIELD,
                    target = "$className#${name.orEmpty()}:${descriptor.orEmpty()}",
                )
        }

    override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor =
        object : MethodVisitor(Opcodes.ASM9) {
            override fun visitAnnotation(annotationDescriptor: String?, visible: Boolean): AnnotationVisitor? =
                directiveAnnotationVisitor(
                    descriptor = annotationDescriptor,
                    targetKind = AnnotationTargetKind.METHOD,
                    target = "$className#${name.orEmpty()}:${descriptor.orEmpty()}",
                )
        }

    private fun directiveAnnotationVisitor(descriptor: String?, targetKind: AnnotationTargetKind, target: String): AnnotationVisitor? = when (descriptor) {
        JAVA_SHROUD_PASS_DESCRIPTOR -> PassAnnotationVisitor(targetKind, target) { directives += it }
        JAVA_SHROUD_PASSES_DESCRIPTOR -> PassesAnnotationVisitor(targetKind, target) { directives += it }
        else -> null
    }
}

private class PassesAnnotationVisitor(
    private val targetKind: AnnotationTargetKind,
    private val target: String,
    private val emit: (AnnotationDirective) -> Unit,
) : AnnotationVisitor(Opcodes.ASM9) {
    override fun visitArray(name: String?): AnnotationVisitor? =
        if (name == "value") {
            object : AnnotationVisitor(Opcodes.ASM9) {
                override fun visitAnnotation(name: String?, descriptor: String?): AnnotationVisitor? =
                    if (descriptor == JAVA_SHROUD_PASS_DESCRIPTOR) PassAnnotationVisitor(targetKind, target, emit) else null
            }
        } else {
            null
        }
}

private class PassAnnotationVisitor(
    private val targetKind: AnnotationTargetKind,
    private val target: String,
    private val emit: (AnnotationDirective) -> Unit,
) : AnnotationVisitor(Opcodes.ASM9) {
    private var passId: String = ""
    private var enabled: Boolean = true
    private val options = linkedMapOf<String, String>()

    override fun visit(name: String?, value: Any?) {
        when (name) {
            "id" -> passId = value?.toString().orEmpty()
            "enabled" -> enabled = value as? Boolean ?: value?.toString()?.toBooleanStrictOrNull() ?: enabled
        }
    }

    override fun visitArray(name: String?): AnnotationVisitor? =
        if (name == "options") {
            object : AnnotationVisitor(Opcodes.ASM9) {
                override fun visitAnnotation(name: String?, descriptor: String?): AnnotationVisitor? =
                    if (descriptor == JAVA_SHROUD_OPTION_DESCRIPTOR) OptionAnnotationVisitor(options) else null
            }
        } else {
            null
        }

    override fun visitEnd() {
        if (passId.isNotBlank()) {
            emit(
                AnnotationDirective(
                    target = target,
                    targetKind = targetKind,
                    passId = passId,
                    enabled = enabled,
                    options = options.toMap(),
                ),
            )
        }
    }
}

private class OptionAnnotationVisitor(
    private val options: MutableMap<String, String>,
) : AnnotationVisitor(Opcodes.ASM9) {
    private var key: String = ""
    private var value: String = ""

    override fun visit(name: String?, value: Any?) {
        when (name) {
            "key" -> key = value?.toString().orEmpty()
            "value" -> this.value = value?.toString().orEmpty()
        }
    }

    override fun visitEnd() {
        if (key.isNotBlank()) options[key] = value
    }
}