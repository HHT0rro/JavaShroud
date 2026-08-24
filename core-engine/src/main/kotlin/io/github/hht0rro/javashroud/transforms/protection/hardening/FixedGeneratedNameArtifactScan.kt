package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.artifact.isSupportedClassBindingMetadataResource
import io.github.hht0rro.javashroud.naming.isFixedGeneratedClassEntryPath
import io.github.hht0rro.javashroud.naming.isFixedGeneratedDottedName
import io.github.hht0rro.javashroud.naming.isFixedGeneratedInternalName
import java.nio.charset.StandardCharsets
import java.util.jar.JarFile
import org.objectweb.asm.AnnotationVisitor
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.Handle
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.RecordComponentVisitor
import org.objectweb.asm.Type

/** Final current-format release gate for retired r.<digits> generated names. */
internal object FixedGeneratedNameArtifactScan {
    internal const val CHECK = "fixed-generated-name"

    private const val SERVICES_PREFIX = "META-INF/services/"
    private val dottedReference = Regex("r\\.[0-9]+\\.[A-Za-z0-9_$]+")
    private val internalReference = Regex("r/[0-9]+/[A-Za-z0-9_$]+")

    fun scanArtifact(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val entryViolation = artifact.jarEntries.asSequence()
            .mapNotNull { entry ->
                if (entry.name.endsWith(".class")) {
                    entryPathViolation(entry.name, "artifact-final-state")
                } else {
                    resourceViolation(entry.name, entry.bytes, "artifact-final-state")
                }
            }
            .firstOrNull()
        val classViolation = if (entryViolation == null) {
            artifact.classArtifacts.asSequence()
                .mapNotNull { classArtifact -> classViolation(classArtifact.entryName, classArtifact.bytes, "artifact-final-state") }
                .firstOrNull()
        } else {
            null
        }
        return finding(entryViolation ?: classViolation)
    }

    fun scanJarFile(jar: JarFile): ReleaseArtifactScanReport.Finding {
        var violation: String? = null
        val entries = jar.entries()
        while (entries.hasMoreElements() && violation == null) {
            val entry = entries.nextElement()
            if (entry.isDirectory) continue
            val bytes = jar.getInputStream(entry).use { it.readBytes() }
            violation = if (entry.name.endsWith(".class")) {
                classViolation(entry.name, bytes, "output-jar")
            } else {
                resourceViolation(entry.name, bytes, "output-jar")
            }
        }
        return finding(violation)
    }

    private fun finding(violation: String?): ReleaseArtifactScanReport.Finding =
        ReleaseArtifactScanReport.Finding(CHECK, violation == null, violation ?: "absent")

    private fun entryPathViolation(entryName: String, origin: String): String? =
        if (isFixedGeneratedClassEntryPath(entryName)) {
            detail(entryName, entryName.removeSuffix(".class"), origin, "class-entry-path")
        } else {
            null
        }

    private fun resourceViolation(entryName: String, bytes: ByteArray, origin: String): String? {
        if (entryName.startsWith(SERVICES_PREFIX)) {
            val serviceName = entryName.removePrefix(SERVICES_PREFIX)
            if (isFixedGeneratedDottedName(serviceName)) {
                return detail(entryName, serviceName.replace('.', '/'), origin, "service-interface-path")
            }
        }
        if (
            entryName.equals("META-INF/MANIFEST.MF", ignoreCase = true) ||
            entryName.startsWith(SERVICES_PREFIX) ||
            isSupportedClassBindingMetadataResource(entryName)
        ) {
            firstTextReference(String(bytes, StandardCharsets.UTF_8))?.let { reference ->
                return detail(entryName, reference, origin, "resource-class-reference")
            }
        }
        return null
    }

    private fun classViolation(entryName: String, bytes: ByteArray, origin: String): String? {
        entryPathViolation(entryName, origin)?.let { return it }
        return try {
            val visitor = FixedNameClassVisitor(entryName, origin)
            ClassReader(bytes).accept(visitor, 0)
            visitor.violation
        } catch (error: Throwable) {
            "entry=$entryName; class=<unparsed>; stage=release-scan; origin=$origin; " +
                "reason=class-parse-failed:${error.javaClass.simpleName}"
        }
    }

    private fun firstTextReference(text: String): String? {
        // Text resources are scanned independently from ASM metadata.  Keep the
        // numeric and two-hex-shard retired namespaces in lockstep with
        // FixedGeneratedNamePolicy so a relocated class cannot leak through a
        // manifest, service descriptor, binding resource, or supported
        // reflection string.
        val dotted = listOf(
            Regex("r\\.[0-9]+\\.[A-Za-z0-9_$]+"),
            Regex("r\\.[0-9a-fA-F]{2}\\.C[0-9a-fA-F]{8,}"),
        )
        val internal = listOf(
            Regex("r/[0-9]+/[A-Za-z0-9_$]+"),
            Regex("r/[0-9a-fA-F]{2}/C[0-9a-fA-F]{8,}"),
        )
        val matches = (dotted + internal).mapNotNull { it.find(text) }
        return matches.minByOrNull { it.range.first }?.value
    }

    private fun detail(entryName: String, className: String, origin: String, reason: String): String =
        "entry=$entryName; class=$className; stage=release-scan; origin=$origin; reason=$reason"

    private class FixedNameClassVisitor(
        private val entryName: String,
        private val origin: String,
    ) : ClassVisitor(Opcodes.ASM9) {
        var violation: String? = null
            private set

        override fun visit(
            version: Int,
            access: Int,
            name: String?,
            signature: String?,
            superName: String?,
            interfaces: Array<out String>?,
        ) {
            inspectInternal("class-name", name)
            inspectSignature("class-signature", signature)
            inspectInternal("super-name", superName)
            interfaces.orEmpty().forEach { inspectInternal("interface", it) }
        }

        override fun visitOuterClass(owner: String?, name: String?, descriptor: String?) {
            inspectInternal("enclosing-owner", owner)
            inspectDescriptor("enclosing-descriptor", descriptor)
        }

        override fun visitInnerClass(name: String, outerName: String?, innerName: String?, access: Int) {
            inspectInternal("inner-name", name)
            inspectInternal("inner-outer", outerName)
        }

        override fun visitNestHost(nestHost: String?) {
            inspectInternal("nest-host", nestHost)
        }

        override fun visitNestMember(nestMember: String?) {
            inspectInternal("nest-member", nestMember)
        }

        override fun visitPermittedSubclass(permittedSubclass: String?) {
            inspectInternal("permitted-subclass", permittedSubclass)
        }

        override fun visitAnnotation(descriptor: String?, visible: Boolean): AnnotationVisitor =
            annotationVisitor("class-annotation", descriptor)

        override fun visitTypeAnnotation(
            typeRef: Int,
            typePath: org.objectweb.asm.TypePath?,
            descriptor: String?,
            visible: Boolean,
        ): AnnotationVisitor = annotationVisitor("class-type-annotation", descriptor)

        override fun visitRecordComponent(
            name: String?,
            descriptor: String?,
            signature: String?,
        ): RecordComponentVisitor {
            inspectDescriptor("record-component", descriptor)
            inspectSignature("record-component-signature", signature)
            return object : RecordComponentVisitor(Opcodes.ASM9) {
                override fun visitAnnotation(annotationDescriptor: String?, visible: Boolean): AnnotationVisitor =
                    annotationVisitor("record-component-annotation", annotationDescriptor)

                override fun visitTypeAnnotation(
                    typeRef: Int,
                    typePath: org.objectweb.asm.TypePath?,
                    annotationDescriptor: String?,
                    visible: Boolean,
                ): AnnotationVisitor = annotationVisitor("record-component-type-annotation", annotationDescriptor)
            }
        }

        override fun visitField(
            access: Int,
            name: String?,
            descriptor: String?,
            signature: String?,
            value: Any?,
        ): FieldVisitor {
            inspectDescriptor("field-descriptor", descriptor)
            inspectSignature("field-signature", signature)
            inspectValue("field-constant", value)
            return object : FieldVisitor(Opcodes.ASM9) {
                override fun visitAnnotation(annotationDescriptor: String?, visible: Boolean): AnnotationVisitor =
                    annotationVisitor("field-annotation", annotationDescriptor)

                override fun visitTypeAnnotation(
                    typeRef: Int,
                    typePath: org.objectweb.asm.TypePath?,
                    annotationDescriptor: String?,
                    visible: Boolean,
                ): AnnotationVisitor = annotationVisitor("field-type-annotation", annotationDescriptor)
            }
        }

        override fun visitMethod(
            access: Int,
            name: String?,
            descriptor: String?,
            signature: String?,
            exceptions: Array<out String>?,
        ): MethodVisitor {
            inspectDescriptor("method-descriptor", descriptor)
            inspectSignature("method-signature", signature)
            exceptions.orEmpty().forEach { inspectInternal("method-exception", it) }
            return object : MethodVisitor(Opcodes.ASM9) {
                override fun visitAnnotation(annotationDescriptor: String?, visible: Boolean): AnnotationVisitor =
                    annotationVisitor("method-annotation", annotationDescriptor)

                override fun visitTypeAnnotation(
                    typeRef: Int,
                    typePath: org.objectweb.asm.TypePath?,
                    annotationDescriptor: String?,
                    visible: Boolean,
                ): AnnotationVisitor = annotationVisitor("method-type-annotation", annotationDescriptor)

                override fun visitParameterAnnotation(
                    parameter: Int,
                    annotationDescriptor: String?,
                    visible: Boolean,
                ): AnnotationVisitor = annotationVisitor("parameter-annotation", annotationDescriptor)

                override fun visitTypeInsn(opcode: Int, type: String?) {
                    inspectInternal("type-insn", type)
                }

                override fun visitFieldInsn(opcode: Int, owner: String?, name: String?, fieldDescriptor: String?) {
                    inspectInternal("field-owner", owner)
                    inspectDescriptor("field-insn-descriptor", fieldDescriptor)
                }

                override fun visitMethodInsn(
                    opcode: Int,
                    owner: String?,
                    name: String?,
                    methodDescriptor: String?,
                    isInterface: Boolean,
                ) {
                    inspectInternal("method-owner", owner)
                    inspectDescriptor("method-insn-descriptor", methodDescriptor)
                }

                override fun visitInvokeDynamicInsn(
                    name: String,
                    descriptor: String,
                    bootstrapMethodHandle: Handle,
                    vararg bootstrapMethodArguments: Any,
                ) {
                    inspectDescriptor("indy-descriptor", descriptor)
                    inspectValue("indy-bootstrap", bootstrapMethodHandle)
                    bootstrapMethodArguments.forEach { inspectValue("indy-bootstrap-arg", it) }
                }

                override fun visitLdcInsn(value: Any?) {
                    inspectValue("ldc", value)
                }

                override fun visitMultiANewArrayInsn(descriptor: String?, numDimensions: Int) {
                    inspectDescriptor("multi-array", descriptor)
                }

                override fun visitTryCatchBlock(start: Label?, end: Label?, handler: Label?, type: String?) {
                    inspectInternal("try-catch", type)
                }

                override fun visitLocalVariable(
                    name: String?,
                    localDescriptor: String?,
                    localSignature: String?,
                    start: Label?,
                    end: Label?,
                    index: Int,
                ) {
                    inspectDescriptor("local-descriptor", localDescriptor)
                    inspectSignature("local-signature", localSignature)
                }

                override fun visitFrame(
                    type: Int,
                    numLocal: Int,
                    local: Array<out Any>?,
                    numStack: Int,
                    stack: Array<out Any>?,
                ) {
                    local.orEmpty().forEach { inspectValue("frame-local", it) }
                    stack.orEmpty().forEach { inspectValue("frame-stack", it) }
                }
            }
        }

        private fun annotationVisitor(reason: String, descriptor: String?): AnnotationVisitor {
            inspectDescriptor(reason, descriptor)
            return object : AnnotationVisitor(Opcodes.ASM9) {
                override fun visit(name: String?, value: Any?) {
                    inspectValue("$reason-value", value)
                }

                override fun visitEnum(name: String?, enumDescriptor: String?, value: String?) {
                    inspectDescriptor("$reason-enum", enumDescriptor)
                }

                override fun visitAnnotation(name: String?, nestedDescriptor: String?): AnnotationVisitor =
                    annotationVisitor("$reason-nested", nestedDescriptor)

                override fun visitArray(name: String?): AnnotationVisitor = annotationVisitor("$reason-array", null)
            }
        }

        private fun inspectValue(reason: String, value: Any?) {
            when (value) {
                is Type -> inspectType(reason, value)
                is Handle -> {
                    inspectInternal("$reason-owner", value.owner)
                    inspectDescriptor("$reason-descriptor", value.desc)
                }
                is ConstantDynamic -> {
                    inspectDescriptor("$reason-descriptor", value.descriptor)
                    inspectValue("$reason-bootstrap", value.bootstrapMethod)
                    repeat(value.bootstrapMethodArgumentCount) { index ->
                        inspectValue("$reason-bootstrap-arg", value.getBootstrapMethodArgument(index))
                    }
                }
                is String -> inspectText(reason, value)
                is Array<*> -> value.forEach { inspectValue(reason, it) }
                is List<*> -> value.forEach { inspectValue(reason, it) }
            }
        }

        private fun inspectDescriptor(reason: String, descriptor: String?) {
            if (descriptor == null) return
            try {
                inspectType(
                    reason,
                    if (descriptor.startsWith("(")) Type.getMethodType(descriptor) else Type.getType(descriptor),
                )
            } catch (_: IllegalArgumentException) {
                inspectText(reason, descriptor)
            }
        }

        private fun inspectType(reason: String, type: Type) {
            when (type.sort) {
                Type.OBJECT -> inspectInternal(reason, type.internalName)
                Type.ARRAY -> inspectType(reason, type.elementType)
                Type.METHOD -> {
                    type.argumentTypes.forEach { inspectType(reason, it) }
                    inspectType(reason, type.returnType)
                }
            }
        }

        private fun inspectSignature(reason: String, signature: String?) {
            if (signature != null) inspectText(reason, signature)
        }

        private fun inspectText(reason: String, value: String) {
            if (violation != null) return
            val reference = firstTextReference(value) ?: return
            violation = detail(entryName, reference, origin, reason)
        }

        private fun inspectInternal(reason: String, internalName: String?) {
            if (violation != null || internalName == null || !isFixedGeneratedInternalName(internalName)) return
            violation = detail(entryName, internalName, origin, reason)
        }
    }
}
