package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

fun analyzeClassBytes(classBytes: ByteArray): ClassAnalysisSummary {
    val classReader = buildClassReader(classBytes)
    val collector = collectClassStructure(classReader)
    return buildCollectedClassSummary(classReader, collector)
}

internal fun buildClassReader(classBytes: ByteArray): ClassReader = ClassReader(classBytes)

internal fun collectClassStructure(classReader: ClassReader): ClassStructureCollector {
    val collector = ClassStructureCollector()
    classReader.accept(collector, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
    return collector
}

internal fun buildCollectedClassSummary(
    classReader: ClassReader,
    collector: ClassStructureCollector,
): ClassAnalysisSummary = buildClassAnalysisSummary(
    className = classReader.className,
    collector = collector,
)

internal class ClassStructureCollector : ClassVisitor(Opcodes.ASM9) {
    var internalName: String? = null
    var superName: String? = null
    var accessFlags: Int = 0
    val interfaceNames: MutableList<String> = mutableListOf()
    val fieldSummaries: MutableList<MemberSummary> = mutableListOf()
    val methodSummaries: MutableList<MemberSummary> = mutableListOf()

    override fun visit(version: Int, access: Int, name: String?, signature: String?, superName: String?, interfaces: Array<out String>?) {
        internalName = name
        this.superName = superName
        accessFlags = access
        resetInterfaceNames(interfaceNames, interfaces)
    }

    override fun visitField(access: Int, name: String?, descriptor: String?, signature: String?, value: Any?): FieldVisitor? {
        collectFieldSummary(fieldSummaries, access, name, descriptor)
        return null
    }

    override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
        collectMethodSummary(methodSummaries, access, name, descriptor)
        return null
    }
}

internal fun resetInterfaceNames(interfaceNames: MutableList<String>, interfaces: Array<out String>?): Unit {
    interfaceNames.clear()
    if (interfaces != null) {
        interfaceNames.addAll(interfaces)
    }
}

internal fun collectFieldSummary(
    fieldSummaries: MutableList<MemberSummary>,
    access: Int,
    name: String?,
    descriptor: String?,
): Unit {
    if (name != null && descriptor != null) {
        fieldSummaries += buildMemberSummary(
            kind = MemberKind.FIELD,
            name = name,
            descriptor = descriptor,
            accessFlags = access,
        )
    }
}

internal fun collectMethodSummary(
    methodSummaries: MutableList<MemberSummary>,
    access: Int,
    name: String?,
    descriptor: String?,
): Unit {
    if (name != null && descriptor != null) {
        methodSummaries += buildMemberSummary(
            kind = MemberKind.METHOD,
            name = name,
            descriptor = descriptor,
            accessFlags = access,
        )
    }
}

internal fun buildClassAnalysisSummary(className: String, collector: ClassStructureCollector): ClassAnalysisSummary = ClassAnalysisSummary(
    internalName = collector.internalName ?: className,
    superName = collector.superName,
    interfaceNames = collector.interfaceNames.toList(),
    accessFlags = collector.accessFlags,
    fieldCount = collector.fieldSummaries.size,
    methodCount = collector.methodSummaries.size,
    fieldSummaries = collector.fieldSummaries.toList(),
    methodSummaries = collector.methodSummaries.toList(),
)

internal fun buildMemberSummary(kind: MemberKind, name: String, descriptor: String, accessFlags: Int): MemberSummary = MemberSummary(
    kind = kind,
    name = name,
    descriptor = descriptor,
    accessFlags = accessFlags,
)
