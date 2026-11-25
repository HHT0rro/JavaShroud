package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.bytecode.remapClasses
import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.rename.renameClasses
import io.github.hht0rro.javashroud.transforms.rename.renamePackages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

class ApkAccessWideningTest {
    @Test
    fun packagePrivateAbstractOverridesSurviveEitherSideMoving() = checkCovariantOverride(parentAccess = 0, childAccess = 0)

    @Test
    fun packagePrivateAbstractParentsDispatchThroughPublicCovariantBridges() =
        checkCovariantOverride(parentAccess = 0, childAccess = Opcodes.ACC_PUBLIC)

    @Test
    fun packagePrivateConcreteOverridesKeepTheirDispatchAfterRelocation() =
        checkCovariantOverride(parentAccess = 0, childAccess = Opcodes.ACC_PUBLIC, abstractParent = false)

    @Test
    fun protectedAbstractOverridesSurviveEitherSideMoving() =
        checkCovariantOverride(parentAccess = Opcodes.ACC_PROTECTED, childAccess = Opcodes.ACC_PROTECTED)

    @Test
    fun publicAbstractOverridesSurviveEitherSideMoving() =
        checkCovariantOverride(parentAccess = Opcodes.ACC_PUBLIC, childAccess = Opcodes.ACC_PUBLIC)

    @Test
    fun abstractOverridesFollowSuperclassChainsWithoutAnIntermediateDeclaration() =
        checkCovariantOverride(parentAccess = 0, childAccess = 0, intermediate = true)

    @Test
    fun packagePrivateOverrideFamiliesRemainValidWhenAllClassesMoveTogether() =
        checkCovariantOverride(parentAccess = 0, childAccess = 0, crossBoundary = false)

    @Test
    fun privateParentMethodsKeepIndependentDispatch() =
        checkCovariantOverride(parentAccess = Opcodes.ACC_PRIVATE, childAccess = Opcodes.ACC_PUBLIC, abstractParent = false)

    @Test
    fun originallyDifferentPackageMethodsKeepIndependentDispatch() =
        checkCovariantOverride(parentAccess = 0, childAccess = Opcodes.ACC_PUBLIC, abstractParent = false, samePackage = false)

    private fun checkCovariantOverride(
        parentAccess: Int,
        childAccess: Int,
        abstractParent: Boolean = true,
        samePackage: Boolean = true,
        intermediate: Boolean = false,
        crossBoundary: Boolean = true,
    ) {
        val parent = "fixture/original/BaseProgressIndicator"
        val child = if (samePackage) "fixture/original/LinearProgressIndicator" else "fixture/other/LinearProgressIndicator"
        val baseSpec = "fixture/original/BaseProgressIndicatorSpec"
        val linearSpec = "fixture/original/LinearProgressIndicatorSpec"
        val middle = "fixture/original/IntermediateIndicator"
        val classes = linkedMapOf<String, ByteArray>()
        fun type(owner: String, superclass: String = "java/lang/Object", access: Int = 0, body: ClassWriter.() -> Unit) {
            classes[owner] = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
                visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or access, owner, null, superclass, null)
                body()
                visitEnd()
            }.toByteArray()
        }
        fun ClassWriter.constructor(superclass: String, specValue: Int? = null) {
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                if (specValue != null) visitIntInsn(Opcodes.BIPUSH, specValue)
                visitMethodInsn(Opcodes.INVOKESPECIAL, superclass, "<init>", if (specValue == null) "()V" else "(I)V", false)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        type(baseSpec) {
            visitField(Opcodes.ACC_PUBLIC, "value", "I", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
                visitVarInsn(Opcodes.ALOAD, 0)
                visitVarInsn(Opcodes.ILOAD, 1)
                visitFieldInsn(Opcodes.PUTFIELD, baseSpec, "value", "I")
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        type(linearSpec, baseSpec) { constructor(baseSpec, specValue = 42) }
        type(parent, access = if (abstractParent) Opcodes.ACC_ABSTRACT else 0) {
            visitField(Opcodes.ACC_PUBLIC, "spec", "L$baseSpec;", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
                visitVarInsn(Opcodes.ALOAD, 0)
                visitVarInsn(Opcodes.ALOAD, 0)
                val opcode = if (parentAccess == Opcodes.ACC_PRIVATE) Opcodes.INVOKESPECIAL else Opcodes.INVOKEVIRTUAL
                visitMethodInsn(opcode, parent, "createSpec", "()L$baseSpec;", false)
                visitFieldInsn(Opcodes.PUTFIELD, parent, "spec", "L$baseSpec;")
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(parentAccess or if (abstractParent) Opcodes.ACC_ABSTRACT else 0,
                "createSpec", "()L$baseSpec;", null, null).apply {
                if (!abstractParent) {
                    visitCode()
                    visitTypeInsn(Opcodes.NEW, baseSpec)
                    visitInsn(Opcodes.DUP)
                    visitIntInsn(Opcodes.BIPUSH, 11)
                    visitMethodInsn(Opcodes.INVOKESPECIAL, baseSpec, "<init>", "(I)V", false)
                    visitInsn(Opcodes.ARETURN)
                    visitMaxs(0, 0)
                }
                visitEnd()
            }
        }
        if (intermediate) type(middle, parent) { constructor(parent) }
        type(child, if (intermediate) middle else parent) {
            constructor(if (intermediate) middle else parent)
            visitMethod(childAccess, "createSpec", "()L$linearSpec;", null, null).apply {
                visitCode()
                visitTypeInsn(Opcodes.NEW, linearSpec)
                visitInsn(Opcodes.DUP)
                visitMethodInsn(Opcodes.INVOKESPECIAL, linearSpec, "<init>", "()V", false)
                visitInsn(Opcodes.ARETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(childAccess or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC,
                "createSpec", "()L$baseSpec;", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKEVIRTUAL, child, "createSpec", "()L$linearSpec;", false)
                visitInsn(Opcodes.ARETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        val expected = if (parentAccess == Opcodes.ACC_PRIVATE || !samePackage) 11 else 42
        val keptSets = when {
            !crossBoundary -> listOf(emptySet())
            !samePackage -> listOf(setOf(child))
            else -> listOf(setOf(child), setOf(parent))
        }
        for (kept in keptSets) {
            val widened = ApkAccessWidening.widen(classes.map { (owner, bytes) -> "$owner.class" to bytes }, kept)
            if (!crossBoundary) assertEquals(0, widened.widenedMembers)
            val artifact = testAttachedArtifact(classArtifacts = widened.classes.map { (entry, bytes) ->
                ClassArtifact(entry, analyzeClassBytes(bytes), bytes)
            })
            val rules = RuleSet(rules = kept.map { RuleSpec(target = it, action = "exclude") })
            val renamed = renameClasses(artifact, buildRuleMatches(rules, artifact.analysisSummary.classSummaries), emptyMap()).artifact
            val result = renamePackages(renamed, buildRuleMatches(rules, renamed.analysisSummary.classSummaries), emptyMap()).artifact
            val names = classes.keys.zip(result.classArtifacts.map { it.summary.internalName }).toMap()
            val output = result.classArtifacts.associate { it.summary.internalName to it.bytes }
            val loader = object : ClassLoader(null) {
                override fun findClass(name: String): Class<*> {
                    val bytes = output[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
                    return defineClass(name, bytes, 0, bytes.size)
                }
            }
            val type = loader.loadClass(names.getValue(child).replace('/', '.'))
            val spec = type.getField("spec").get(type.getConstructor().newInstance())
            assertEquals(expected, spec.javaClass.getField("value").getInt(spec))
            val node = ClassNode().also { ClassReader(output.getValue(names.getValue(parent))).accept(it, 0) }
            val declaration = node.methods.single { it.name == "createSpec" }
            val expectedAccess = if (crossBoundary && samePackage && parentAccess == 0) Opcodes.ACC_PUBLIC else parentAccess
            assertEquals(expectedAccess, declaration.access and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PROTECTED or Opcodes.ACC_PRIVATE))
            val childNode = ClassNode().also { ClassReader(output.getValue(names.getValue(child))).accept(it, 0) }
            val bridge = childNode.methods.single { it.access and Opcodes.ACC_BRIDGE != 0 }
            assertTrue(bridge.access and Opcodes.ACC_SYNTHETIC != 0)
            assertEquals("createSpec", bridge.name)
        }
    }

    @Test
    fun inheritedFieldReferencesOnKeptSubclassesRemainAccessible() = checkInheritedAccess(methodReference = false)

    @Test
    fun inheritedMethodReferencesOnKeptSubclassesRemainAccessible() = checkInheritedAccess(methodReference = true)

    private fun checkInheritedAccess(methodReference: Boolean) {
        val parent = "fixture/MovingParent"
        val child = "fixture/KeptChild"
        val base = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, parent, null, "java/lang/Object", null)
            visitField(0, "value", "I", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
                visitVarInsn(Opcodes.ALOAD, 0)
                visitIntInsn(Opcodes.BIPUSH, 42)
                visitFieldInsn(Opcodes.PUTFIELD, parent, "value", "I")
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(0, "calculate", "()I", null, null).apply {
                visitCode()
                visitIntInsn(Opcodes.BIPUSH, 42)
                visitInsn(Opcodes.IRETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitEnd()
        }.toByteArray()
        val subclass = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, child, null, parent, null)
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC, "probe", "()I", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                if (methodReference) visitMethodInsn(Opcodes.INVOKEVIRTUAL, child, "calculate", "()I", false)
                else visitFieldInsn(Opcodes.GETFIELD, child, "value", "I")
                visitInsn(Opcodes.IRETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitEnd()
        }.toByteArray()
        val mapping = mapOf(parent to "moved/Parent")
        val widened = ApkAccessWidening.widen(listOf("$parent.class" to base, "$child.class" to subclass), setOf(child))
        val output = widened.classes.associate { (entry, bytes) ->
            val owner = entry.removeSuffix(".class")
            (mapping[owner] ?: owner) to remapClasses(bytes, mapping)
        }
        val loader = object : ClassLoader(null) {
            override fun findClass(name: String): Class<*> {
                val bytes = output[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
                return defineClass(name, bytes, 0, bytes.size)
            }
        }
        val type = loader.loadClass(child.replace('/', '.'))
        assertEquals(42, type.getMethod("probe").invoke(type.getConstructor().newInstance()))
    }

    @Test
    fun samePackageProtectedConstructorRemainsCallableAfterTheOtherClassMoves() {
        val caller = "fixture/KeptCaller"
        val callee = "fixture/MovingTarget"
        val target = ClassWriter(ClassWriter.COMPUTE_MAXS)
        target.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, callee, null, "java/lang/Object", null)
        target.visitField(0, "packageValue", "I", null, null).visitEnd()
        target.visitField(Opcodes.ACC_PROTECTED, "protectedValue", "I", null, null).visitEnd()
        target.visitField(Opcodes.ACC_PROTECTED, "unreferenced", "I", null, null).visitEnd()
        target.visitMethod(Opcodes.ACC_PROTECTED, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitIntInsn(Opcodes.BIPUSH, 7)
            visitFieldInsn(Opcodes.PUTFIELD, callee, "packageValue", "I")
            visitVarInsn(Opcodes.ALOAD, 0)
            visitIntInsn(Opcodes.BIPUSH, 11)
            visitFieldInsn(Opcodes.PUTFIELD, callee, "protectedValue", "I")
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        target.visitMethod(Opcodes.ACC_PRIVATE, "privateHelper", "()V", null, null).apply {
            visitCode()
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        target.visitEnd()
        val entry = ClassWriter(ClassWriter.COMPUTE_MAXS)
        entry.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, caller, null, "java/lang/Object", null)
        entry.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "make", "()Ljava/lang/Object;", null, null).apply {
            visitCode()
            visitTypeInsn(Opcodes.NEW, callee)
            visitInsn(Opcodes.DUP)
            visitMethodInsn(Opcodes.INVOKESPECIAL, callee, "<init>", "()V", false)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        entry.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read", "()I", null, null).apply {
            visitCode()
            visitTypeInsn(Opcodes.NEW, callee)
            visitInsn(Opcodes.DUP)
            visitMethodInsn(Opcodes.INVOKESPECIAL, callee, "<init>", "()V", false)
            visitInsn(Opcodes.DUP)
            visitFieldInsn(Opcodes.GETFIELD, callee, "packageValue", "I")
            visitInsn(Opcodes.SWAP)
            visitFieldInsn(Opcodes.GETFIELD, callee, "protectedValue", "I")
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        entry.visitEnd()
        val input = listOf("$caller.class" to entry.toByteArray(), "$callee.class" to target.toByteArray())
        for (kept in listOf(setOf(caller), setOf(callee))) {
            val result = ApkAccessWidening.widen(input, kept)
            val mapping = (setOf(caller, callee) - kept).associateWith { "moved/${it.substringAfterLast('/')}" }
            val output = result.classes.associate { (name, bytes) ->
                val owner = name.removeSuffix(".class")
                (mapping[owner] ?: owner) to remapClasses(bytes, mapping)
            }
            val loader = object : ClassLoader(null) {
                override fun findClass(name: String): Class<*> {
                    val bytes = output[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
                    return defineClass(name, bytes, 0, bytes.size)
                }
            }
            val renamedCaller = (mapping[caller] ?: caller).replace('/', '.')
            val value = loader.loadClass(renamedCaller).getMethod("make").invoke(null)
            assertEquals((mapping[callee] ?: callee).replace('/', '.'), value.javaClass.name)
            assertEquals(18, loader.loadClass(renamedCaller).getMethod("read").invoke(null))
            val node = ClassNode()
            ClassReader(output.getValue(mapping[callee] ?: callee)).accept(node, 0)
            assertEquals(Opcodes.ACC_PRIVATE, node.methods.single { it.name == "privateHelper" }.access)
            assertEquals(Opcodes.ACC_PROTECTED, node.fields.single { it.name == "unreferenced" }.access)
        }
    }
}
