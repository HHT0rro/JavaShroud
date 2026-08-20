package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.PassSelectionSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.passes.applyRegisteredPassWithMetrics
import io.github.hht0rro.javashroud.passes.requireExecutablePass
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PassExecutionRuleRemapTest {
    private val mapper = ObjectMapper()

    @Test
    fun class_rename_remaps_selectedOnly_method_virtualization_selector() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val config = testConfig(
            allowOptInPasses = true,
            ruleSet = RuleSet(listOf(RuleSpec("example/Target", "rename-classes"))),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(RuleSpec("example/Target#value:()I", "obfuscate")),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = "example/Target",
                    bytes = targetClassBytes(),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "value", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                ),
            ),
            config = config,
        )
        val initialContext = PassContext(config = config, artifact = artifact, events = emptyList())

        val renamed = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "rename-classes",
                params = mapOf(
                    "dictionaryStyle" to mapper.valueToTree("sequential"),
                    "preservePackageDepth" to mapper.valueToTree(0),
                    "collisionPolicy" to mapper.valueToTree("append-index"),
                ),
            ),
            executable = requireExecutablePass("rename-classes"),
            context = initialContext,
        ).context
        val renamedClassName = renamed.artifact.classArtifacts.single().summary.internalName

        val virtualized = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(0),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(0),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = renamed,
        )
        val classBytes = virtualized.context.artifact.classArtifactIndex.getValue(renamedClassName).bytes

        assertEquals(1, virtualized.transformedMemberCount, "Selected-only method selector must survive class renaming")
        assertTrue(methodCallsVmDispatcher(classBytes, "value", "()I"), "Renamed class should still have its selected method lowered to VBC4")
        assertEquals(
            "$renamedClassName#value:()I",
            virtualized.context.config.passSelections.single().rules.single().target,
            "The persisted selected-only selector must be remapped to the renamed class owner",
        )
    }

    @Test
    fun selectedOnly_independent_scope_excludes_only_explicit_method() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val classScope = "example/ClassScope"
        val methodScope = "example/MethodScope"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(
                        RuleSpec("$classScope#skipped:()I", "exclude"),
                    ),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = classScope,
                    bytes = twoPublicStaticIntMethodsClassBytes(classScope, "broadAllowed", "skipped"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "broadAllowed", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "skipped", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
                testClassArtifact(
                    internalName = methodScope,
                    bytes = twoPublicStaticIntMethodsClassBytes(methodScope, "explicitlyAllowed", "untouched"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "explicitlyAllowed", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "untouched", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(0),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classScopeBytes = result.context.artifact.classArtifactIndex.getValue(classScope).bytes
        val methodScopeBytes = result.context.artifact.classArtifactIndex.getValue(methodScope).bytes
        assertEquals(3, result.transformedMemberCount)
        assertTrue(methodCallsVmDispatcher(classScopeBytes, "broadAllowed", "()I"))
        assertTrue(!methodCallsVmDispatcher(classScopeBytes, "skipped", "()I"))
        assertTrue(methodCallsVmDispatcher(methodScopeBytes, "explicitlyAllowed", "()I"))
        assertTrue(methodCallsVmDispatcher(methodScopeBytes, "untouched", "()I"))
    }

    @Test
    fun selectedOnly_empty_independent_scope_virtualizes_every_owner_scope() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val classA = "example/ClassA"
        val classB = "example/ClassB"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = emptyList(),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = classA,
                    bytes = twoPublicStaticIntMethodsClassBytes(classA, "first", "second"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "first", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "second", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
                testClassArtifact(
                    internalName = classB,
                    bytes = twoPublicStaticIntMethodsClassBytes(classB, "foo", "bar"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "foo", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "bar", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(0),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classABytes = result.context.artifact.classArtifactIndex.getValue(classA).bytes
        val classBBytes = result.context.artifact.classArtifactIndex.getValue(classB).bytes
        assertEquals(4, result.transformedMemberCount)
        assertTrue(methodCallsVmDispatcher(classABytes, "first", "()I"))
        assertTrue(methodCallsVmDispatcher(classABytes, "second", "()I"))
        assertTrue(methodCallsVmDispatcher(classBBytes, "foo", "()I"))
        assertTrue(methodCallsVmDispatcher(classBBytes, "bar", "()I"))
    }

    @Test
    fun selectedOnly_independent_scope_method_exclude_skips_only_that_member_in_virtualization() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val owner = "example/ExcludedMember"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(
                        RuleSpec("$owner#bar:()I", "exclude"),
                    ),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = owner,
                    bytes = twoPublicStaticIntMethodsClassBytes(owner, "foo", "bar"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "foo", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "bar", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(0),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classBytes = result.context.artifact.classArtifactIndex.getValue(owner).bytes
        assertEquals(1, result.transformedMemberCount)
        assertTrue(methodCallsVmDispatcher(classBytes, "foo", "()I"))
        assertTrue(!methodCallsVmDispatcher(classBytes, "bar", "()I"))
    }

    @Test
    fun selectedOnly_empty_independent_scope_keeps_broad_virtualization_budget() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val owner = "example/SelectedOnlyBudget"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = emptyList(),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = owner,
                    bytes = twoPublicStaticIntMethodsClassBytes(owner, "first", "second"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "first", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "second", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(1),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classBytes = result.context.artifact.classArtifactIndex.getValue(owner).bytes
        assertEquals(1, result.transformedMemberCount)
        assertTrue(methodCallsVmDispatcher(classBytes, "first", "()I"))
        assertTrue(!methodCallsVmDispatcher(classBytes, "second", "()I"))
    }

    @Test
    fun selectedOnly_class_exclude_with_method_obfuscate_virtualizes_only_that_member() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val owner = "example/MethodOverride"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(
                        RuleSpec(owner, "exclude"),
                        RuleSpec("$owner#foo:()I", "obfuscate"),
                    ),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = owner,
                    bytes = twoPublicStaticIntMethodsClassBytes(owner, "foo", "bar"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "foo", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "bar", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(0),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classBytes = result.context.artifact.classArtifactIndex.getValue(owner).bytes
        assertEquals(1, result.transformedMemberCount)
        assertTrue(methodCallsVmDispatcher(classBytes, "foo", "()I"))
        assertTrue(!methodCallsVmDispatcher(classBytes, "bar", "()I"))
    }

    @Test
    fun inheritGlobal_class_action_keeps_broad_budget_and_high_value_deny_behavior() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val owner = "example/LegacyBroad"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            ruleSet = RuleSet(listOf(RuleSpec(owner, "method-virtualization"))),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = owner,
                    bytes = publicStaticIntMethodsClassBytes(owner, "denied", "firstAllowed", "secondAllowed"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "denied", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "firstAllowed", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "secondAllowed", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("all-compatible"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(1),
                    "highValueMethodDeny" to mapper.valueToTree("$owner#denied:()I"),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classBytes = result.context.artifact.classArtifactIndex.getValue(owner).bytes
        assertEquals(1, result.transformedMemberCount, "Global class action must retain the pre-existing broad coverage cap")
        assertTrue(!methodCallsVmDispatcher(classBytes, "denied", "()I"), "Global class action must retain highValueMethodDeny filtering")
        assertTrue(methodCallsVmDispatcher(classBytes, "firstAllowed", "()I"))
        assertTrue(!methodCallsVmDispatcher(classBytes, "secondAllowed", "()I"), "The broad cap must stop subsequent otherwise eligible methods")
    }

    @Test
    fun inheritGlobal_method_action_remains_a_direct_member_scope() = withVbc4BuildContext(defaultVbc4BuildContext()) {
        val owner = "example/LegacyDirect"
        val config = testConfig(
            allowOptInPasses = true,
            passes = listOf(testPassSpec(id = "method-virtualization")),
            ruleSet = RuleSet(listOf(RuleSpec("$owner#foo:()I", "method-virtualization"))),
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = owner,
                    bytes = twoPublicStaticIntMethodsClassBytes(owner, "foo", "bar"),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "foo", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "bar", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
            config = config,
        )

        val result = applyRegisteredPassWithMetrics(
            spec = testPassSpec(
                id = "method-virtualization",
                params = mapOf(
                    "methodSelection" to mapper.valueToTree("safe"),
                    "strictVirtualization" to mapper.valueToTree(true),
                    "maxInstructions" to mapper.valueToTree(128),
                    "maxBroadVirtualizedMethods" to mapper.valueToTree(1),
                    "highValueMethodDeny" to mapper.valueToTree("$owner#foo:()I"),
                ),
            ),
            executable = requireExecutablePass("method-virtualization"),
            context = PassContext(config = config, artifact = artifact, events = emptyList()),
        )

        val classBytes = result.context.artifact.classArtifactIndex.getValue(owner).bytes
        assertEquals(1, result.transformedMemberCount)
        assertTrue(methodCallsVmDispatcher(classBytes, "foo", "()I"), "The direct global action must remain an explicit override")
        assertTrue(!methodCallsVmDispatcher(classBytes, "bar", "()I"), "A direct global action must not expand to sibling methods")
    }

    private fun targetClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/Target", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitIntInsn(Opcodes.BIPUSH, 7)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(1, 0)
        value.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun twoPublicStaticIntMethodsClassBytes(owner: String, firstName: String, secondName: String): ByteArray =
        publicStaticIntMethodsClassBytes(owner, firstName, secondName)

    private fun publicStaticIntMethodsClassBytes(owner: String, vararg names: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null)
        names.forEachIndexed { index, name -> publicStaticIntMethod(writer, name, 7 + index * 4) }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun publicStaticIntMethod(writer: ClassWriter, name: String, value: Int) {
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, name, "()I", null, null)
        method.visitCode()
        method.visitIntInsn(Opcodes.BIPUSH, value)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(1, 0)
        method.visitEnd()
    }

    private fun methodCallsVmDispatcher(classBytes: ByteArray, methodName: String, descriptor: String): Boolean {
        var callsDispatcher = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String, desc: String, signature: String?, exceptions: Array<String>?): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, methodDescriptor: String, isInterface: Boolean) {
                        if (owner.endsWith("JniMicrokernelHelper") && name.startsWith("executeVmResource")) callsDispatcher = true
                    }
                }
            }
        }, 0)
        return callsDispatcher
    }
}
