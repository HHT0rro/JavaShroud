package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.rename.applyMethodDescriptorPadding
import io.github.hht0rro.javashroud.transforms.rename.renameMethods
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.TypeReference
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode

class MethodDescriptorPaddingTransformsTest {
    @Test
    fun private_static_direct_calls_are_rewritten_and_preserve_runtime_behavior() {
        val owner = "sample/PrivateParameterHost"
        val result = transform(
            artifactOf(owner to buildPrivateParameterHost(owner)),
            selected(owner, "increment", "(I)I"),
            params = mapOf("descriptorPadding" to "fixed"),
        )

        assertEquals("(IJ)I", result.descriptors.values.single())
        val type = load(result.artifact.classArtifactIndex.getValue(owner).bytes)
        assertEquals(8, type.getMethod("run").invoke(null))
    }

    @Test
    fun object_array_lowering_preserves_category_two_arguments() {
        val owner = "sample/CategoryTwoParameterHost"
        val result = transform(
            artifactOf(owner to buildCategoryTwoParameterHost(owner)),
            selected(owner, "combine", "(IJ)J"),
            params = mapOf("parameterPacking" to "object-array"),
        )

        assertEquals("([Ljava/lang/Object;)J", result.descriptors.values.single())
        val type = load(result.artifact.classArtifactIndex.getValue(owner).bytes)
        assertEquals(12L, type.getMethod("run").invoke(null))
    }

    @Test
    fun object_array_lowering_unpacks_synthesized_category_two_context_parameter() {
        val owner = "sample/CombinedParameterHost"
        val result = transform(
            artifactOf(owner to buildCategoryTwoParameterHost(owner)),
            selected(owner, "combine", "(IJ)J"),
            params = mapOf(
                "descriptorPadding" to "fixed",
                "parameterPacking" to "object-array",
                "seed" to 17L,
            ),
        )

        assertEquals("([Ljava/lang/Object;)J", result.descriptors.values.single())
        val node = readNode(result.artifact.classArtifactIndex.getValue(owner).bytes)
        val target = node.methods.single { it.name == "combine" }
        val caller = node.methods.single { it.name == "run" }

        assertEquals("([Ljava/lang/Object;)J", target.desc)
        assertEquals(3, target.instructions.count { it.opcode == Opcodes.AALOAD })
        assertTrue(target.instructions.any { instruction ->
            instruction is VarInsnNode && instruction.opcode == Opcodes.LSTORE && instruction.`var` == 4
        })
        assertTrue(target.maxLocals >= 6)
        assertTrue(caller.instructions.any { instruction ->
            instruction is TypeInsnNode && instruction.opcode == Opcodes.ANEWARRAY && instruction.desc == "java/lang/Object"
        })
        assertEquals(3, caller.instructions.count { it.opcode == Opcodes.AASTORE })
        assertTrue(caller.instructions.any { instruction ->
            instruction is MethodInsnNode &&
                instruction.opcode == Opcodes.INVOKESTATIC &&
                instruction.name == "combine" &&
                instruction.desc == "([Ljava/lang/Object;)J"
        })
        assertEquals(12L, load(result.artifact.classArtifactIndex.getValue(owner).bytes).getMethod("run").invoke(null))
    }

    @Test
    fun conflicting_public_dynamic_and_reflection_sensitive_targets_are_skipped() {
        val collisionOwner = "sample/ParameterCollisionHost"
        val collisionOriginal = buildOverloadedPrivateHost(collisionOwner)
        val collision = transform(
            artifactOf(collisionOwner to collisionOriginal),
            selected(collisionOwner, "same", "(I)I"),
            selected(collisionOwner, "same", "(Ljava/lang/String;)I"),
            params = mapOf("parameterPacking" to "object-array"),
        )
        assertEquals(0, collision.transformedMemberCount)
        assertContentEquals(collisionOriginal, collision.artifact.classArtifactIndex.getValue(collisionOwner).bytes)

        val publicOwner = "sample/PublicParameterHost"
        val publicOriginal = buildPublicStaticHost(publicOwner)
        val publicResult = transform(
            artifactOf(publicOwner to publicOriginal),
            selected(publicOwner, "api", "(I)I"),
            params = mapOf("descriptorPadding" to "fixed"),
        )
        assertEquals(0, publicResult.transformedMemberCount)
        assertContentEquals(publicOriginal, publicResult.artifact.classArtifactIndex.getValue(publicOwner).bytes)

        val condyOwner = "sample/CondyBootstrapHost"
        val condyOriginal = buildCondyBootstrapHost(condyOwner)
        val condyResult = transform(
            artifactOf(condyOwner to condyOriginal),
            selected(condyOwner, "bootstrap", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"),
            params = mapOf("descriptorPadding" to "fixed"),
        )
        assertEquals(0, condyResult.transformedMemberCount)
        assertContentEquals(condyOriginal, condyResult.artifact.classArtifactIndex.getValue(condyOwner).bytes)

        val reflectionOwner = "sample/ReflectionParameterHost"
        val reflectorOwner = "sample/ParameterReflector"
        val reflectionOriginal = buildPrivateStaticHost(reflectionOwner, "hidden")
        val reflectionResult = transform(
            artifactOf(
                reflectionOwner to reflectionOriginal,
                reflectorOwner to buildReflector(reflectorOwner, reflectionOwner),
            ),
            selected(reflectionOwner, "hidden", "(I)I"),
            params = mapOf("descriptorPadding" to "fixed"),
        )
        assertEquals(0, reflectionResult.transformedMemberCount)
        assertContentEquals(reflectionOriginal, reflectionResult.artifact.classArtifactIndex.getValue(reflectionOwner).bytes)
    }

    @Test
    fun descriptor_rewrite_clears_stale_parameter_and_type_metadata() {
        val owner = "sample/MetadataParameterHost"
        val result = transform(
            artifactOf(owner to buildAnnotatedPrivateHost(owner)),
            selected(owner, "identity", "(Ljava/lang/Object;)Ljava/lang/Object;"),
            params = mapOf("descriptorPadding" to "fixed"),
        )
        val method = readNode(result.artifact.classArtifactIndex.getValue(owner).bytes).methods.single { it.name == "identity" }

        assertEquals("(Ljava/lang/Object;J)Ljava/lang/Object;", method.desc)
        assertNull(method.signature)
        assertNull(method.parameters)
        assertNull(method.visibleParameterAnnotations)
        assertNull(method.invisibleParameterAnnotations)
        assertEquals(0, method.visibleAnnotableParameterCount)
        assertEquals(0, method.invisibleAnnotableParameterCount)
        assertNull(method.visibleTypeAnnotations)
        assertNull(method.invisibleTypeAnnotations)
        assertNull(method.visibleLocalVariableAnnotations)
        assertNull(method.invisibleLocalVariableAnnotations)
    }

    @Test
    fun aggressive_method_renaming_reuses_a_short_name_only_across_distinct_final_descriptors() {
        val owner = "sample/AggressiveRenameHost"
        val result = renameMethods(
            artifactOf(owner to buildAggressiveRenameHost(owner)),
            emptyList(),
            mapOf("returnSensitiveNaming" to true),
        )
        val methodsByName = readNode(result.artifact.classArtifactIndex.getValue(owner).bytes)
            .methods
            .filter { it.desc in setOf("()I", "()J") }
            .groupBy { it.name }

        assertEquals(3, result.transformedMemberCount)
        assertTrue(methodsByName.values.any { methods -> methods.map { it.desc }.toSet() == setOf("()I", "()J") })
        assertEquals(2, methodsByName.values.sumOf { methods -> methods.count { it.desc == "()I" } })
        assertTrue(methodsByName.values.all { methods -> methods.count { it.desc == "()I" } <= 1 })
    }

    @Test
    fun aggressive_method_renaming_skips_short_names_occupied_by_unselected_methods() {
        val owner = "sample/AggressiveRenameCollisionHost"
        val result = renameMethods(
            artifactOf(owner to buildAggressiveRenameCollisionHost(owner)),
            listOf(memberRuleMatch(owner, "target", "()I")),
            mapOf("returnSensitiveNaming" to true),
        )

        val methods = readNode(result.artifact.classArtifactIndex.getValue(owner).bytes).methods
        assertEquals(1, methods.count { it.name == "m0000" && it.desc == "()I" })
        assertTrue(methods.any { it.name == "m0001" && it.desc == "()I" })
        assertEquals(11, load(result.artifact.classArtifactIndex.getValue(owner).bytes).getMethod("run").invoke(null))
    }

    private fun transform(
        artifact: BytecodeArtifact,
        vararg selected: MatchedMember,
        params: Map<String, Any>,
    ) = applyMethodDescriptorPadding(artifact, selected.toList(), params)

    private fun selected(owner: String, name: String, descriptor: String): MatchedMember =
        MatchedMember(owner, MemberKind.METHOD, name, descriptor)

    private fun artifactOf(vararg classes: Pair<String, ByteArray>): BytecodeArtifact = testAttachedArtifact(
        classArtifacts = classes.map { (owner, bytes) -> testClassArtifact(internalName = owner, bytes = bytes) },
    )

    private fun buildPrivateParameterHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        val target = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "increment", "(I)I", null, null)
        target.visitCode()
        target.visitVarInsn(Opcodes.ILOAD, 0)
        target.visitInsn(Opcodes.ICONST_1)
        target.visitInsn(Opcodes.IADD)
        target.visitInsn(Opcodes.IRETURN)
        target.visitMaxs(0, 0)
        target.visitEnd()

        val run = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        run.visitCode()
        run.visitIntInsn(Opcodes.BIPUSH, 7)
        run.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "increment", "(I)I", false)
        run.visitInsn(Opcodes.IRETURN)
        run.visitMaxs(0, 0)
        run.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildCategoryTwoParameterHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        val target = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "combine", "(IJ)J", null, null)
        target.visitCode()
        target.visitVarInsn(Opcodes.ILOAD, 0)
        target.visitInsn(Opcodes.I2L)
        target.visitVarInsn(Opcodes.LLOAD, 1)
        target.visitInsn(Opcodes.LADD)
        target.visitInsn(Opcodes.LRETURN)
        target.visitMaxs(0, 0)
        target.visitEnd()

        val run = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()J", null, null)
        run.visitCode()
        run.visitInsn(Opcodes.ICONST_5)
        run.visitLdcInsn(7L)
        run.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "combine", "(IJ)J", false)
        run.visitInsn(Opcodes.LRETURN)
        run.visitMaxs(0, 0)
        run.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildOverloadedPrivateHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        simplePrivateIntMethod(writer, "same", "(I)I")
        simplePrivateIntMethod(writer, "same", "(Ljava/lang/String;)I")
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildPublicStaticHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "api", "(I)I", null, null)
        method.visitCode()
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildCondyBootstrapHost(owner: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null)
        val bootstrapDescriptor = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
        val bootstrap = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "bootstrap", bootstrapDescriptor, null, null)
        bootstrap.visitCode()
        bootstrap.visitLdcInsn("value")
        bootstrap.visitInsn(Opcodes.ARETURN)
        bootstrap.visitMaxs(0, 0)
        bootstrap.visitEnd()

        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()Ljava/lang/String;", null, null)
        value.visitCode()
        value.visitLdcInsn(
            ConstantDynamic(
                "value",
                "Ljava/lang/String;",
                Handle(Opcodes.H_INVOKESTATIC, owner, "bootstrap", bootstrapDescriptor, false),
            ),
        )
        value.visitInsn(Opcodes.ARETURN)
        value.visitMaxs(0, 0)
        value.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildPrivateStaticHost(owner: String, name: String): ByteArray {
        val writer = newWriter(owner)
        simplePrivateIntMethod(writer, name, "(I)I")
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildAggressiveRenameHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        simplePrivateIntMethod(writer, "intValue", "()I")
        val longMethod = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "longValue", "()J", null, null)
        longMethod.visitCode()
        longMethod.visitInsn(Opcodes.LCONST_1)
        longMethod.visitInsn(Opcodes.LRETURN)
        longMethod.visitMaxs(0, 0)
        longMethod.visitEnd()
        simplePrivateIntMethod(writer, "otherIntValue", "()I")
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildAggressiveRenameCollisionHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        simplePrivateIntMethod(writer, "target", "()I")
        val occupied = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "m0000", "()I", null, null)
        occupied.visitCode()
        occupied.visitIntInsn(Opcodes.BIPUSH, 7)
        occupied.visitInsn(Opcodes.IRETURN)
        occupied.visitMaxs(0, 0)
        occupied.visitEnd()
        val run = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        run.visitCode()
        run.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "target", "()I", false)
        run.visitIntInsn(Opcodes.BIPUSH, 10)
        run.visitInsn(Opcodes.IADD)
        run.visitInsn(Opcodes.IRETURN)
        run.visitMaxs(0, 0)
        run.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun memberRuleMatch(owner: String, name: String, descriptor: String): RuleMatch = RuleMatch(
        rule = RuleSpec(target = "$owner#$name", action = "rename-methods"),
        selector = TargetSelector(classPattern = owner, memberPattern = name, memberDescriptorPattern = descriptor),
        matchedClassNames = listOf(owner),
        matchedMembers = listOf(MatchedMember(owner, MemberKind.METHOD, name, descriptor)),
    )

    private fun buildReflector(owner: String, targetOwner: String): ByteArray {
        val writer = newWriter(owner)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "lookup", "()Ljava/lang/reflect/Method;", null, null)
        method.visitCode()
        method.visitLdcInsn(Type.getObjectType(targetOwner))
        method.visitLdcInsn("hidden")
        method.visitInsn(Opcodes.ACONST_NULL)
        method.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            false,
        )
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildAnnotatedPrivateHost(owner: String): ByteArray {
        val writer = newWriter(owner)
        val method = writer.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC,
            "identity",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            "<T:Ljava/lang/Object;>(TT;)TT;",
            null,
        )
        method.visitParameter("value", 0)
        method.visitParameterAnnotation(0, "Lsample/ParameterMarker;", true).visitEnd()
        method.visitTypeAnnotation(
            TypeReference.newFormalParameterReference(0).value,
            null,
            "Lsample/TypeMarker;",
            true,
        ).visitEnd()
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun simplePrivateIntMethod(writer: ClassWriter, name: String, descriptor: String) {
        val method = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, name, descriptor, null, null)
        method.visitCode()
        method.visitInsn(Opcodes.ICONST_1)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
    }

    private fun newWriter(owner: String): ClassWriter = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS).also { writer ->
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null)
    }

    private fun readNode(bytes: ByteArray): ClassNode = ClassNode().also { node -> ClassReader(bytes).accept(node, 0) }

    private fun load(bytes: ByteArray): Class<*> = object : ClassLoader(javaClass.classLoader) {
        fun define(): Class<*> = defineClass(null, bytes, 0, bytes.size)
    }.define()
}
