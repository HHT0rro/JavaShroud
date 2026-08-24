package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.NumericResolverConfig
import io.github.hht0rro.javashroud.bytecode.EmbeddedStringResolverConfig
import io.github.hht0rro.javashroud.bytecode.encryptClassStringsEmbeddedResolver
import io.github.hht0rro.javashroud.bytecode.indirectConstantResolverCalls
import io.github.hht0rro.javashroud.bytecode.obfuscateNumericConstantsResolver
import io.github.hht0rro.javashroud.transforms.rename.METHOD_RENAME_BINDINGS_RESOURCE
import io.github.hht0rro.javashroud.transforms.rename.renameMethods
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TypeInsnNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EmbeddedResolverTransformsTest {

    @Test
    fun embedded_string_resolvers_decode_xor_and_des_without_native_helper() {
        listOf("standard", "strong", "flow-guarded", "max").forEachIndexed { index, strength ->
            val value = "$strength-secret"
            val bytes = encryptClassStringsEmbeddedResolver(
                buildFixture("resolver/StringMode$index", value),
                EmbeddedStringResolverConfig(seed = 41L + index, strength = strength),
            )
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains(value))
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("StringEncryptionHelper"))
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("DES/CBC/PKCS5Padding"))
            val decoded = load(bytes).getMethod("stringValue").invoke(null) as String
            assertEquals(value, decoded)
        }

        val desOriginal = buildFixture("resolver/StringDes", "DES content: \u4f60\u597d")
        val desBytes = encryptClassStringsEmbeddedResolver(
            desOriginal,
            EmbeddedStringResolverConfig(seed = 42L, strength = "max", payloadCodec = "aes-gcm"),
        )
        assertFalse(String(desBytes, Charsets.ISO_8859_1).contains("DES content: \u4f60\u597d"))
        assertTrue(String(desBytes, Charsets.ISO_8859_1).contains("AES/GCM/NoPadding"))
        val desDecoded = load(desBytes).getMethod("stringValue").invoke(null) as String
        assertEquals("DES content: \u4f60\u597d", desDecoded)
    }

    @Test
    fun embedded_indexed_codec_emits_local_permutation_metadata_and_decodes_empty_values() {
        val value = "indexed-secret-\u4f60\u597d"
        val bytes = encryptClassStringsEmbeddedResolver(
            buildFixture("resolver/IndexedCodec", value),
            EmbeddedStringResolverConfig(seed = 4242L, strength = "max", payloadCodec = "indexed"),
        )
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains("indexed-secret"))

        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        val generatedFields = node.fields.filter { it.name.startsWith("\$_jsr_") }
        val intArrays = generatedFields.filter { it.desc == "[I" }
        val byteArrays = generatedFields.filter { it.desc == "[B" }
        assertTrue(intArrays.size >= 2)
        assertEquals(1, byteArrays.size)
        assertTrue(generatedFields.all { it.value == null })

        val resolver = node.methods.single {
            it.name.startsWith("\$_jsr_") && it.desc == "(I)Ljava/lang/String;"
        }
        val resolverInstructions = resolver.instructions.toArray().toList()
        assertTrue(resolverInstructions.any { it.opcode == Opcodes.BALOAD })
        assertTrue(resolverInstructions.any { it.opcode == Opcodes.BASTORE })
        assertTrue(resolverInstructions.any { it.opcode == Opcodes.IUSHR })
        assertFalse(
            resolverInstructions.filterIsInstance<MethodInsnNode>().any {
                it.owner == "java/lang/String" && it.name == "intern" && it.desc == "()Ljava/lang/String;"
            },
        )

        val type = load(bytes)
        val permutationField = type.declaredFields.single { it.name.startsWith("\$_jsr_") && it.type == ByteArray::class.java }
        permutationField.isAccessible = true
        val permutation = permutationField.get(null) as ByteArray
        assertEquals(256, permutation.size)
        assertEquals(256, permutation.toSet().size)

        val metadata = type.declaredFields
            .filter { it.name.startsWith("\$_jsr_") && it.type == IntArray::class.java }
            .map { field ->
                field.isAccessible = true
                field.get(null) as IntArray
            }
        assertEquals(2, metadata.size)
        assertEquals(metadata[0].size, metadata[1].size)
        assertEquals((0 until metadata[0].size).toSet(), metadata[1].toSet())

        val first = type.getMethod("stringValue").invoke(null) as String
        val second = type.getMethod("stringValue").invoke(null) as String
        assertEquals(value, first)
        assertTrue(first === second)

        val emptyBytes = encryptClassStringsEmbeddedResolver(
            buildFixture("resolver/IndexedEmpty", ""),
            EmbeddedStringResolverConfig(seed = 4243L, strength = "max", payloadCodec = "indexed"),
        )
        assertEquals("", load(emptyBytes).getMethod("stringValue").invoke(null))
    }

    @Test
    fun embedded_string_constant_values_follow_strength_coverage() {
        val classValue = "class-field-secret"
        val normalClass = encryptClassStringsEmbeddedResolver(
            buildFixture("resolver/StringFieldNormal", "method-secret", classValue),
            EmbeddedStringResolverConfig(seed = 51L, strength = "standard"),
        )
        assertEquals(null, stringConstantValue(normalClass, "CLASS_TEXT_FIELD"))
        assertEquals(classValue, load(normalClass).getField("CLASS_TEXT_FIELD").get(null))

        val interfaceValue = "interface-field-secret"
        val normalInterface = encryptClassStringsEmbeddedResolver(
            buildInterfaceStringFixture("resolver/StringInterfaceNormal", interfaceValue),
            EmbeddedStringResolverConfig(seed = 52L, strength = "standard"),
        )
        assertEquals(interfaceValue, stringConstantValue(normalInterface, "TEXT"))
        assertEquals(interfaceValue, load(normalInterface).getField("TEXT").get(null))

        listOf("strong", "flow-guarded", "max").forEachIndexed { index, strength ->
            val protected = encryptClassStringsEmbeddedResolver(
                buildInterfaceStringFixture("resolver/StringInterface${index}", interfaceValue),
                EmbeddedStringResolverConfig(seed = 53L + index, strength = strength),
            )
            assertEquals(null, stringConstantValue(protected, "TEXT"))
            assertFalse(String(protected, Charsets.ISO_8859_1).contains(interfaceValue))
            assertEquals(interfaceValue, load(protected).getField("TEXT").get(null))
        }
    }

    @Test
    fun embedded_resolvers_preserve_java8_and_java21_classfile_versions() {
        for (classVersion in listOf(Opcodes.V1_8, Opcodes.V21)) {
            val value = "version-$classVersion"
            val transformed = encryptClassStringsEmbeddedResolver(
                buildFixture("resolver/Version$classVersion", value, classVersion = classVersion),
                EmbeddedStringResolverConfig(seed = classVersion.toLong(), strength = "max"),
            )
            val node = ClassNode()
            ClassReader(transformed).accept(node, ClassReader.SKIP_CODE)
            assertEquals(classVersion, node.version)
            assertEquals(value, load(transformed).getMethod("stringValue").invoke(null))
        }
    }

    @Test
    fun numeric_resolvers_preserve_int_and_long_for_xor_and_des() {
        val xorBytes = obfuscateNumericConstantsResolver(
            buildFixture("resolver/NumericXor", "numeric"),
            NumericResolverConfig(seed = 101L, intCoverage = "normal", longCoverage = "normal", resolverCodec = "xor"),
        )
        assertNumericConstantValuesMoved(xorBytes)
        val xorClass = load(xorBytes)
        assertEquals(0x12345678, xorClass.getMethod("intValue").invoke(null))
        assertEquals(0x123456789ABCDEFL, xorClass.getMethod("longValue").invoke(null))
        assertEquals(0x12345678, xorClass.getField("INT_FIELD").getInt(null))
        assertEquals(7, xorClass.getField("SMALL_INT_FIELD").getInt(null))
        assertEquals(0x123456789ABCDEFL, xorClass.getField("LONG_FIELD").getLong(null))

        assertFailsWith<IllegalArgumentException> {
            obfuscateNumericConstantsResolver(
                buildFixture("resolver/NumericDes", "numeric"),
                NumericResolverConfig(seed = 102L, intCoverage = "aggressive", longCoverage = "normal", resolverCodec = "des"),
            )
        }

        assertFailsWith<IllegalArgumentException> {
            obfuscateNumericConstantsResolver(
                buildFixture("resolver/InvalidLongLevel", "numeric"),
                NumericResolverConfig(intCoverage = "none", longCoverage = "aggressive"),
            )
        }
    }

    @Test
    fun indy_wraps_string_int_and_long_resolvers_with_mutable_call_sites() {
        val stringProtected = encryptClassStringsEmbeddedResolver(
            buildFixture("resolver/Indy", "indy-secret"),
            EmbeddedStringResolverConfig(seed = 303L, strength = "max", payloadCodec = "indexed"),
        )
        val numericProtected = obfuscateNumericConstantsResolver(
            stringProtected,
            NumericResolverConfig(seed = 304L, intCoverage = "aggressive", longCoverage = "normal"),
        )
        val transformed = indirectConstantResolverCalls(numericProtected, seed = 305L)

        val descriptors = mutableSetOf<String>()
        var mutableCallSiteBootstrap = false
        var installsConstantTarget = false
        var dropsConstantArguments = false
        var updatesCallSite = false
        val node = ClassNode()
        ClassReader(transformed).accept(node, 0)
        for (method in node.methods) {
            for (instruction in method.instructions.toArray()) {
                if (instruction is InvokeDynamicInsnNode) descriptors += instruction.desc
                if (instruction is TypeInsnNode && instruction.opcode == Opcodes.NEW && instruction.desc == "java/lang/invoke/MutableCallSite") {
                    mutableCallSiteBootstrap = true
                }
                if (instruction is MethodInsnNode && instruction.owner == "java/lang/invoke/MethodHandles" && instruction.name == "constant") {
                    installsConstantTarget = true
                }
                if (instruction is MethodInsnNode && instruction.owner == "java/lang/invoke/MethodHandles" && instruction.name == "dropArguments") {
                    dropsConstantArguments = true
                }
                if (instruction is MethodInsnNode && instruction.owner == "java/lang/invoke/MutableCallSite" && instruction.name == "setTarget") {
                    updatesCallSite = true
                }
            }
        }
        assertTrue("(IJ)Ljava/lang/String;" in descriptors)
        assertTrue("(IJ)I" in descriptors)
        assertTrue("(IJ)J" in descriptors)
        assertTrue(mutableCallSiteBootstrap)
        assertTrue(installsConstantTarget)
        assertTrue(dropsConstantArguments)
        assertTrue(updatesCallSite)

        val type = load(transformed)
        assertEquals("indy-secret", type.getMethod("stringValue").invoke(null))
        assertEquals(0x12345678, type.getMethod("intValue").invoke(null))
        assertEquals(0x123456789ABCDEFL, type.getMethod("longValue").invoke(null))
    }

    @Test
    fun resolver_abis_survive_empty_rule_rename_parameter_and_indy_chain() {
        val owner = "resolver/RenameIndyChain"
        val value = "rename-indy-secret"
        val stringProtected = encryptClassStringsEmbeddedResolver(
            buildRenameChainFixture(owner, value),
            EmbeddedStringResolverConfig(seed = 401L, strength = "max", payloadCodec = "indexed"),
        )
        val numericProtected = obfuscateNumericConstantsResolver(
            stringProtected,
            NumericResolverConfig(seed = 402L, intCoverage = "aggressive", longCoverage = "normal"),
        )
        val resolverAbis = resolverMethodAbis(numericProtected)
        assertTrue(resolverAbis.any { it.second == "(I)Ljava/lang/String;" })
        assertTrue(resolverAbis.any { it.second == "(I)I" })
        assertTrue(resolverAbis.any { it.second == "(I)J" })

        val renamedArtifact = renameMethods(
            testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = owner, bytes = numericProtected)),
            ),
            emptyList(),
            mapOf(
                "descriptorPadding" to "random",
                "parameterPacking" to "object-array",
                "returnSensitiveNaming" to true,
                "seed" to 403L,
            ),
        ).artifact
        val renamedBytes = renamedArtifact.classArtifactIndex.getValue(owner).bytes
        assertEquals(resolverAbis, resolverMethodAbis(renamedBytes))
        assertTrue(
            ClassNode().also { ClassReader(renamedBytes).accept(it, 0) }.methods.any {
                it.desc == "([Ljava/lang/Object;)J" && !it.name.startsWith("\$_jsr_")
            },
        )

        val transformed = indirectConstantResolverCalls(renamedBytes, seed = 404L)
        val descriptors = ClassNode().also { ClassReader(transformed).accept(it, 0) }
            .methods
            .flatMap { method -> method.instructions.toArray().filterIsInstance<InvokeDynamicInsnNode>() }
            .mapTo(linkedSetOf()) { it.desc }
        assertTrue("(IJ)Ljava/lang/String;" in descriptors)
        assertTrue("(IJ)I" in descriptors)
        assertTrue("(IJ)J" in descriptors)

        val type = load(transformed)
        assertEquals(value, invokeRenamedStatic(type, renamedArtifact, owner, "stringValue", "()Ljava/lang/String;"))
        assertEquals(0x12345678, invokeRenamedStatic(type, renamedArtifact, owner, "intValue", "()I"))
        assertEquals(0x123456789ABCDEFL, invokeRenamedStatic(type, renamedArtifact, owner, "longValue", "()J"))
        assertEquals(12L, invokeRenamedStatic(type, renamedArtifact, owner, "run", "()J"))
    }

    private fun load(bytes: ByteArray): Class<*> {
        val name = ClassReader(bytes).className
        return object : ClassLoader(javaClass.classLoader) {
            fun define(name: String, value: ByteArray): Class<*> = defineClass(name, value, 0, value.size)
        }.define(name.replace('/', '.'), bytes)
    }

    private fun resolverMethodAbis(bytes: ByteArray): Set<Pair<String, String>> = ClassNode().also {
        ClassReader(bytes).accept(it, ClassReader.SKIP_DEBUG)
    }.methods
        .filter { method -> method.name.startsWith("\$_jsr_") }
        .mapTo(linkedSetOf()) { method -> method.name to method.desc }

    private fun renamedMethodName(
        artifact: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact,
        owner: String,
        originalName: String,
        descriptor: String,
    ): String {
        val binding = artifact.jarEntries.single { it.name == METHOD_RENAME_BINDINGS_RESOURCE }
            .bytes
            .toString(Charsets.UTF_8)
            .lineSequence()
            .map { it.split('|') }
            .firstOrNull { fields ->
                fields.size == 4 && fields[0] == owner && fields[1] == originalName && fields[2] == descriptor
        }
        return binding?.get(3) ?: originalName
    }

    private fun invokeRenamedStatic(
        type: Class<*>,
        artifact: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact,
        owner: String,
        originalName: String,
        descriptor: String,
    ): Any? {
        val name = renamedMethodName(artifact, owner, originalName, descriptor)
        val method = type.declaredMethods.single { candidate ->
            candidate.name == name && Type.getMethodDescriptor(candidate) == descriptor
        }
        return method.invoke(null)
    }

    private fun assertNumericConstantValuesMoved(bytes: ByteArray) {
        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        assertEquals(null, node.fields.single { it.name == "INT_FIELD" }.value)
        assertEquals(null, node.fields.single { it.name == "SMALL_INT_FIELD" }.value)
        assertEquals(-1, node.fields.single { it.name == "NEGATIVE_ONE_INT_FIELD" }.value)
        assertEquals(0, node.fields.single { it.name == "ZERO_INT_FIELD" }.value)
        assertEquals(1, node.fields.single { it.name == "ONE_INT_FIELD" }.value)
        assertEquals(null, node.fields.single { it.name == "LONG_FIELD" }.value)
    }

    private fun stringConstantValue(bytes: ByteArray, name: String): String? {
        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        return node.fields.single { it.name == name }.value as? String
    }

    private fun buildFixture(
        name: String,
        value: String,
        fieldValue: String = "field-$value",
        classVersion: Int = Opcodes.V1_8,
    ): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(classVersion, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, name, null, "java/lang/Object", null)
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "INT_FIELD",
            "I",
            null,
            0x12345678,
        ).visitEnd()
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "SMALL_INT_FIELD",
            "I",
            null,
            7,
        ).visitEnd()
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "NEGATIVE_ONE_INT_FIELD",
            "I",
            null,
            -1,
        ).visitEnd()
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "ZERO_INT_FIELD",
            "I",
            null,
            0,
        ).visitEnd()
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "ONE_INT_FIELD",
            "I",
            null,
            1,
        ).visitEnd()
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "LONG_FIELD",
            "J",
            null,
            0x123456789ABCDEFL,
        ).visitEnd()
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "CLASS_TEXT_FIELD",
            "Ljava/lang/String;",
            null,
            fieldValue,
        ).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "stringValue", "()Ljava/lang/String;", null, null).apply {
            visitCode()
            visitLdcInsn(value)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "intValue", "()I", null, null).apply {
            visitCode()
            visitLdcInsn(0x12345678)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "longValue", "()J", null, null).apply {
            visitCode()
            visitLdcInsn(0x123456789ABCDEFL)
            visitInsn(Opcodes.LRETURN)
            visitMaxs(2, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildRenameChainFixture(name: String, value: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, name, null, "java/lang/Object", null)
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "stringValue", "()Ljava/lang/String;", null, null).apply {
            visitCode()
            visitLdcInsn(value)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "intValue", "()I", null, null).apply {
            visitCode()
            visitLdcInsn(0x12345678)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "longValue", "()J", null, null).apply {
            visitCode()
            visitLdcInsn(0x123456789ABCDEFL)
            visitInsn(Opcodes.LRETURN)
            visitMaxs(2, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "combine", "(IJ)J", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ILOAD, 0)
            visitInsn(Opcodes.I2L)
            visitVarInsn(Opcodes.LLOAD, 1)
            visitInsn(Opcodes.LADD)
            visitInsn(Opcodes.LRETURN)
            visitMaxs(3, 3)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()J", null, null).apply {
            visitCode()
            visitInsn(Opcodes.ICONST_5)
            visitLdcInsn(7L)
            visitMethodInsn(Opcodes.INVOKESTATIC, name, "combine", "(IJ)J", false)
            visitInsn(Opcodes.LRETURN)
            visitMaxs(3, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildInterfaceStringFixture(name: String, value: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            name,
            null,
            "java/lang/Object",
            null,
        )
        writer.visitField(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL,
            "TEXT",
            "Ljava/lang/String;",
            null,
            value,
        ).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()Ljava/lang/String;", null, null).apply {
            visitCode()
            visitLdcInsn(value)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }
}
