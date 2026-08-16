package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.loadBytecodeArtifact
import io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.applyClassEncryptionLoader
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
import java.nio.file.Files
import java.nio.file.Path
import java.util.Arrays
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TypeInsnNode

/**
 * Regression coverage for: class-encryption-loader 开启后混淆的 jar 无法正常运行.
 *
 * The injected ClassEncryptionLoaderHelper must not reference any protection
 * helper class that the pass does not also deploy. A dangling reference (e.g.
 * JniMicrokernelHelper) makes the first decrypt throw NoClassDefFoundError in
 * the obfuscated app's <clinit>, so the whole jar fails to start.
 */
class ClassEncryptionLoaderRuntimeRegressionTest {
    private val helperPkg = "io/github/hht0rro/javashroud/transforms/protection"

    @Test
    fun class_encryption_runtime_helpers_are_deployed_with_typed_descriptor_resources() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-cel-input", ".jar"))
        val outputJar = inputJar.resolveSibling("javashroud-cel-output.jar")
        val artifact = loadBytecodeArtifact(
            testConfig(
                inputJarPath = inputJar.toString(),
                outputJarPath = outputJar.toString(),
            ),
        )
        val context = defaultVbc4BuildContext()

        try {
            withVbc4BuildContext(context) {
                val transformed = applyClassEncryptionLoader(
                    artifact = artifact,
                    ruleMatches = emptyList(),
                    params = mapOf("encryptionStrategy" to "aes-256", "keyMode" to "per-class", "seed" to 31),
                )
                val withHelpers = EmbeddedHelperDeployment.injectRequiredHelpers(
                    artifact = transformed.artifact,
                    executedPassIds = listOf("class-encryption-loader"),
                )
                assertFalse(
                    withHelpers.jarEntries.any { entry -> entry.name.startsWith("__jse/") },
                    "Class-encryption output must not recreate the retired central manifest",
                )
                assertTrue(
                    RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(
                        artifact = withHelpers,
                        seed = context.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                    artifact = withHelpers,
                    seed = context.nativeSeed,
                )
                val sealed = RuntimeArtifactSealing.sealIfRequested(
                    artifact = materialized,
                    config = testConfig(
                        inputJarPath = inputJar.toString(),
                        outputJarPath = outputJar.toString(),
                        passes = listOf(testPassSpec("class-encryption-loader")),
                        allowOptInPasses = true,
                    ),
                )
                writeBytecodeArtifact(outputJar, sealed)

                val helperClasses = injectedHelperInternalNames(outputJar)
                assertTrue(
                    helperClasses.any { it.startsWith("r/") },
                    "Typed class-page helpers should be sealed into neutral entries. Found: $helperClasses",
                )

                val loaderBytes = readClassWithMethodDescriptor(outputJar, "(Ljava/lang/String;)Ljava/lang/Class;")
                assertTrue(
                    loaderBytes != null,
                    "Sealed ClassEncryptionLoaderHelper should expose the typed loadAkenClass(String) linkage",
                )
                val referencedHelpers = protectionHelperReferences(loaderBytes)
                val danglingHelpers = referencedHelpers.filterNot { helperClasses.contains(it) }.toSet()
                assertEquals(
                    emptySet(),
                    danglingHelpers,
                    "Injected ClassEncryptionLoaderHelper references undeployed helpers: $danglingHelpers",
                )

                val descriptorCandidates = listOf(
                    "e2e/Root",
                    "e2e/Root" + "$" + "Inner",
                    "e2e/Base",
                    "e2e/Impl",
                    "e2e/Shape",
                    "e2e/LambdaStyle",
                )
                val emittedDescriptorOwners = descriptorCandidates.filter { internalName ->
                    readJarEntry(
                        outputJar,
                        AkenClassPageDescriptor.resourcePathForInternalNameForBuild(internalName),
                    ) != null
                }
                assertTrue(
                    emittedDescriptorOwners.isNotEmpty(),
                    "At least one safe fixture class must retain its own class-local AKEN descriptor route",
                )
                assertFalse(
                    readJarEntry(outputJar, "__jse/index.tab") != null,
                    "Class-encryption output must not retain the retired central __jse manifest",
                )
            }
        } finally {
            context.wipe()
            Files.deleteIfExists(outputJar)
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun typed_class_page_runtime_helpers_are_deployed_and_sealed_with_class_encryption_loader() {
        val deploymentSource = Files.readString(
            sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/EmbeddedHelperDeployment.kt"),
        )
        val sealingSource = Files.readString(
            sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"),
        )

        assertTrue(
            deploymentSource.contains("AkenClassPageRuntimeDescriptor") &&
                deploymentSource.contains("JniMicrokernelHelper"),
            "Class-encryption must deploy the typed ClassPage descriptor reader and native page bridge together",
        )
        assertTrue(
            sealingSource.contains("AkenClassPageRuntimeDescriptor") &&
                sealingSource.contains("JniMicrokernelHelper"),
            "Runtime sealing must relocate typed ClassPage and native bridge helpers together",
        )
    }

    @Test
    fun runtime_sealing_materializes_and_validates_class_local_page_descriptors() {
        val sealingSource = Files.readString(
            sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/RuntimeArtifactSealing.kt"),
        )
        val materializerSource = Files.readString(
            sourcePath("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/AkenVbc4ProductionMaterializer.kt"),
        )

        assertTrue(
            sealingSource.contains("reserveAkenClassPageDescriptorRoutesIfNeeded"),
            "Sealing must reserve a collision-free descriptor route per protected class",
        )
        assertTrue(
            materializerSource.contains("materializeClassPageDescriptorsIfNeeded"),
            "Class-local descriptors must be emitted before the artifact is written",
        )
        assertTrue(
            materializerSource.contains("verifyClassPageDescriptorsForBuild"),
            "Final materialization must bind each descriptor back to its final ClassPage handle and proof",
        )
    }

    @Test
    fun class_encryption_loader_keeps_manifest_entrypoint_closure_out_of_class_pages() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-cel-boundary-input", ".jar"))
        val excludedClassNames = listOf("e2e/Root", "e2e/Root" + "$" + "Inner")
        val artifact = loadBytecodeArtifact(
            testConfig(
                inputJarPath = inputJar.toString(),
                outputJarPath = inputJar.resolveSibling("unused-output.jar").toString(),
            ),
        )
        val context = defaultVbc4BuildContext()

        try {
            withVbc4BuildContext(context) {
                val result = applyClassEncryptionLoader(
                    artifact = artifact,
                    ruleMatches = emptyList(),
                    params = mapOf("encryptionStrategy" to "aes-256", "keyMode" to "per-class", "seed" to 31),
                )

                assertFalse(
                    result.artifact.jarEntries.any { entry -> entry.name.startsWith("__jse/") },
                    "Class-encryption output must not recreate the retired central manifest",
                )
                for (internalName in excludedClassNames) {
                    assertContentEquals(
                        checkNotNull(artifact.classArtifactIndex[internalName]).bytes,
                        checkNotNull(result.artifact.classArtifactIndex[internalName]).bytes,
                        "Class-encryption-loader must preserve $internalName in the application loader namespace",
                    )
                }
                requireVbc4BuildContext().withAkenClassPageDescriptorSourcesForBuild { sources ->
                    val descriptorOwners = sources.mapTo(linkedSetOf()) { source -> source.internalName }
                    assertTrue(
                        descriptorOwners.intersect(excludedClassNames.toSet()).isEmpty(),
                        "Manifest Main-Class closure must not receive ClassPage descriptors",
                    )
                }
            }
        } finally {
            context.wipe()
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun class_encryption_loader_preserves_package_private_loader_namespace() {
        val entryName = "pkg/Entry"
        val packagePrivateName = "pkg/HiddenState"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = entryName,
                    bytes = buildPackagePrivateCaller(entryName, packagePrivateName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "value", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                    accessFlags = Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER,
                ),
                testClassArtifact(
                    internalName = packagePrivateName,
                    bytes = buildPackagePrivateState(packagePrivateName),
                    fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "result", "I", 0)),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "<init>", "(II)V", 0)),
                    accessFlags = Opcodes.ACC_SUPER,
                ),
            ),
        )
        val context = defaultVbc4BuildContext()

        try {
            withVbc4BuildContext(context) {
                val result = applyClassEncryptionLoader(
                    artifact = artifact,
                    ruleMatches = listOf(
                        ruleMatchForClassEncryption(entryName),
                        ruleMatchForClassEncryption(packagePrivateName),
                    ),
                    params = mapOf("encryptionStrategy" to "aes-128", "keyMode" to "per-class", "seed" to 7),
                )

                assertFalse(
                    result.artifact.jarEntries.any { entry -> entry.name.startsWith("__jse/") },
                    "AKEN ClassPage output must not create a central class manifest",
                )
                assertContentEquals(
                    checkNotNull(artifact.classArtifactIndex[entryName]).bytes,
                    checkNotNull(result.artifact.classArtifactIndex[entryName]).bytes,
                    "A class that accesses package-private app-loader state must remain unmodified",
                )
                assertContentEquals(
                    checkNotNull(artifact.classArtifactIndex[packagePrivateName]).bytes,
                    checkNotNull(result.artifact.classArtifactIndex[packagePrivateName]).bytes,
                    "Unsafe package-private state must remain in the application loader namespace",
                )
                assertFalse(
                    requireVbc4BuildContext().hasAkenClassPageDescriptorSources(),
                    "Unsafe package-private split must not register an AKEN class descriptor",
                )
            }
        } finally {
            context.wipe()
        }
    }

    @Test
    fun class_encryption_loader_emits_class_local_aken_descriptor_and_typed_loader_abi() {
        val internalName = "sample/EncryptedStaticHost"
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = internalName,
                    bytes = buildStaticOnlyTarget(internalName),
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "value", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
                    accessFlags = Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER,
                ),
            ),
        )
        val context = defaultVbc4BuildContext()

        try {
            withVbc4BuildContext(context) {
                val result = applyClassEncryptionLoader(
                    artifact = artifact,
                    ruleMatches = listOf(ruleMatchForClassEncryption(internalName)),
                    params = mapOf("encryptionStrategy" to "aes-256", "keyMode" to "per-class", "seed" to 31),
                )

                assertFalse(
                    result.artifact.jarEntries.any { entry -> entry.name.startsWith("__jse/") },
                    "Class encryption must not emit the retired __jse manifest or class payload namespace",
                )
                val transformed = checkNotNull(result.artifact.classArtifactIndex[internalName])
                val stub = ClassNode()
                ClassReader(transformed.bytes).accept(stub, 0)
                val hasTypedBootstrap = stub.methods
                    .single { method -> method.name == "<clinit>" }
                    .instructions
                    .asSequence()
                    .filterIsInstance<MethodInsnNode>()
                    .any { instruction ->
                        instruction.owner ==
                            "io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper" &&
                            instruction.name == "loadAkenClass" &&
                            instruction.desc == "(Ljava/lang/String;)Ljava/lang/Class;"
                    }
                assertTrue(
                    hasTypedBootstrap,
                    "Generated stubs must bootstrap only the typed loadAkenClass(String) ABI",
                )

                val scoped = requireVbc4BuildContext()
                assertTrue(scoped.hasAkenClassPageDescriptorSources())
                assertTrue(
                    RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(
                        artifact = result.artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                    artifact = result.artifact,
                    seed = scoped.nativeSeed,
                )
                val descriptorPath = AkenClassPageDescriptor.resourcePathForInternalNameForBuild(internalName)
                val descriptorBytes = checkNotNull(
                    materialized.jarEntries.singleOrNull { entry -> entry.name == descriptorPath },
                ).bytes.copyOf()
                var descriptor: AkenClassPageDescriptor? = null
                try {
                    descriptor = AkenClassPageDescriptor.decodeForBuild(descriptorBytes)
                    assertEquals(internalName, descriptor.internalName)
                    assertEquals(1, descriptor.pageCount)
                } finally {
                    descriptor?.wipe()
                    Arrays.fill(descriptorBytes, 0)
                }
            }
        } finally {
            context.wipe()
        }

        val helperSource = Files.readString(
            sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper.java"),
        )
        assertFalse("AES/CBC/PKCS5Padding" in helperSource, "Class encryption helper must not keep CBC decrypt fallback")
        assertFalse("Legacy direct-key" in helperSource, "Class encryption helper must not accept legacy direct-key metadata")
        assertFalse("javax.crypto.Cipher" in helperSource, "Class encryption helper must not expose a Java JCA decrypt hook")
        assertTrue(
            "loadAkenClass(String name)" in helperSource &&
                "AkenClassPageRuntimeDescriptor.openClassBytesIfPresent(name)" in helperSource,
            "Class encryption helper must resolve only its requested class-local typed descriptor",
        )
    }
    private fun injectedHelperInternalNames(jarPath: Path): Set<String> {
        val names = mutableSetOf<String>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                val name = entry.name
                if (!entry.isDirectory && name.endsWith(".class") && (name.startsWith("$helperPkg/") || name.startsWith("r/"))) {
                    names.add(name.removeSuffix(".class"))
                }
                jar.closeEntry()
            }
        }
        return names
    }

    private fun readJarEntry(jarPath: Path, entryName: String): ByteArray? {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == entryName) {
                    return jar.readBytes()
                }
                jar.closeEntry()
            }
        }
        return null
    }

    private fun readClassWithMethodDescriptor(jarPath: Path, methodDescriptor: String): ByteArray? {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".class")) {
                    val bytes = jar.readBytes()
                    val node = ClassNode()
                    ClassReader(bytes).accept(node, ClassReader.SKIP_CODE)
                    if (node.methods.any { it.desc == methodDescriptor }) return bytes
                }
                jar.closeEntry()
            }
        }
        return null
    }

    private fun protectionHelperReferences(classBytes: ByteArray): Set<String> {
        val node = ClassNode()
        ClassReader(classBytes).accept(node, 0)
        val self = node.name
        val innerPrefix = "$self$"
        val refs = mutableSetOf<String>()
        for (method in node.methods) {
            for (insn in method.instructions) {
                val owner = when (insn) {
                    is MethodInsnNode -> insn.owner
                    is FieldInsnNode -> insn.owner
                    is TypeInsnNode -> insn.desc
                    else -> null
                } ?: continue
                val normalized = owner.removePrefix("[").removeSuffix(";").removePrefix("L")
                if (
                    (normalized.startsWith("$helperPkg/") || normalized.startsWith("r/")) &&
                    normalized != self &&
                    !normalized.startsWith(innerPrefix)
                ) {
                    refs.add(normalized)
                }
            }
        }
        return refs
    }

    private fun ruleMatchForClassEncryption(internalName: String) = RuleMatch(
        rule = RuleSpec(target = internalName, action = "class-encryption-loader"),
        selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
        matchedClassNames = listOf(internalName),
        matchedMembers = emptyList(),
    )

    private fun buildPackagePrivateCaller(internalName: String, dependencyName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitTypeInsn(Opcodes.NEW, dependencyName)
        value.visitInsn(Opcodes.DUP)
        value.visitInsn(Opcodes.ICONST_1)
        value.visitInsn(Opcodes.ICONST_2)
        value.visitMethodInsn(Opcodes.INVOKESPECIAL, dependencyName, "<init>", "(II)V", false)
        value.visitFieldInsn(Opcodes.GETFIELD, dependencyName, "result", "I")
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(4, 0)
        value.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildPackagePrivateState(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        cw.visitField(0, "result", "I", null, null).visitEnd()
        val init = cw.visitMethod(0, "<init>", "(II)V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitVarInsn(Opcodes.ILOAD, 1)
        init.visitVarInsn(Opcodes.ILOAD, 2)
        init.visitInsn(Opcodes.IADD)
        init.visitFieldInsn(Opcodes.PUTFIELD, internalName, "result", "I")
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(3, 3)
        init.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildStaticOnlyTarget(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val value = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitIntInsn(Opcodes.BIPUSH, 9)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(1, 0)
        value.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun sourcePath(relative: String): Path {
        val direct = Path.of(relative)
        if (Files.exists(direct)) return direct
        val nested = Path.of("core-engine").resolve(relative)
        if (Files.exists(nested)) return nested
        return direct
    }
}
