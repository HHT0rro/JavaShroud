package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyClassEncryptionLoader
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
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
    private val objectMapper = ObjectMapper()
    private val helperPkg = "io/github/hht0rro/javashroud/transforms/protection"

    @Test
    fun injected_loader_helper_only_references_deployed_helpers() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-cel-input", ".jar"))
        val outputJar = inputJar.resolveSibling("javashroud-cel-output.jar")
        val configPath = inputJar.resolveSibling("javashroud-cel-config.toml")
        try {
            writeRunConfig(configPath, inputJar, outputJar, listOf("class-encryption-loader"))
            captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }
            assertTrue(Files.exists(outputJar), "Engine should write an output jar")

            val helperClasses = injectedHelperInternalNames(outputJar)
            assertTrue(helperClasses.any { it.startsWith("r/") }, "Loader helper should be sealed into neutral entries. Found: $helperClasses")

            val loaderBytes = readClassWithMethodDescriptor(outputJar, "(Ljava/lang/String;Ljava/lang/String;)V")
            assertTrue(loaderBytes != null, "Sealed ClassEncryptionLoaderHelper should keep its two-string loader entry linkage")

            val referencedHelpers = protectionHelperReferences(loaderBytes!!)
            val danglingHelpers = referencedHelpers.filterNot { helperClasses.contains(it) }.toSet()
            assertEquals(
                emptySet(),
                danglingHelpers,
                "Injected ClassEncryptionLoaderHelper references undeployed helpers: $danglingHelpers",
            )
        } finally {
            Files.deleteIfExists(outputJar)
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun class_encryption_loader_skips_entrypoint_closure_and_stateful_instance_classes() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-cel-boundary-input", ".jar"))
        val outputJar = inputJar.resolveSibling("javashroud-cel-boundary-output.jar")
        val configPath = inputJar.resolveSibling("javashroud-cel-boundary-config.toml")
        try {
            writeRunConfig(configPath, inputJar, outputJar, listOf("class-encryption-loader"))
            captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }
            val encryptedIndex = readJarEntry(outputJar, "__jse/index.tab")?.toString(Charsets.UTF_8).orEmpty()
            assertTrue("e2e/Root" !in encryptedIndex, "Manifest Main-Class must stay in the app loader namespace")
            assertTrue("e2e/Root$" !in encryptedIndex, "Manifest Main-Class nested types must stay with the entrypoint")
            assertTrue("e2e/Impl" !in encryptedIndex, "Stateful instance classes cannot be safely proxied by class-encryption-loader")
        } finally {
            Files.deleteIfExists(outputJar)
            Files.deleteIfExists(configPath)
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

        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyClassEncryptionLoader(
                artifact = artifact,
                ruleMatches = listOf(ruleMatchForClassEncryption(entryName), ruleMatchForClassEncryption(packagePrivateName)),
                params = mapOf("encryptionStrategy" to "aes-128", "keyMode" to "per-class", "seed" to 7),
            )
        }

        val encryptedIndex = result.artifact.jarEntries.singleOrNull { it.name == "__jse/index.tab" }?.bytes?.toString(Charsets.UTF_8).orEmpty()
        assertTrue(entryName !in encryptedIndex, "A class that would access package-private app-loader state must not be split into the class-encryption loader")
        assertTrue(packagePrivateName !in encryptedIndex, "Unsafe package-private dependency should remain in the app loader namespace")
    }

    @Test
    fun class_encryption_loader_emits_v2_aead_metadata_and_no_cbc_helper_path() {
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

        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            applyClassEncryptionLoader(
                artifact = artifact,
                ruleMatches = listOf(ruleMatchForClassEncryption(internalName)),
                params = mapOf("encryptionStrategy" to "aes-256", "keyMode" to "per-class", "seed" to 31),
            )
        }

        val encryptedIndex = result.artifact.jarEntries.single { it.name == "__jse/index.tab" }.bytes.toString(Charsets.UTF_8)
        val metadata = encryptedIndex.trim().split('\t')[2]
        assertTrue(metadata.startsWith("v2:aes-256:"), "Class encryption metadata must be versioned AES-GCM metadata")
        assertEquals(6, metadata.split(':').size, "Class encryption v2 metadata must include strategy, key id, salt, nonce, and AAD hash")

        val helperSource = Files.readString(sourcePath("src/main/java/io/github/hht0rro/javashroud/transforms/protection/ClassEncryptionLoaderHelper.java"))
        assertFalse("AES/CBC/PKCS5Padding" in helperSource, "Class encryption helper must not keep CBC decrypt fallback")
        assertFalse("Legacy direct-key" in helperSource, "Class encryption helper must not accept legacy direct-key metadata")
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
        val innerPrefix = self + "$"
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
                if (normalized.startsWith("$helperPkg/") &&
                    normalized != self &&
                    !normalized.startsWith(innerPrefix)
                ) {
                    refs.add(normalized)
                }
            }
        }
        return refs
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path, passIds: List<String>) {
        writeTestRunConfigToml(configPath, inputJar, outputJar, passIds)
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

    private fun captureStdout(block: () -> Unit): String {
        val originalOut = System.out
        val buffer = ByteArrayOutputStream()
        System.setOut(PrintStream(buffer, true, Charsets.UTF_8))
        return try {
            block()
            buffer.toString(Charsets.UTF_8)
        } finally {
            System.setOut(originalOut)
        }
    }

    private fun sourcePath(relative: String): Path {
        val direct = Path.of(relative)
        if (Files.exists(direct)) return direct
        val nested = Path.of("core-engine").resolve(relative)
        if (Files.exists(nested)) return nested
        return direct
    }
}
