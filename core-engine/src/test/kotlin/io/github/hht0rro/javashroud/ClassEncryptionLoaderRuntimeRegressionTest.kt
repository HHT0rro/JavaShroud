package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
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
}
