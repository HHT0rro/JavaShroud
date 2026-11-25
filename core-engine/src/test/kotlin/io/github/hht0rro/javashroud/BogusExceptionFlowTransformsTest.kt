package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.ControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.insertBogusExceptionFlow
import io.github.hht0rro.javashroud.bytecode.insertOpaquePredicates
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode
import kotlin.test.Test
import kotlin.test.assertTrue

class BogusExceptionFlowTransformsTest {
    @Test
    fun bogus_exception_flow_preserves_full_frame_parse_for_methods_with_existing_try_catch() {
        val original = buildDiverseFixtureJar(java.nio.file.Files.createTempFile("javashroud-bogus-fixture", ".jar"))
        try {
            val rootBytes = loadJarEntryBytes(original, "e2e/Root.class")
            val transformed = insertBogusExceptionFlow(
                rootBytes,
                ControlFlowConfig(density = 2, handlerComplexity = "nop", seed = 7),
            )

            val node = ClassNode()
            ClassReader(transformed).accept(node, 0)

            assertTrue(node.methods.any { it.name.startsWith("m_") }, "Expected neutral bogus helper methods")
        } finally {
            java.nio.file.Files.deleteIfExists(original)
        }
    }

    @Test
    fun bogus_exception_flow_method_call_handler_keeps_valid_frames() {
        val original = buildDiverseFixtureJar(java.nio.file.Files.createTempFile("javashroud-bogus-methodcall", ".jar"))
        try {
            val rootBytes = loadJarEntryBytes(original, "e2e/Root.class")
            val transformed = insertBogusExceptionFlow(
                rootBytes,
                ControlFlowConfig(density = 1, handlerComplexity = "method-call", seed = 11),
            )

            val node = ClassNode()
            ClassReader(transformed).accept(node, 0)

            assertTrue(node.methods.any { it.name.startsWith("m_") }, "Expected neutral handler body helper")
        } finally {
            java.nio.file.Files.deleteIfExists(original)
        }
    }

    @Test
    fun bogus_exception_flow_field_write_handler_adds_state_field_once() {
        val original = buildDiverseFixtureJar(java.nio.file.Files.createTempFile("javashroud-bogus-field", ".jar"))
        try {
            val rootBytes = loadJarEntryBytes(original, "e2e/Root.class")
            val transformed = insertBogusExceptionFlow(
                rootBytes,
                ControlFlowConfig(density = 3, handlerComplexity = "field-write", seed = 19),
            )

            val node = ClassNode()
            ClassReader(transformed).accept(node, 0)

            assertTrue(node.fields.count { it.name == "__js_bogus_state" && it.desc == "I" } == 1)
        } finally {
            java.nio.file.Files.deleteIfExists(original)
        }
    }

    @Test
    fun bogus_exception_flow_keeps_valid_frames_after_prior_stack_sensitive_passes() {
        val original = buildDiverseFixtureJar(java.nio.file.Files.createTempFile("javashroud-bogus-combo", ".jar"))
        try {
            val rootBytes = loadJarEntryBytes(original, "e2e/Root.class")
            val preTransformed = insertOpaquePredicates(
                rootBytes,
                config = ControlFlowConfig(frequency = 2, seed = 23),
            )
            val transformed = insertBogusExceptionFlow(
                preTransformed,
                ControlFlowConfig(density = 10, handlerComplexity = "method-call", seed = 29),
            )

            val node = ClassNode()
            ClassReader(transformed).accept(node, 0)

            assertTrue(node.methods.any { it.name.startsWith("m_") }, "Expected neutral bogus helper methods")
        } finally {
            java.nio.file.Files.deleteIfExists(original)
        }
    }

    private fun loadJarEntryBytes(jarPath: java.nio.file.Path, entryName: String): ByteArray {
        java.util.jar.JarInputStream(java.nio.file.Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == entryName) {
                    return jar.readBytes()
                }
                jar.closeEntry()
            }
        }
        error("Missing JAR entry: $entryName")
    }
}
