package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.naming.RenameConfig
import io.github.hht0rro.javashroud.naming.isFixedGeneratedClassEntryPath
import io.github.hht0rro.javashroud.naming.isFixedGeneratedDottedName
import io.github.hht0rro.javashroud.naming.isFixedGeneratedInternalName
import io.github.hht0rro.javashroud.transforms.protection.hardening.FixedGeneratedNameArtifactScan
import io.github.hht0rro.javashroud.transforms.rename.removeFixedGeneratedNames
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type

class FixedGeneratedNameRemovalTest {
    @Test
    fun fixed_hex_shard_generated_names_are_reserved_too() {
        assertTrue(isFixedGeneratedDottedName("r.d2.C03c6b81f63fb4dc18f2033e7"))
        assertTrue(isFixedGeneratedDottedName("r.d2.C03c6b81f63fb4dc18f2033e7.m_member"))
        assertTrue(isFixedGeneratedInternalName("r/d2/C03c6b81f63fb4dc18f2033e7"))
        assertTrue(isFixedGeneratedInternalName("r/d2/C03c6b81f63fb4dc18f2033e7${'$'}Inner"))
        assertTrue(isFixedGeneratedClassEntryPath("r/d2/C03c6b81f63fb4dc18f2033e7.class"))
    }

    @Test
    fun fixed_generated_classes_are_relocated_and_all_supported_bindings_follow() {
        val artifact = fixedGeneratedArtifact()

        val result = removeFixedGeneratedNames(artifact, RenameConfig(seed = 73L))
        val updated = result.artifact

        assertEquals(2, result.transformedClassCount)
        assertTrue(updated.classArtifacts.none { isFixedGeneratedInternalName(it.summary.internalName) })
        assertTrue(updated.jarEntries.none { isFixedGeneratedClassEntryPath(it.name) })
        assertTrue(updated.jarEntries.none { it.name.startsWith("r/86/") })
        assertTrue(updated.jarEntries.none { entry ->
            entry.name.startsWith("META-INF/services/r.86.") ||
                (!entry.name.endsWith(".class") && String(entry.bytes, StandardCharsets.UTF_8).contains(FIXED_BINARY))
        }, updated.jarEntries.filter { entry ->
            entry.name.startsWith("META-INF/services/r.86.") ||
                (!entry.name.endsWith(".class") && String(entry.bytes, StandardCharsets.UTF_8).contains(FIXED_BINARY))
        }.joinToString { it.name })

        val manifest = updated.jarEntries.single { it.name.equals("META-INF/MANIFEST.MF", ignoreCase = true) }
        assertFalse(String(manifest.bytes, StandardCharsets.UTF_8).contains(FIXED_BINARY))

        val service = updated.jarEntries.single { it.name.startsWith("META-INF/services/") }
        assertFalse(isFixedGeneratedDottedName(service.name.removePrefix("META-INF/services/")))
        assertFalse(String(service.bytes, StandardCharsets.UTF_8).contains(FIXED_BINARY))

        val gate = FixedGeneratedNameArtifactScan.scanArtifact(updated)
        assertTrue(gate.passed, gate.detail)

        val outputJar = Files.createTempFile("javashroud-fixed-name-clean", ".jar")
        try {
            writeBytecodeArtifact(outputJar, updated)
            JarFile(outputJar.toFile()).use { jar ->
                assertTrue(jar.entries().toList().none { isFixedGeneratedClassEntryPath(it.name) })
            }
        val finalGate = JarFile(outputJar.toFile()).use(FixedGeneratedNameArtifactScan::scanJarFile)
            assertTrue(finalGate.passed, finalGate.detail)
        } finally {
            Files.deleteIfExists(outputJar)
        }
    }

    @Test
    fun fixed_generated_name_scan_rejects_nested_metadata_without_a_matching_entry_path() {
        val carrierBytes = buildCarrierWithFixedNestedMetadata()
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(CARRIER, bytes = carrierBytes)),
            jarEntries = listOf(JarEntryData("$CARRIER.class", carrierBytes)),
        )

        val finding = FixedGeneratedNameArtifactScan.scanArtifact(artifact)

        assertFalse(finding.passed)
        assertTrue(finding.detail.contains("entry=$CARRIER.class"), finding.detail)
        assertTrue(finding.detail.contains("class=$FIXED") || finding.detail.contains("class=$FIXED_INNER"), finding.detail)
        assertTrue(finding.detail.contains("inner-") || finding.detail.contains("nest-") || finding.detail.contains("method-descriptor"), finding.detail)
    }

    @Test
    fun fixed_generated_runtime_bound_surface_fails_closed_without_binding_relocation() {
        val bytes = buildFixedRuntimeBound()
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(FIXED, bytes = bytes)),
            jarEntries = listOf(JarEntryData("$FIXED.class", bytes)),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            removeFixedGeneratedNames(artifact, RenameConfig(seed = 73L))
        }
        assertTrue(failure.message.orEmpty().contains(FIXED))
        assertTrue(failure.message.orEmpty().contains("sealed runtime/native binding"))
    }

    @Test
    fun output_jar_scan_rejects_fixed_manifest_and_service_references() {
        val jarPath = Files.createTempFile("javashroud-fixed-name-release-gate", ".jar")
        try {
            JarOutputStream(Files.newOutputStream(jarPath)).use { jar ->
                jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
                jar.write("Manifest-Version: 1.0\r\nMain-Class: $FIXED_BINARY\r\n\r\n".toByteArray(StandardCharsets.UTF_8))
                jar.closeEntry()
                jar.putNextEntry(JarEntry("META-INF/services/$FIXED_BINARY"))
                jar.write("$FIXED_BINARY\n".toByteArray(StandardCharsets.UTF_8))
                jar.closeEntry()
            }

            JarFile(jarPath.toFile()).use { jar ->
                val finding = FixedGeneratedNameArtifactScan.scanJarFile(jar)
                assertFalse(finding.passed)
                assertTrue(finding.detail.contains("META-INF/MANIFEST.MF"), finding.detail)
            }
        } finally {
            Files.deleteIfExists(jarPath)
        }
    }

    @Test
    fun output_jar_scan_rejects_fixed_hex_shard_manifest_and_service_references() {
        val jarPath = Files.createTempFile("javashroud-fixed-hex-name-release-gate", ".jar")
        try {
            JarOutputStream(Files.newOutputStream(jarPath)).use { jar ->
                jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
                jar.write(
                    "Manifest-Version: 1.0\r\nMain-Class: r.d2.C03c6b81f63fb4dc18f2033e7\r\n\r\n"
                        .toByteArray(StandardCharsets.UTF_8),
                )
                jar.closeEntry()
                jar.putNextEntry(JarEntry("META-INF/services/r.d2.C03c6b81f63fb4dc18f2033e7"))
                jar.write("r.d2.C03c6b81f63fb4dc18f2033e7\n".toByteArray(StandardCharsets.UTF_8))
                jar.closeEntry()
                jar.putNextEntry(JarEntry("META-INF/jsrt/bindings.properties"))
                jar.write("owner=r/d2/C03c6b81f63fb4dc18f2033e7\n".toByteArray(StandardCharsets.UTF_8))
                jar.closeEntry()
            }

            JarFile(jarPath.toFile()).use { jar ->
                val finding = FixedGeneratedNameArtifactScan.scanJarFile(jar)
                assertFalse(finding.passed)
                assertTrue(finding.detail.contains("META-INF/MANIFEST.MF"), finding.detail)
                assertTrue(finding.detail.contains("r.d2.C03c6b81f63fb4dc18f2033e7"), finding.detail)
            }
        } finally {
            Files.deleteIfExists(jarPath)
        }
    }

    private fun fixedGeneratedArtifact() = testAttachedArtifact(
        classArtifacts = listOf(
            testClassArtifact(FIXED, bytes = buildFixedOuter()),
            testClassArtifact(FIXED_INNER, bytes = buildFixedInner()),
            testClassArtifact(CARRIER, bytes = buildCarrier()),
        ),
        jarEntries = listOf(
            JarEntryData("$FIXED.class", buildFixedOuter()),
            JarEntryData("$FIXED_INNER.class", buildFixedInner()),
            JarEntryData("$CARRIER.class", buildCarrier()),
            JarEntryData(
                "META-INF/MANIFEST.MF",
                (
                    "Manifest-Version: 1.0\r\n" +
                        "Main-Class: $FIXED_BINARY\r\n" +
                        "Premain-Class: $FIXED_BINARY\r\n\r\n"
                    ).toByteArray(StandardCharsets.UTF_8),
            ),
            JarEntryData("META-INF/services/$FIXED_BINARY", "$FIXED_BINARY\n$FIXED_INNER_BINARY\n".toByteArray(StandardCharsets.UTF_8)),
            JarEntryData("r/86/resources/binding.properties", "owner=$FIXED_BINARY\n".toByteArray(StandardCharsets.UTF_8)),
        ),
        manifestPresent = true,
    )

    private fun buildFixedOuter(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, FIXED, null, "java/lang/Object", null)
        writer.visitNestMember(FIXED_INNER)
        writer.visitInnerClass(FIXED_INNER, FIXED, "Inner", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "SELF", "L$FIXED;", null, null).visitEnd()

        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }

        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "bootstrap", BOOTSTRAP_DESC, null, null).apply {
            visitCode()
            visitInsn(Opcodes.ACONST_NULL)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(1, 3)
            visitEnd()
        }

        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "references", "()V", null, null).apply {
            visitCode()
            visitLdcInsn(Type.getObjectType(FIXED))
            visitInsn(Opcodes.POP)
            visitLdcInsn(FIXED_BINARY)
            visitInsn(Opcodes.POP)
            visitLdcInsn("$FIXED_BINARY.m_bf5fb2488f9f6ce3")
            visitInsn(Opcodes.POP)
            visitInvokeDynamicInsn("generated", "()L$FIXED;", FIXED_BOOTSTRAP, Type.getObjectType(FIXED))
            visitInsn(Opcodes.POP)
            visitLdcInsn(ConstantDynamic("generated", "L$FIXED;", FIXED_BOOTSTRAP, Type.getObjectType(FIXED)))
            visitInsn(Opcodes.POP)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildFixedInner(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, FIXED_INNER, null, "java/lang/Object", null)
        writer.visitNestHost(FIXED)
        writer.visitInnerClass(FIXED_INNER, FIXED, "Inner", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildCarrier(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, CARRIER, null, "java/lang/Object", null)
        writer.visitInnerClass(FIXED_INNER, FIXED, "Inner", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        writer.visitField(Opcodes.ACC_PUBLIC, "value", "L$FIXED;", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "convert", "(L$FIXED;)L$FIXED;", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 1)
            visitTypeInsn(Opcodes.CHECKCAST, FIXED)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(1, 2)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildCarrierWithFixedNestedMetadata(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, CARRIER, null, "java/lang/Object", null)
        writer.visitNestMember(FIXED_INNER)
        writer.visitInnerClass(FIXED_INNER, FIXED, "Inner", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        writer.visitEnd()
        return writer.toByteArray()
    }

    /**
     * A fixed-name class that is also part of the old sealed runtime surface.
     * The explicit loadKernel call is intentionally left without a binding
     * relocation map; cleanup must reject the artifact rather than silently
     * moving the class and breaking the native owner contract.
     */
    private fun buildFixedRuntimeBound(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, FIXED, null, "java/lang/Object", null)
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "load", "()V", null, null).apply {
            visitCode()
            visitMethodInsn(Opcodes.INVOKESTATIC, FIXED, "loadKernel", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "loadKernel", "()V", null, null).apply {
            visitCode()
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private companion object {
        const val FIXED = "r/86/C0c7023a5e7b5fc057000314f"
        const val FIXED_BINARY = "r.86.C0c7023a5e7b5fc057000314f"
        const val FIXED_INNER = "r/86/C0c7023a5e7b5fc057000314f\$Inner"
        const val FIXED_INNER_BINARY = "r.86.C0c7023a5e7b5fc057000314f\$Inner"
        const val CARRIER = "sample/Carrier"
        const val BOOTSTRAP_DESC = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"

        val FIXED_BOOTSTRAP = Handle(Opcodes.H_INVOKESTATIC, FIXED, "bootstrap", BOOTSTRAP_DESC, false)
    }
}
