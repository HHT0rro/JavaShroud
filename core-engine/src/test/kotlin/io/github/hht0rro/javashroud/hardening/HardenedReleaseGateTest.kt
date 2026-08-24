package io.github.hht0rro.javashroud.hardening

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.testClassArtifact
import io.github.hht0rro.javashroud.testConfig
import io.github.hht0rro.javashroud.transforms.protection.hardening.HardenedArtifactFinalizer
import io.github.hht0rro.javashroud.transforms.protection.hardening.IndyTargetTokenEnvelope
import io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat
import io.github.hht0rro.javashroud.transforms.protection.hardening.ReleaseArtifactScan
import io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap
import io.github.hht0rro.javashroud.transforms.protection.hardening.VmDialectDescriptor
import io.github.hht0rro.javashroud.transforms.rename.METHOD_RENAME_BINDINGS_RESOURCE
import java.nio.file.Files
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode

class HardenedReleaseGateTest {
    @Test
    fun default_profile_is_release_hardened() {
        assertEquals(HardenedProtectionProfile.RELEASE_HARDENED, testConfig().protectionProfile)
        assertEquals(HardenedProtectionProfile.RELEASE_HARDENED, HardenedProtectionProfile.fromWireValue("release-hardened"))
        assertTrue(HardenedProtectionProfile.MINIMAL.isLowProtection)
    }

    @Test
    fun signed_debug_map_round_trips_and_binds_digest() {
        val digest = ByteArray(32) { it.toByte() }
        val draft = SignedDebugMap.Draft(
            methodMappings = listOf(SignedDebugMap.MemberMapping("a/B", "old", "()V", "m1")),
            fieldMappings = emptyList(),
            transformVersion = ProtectionFormat.CURRENT,
            buildId = "1",
        )
        val map = SignedDebugMap.create(digest, draft)
        val parsed = SignedDebugMap.parse(map.encoded)
        assertEquals("old", parsed.methodMappings.single().originalName)
        assertFailsWith<IllegalArgumentException> { parsed.verify(ByteArray(32) { 1 }) }
    }

    @Test
    fun indy_token_hides_owner_and_fails_closed_on_tamper() {
        val key = ByteArray(16) { (it + 3).toByte() }
        val binding = zerosBinding()
        val token = IndyTargetTokenEnvelope.seal(
            IndyTargetTokenEnvelope.Target("com/example/T", "work", "(I)I", Opcodes.H_INVOKESTATIC, false),
            binding,
            key,
            SecureRandom(byteArrayOf(1, 2, 3, 4)),
        )
        assertFalse(token.contains("com/example/T"))
        assertFalse(token.contains("work"))
        val opened = IndyTargetTokenEnvelope.open(token, binding, key)
        assertEquals("com/example/T", opened.owner)
        assertEquals("work", opened.name)
        val tampered = token.dropLast(2) + "ab"
        assertFailsWith<SecurityException> { IndyTargetTokenEnvelope.open(tampered, binding, key) }
        val otherKey = ByteArray(16) { 9 }
        assertFailsWith<SecurityException> { IndyTargetTokenEnvelope.open(token, binding, otherKey) }
    }

    @Test
    fun classfile_whitelist_strips_source_and_parameter_debug() {
        val writer = org.objectweb.asm.ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/Dbg", null, "java/lang/Object", null)
        writer.visitSource("Dbg.java", null)
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()V", null, null)
        mv.visitParameter("arg", 0)
        mv.visitCode()
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        writer.visitEnd()
        val stripped = io.github.hht0rro.javashroud.bytecode.stripCompileDebug(writer.toByteArray())
        val latin = String(stripped, Charsets.ISO_8859_1)
        assertFalse(latin.contains("Dbg.java"))
        val node = org.objectweb.asm.tree.ClassNode()
        org.objectweb.asm.ClassReader(stripped).accept(node, 0)
        assertTrue(node.sourceFile == null || node.sourceFile.isEmpty())
    }

    @Test
    fun retired_des_string_codec_is_rejected() {
        assertFailsWith<IllegalArgumentException> {
            io.github.hht0rro.javashroud.bytecode.encryptClassStringsEmbeddedResolver(
                emptyClass("sample/DesHost"),
                io.github.hht0rro.javashroud.bytecode.EmbeddedStringResolverConfig(seed = 1L, payloadCodec = "des"),
            )
        }
    }

    @Test
    fun legacy_catalog_magic_is_rejected() {
        assertTrue("JSC1" in ProtectionFormat.FORBIDDEN_RELEASE_MAGICS)
        assertFalse("JSR1" in ProtectionFormat.FORBIDDEN_RELEASE_MAGICS)
    }

    @Test
    fun finalizer_does_not_hide_retired_entries_and_release_scan_rejects_them() {
        val classBytes = emptyClass("sample/Host")
        val classArtifact = testClassArtifact(internalName = "sample/Host", bytes = classBytes)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(classArtifact),
            jarEntries = listOf(
                JarEntryData("sample/Host.class", classBytes),
                JarEntryData(METHOD_RENAME_BINDINGS_RESOURCE, "sample/Host|run|()V|a\n".toByteArray()),
                JarEntryData("META-INF/.r/boot.dat", "JSBM".toByteArray()),
            ),
        )
        val finalized = HardenedArtifactFinalizer.finalizeForWrite(artifact, testConfig())
        assertTrue(finalized.jarEntries.any { it.name == METHOD_RENAME_BINDINGS_RESOURCE })
        assertTrue(finalized.jarEntries.any { it.name == "META-INF/.r/boot.dat" })
        val dir = Files.createTempDirectory("js-hard")
        val jar = dir.resolve("out.jar")
        io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, finalized)
        val report = ReleaseArtifactScan.scan(jar, finalized, HardenedProtectionProfile.RELEASE_HARDENED, listOf("rename-methods"))
        assertFalse(report.findings.single { it.check == "rename-map" }.passed)
        assertFalse(report.findings.single { it.check == "legacy-path" }.passed)
        assertFalse(report.passed)
        Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }

    @Test
    fun scan_fails_on_plaintext_business_handle() {
        val classBytes = classWithBusinessHandle()
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/Caller", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-hard-indy")
        val jar = dir.resolve("out.jar")
        io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
        val report = ReleaseArtifactScan.scan(jar, artifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
        assertFalse(report.findings.single { it.check == "indy-target-opacity" }.passed)
        assertFailsWith<SecurityException> { report.requirePass() }
        Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }

    @Test
    fun vm_dialect_differs_across_build_streams_and_round_trips() {
        val first = VmDialectDescriptor.fromStream(ByteArray(512) { it.toByte() })
        val second = VmDialectDescriptor.fromStream(ByteArray(512) { (it * 3 + 7).toByte() })
        assertFalse(first.commitment.contentEquals(second.commitment))
        assertNotEquals(first.encodeOpcode(0x40), second.encodeOpcode(0x40))
        val encoded = first.encodeOpcode(0x02)
        assertEquals(0x02, first.decodeOpcode(encoded))
        assertTrue(first.fusedOpcode >= 0x100)
    }

    @Test
    fun vm_dialect_from_key_material_is_build_bound() {
        val cryptoA = ByteArray(32) { 0x11 }
        val cryptoB = ByteArray(32) { 0x33 }
        val layout = ByteArray(32) { 0x22 }
        val first = VmDialectDescriptor.fromKeyMaterial(cryptoA, layout)
        val second = VmDialectDescriptor.fromKeyMaterial(cryptoB, layout)
        assertFalse(first.commitment.contentEquals(second.commitment))
        assertNotEquals(first.encodeOpcode(0x02), second.encodeOpcode(0x02))
        assertEquals(0x02, first.decodeOpcode(first.encodeOpcode(0x02)))
        assertEquals(0x40, first.decodeOpcode(first.encodeOpcode(0x40)))
        assertEquals(0x53, first.encodeOpcode(0x02))
        assertEquals(0x5f, first.encodeOpcode(0x40))
        assertEquals(0x44, first.encodeOpcode(0x90))
        assertEquals(0xfd.let { first.encodeOpcode(it) }, 0xf3)
    }

    private fun zerosBinding(): IndyTargetTokenEnvelope.Binding {
        val z = ByteArray(32)
        return IndyTargetTokenEnvelope.Binding(z, z, z, z, z)
    }

    private fun emptyClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classWithBusinessHandle(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/Caller", null, "java/lang/Object", null)
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        mv.visitCode()
        mv.visitInvokeDynamicInsn(
            "work",
            "()I",
            Handle(Opcodes.H_INVOKESTATIC, "sample/Caller", "a_bsm0", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;", false),
            Handle(Opcodes.H_INVOKESTATIC, "com/example/Target", "work", "()I", false),
        )
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
}
