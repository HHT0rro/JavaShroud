package io.github.hht0rro.javashroud.hardening

import io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.testClassArtifact
import io.github.hht0rro.javashroud.transforms.protection.hardening.IndyTargetTokenEnvelope
import io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat
import io.github.hht0rro.javashroud.transforms.protection.hardening.ReleaseArtifactScan
import io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class HardenedNegativeTamperTest {
    @Test
    fun itk_token_does_not_open_across_artifacts_or_sites() {
        val target = IndyTargetTokenEnvelope.Target("com/example/T", "work", "(I)I", Opcodes.H_INVOKESTATIC, false)
        val artifactA = binding(digestFill = 3, owner = "com/foo/A", site = 1)
        val artifactB = binding(digestFill = 9, owner = "com/foo/A", site = 1)
        val siteB = binding(digestFill = 3, owner = "com/foo/A", site = 2)
        val sealed = IndyTargetTokenEnvelope.seal(target, artifactA)
        IndyTargetTokenEnvelope.open(sealed, artifactA)
        assertFailsWith<SecurityException> { IndyTargetTokenEnvelope.open(sealed, artifactB) }
        assertFailsWith<SecurityException> { IndyTargetTokenEnvelope.open(sealed, siteB) }
    }

    @Test
    fun debug_map_corrupt_mix_and_embedded_fail_closed() {
        val classBytes = emptyClass("sample/NegHost")
        val classArtifact = testClassArtifact(internalName = "sample/NegHost", bytes = classBytes)
        val artifactA = testAttachedArtifact(classArtifacts = listOf(classArtifact))
        val otherBytes = emptyClass("sample/NegOther")
        val artifactB = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/NegOther", bytes = otherBytes)),
        )
        val dir = Files.createTempDirectory("js-neg-debugmap")
        try {
            val jarA = dir.resolve("a.jar")
            val jarB = dir.resolve("b.jar")
            writeBytecodeArtifact(jarA, artifactA)
            writeBytecodeArtifact(jarB, artifactB)
            val digestA = SignedDebugMap.sha256(jarA)
            val digestB = SignedDebugMap.sha256(jarB)
            val issuer = SignedDebugMap.Issuer.generate("org-test")
            val mapA = SignedDebugMap.create(digestA, boundDraft(), issuer)
            assertFailsWith<IllegalArgumentException> { mapA.verify(digestB) }
            assertFailsWith<IllegalArgumentException> { SignedDebugMap.parse(mapA.encoded.copyOf(12)) }
            val flipped = mapA.encoded.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            assertFailsWith<IllegalArgumentException> { SignedDebugMap.parse(flipped) }

            val embedded = testAttachedArtifact(
                classArtifacts = listOf(classArtifact),
                jarEntries = listOf(
                    JarEntryData("sample/NegHost.class", classBytes),
                    JarEntryData("META-INF/out.debugmap", mapA.encoded),
                ),
            )
            val embeddedJar = dir.resolve("embedded.jar")
            writeBytecodeArtifact(embeddedJar, embedded)
            val embeddedReport = ReleaseArtifactScan.scan(
                embeddedJar,
                embedded,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertFalse(embeddedReport.findings.single { it.check == "debug-map-provenance" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun old_protocol_magic_fails_release_scan() {
        val classBytes = emptyClass("sample/LegacyHost")
        val classArtifact = testClassArtifact(internalName = "sample/LegacyHost", bytes = classBytes)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(classArtifact),
            jarEntries = listOf(
                JarEntryData("sample/LegacyHost.class", classBytes),
                JarEntryData("META-INF/jsrt/catalog/directory.jsr1", "JSR1DIR".toByteArray()),
            ),
        )
        val dir = Files.createTempDirectory("js-neg-magic")
        try {
            val jar = dir.resolve("legacy.jar")
            writeBytecodeArtifact(jar, artifact)
            val report = ReleaseArtifactScan.scan(
                jar,
                artifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertFalse(report.findings.single { it.check == "legacy-magic" }.passed)
            assertTrue(report.findings.none { it.check == "legacy-magic" && it.passed })
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun binding(digestFill: Int, owner: String, site: Int): IndyTargetTokenEnvelope.Binding =
        IndyTargetTokenEnvelope.Binding(
            artifactDigest = ByteArray(32) { (it + digestFill).toByte() },
            callerOwner = owner,
            indyName = "run",
            indyMethodType = "(I)V",
            siteIndex = site,
        )

    private fun boundDraft(): SignedDebugMap.Draft = SignedDebugMap.Draft(
        methodMappings = emptyList(),
        fieldMappings = emptyList(),
        transformVersion = ProtectionFormat.CURRENT,
        buildId = "build-1",
        issuerKeyId = "org-test",
        passConfigDigest = ByteArray(32) { (it + 1).toByte() },
        nativeSha256 = ByteArray(32) { (it + 2).toByte() },
        abiDigest = ByteArray(32) { (it + 3).toByte() },
        specializationDigest = ByteArray(32) { (it + 4).toByte() },
        targetTriple = "x86_64-pc-windows-gnu",
    )

    private fun emptyClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        writer.visitEnd()
        return writer.toByteArray()
    }
}
