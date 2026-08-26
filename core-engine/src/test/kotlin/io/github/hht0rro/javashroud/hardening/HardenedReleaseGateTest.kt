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
import org.objectweb.asm.Label
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
    fun perf_budget_matches_hardened_plan_ceilings() {
        assertEquals(2.0, io.github.hht0rro.javashroud.model.config.HardenedPerfBudget.STARTUP_MULTIPLIER)
        assertEquals(2.0, io.github.hht0rro.javashroud.model.config.HardenedPerfBudget.ARTIFACT_SIZE_MULTIPLIER)
        assertEquals(3.0, io.github.hht0rro.javashroud.model.config.HardenedPerfBudget.CALL_OVERHEAD_MULTIPLIER)
    }

    @Test
    fun scan_rejects_build_machine_cwd_paths() {
        val dir = Files.createTempDirectory("js-hard-cwd")
        try {
            val leaked = emptyClass("sample/CwdLeak") + "C:\\Users\\builder\\project".toByteArray()
            val leakArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/CwdLeak", bytes = leaked)),
            )
            val leakJar = dir.resolve("leak.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(leakJar, leakArtifact)
            val leakReport = ReleaseArtifactScan.scan(
                leakJar,
                leakArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertFalse(leakReport.findings.single { it.check == "fresh-cwd-reproducibility" }.passed)

            val cleanBytes = emptyClass("sample/CwdClean")
            val cleanArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/CwdClean", bytes = cleanBytes)),
            )
            val cleanJar = dir.resolve("clean.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(cleanJar, cleanArtifact)
            val cleanReport = ReleaseArtifactScan.scan(
                cleanJar,
                cleanArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertTrue(cleanReport.findings.single { it.check == "fresh-cwd-reproducibility" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_blocks_release_when_artifact_exceeds_size_budget() {
        val classBytes = emptyClass("sample/PerfHost")
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/PerfHost", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-hard-perf")
        try {
            val jar = dir.resolve("out.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
            val blocked = ReleaseArtifactScan.scan(
                jar,
                artifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
                inputJarBytes = 1L,
            )
            assertFalse(blocked.findings.single { it.check == "perf-budget" }.passed)
            val analysis = ReleaseArtifactScan.scan(
                jar,
                artifact,
                HardenedProtectionProfile.ANALYSIS_ONLY,
                emptyList(),
                inputJarBytes = 1L,
            )
            assertTrue(analysis.findings.single { it.check == "perf-budget" }.passed)
            val within = ReleaseArtifactScan.scan(
                jar,
                artifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
                inputJarBytes = Files.size(jar),
            )
            assertTrue(within.findings.single { it.check == "perf-budget" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_rejects_vbc4_fixed_domain_labels() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/VbcLeak", null, "java/lang/Object", null)
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()Ljava/lang/String;", null, null)
        mv.visitCode()
        mv.visitLdcInsn("javashroud-aken-r1-vbc4-inner-crypto-v3")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        writer.visitEnd()
        val leaked = writer.toByteArray()
        val leakArtifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/VbcLeak", bytes = leaked)),
        )
        val dir = Files.createTempDirectory("js-hard-vbc4")
        try {
            val leakJar = dir.resolve("leak.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(leakJar, leakArtifact)
            val leakReport = ReleaseArtifactScan.scan(
                leakJar,
                leakArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertFalse(leakReport.findings.single { it.check == "vbc4-fixed-material" }.passed)

            val cleanBytes = emptyClass("sample/VbcClean")
            val cleanArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/VbcClean", bytes = cleanBytes)),
            )
            val cleanJar = dir.resolve("clean.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(cleanJar, cleanArtifact)
            val cleanReport = ReleaseArtifactScan.scan(
                cleanJar,
                cleanArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertTrue(cleanReport.findings.single { it.check == "vbc4-fixed-material" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun packaged_native_runtime_omits_vbc4_ascii_domains() {
        val native = javaClass.classLoader.getResourceAsStream("META-INF/jsrt/windows-x64/jsrt_ffi.dll")?.use { it.readBytes() }
            ?: javaClass.classLoader.getResourceAsStream("META-INF/jsrt/linux-x64/libjsrt_ffi.so")?.use { it.readBytes() }
            ?: return
        val classBytes = emptyClass("sample/NativeLabelHost")
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/NativeLabelHost", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-hard-native-label")
        try {
            val jar = dir.resolve("out.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
            val report = ReleaseArtifactScan.scan(
                jar,
                artifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
                nativeBytes = listOf(native),
            )
            assertTrue(report.findings.single { it.check == "vbc4-fixed-material" }.passed, report.toReportText())
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_requires_debug_map_sidecar_provenance() {
        val classBytes = emptyClass("sample/DbgHost")
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/DbgHost", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-hard-debugmap")
        try {
            val jar = dir.resolve("out.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
            val absent = ReleaseArtifactScan.scan(jar, artifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
            assertTrue(absent.findings.single { it.check == "debug-map-provenance" }.passed)

            val digest = SignedDebugMap.sha256(jar)
            val weak = SignedDebugMap.Draft(
                methodMappings = emptyList(),
                fieldMappings = emptyList(),
                transformVersion = ProtectionFormat.CURRENT,
                buildId = "1",
            )
            SignedDebugMap.write(jar, weak, digest, SignedDebugMap.Issuer.generate("ephemeral"))
            val weakReport = ReleaseArtifactScan.scan(jar, artifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
            assertFalse(weakReport.findings.single { it.check == "debug-map-provenance" }.passed)

            val bound = SignedDebugMap.Draft(
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
            SignedDebugMap.write(jar, bound, digest, SignedDebugMap.Issuer.generate("org-test"))
            val boundReport = ReleaseArtifactScan.scan(jar, artifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
            assertTrue(boundReport.findings.single { it.check == "debug-map-provenance" }.passed, boundReport.toReportText())
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_rejects_static_handle_page_proof_triples() {
        val leakWriter = ClassWriter(0)
        leakWriter.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "jsh/TripleHost", null, "java/lang/Object", null)
        val leakMv = leakWriter.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        leakMv.visitCode()
        leakMv.visitIntInsn(Opcodes.BIPUSH, 24)
        leakMv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        leakMv.visitInsn(Opcodes.ICONST_3)
        leakMv.visitIntInsn(Opcodes.BIPUSH, 8)
        leakMv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        leakMv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "sample/Helper",
            "open",
            "([BI[B)Ljava/lang/String;",
            false,
        )
        leakMv.visitInsn(Opcodes.POP)
        leakMv.visitInsn(Opcodes.RETURN)
        leakMv.visitMaxs(3, 0)
        leakMv.visitEnd()
        leakWriter.visitEnd()
        val leakArtifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "jsh/TripleHost", bytes = leakWriter.toByteArray())),
        )

        val packedWriter = ClassWriter(0)
        packedWriter.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/PackedHost", null, "java/lang/Object", null)
        val packedMv = packedWriter.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()Ljava/lang/String;", null, null)
        packedMv.visitCode()
        packedMv.visitIntInsn(Opcodes.BIPUSH, 60)
        packedMv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        packedMv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper",
            "invokeAkenStringTerminal",
            "([B)Ljava/lang/String;",
            false,
        )
        packedMv.visitInsn(Opcodes.ARETURN)
        packedMv.visitMaxs(1, 0)
        packedMv.visitEnd()
        packedWriter.visitEnd()
        val packedArtifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/PackedHost", bytes = packedWriter.toByteArray())),
        )

        val nativeChunkWriter = ClassWriter(0)
        nativeChunkWriter.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/NativeChunkHost", null, "java/lang/Object", null)
        val nativeChunkMv = nativeChunkWriter.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()V", null, null)
        nativeChunkMv.visitCode()
        nativeChunkMv.visitIntInsn(Opcodes.BIPUSH, 24)
        nativeChunkMv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        nativeChunkMv.visitInsn(Opcodes.ICONST_0)
        nativeChunkMv.visitIntInsn(Opcodes.BIPUSH, 8)
        nativeChunkMv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        nativeChunkMv.visitMethodInsn(Opcodes.INVOKESTATIC, "sample/Helper", "open", "([BI[B)V", false)
        nativeChunkMv.visitInsn(Opcodes.RETURN)
        nativeChunkMv.visitMaxs(3, 0)
        nativeChunkMv.visitEnd()
        nativeChunkWriter.visitEnd()
        val nativeChunkArtifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/NativeChunkHost", bytes = nativeChunkWriter.toByteArray())),
        )

        val dir = Files.createTempDirectory("js-hard-triple")
        try {
            val leakJar = dir.resolve("leak.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(leakJar, leakArtifact)
            val leakReport = ReleaseArtifactScan.scan(
                leakJar,
                leakArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                listOf("string-encryption"),
            )
            assertFalse(leakReport.findings.single { it.check == "string-static-triple" }.passed)

            val packedJar = dir.resolve("packed.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(packedJar, packedArtifact)
            val packedReport = ReleaseArtifactScan.scan(
                packedJar,
                packedArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertTrue(packedReport.findings.single { it.check == "string-static-triple" }.passed)

            val nativeChunkJar = dir.resolve("native-chunk.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(nativeChunkJar, nativeChunkArtifact)
            val nativeChunkReport = ReleaseArtifactScan.scan(
                nativeChunkJar,
                nativeChunkArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertTrue(nativeChunkReport.findings.single { it.check == "string-static-triple" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun hardened_jdk_matrix_blocks_unsupported_runtimes() {
        assertEquals(setOf(17, 21), io.github.hht0rro.javashroud.model.config.HardenedJdkMatrix.BLOCKING)
        assertEquals(setOf(8, 11), io.github.hht0rro.javashroud.model.config.HardenedJdkMatrix.OBSERVATIONAL)
        assertTrue(io.github.hht0rro.javashroud.model.config.HardenedJdkMatrix.isBlockingRuntime())
        val classBytes = emptyClass("sample/JdkHost")
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/JdkHost", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-hard-jdk")
        try {
            val jar = dir.resolve("out.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
            val report = ReleaseArtifactScan.scan(jar, artifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
            assertTrue(report.findings.single { it.check == "jdk-blocking-matrix" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun signed_debug_map_round_trips_and_binds_digest() {
        val digest = ByteArray(32) { it.toByte() }
        val issuer = SignedDebugMap.Issuer.generate("org-test")
        val draft = SignedDebugMap.Draft(
            methodMappings = listOf(SignedDebugMap.MemberMapping("a/B", "old", "()V", "m1")),
            fieldMappings = emptyList(),
            transformVersion = ProtectionFormat.CURRENT,
            buildId = "1",
            nativeSha256 = ByteArray(32) { (it + 2).toByte() },
            abiDigest = ByteArray(32) { (it + 3).toByte() },
            specializationDigest = ByteArray(32) { (it + 4).toByte() },
            targetTriple = "x86_64-pc-windows-gnu",
        )
        val map = SignedDebugMap.create(digest, draft, issuer)
        val again = SignedDebugMap.create(digest, draft, issuer)
        val parsed = SignedDebugMap.parse(map.encoded)
        assertEquals("old", parsed.methodMappings.single().originalName)
        assertEquals("org-test", parsed.issuerKeyId)
        assertEquals("x86_64-pc-windows-gnu", parsed.targetTriple)
        assertTrue(parsed.publicKey.contentEquals(again.publicKey))
        assertFailsWith<IllegalArgumentException> { parsed.verify(ByteArray(32) { 1 }) }
        val other = SignedDebugMap.create(ByteArray(32) { 9 }, draft, issuer)
        assertFailsWith<IllegalArgumentException> { other.verify(digest) }
        val flipped = map.encoded.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<IllegalArgumentException> { SignedDebugMap.parse(flipped).verify(digest) }
        val oldVersion = map.encoded.copyOf().also { it[5] = 2 }
        assertFailsWith<IllegalArgumentException> { SignedDebugMap.parse(oldVersion) }
    }

    @Test
    fun indy_token_hides_owner_and_fails_closed_on_tamper() {
        val key = ByteArray(16) { (it + 3).toByte() }
        val binding = sampleBinding()
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
    fun scan_rejects_itk_key_lanes_and_accepts_current_bootstrap_aad() {
        val laneBytes = byteArrayOf(
            0x4A, 0x53, 0x52, 0x30,
            0x4A, 0x53, 0x52, 0x31,
            0x4A, 0x53, 0x52, 0x32,
            0x4A, 0x53, 0x52, 0x33,
        )
        val laneClass = emptyClass("sample/Lanes") + laneBytes
        val laneArtifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/Lanes", bytes = laneClass)),
        )
        val dir = Files.createTempDirectory("js-hard-lanes")
        val jar = dir.resolve("out.jar")
        io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, laneArtifact)
        val laneReport = ReleaseArtifactScan.scan(jar, laneArtifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
        assertFalse(laneReport.findings.single { it.check == "itk-key-lane-absent" }.passed)
        Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }

        val helperBytes = javaClass.classLoader.getResourceAsStream(
            "io/github/hht0rro/javashroud/transforms/protection/IndyTargetBootstrap.class",
        )!!.use { it.readBytes() }
        val helperArtifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = "io/github/hht0rro/javashroud/transforms/protection/IndyTargetBootstrap",
                    bytes = helperBytes,
                ),
            ),
        )
        val helperDir = Files.createTempDirectory("js-hard-aad")
        val helperJar = helperDir.resolve("out.jar")
        io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(helperJar, helperArtifact)
        val helperReport = ReleaseArtifactScan.scan(
            helperJar,
            helperArtifact,
            HardenedProtectionProfile.RELEASE_HARDENED,
            emptyList(),
        )
        assertTrue(helperReport.findings.single { it.check == "itk-key-lane-absent" }.passed)
        assertTrue(helperReport.findings.single { it.check == "itk-aad-used" }.passed)
        assertTrue(helperReport.findings.single { it.check == "runtime-binding-nonzero" }.passed)
        Files.walk(helperDir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }

    @Test
    fun scan_rejects_single_rotation_strategy_and_accepts_mixed() {
        val dir = Files.createTempDirectory("js-hard-rot")
        try {
            val singleBytes = classWithRotationStrategies(List(4) { "table" })
            val singleArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/RotSingle", bytes = singleBytes)),
            )
            val singleJar = dir.resolve("single.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(singleJar, singleArtifact)
            val singleReport = ReleaseArtifactScan.scan(
                singleJar,
                singleArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertFalse(singleReport.findings.single { it.check == "rotation-strategy-diversity" }.passed)

            val mixedBytes = classWithRotationStrategies(listOf("mutable", "guarded", "table", "oneshot"))
            val mixedArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/RotMixed", bytes = mixedBytes)),
            )
            val mixedJar = dir.resolve("mixed.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(mixedJar, mixedArtifact)
            val mixedReport = ReleaseArtifactScan.scan(
                mixedJar,
                mixedArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertTrue(mixedReport.findings.single { it.check == "rotation-strategy-diversity" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_rejects_evaluator_dek_overlay() {
        val dir = Files.createTempDirectory("js-hard-eval")
        try {
            val overlay = ByteArray(512)
            overlay[0] = 'A'.code.toByte()
            overlay[1] = 'K'.code.toByte()
            overlay[2] = 'E'.code.toByte()
            overlay[3] = '1'.code.toByte()
            overlay[5] = 4
            var cursor = 6 + 12 + 16 + 32 + 32 + 32
            fun writeU32(value: Int) {
                overlay[cursor] = (value ushr 24).toByte()
                overlay[cursor + 1] = (value ushr 16).toByte()
                overlay[cursor + 2] = (value ushr 8).toByte()
                overlay[cursor + 3] = value.toByte()
                cursor += 4
            }
            repeat(4) { ordinal ->
                overlay[cursor] = (ordinal * 8).toByte()
                overlay[cursor + 1] = 8
                cursor += 5
                writeU32(0)
                cursor += 16
                writeU32(8)
                cursor += 8 + 16
            }
            val classBytes = emptyClass("sample/EvalOverlay") + overlay
            val artifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/EvalOverlay", bytes = classBytes)),
            )
            val jar = dir.resolve("overlay.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
            val report = ReleaseArtifactScan.scan(jar, artifact, HardenedProtectionProfile.RELEASE_HARDENED, emptyList())
            assertFalse(report.findings.single { it.check == "aken-evaluator-direct-recovery" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_rejects_exception_body_clone_handlers() {
        val dir = Files.createTempDirectory("js-hard-exc")
        try {
            val bytes = classWithExceptionBodyClone()
            val artifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/ExcClone", bytes = bytes)),
            )
            val jar = dir.resolve("clone.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(jar, artifact)
            val report = ReleaseArtifactScan.scan(
                jar,
                artifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                listOf("exception-semantic-virtualization"),
            )
            assertFalse(report.findings.single { it.check == "exception-body-clone" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun scan_rejects_fixed_cfg_templates() {
        val dir = Files.createTempDirectory("js-hard-cfg")
        try {
            val badBytes = classWithFixedCfgTemplates()
            val badArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/CfgBad", bytes = badBytes)),
            )
            val badJar = dir.resolve("bad.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(badJar, badArtifact)
            val badReport = ReleaseArtifactScan.scan(
                badJar,
                badArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                listOf("control-flow-obfuscation"),
            )
            val finding = badReport.findings.single { it.check == "cfg-fixed-template" }
            assertFalse(finding.passed, finding.detail)

            val cleanBytes = emptyClass("sample/CfgClean")
            val cleanArtifact = testAttachedArtifact(
                classArtifacts = listOf(testClassArtifact(internalName = "sample/CfgClean", bytes = cleanBytes)),
            )
            val cleanJar = dir.resolve("clean.jar")
            io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact(cleanJar, cleanArtifact)
            val cleanReport = ReleaseArtifactScan.scan(
                cleanJar,
                cleanArtifact,
                HardenedProtectionProfile.RELEASE_HARDENED,
                emptyList(),
            )
            assertTrue(cleanReport.findings.single { it.check == "cfg-fixed-template" }.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
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
        assertEquals(0x90, first.decodeOpcode(first.encodeOpcode(0x90)))
        assertEquals(0xfd, first.decodeOpcode(first.encodeOpcode(0xfd)))
        assertFailsWith<IllegalArgumentException> { first.encodeOpcode(0xEEEE) }
        assertFailsWith<IllegalArgumentException> { first.decodeOpcode(0x1234) }
    }

    private fun sampleBinding(): IndyTargetTokenEnvelope.Binding =
        IndyTargetTokenEnvelope.Binding(
            artifactDigest = ByteArray(32) { (it * 3 + 11).toByte() },
            callerOwner = "com/foo/Bar",
            indyName = "run",
            indyMethodType = "(I)V",
            siteIndex = 7,
        )

    private fun emptyClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classWithExceptionBodyClone(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/ExcClone", null, "java/lang/Object", null)
        val original = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "add", "(II)I", null, null)
        original.visitCode()
        original.visitVarInsn(Opcodes.ILOAD, 0)
        original.visitVarInsn(Opcodes.ILOAD, 1)
        original.visitInsn(Opcodes.IADD)
        original.visitInsn(Opcodes.IRETURN)
        original.visitMaxs(2, 2)
        original.visitEnd()
        val clone = writer.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "\$jsv\$add\$1",
            "(II)I",
            null,
            null,
        )
        clone.visitCode()
        clone.visitVarInsn(Opcodes.ILOAD, 0)
        clone.visitVarInsn(Opcodes.ILOAD, 1)
        clone.visitInsn(Opcodes.IADD)
        clone.visitInsn(Opcodes.IRETURN)
        clone.visitMaxs(2, 2)
        clone.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classWithFixedCfgTemplates(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/CfgBad", null, "java/lang/Object", null)
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        val same = Label()
        val next = Label()
        mv.visitCode()
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitTableSwitchInsn(0, 2, same, same, same, same)
        mv.visitLabel(same)
        mv.visitJumpInsn(Opcodes.GOTO, next)
        mv.visitLabel(next)
        mv.visitInsn(Opcodes.ICONST_3)
        mv.visitInsn(Opcodes.DUP)
        mv.visitInsn(Opcodes.IMUL)
        mv.visitInsn(Opcodes.ICONST_3)
        mv.visitInsn(Opcodes.IADD)
        mv.visitInsn(Opcodes.ICONST_2)
        mv.visitInsn(Opcodes.IREM)
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitMaxs(2, 0)
        mv.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classWithRotationStrategies(strategies: List<String>): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/RotHost", null, "java/lang/Object", null)
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(Ljava/lang/String;)I", null, null)
        mv.visitCode()
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "io/github/hht0rro/javashroud/transforms/protection/CallsiteRotationHelper",
            "createRotatingCallSite",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/invoke/CallSite;",
            false,
        )
        strategies.forEach { strategy ->
            mv.visitVarInsn(Opcodes.ALOAD, 0)
            mv.visitInvokeDynamicInsn("len", "(Ljava/lang/String;)I", bsm, "token-placeholder-value-xxxxxx", strategy)
            mv.visitInsn(Opcodes.POP)
        }
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitMaxs(2, 1)
        mv.visitEnd()
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
