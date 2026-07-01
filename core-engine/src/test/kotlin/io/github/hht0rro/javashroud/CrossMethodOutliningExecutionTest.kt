package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CrossMethodOutliningExecutionTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun cross_method_outlined_vm_methods_preserve_runtime_result_in_transformed_jar() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val inputJar = buildCrossMethodFixtureJar(Files.createTempFile("javashroud-cross-method-input", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJava(inputJar)
            assertEquals(0, baseline.exitCode, "Baseline cross-method fixture must run. output=${baseline.output}")
            assertEquals("34", baseline.output.trim(), "Baseline fixture contract changed")

            outputJar = runEngine(inputJar)
            assertTrue(
                listOf(
                    "seed" to "(I)I",
                    "fold" to "(I)I",
                    "verify" to "()I",
                ).all { (name, descriptor) ->
                    methodInvokesNativeVmDispatcher(outputJar, "e2e/CrossMethodOutliningRoot", name, descriptor)
                },
                "Every selected cross-method fixture method must be replaced by native VM dispatcher stub",
            )

            val transformed = runJava(outputJar)
            assertEquals(0, transformed.exitCode, "Cross-method outlined transformed JAR must run. output=${transformed.output}")
            assertEquals(baseline.output.trim(), transformed.output.trim(), "Cross-method outlining must preserve method semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun cross_method_outlining_emits_shared_mesh_manifests_and_non_standalone_shards() {
        val context = defaultVbc4BuildContext()
        val decodedResources = decodedCrossMethodResources(context = context, seed = 73)

        val preloadIndex = decodedResources[VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE]
            ?.decodeToString()
            ?.trim()
            ?.lines()
            .orEmpty()
            .associate { line ->
                val parts = line.split('|')
                parts[2] to parts[3].toInt()
            }
        val manifests = decodedResources.filterValues { bytes -> bytes.decodeToString().startsWith("VBC4S|1|") }
        assertTrue(manifests.size >= 3, "Cross-method outlining must emit one slice manifest per virtualized method")
        assertEquals(manifests.keys, preloadIndex.keys, "VM preload index must cover every cross-method slice manifest")

        val meshDigests = mutableSetOf<String>()
        val referencedPeerOrdinals = mutableSetOf<Int>()
        for ((manifestPath, manifestBytes) in manifests) {
            val lines = manifestBytes.decodeToString().trim().lines()
            val header = lines.first().split('|')
            val totalSize = header[2].toInt()
            val shardCount = header[3].toInt()
            val ownOrdinal = header[5].toInt()
            meshDigests += header[4]
            assertEquals(manifests.size, header[6].toInt(), "Manifest mesh must bind every virtualized method entry")
            assertEquals(shardCount, preloadIndex[manifestPath], "Preload shard count must match manifest header")
            assertTrue(shardCount in 2..6, "Outlined VMBC must be split across a bounded CSPRNG-selected shard count")

            val assembled = ByteArray(totalSize)
            val shardLines = lines.drop(1)
            assertEquals(shardCount, shardLines.size, "Manifest must enumerate every shard")
            for (line in shardLines) {
                val parts = line.split('|')
                val offset = parts[1].toInt()
                val length = parts[2].toInt()
                val shardPath = parts[4]
                val peerOrdinal = parts[6].toInt()
                val shardBytes = assertNotNull(decodedResources[shardPath], "Manifest shard path must resolve to an emitted opaque resource")
                referencedPeerOrdinals += peerOrdinal
                assertTrue(peerOrdinal in 0 until manifests.size, "Shard peer ordinal must point into shared manifest mesh")
                assertTrue(peerOrdinal != ownOrdinal, "Cross-method shard peer link must point at another method manifest")
                assertEquals(length, shardBytes.size, "Shard length metadata must match decoded bytes")
                assertTrue(shardBytes.size < totalSize, "Single outlined shard must not contain the complete VMBC payload")
                shardBytes.copyInto(assembled, offset)
            }
            assertEquals('V'.code.toByte(), assembled[0], "Reassembled VMBC must preserve VBC4 magic")
            assertEquals('B'.code.toByte(), assembled[1], "Reassembled VMBC must preserve VBC4 magic")
            assertEquals('C'.code.toByte(), assembled[2], "Reassembled VMBC must preserve VBC4 magic")
            assertEquals('4'.code.toByte(), assembled[3], "Reassembled VMBC must preserve VBC4 magic")
            for (line in shardLines) {
                val shardBytes = decodedResources.getValue(line.split('|')[4])
                assertFalse(shardBytes.contentEquals(assembled), "No single outlined shard may independently restore the full VM method")
            }
        }
        assertEquals(1, meshDigests.size, "All sliced method manifests must share one interprocedural mesh digest")
        assertTrue(referencedPeerOrdinals.size >= 2, "Cross-method peer links should distribute across the shared dispatch mesh")
    }

    @Test
    fun cross_method_outlining_is_not_reproducible_for_same_seed_and_vbc4_context() {
        val first = encodedCrossMethodResources(context = fixedContext(0x4A53_0001), seed = 73)
        val second = encodedCrossMethodResources(context = fixedContext(0x4A53_0001), seed = 73)
        val differentContext = encodedCrossMethodResources(context = fixedContext(0x4A53_0002), seed = 73)

        assertTrue(
            first.map { it.name } != second.map { it.name } ||
                first.map { it.bytes.toList() } != second.map { it.bytes.toList() },
            "same seed/context must not reproduce outlined resource paths or encoded resources",
        )
        assertTrue(
            first.map { it.name } != differentContext.map { it.name } ||
                first.map { it.bytes.toList() } != differentContext.map { it.bytes.toList() },
            "outlined manifests/shards must diverge across VBC4 build contexts",
        )
    }

    private fun runEngine(inputJar: Path): Path {
        val outputJar = inputJar.resolveSibling("javashroud-cross-method-output.jar")
        val configPath = inputJar.resolveSibling("javashroud-cross-method-config.toml")
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf("method-virtualization", "jni-microkernel-loader"),
            rules = listOf(
                RuleSpec("e2e/CrossMethodOutliningRoot#seed:(I)I", "method-virtualization"),
                RuleSpec("e2e/CrossMethodOutliningRoot#fold:(I)I", "method-virtualization"),
                RuleSpec("e2e/CrossMethodOutliningRoot#verify:()I", "method-virtualization"),
            ),
            passParams = mapOf(
                "method-virtualization" to mapOf(
                    "strictVirtualization" to objectMapper.valueToTree(true),
                    "methodSelection" to objectMapper.valueToTree("all-compatible"),
                    "maxInstructions" to objectMapper.valueToTree(512),
                ),
                "jni-microkernel-loader" to mapOf(
                    "targetPlatform" to objectMapper.valueToTree(currentNativeTargetPlatform()),
                ),
            ),
        )
        try {
            dispatchRequest(buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())), EngineKernel())
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun buildCrossMethodFixtureJar(target: Path): Path {
        Files.newOutputStream(target).use { out ->
            JarOutputStream(out).use { jar ->
                jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
                jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.CrossMethodOutliningRoot\r\n\r\n".toByteArray())
                jar.closeEntry()
                jar.putNextEntry(JarEntry("e2e/CrossMethodOutliningRoot.class"))
                jar.write(crossMethodFixtureClassBytes())
                jar.closeEntry()
            }
        }
        return target
    }

    private fun crossMethodFixtureClassBytes(): ByteArray {
        val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES or org.objectweb.asm.ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "e2e/CrossMethodOutliningRoot", null, "java/lang/Object", null)
        cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "seed", "(I)I", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ILOAD, 0)
            visitIntInsn(Opcodes.BIPUSH, 7)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(2, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "fold", "(I)I", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ILOAD, 0)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/CrossMethodOutliningRoot", "seed", "(I)I", false)
            visitVarInsn(Opcodes.ILOAD, 0)
            visitInsn(Opcodes.ICONST_1)
            visitInsn(Opcodes.IADD)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/CrossMethodOutliningRoot", "seed", "(I)I", false)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(3, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "verify", "()I", null, null).apply {
            visitCode()
            visitInsn(Opcodes.ICONST_5)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/CrossMethodOutliningRoot", "fold", "(I)I", false)
            visitInsn(Opcodes.ICONST_2)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/CrossMethodOutliningRoot", "seed", "(I)I", false)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(2, 0)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null).apply {
            visitCode()
            visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/CrossMethodOutliningRoot", "verify", "()I", false)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(I)V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 1)
            visitEnd()
        }
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun encodedCrossMethodResources(context: Vbc4BuildContext, seed: Int) =
        withVbc4BuildContext(context) {
            val result = applyMethodVirtualization(
                artifact = crossMethodArtifact(),
                ruleMatches = crossMethodRuleMatches(),
                params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to seed),
            )
            assertEquals(3, result.transformedMemberCount, "Fixture must virtualize all selected cross-method entries")
            result.artifact.jarEntries
                .filter { entry -> entry.name.isVmResourceName() || entry.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }
                .sortedBy { it.name }
        }

    private fun decodedCrossMethodResources(context: Vbc4BuildContext, seed: Int) =
        withVbc4BuildContext(context) {
            encodedCrossMethodResources(context, seed)
                .mapNotNull { entry -> RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it } }
                .toMap()
        }

    private fun crossMethodArtifact() = testAttachedArtifact(
        classArtifacts = listOf(
            testClassArtifact(
                internalName = "e2e/CrossMethodOutliningRoot",
                bytes = crossMethodFixtureClassBytes(),
                methodSummaries = listOf(
                    MemberSummary(MemberKind.METHOD, "seed", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    MemberSummary(MemberKind.METHOD, "fold", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    MemberSummary(MemberKind.METHOD, "verify", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                ),
            ),
        ),
    )

    private fun fixedContext(seed: Int): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (seed ushr ((index and 3) * 8) xor index * 23).toByte() },
        nativeSeed = seed.toLong() xor 0x5C4D_1A33L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (seed.rotateLeft(index and 31) xor index * 37).toByte() },
    )

    private fun crossMethodRuleMatches(): List<RuleMatch> = listOf(
        "seed" to "(I)I",
        "fold" to "(I)I",
        "verify" to "()I",
    ).map { (name, descriptor) ->
        RuleMatch(
            rule = RuleSpec(target = "e2e/CrossMethodOutliningRoot#$name:$descriptor", action = "method-virtualization"),
            selector = TargetSelector(
                classPattern = "e2e/CrossMethodOutliningRoot",
                memberPattern = name,
                memberDescriptorPattern = descriptor,
            ),
            matchedClassNames = listOf("e2e/CrossMethodOutliningRoot"),
            matchedMembers = listOf(MatchedMember("e2e/CrossMethodOutliningRoot", MemberKind.METHOD, name, descriptor)),
        )
    }

    private fun methodInvokesNativeVmDispatcher(jarPath: Path, className: String, targetName: String, targetDescriptor: String): Boolean {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == "$className.class") {
                    var found = false
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?): MethodVisitor {
                            if (name != targetName || descriptor != targetDescriptor) return object : MethodVisitor(Opcodes.ASM9) {}
                            return object : MethodVisitor(Opcodes.ASM9) {
                                override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                                    if (
                                        opcode == Opcodes.INVOKESTATIC &&
                                        (descriptor == "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;" ||
                                            descriptor == "(J[Ljava/lang/Object;)Ljava/lang/Object;" ||
                                            descriptor == "(J)V" ||
                                            descriptor == "(JI)V")
                                    ) {
                                        found = true
                                    }
                                }
                            }
                        }
                    }, ClassReader.SKIP_FRAMES)
                    return found
                }
                jar.closeEntry()
            }
        }
        return false
    }

    private fun runJava(jarPath: Path): ProcessResult {
        val process = ProcessBuilder("java", "-jar", jarPath.toAbsolutePath().normalize().toString())
            .redirectErrorStream(true)
            .start()
        val completed = process.waitFor(60, TimeUnit.SECONDS)
        val output = process.inputStream.bufferedReader().readText()
        if (!completed) {
            process.destroyForcibly()
            return ProcessResult(-1, output)
        }
        return ProcessResult(process.exitValue(), output)
    }

    private fun currentNativeTargetPlatform(): String {
        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch").lowercase()
        return when {
            os.contains("win") -> "windows-x64"
            os.contains("mac") && arch.contains("aarch64") -> "macos-arm64"
            os.contains("mac") -> "macos-x64"
            else -> "linux-x64"
        }
    }

    private fun String.isVmResourceName(): Boolean =
        startsWith("META-INF/") && !endsWith(".class") && !endsWith("/") && length > "META-INF/".length + 10

    private data class ProcessResult(val exitCode: Int, val output: String)
}
