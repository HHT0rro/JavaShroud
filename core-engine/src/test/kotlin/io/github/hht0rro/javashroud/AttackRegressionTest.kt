package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelPacker
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AttackRegressionTest {
    @Test
    fun all_runtime_resource_kinds_reject_header_body_length_and_tag_tampering() = withVbc4BuildContext(fixedContext(1)) {
        for (kind in RuntimeResourceKind.entries) {
            val encoded = RuntimeResourceCodec.encode(
                bytes = "attack-regression-${kind.name}-resource".toByteArray(Charsets.UTF_8),
                kind = kind,
                seed = 0x1234_5678 xor kind.id,
                variantId = 3 + kind.id,
                layerCount = 2,
            )

            val offsets = listOf(5, 6, 7, 8, 24, 28, 32, 40, encoded.size - 33, encoded.lastIndex)
            for (offset in offsets) {
                val tampered = encoded.copyOf()
                tampered[offset] = (tampered[offset].toInt() xor 0x5A).toByte()
                assertEquals(null, RuntimeResourceCodec.decode(tampered), "${kind.name} tampering offset $offset must fail closed")
            }
        }
    }

    @Test
    fun copied_runtime_resource_with_wrong_layout_context_fails_closed() {
        val encoded = withVbc4BuildContext(fixedContext(2)) {
            RuntimeResourceCodec.encode(
                bytes = "layout-bound-vm-resource".toByteArray(Charsets.UTF_8),
                kind = RuntimeResourceKind.VmBytecode,
                seed = 0x2468_1357,
                variantId = 4,
                layerCount = 3,
            )
        }

        assertNotEquals(
            encoded.toList(),
            withVbc4BuildContext(fixedContext(3)) {
                RuntimeResourceCodec.encode(
                    bytes = "layout-bound-vm-resource".toByteArray(Charsets.UTF_8),
                    kind = RuntimeResourceKind.VmBytecode,
                    seed = 0x2468_1357,
                    variantId = 4,
                    layerCount = 3,
                ).toList()
            },
            "different context must produce different authenticated resource bytes",
        )
        assertEquals(null, withVbc4BuildContext(fixedContext(3)) { RuntimeResourceCodec.decode(encoded) }, "wrong layout/runtime key must fail closed")
    }

    @Test
    fun native_runtime_contains_trampoline_and_debugger_poison_gates() {
        val nativeSources = listOf(
            Path.of("src/main/native/js_helpers.c"),
            Path.of("src/main/native/js_antidebug.c"),
            Path.of("src/main/native/js_vm_core.c"),
            Path.of("src/main/native/js_vm_resource.c"),
        ).filter { Files.exists(it) }.joinToString("\n") { Files.readString(it) }

        assertTrue(nativeSources.contains("js_check_trampoline"), "native runtime must keep Frida-like trampoline detection gate")
        assertTrue(nativeSources.contains("js_vm_anti_trace_check"), "native runtime must keep debugger/trace detection gate")
        assertTrue(nativeSources.contains("js_vm_trace_poison_seed"), "debugger strong-signal path must poison VM execution state")
        assertTrue(nativeSources.contains("js_vm_fail_closed"), "attack checks must terminate through fail-closed native path")
    }

    @Test
    fun native_runtime_rotates_resident_blocks_not_only_single_opcode_rewraps() {
        val core = Files.readString(Path.of("src/main/native/js_vm_core.c"))
        val executeLoop = core.substringAfter("JS_HIDDEN int js_vm_execute(")

        assertTrue(core.contains("js_vm_rotate_resident_block"), "native runtime must keep block-level resident rotation")
        assertTrue(core.contains("p->resident_rotation_epoch ^="), "block rotation must mutate resident block epoch")
        assertTrue(core.contains("window = 2 +"), "block rotation must cover more than one resident opcode")
        assertTrue(core.contains("for (int offset = 0; offset < window; offset++)"), "block rotation must re-mask every opcode in the window")
        assertTrue(
            executeLoop.indexOf("js_vm_rotate_resident_block") in 0 until executeLoop.indexOf("js_vm_rewrap_resident_opcode"),
            "execute loop must rotate resident block before per-opcode rewrap",
        )
    }

    @Test
    fun native_bootstrap_index_tampering_fails_closed() = withVbc4BuildContext(fixedContext(4, ByteArray(32))) {
        val inputDir = Files.createTempDirectory("javashroud-native-pack-input")
        val outputDir = Files.createTempDirectory("javashroud-native-pack-output")
        val wrongTokenOutputDir = Files.createTempDirectory("javashroud-native-pack-wrong-token")
        try {
            Files.writeString(inputDir.resolve("js_kernel_linux-x64.so"), "bootstrap-index-regression")
            val packed = NativeKernelPacker.pack(inputDir, outputDir, 0x5EEDL)
            val decode = JniMicrokernelHelper::class.java.getDeclaredMethod("decodeBootstrapNativeIndex", ByteArray::class.java)
            decode.isAccessible = true

            val decoded = decode.invoke(null, packed.indexBytes) as ByteArray?
            assertTrue(decoded != null && decoded.isNotEmpty(), "valid bootstrap index must decode")

            for (offset in listOf(0, 4, 5, 8, 9, packed.indexBytes.size - 33, packed.indexBytes.lastIndex)) {
                val tampered = packed.indexBytes.copyOf()
                tampered[offset] = (tampered[offset].toInt() xor 0x5A).toByte()
                assertEquals(null, decode.invoke(null, tampered), "tampering offset $offset must fail closed")
            }

            val wrongLength = packed.indexBytes.copyOf()
            wrongLength[5] = (wrongLength[5].toInt() xor 0x01).toByte()
            assertEquals(null, decode.invoke(null, wrongLength), "length tamper must fail closed")

            val wrongTokenIndex = withVbc4BuildContext(fixedContext(44, ByteArray(32) { index -> (index + 1).toByte() })) {
                NativeKernelPacker.pack(inputDir, wrongTokenOutputDir, 0x5EEDL).indexBytes
            }
            assertEquals(null, decode.invoke(null, wrongTokenIndex), "wrong bootstrap runtime token must fail closed")
        } finally {
            Files.walk(wrongTokenOutputDir).use { stream ->
                stream.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
            Files.walk(outputDir).use { stream ->
                stream.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
            Files.walk(inputDir).use { stream ->
                stream.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun sliced_vm_resources_reject_tampered_manifest_missing_shard_and_shard_digest_mismatch() = withVbc4BuildContext(fixedContext(5)) {
        val encodedResources = attackVmResources()
        val decodedResources = encodedResources.mapNotNull { entry ->
            RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it }
        }.toMap()
        val manifest = decodedResources.entries.firstOrNull { it.value.decodeToString().startsWith("VBC4S|1|") }
        assertTrue(manifest != null, "attack fixture must emit at least one sliced VM manifest")
        assertTrue(slicedManifestIsComplete(manifest.value, decodedResources), "valid generated sliced manifest must reassemble")

        val manifestLines = manifest.value.decodeToString().trim().lines()
        val firstShardPath = manifestLines.drop(1).first().split('|')[4]

        val tamperedManifest = manifestLines.toMutableList().also { lines ->
            val parts = lines[1].split('|').toMutableList()
            parts[3] = parts[3].replaceRange(0, 1, if (parts[3][0] == '0') "1" else "0")
            lines[1] = parts.joinToString("|")
        }.joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
        assertEquals(false, slicedManifestIsComplete(tamperedManifest, decodedResources), "tampered manifest digest must fail closed")

        assertEquals(
            false,
            slicedManifestIsComplete(manifest.value, decodedResources - firstShardPath),
            "missing shard resource must fail closed",
        )

        val tamperedShardResources = decodedResources.toMutableMap()
        tamperedShardResources[firstShardPath] = tamperedShardResources.getValue(firstShardPath).copyOf().also { shard ->
            shard[shard.lastIndex] = (shard.last().toInt() xor 0x5A).toByte()
        }
        assertEquals(false, slicedManifestIsComplete(manifest.value, tamperedShardResources), "shard digest mismatch must fail closed")

        val encodedManifest = encodedResources.first { it.name == manifest.key }
        val tamperedEncodedManifest = encodedManifest.bytes.copyOf().also { bytes ->
            bytes[bytes.lastIndex - 1] = (bytes[bytes.lastIndex - 1].toInt() xor 0x5A).toByte()
        }
        assertEquals(null, RuntimeResourceCodec.decode(tamperedEncodedManifest), "encoded manifest byte tampering must fail closed")
    }

    private fun attackVmResources() = applyMethodVirtualization(
        artifact = testAttachedArtifact(
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = "attack/SlicedVmAttackRoot",
                    bytes = attackFixtureClassBytes(),
                    methodSummaries = listOf(
                        MemberSummary(MemberKind.METHOD, "seed", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "fold", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                        MemberSummary(MemberKind.METHOD, "verify", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    ),
                ),
            ),
        ),
        ruleMatches = listOf(
            "seed" to "(I)I",
            "fold" to "(I)I",
            "verify" to "()I",
        ).map { (name, descriptor) ->
            RuleMatch(
                rule = RuleSpec(target = "attack/SlicedVmAttackRoot#$name:$descriptor", action = "method-virtualization"),
                selector = TargetSelector(
                    classPattern = "attack/SlicedVmAttackRoot",
                    memberPattern = name,
                    memberDescriptorPattern = descriptor,
                ),
                matchedClassNames = listOf("attack/SlicedVmAttackRoot"),
                matchedMembers = listOf(MatchedMember("attack/SlicedVmAttackRoot", MemberKind.METHOD, name, descriptor)),
            )
        },
        params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to 91),
    ).artifact.jarEntries.filter { entry -> entry.name.isVmResourceName() || entry.name == "META-INF/.r/vm.idx" }

    private fun slicedManifestIsComplete(manifestBytes: ByteArray, resources: Map<String, ByteArray>): Boolean {
        val lines = manifestBytes.decodeToString().trim().lines()
        val header = lines.firstOrNull()?.split('|') ?: return false
        if (header.size != 7 || header[0] != "VBC4S" || header[1] != "1") return false
        val totalSize = header[2].toIntOrNull() ?: return false
        val shardCount = header[3].toIntOrNull() ?: return false
        if (totalSize <= 0 || shardCount <= 0 || lines.size != shardCount + 1) return false
        val covered = BooleanArray(totalSize)
        val seenIndexes = mutableSetOf<Int>()
        for (line in lines.drop(1)) {
            val parts = line.split('|')
            if (parts.size != 8) return false
            val index = parts[0].toIntOrNull() ?: return false
            val offset = parts[1].toIntOrNull() ?: return false
            val length = parts[2].toIntOrNull() ?: return false
            val expectedDigest = parts[3]
            val shardBytes = resources[parts[4]] ?: return false
            if (!seenIndexes.add(index) || length != shardBytes.size || offset < 0 || offset + length > totalSize) return false
            if (sha256Hex(shardBytes) != expectedDigest) return false
            for (cursor in offset until offset + length) {
                if (covered[cursor]) return false
                covered[cursor] = true
            }
        }
        return seenIndexes.size == shardCount && covered.all { it }
    }

    private fun attackFixtureClassBytes(): ByteArray {
        val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES or org.objectweb.asm.ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "attack/SlicedVmAttackRoot", null, "java/lang/Object", null)
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
            visitIntInsn(Opcodes.BIPUSH, 9)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(2, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "fold", "(I)I", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ILOAD, 0)
            visitMethodInsn(Opcodes.INVOKESTATIC, "attack/SlicedVmAttackRoot", "seed", "(I)I", false)
            visitVarInsn(Opcodes.ILOAD, 0)
            visitInsn(Opcodes.ICONST_2)
            visitInsn(Opcodes.IADD)
            visitMethodInsn(Opcodes.INVOKESTATIC, "attack/SlicedVmAttackRoot", "seed", "(I)I", false)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(3, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "verify", "()I", null, null).apply {
            visitCode()
            visitInsn(Opcodes.ICONST_4)
            visitMethodInsn(Opcodes.INVOKESTATIC, "attack/SlicedVmAttackRoot", "fold", "(I)I", false)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }

    private fun String.isVmResourceName(): Boolean =
        startsWith("META-INF/") && !endsWith(".class") && !endsWith("/") && length > "META-INF/".length + 10

    private fun fixedContext(seed: Int, runtimeResourceKey: ByteArray? = null): Vbc4BuildContext {
        val masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (seed * 19 + index * 7).toByte() }
        val nativeSeed = seed.toLong() * 0x1234_5679L
        val jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (seed * 23 + index * 11).toByte() }
        return if (runtimeResourceKey == null) {
            Vbc4BuildContext(
                masterKey = masterKey,
                nativeSeed = nativeSeed,
                jarLayoutDigest = jarLayoutDigest,
            )
        } else {
            Vbc4BuildContext(
                masterKey = masterKey,
                nativeSeed = nativeSeed,
                jarLayoutDigest = jarLayoutDigest,
                runtimeResourceKey = runtimeResourceKey,
            )
        }
    }
}
