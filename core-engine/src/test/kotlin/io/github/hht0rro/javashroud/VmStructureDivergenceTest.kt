package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.Vbc4EntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VmStructureDivergenceTest {
    private companion object {
        const val VBC4_FLAG_NESTED_VM_TEST = 0x1000
    }

    @Test
    fun same_guest_program_has_seed_divergent_block_layout_and_dispatch_tokens() {
        val first = serializedLayout(0x1100_0001)
        val second = serializedLayout(0x2200_0002)

        assertFalse(first.payload.contentEquals(second.payload), "same guest program must not serialize to reusable VMBC bytes across build seeds")
        assertTrue(first.blockCount > 1 && second.blockCount > 1, "fixture must exercise multi-block VMBC layout")
        assertTrue(
            first.blockIds != second.blockIds || first.dispatchTokens != second.dispatchTokens,
            "block order or dispatch tokens must differ across build seeds",
        )
    }

    @Test
    fun same_guest_program_is_not_reproducible_for_same_seed_and_context() {
        val first = serializedLayout(0x3300_0003)
        val second = serializedLayout(0x3300_0003)

        assertFalse(first.payload.contentEquals(second.payload), "same seed/context must not reproduce exact VMBC bytes")
        assertTrue(
            first.blockIds != second.blockIds || first.dispatchTokens != second.dispatchTokens,
            "same seed/context must not reproduce block order and dispatch metadata",
        )
    }

    @Test
    fun repeated_same_seed_same_context_builds_have_high_uniqueness() {
        val snapshots = (0 until 16).map { serializedLayout(0x3300_0003, contextSeed = 0x3300_0003) }
        assertTrue(snapshots.map { sha256Hex(it.payload) }.toSet().size >= 14, "VMBC payloads should be mostly unique across same-seed builds")
        assertTrue(snapshots.map { it.blockIds.joinToString(",") }.toSet().size >= 2, "block storage order should vary across same-seed builds")
        assertTrue(snapshots.map { it.dispatchTokens.joinToString(",") }.toSet().size >= 14, "dispatch tokens should be mostly unique across same-seed builds")
    }

    @Test
    fun branch_switch_and_try_methods_keep_partitioned_layout() {
        val snapshots = (0 until 12).map { controlFlowLayout(0x4100_0000 + it) }
        assertTrue(snapshots.all { it.blockCount > 1 }, "control-flow methods must not collapse to a stable single VBC4 block")
        assertTrue(snapshots.any { it.blockIds != it.blockIds.sorted() }, "control-flow methods should still allow shuffled storage order")
    }

    @Test
    fun same_build_seed_uses_vbc4_build_context_for_structure_derivation() {
        val first = serializedLayout(seed = 0x4400_0004, contextSeed = 0x5500_0005)
        val second = serializedLayout(seed = 0x4400_0004, contextSeed = 0x6600_0006)

        assertFalse(first.payload.contentEquals(second.payload), "same guest program and seed must still bind VMBC bytes to per-build VBC4 context")
        assertTrue(
            first.blockIds != second.blockIds || first.dispatchTokens != second.dispatchTokens,
            "VBC4 build context must participate in block order or dispatch metadata derivation",
        )
    }

    @Test
    fun block_dispatch_tokens_carry_state_bound_payload_not_plain_linear_next() {
        val snapshot = serializedLayout(0x7700_0007)
        assertTrue(snapshot.blockCount > 1, "fixture must exercise multi-block dispatch")
        val effectiveSeed = snapshot.effectiveSeed

        for (entry in snapshot.entries) {
            val legacyPayload = entry.token xor dispatchMask(effectiveSeed, entry.blockId, snapshot.blockCount)
            val expectedNext = if (entry.blockId + 1 < snapshot.blockCount) entry.blockId + 1 else snapshot.blockCount
            assertTrue(
                legacyPayload !in 0..snapshot.blockCount,
                "multi-block dispatch must not emit legacy raw-next ids",
            )
            assertEquals(expectedNext, decodeDispatchNext(effectiveSeed, entry.blockId, snapshot.blockCount, entry.token), "state-bound dispatch payload must decode to semantic next block")
        }
    }

    @Test
    fun dispatch_chain_reassembles_logical_order_from_shuffled_storage_order() {
        val snapshot = (0 until 32)
            .asSequence()
            .map { serializedLayout(0x7800_0000 + it) }
            .first { it.blockIds != (0 until it.blockCount).toList() }

        assertEquals((0 until snapshot.blockCount).toList(), dispatchChain(snapshot), "state-bound dispatch chain must recover logical execution order from shuffled storage")
    }

    @Test
    fun full_chain_structure_diverges_across_repeated_same_context_builds() {
        val first = fullChainSnapshot(seed = 0x5100_0001, contextSeed = 0x6100_0001)
        val second = fullChainSnapshot(seed = 0x5100_0001, contextSeed = 0x6100_0001)
        val different = fullChainSnapshot(seed = 0x5100_0001, contextSeed = 0x6200_0002)

        assertTrue(
            first.blockIds != second.blockIds ||
                first.dispatchTokens != second.dispatchTokens ||
                first.nestedDigest != second.nestedDigest ||
                first.resourceNames != second.resourceNames ||
                first.resourceDigests != second.resourceDigests ||
                first.manifestHeaders != second.manifestHeaders,
            "full-chain structure must not reproduce for same seed/context",
        )
        assertTrue(first.blockIds != different.blockIds || first.dispatchTokens != different.dispatchTokens, "flattened block layout or dispatch tokens must diverge across VBC4 contexts")
        assertTrue(first.nestedFlags != 0, "full-chain fixture must enable nested VM layer")
        assertTrue(first.nestedDigest != different.nestedDigest, "nested VM envelope must diverge across VBC4 contexts")
        assertTrue(first.resourceNames != different.resourceNames || first.resourceDigests != different.resourceDigests, "outlined resources and shared dispatch mesh must diverge across VBC4 contexts")
        assertTrue(first.manifestHeaders != different.manifestHeaders, "outlined manifest mesh metadata must diverge across VBC4 contexts")
    }

    @Test
    fun self_heal_rotation_contract_uses_resident_seed_and_shared_dispatch_state() {
        val core = Files.readString(Path.of("src/main/native/js_vm_core.c"))
        val rotateBlock = core.substringAfter("JS_HIDDEN void js_vm_rotate_resident_block(").substringBefore("JS_HIDDEN")
        val executeLoop = core.substringAfter("JS_HIDDEN int js_vm_execute(")

        assertTrue(rotateBlock.contains("js_vm_load_resident_build_seed"), "resident block rotation must bind to resident build seed")
        assertTrue(rotateBlock.contains("resident_rotation_epoch"), "resident block rotation must mutate resident epoch")
        assertTrue(executeLoop.contains("js_vm_shared_dispatch_seed_for"), "execute loop must derive shared dispatch seed")
        assertTrue(executeLoop.indexOf("js_vm_rotate_resident_block") in 0 until executeLoop.indexOf("js_vm_rewrap_resident_opcode"), "execute loop must rotate resident block before per-opcode rewrap")

        val initial = residentDump(
            opcodes = List(12) { index -> 0x50 + index * 7 },
            epochs = List(12) { index -> 0x1000_0000.toInt() xor index * 0x0101_0101 },
            residentEpoch = 0x2468_1357,
        )
        val first = rotateResidentDump(initial, buildSeed = 0x1234_5678, macKey = 0x3322_1100, anchor = 5, step = 64, dispatchDriftState = 0x4567_1357, pcAfterFetch = 9, stackDepth = 3)
        val repeat = rotateResidentDump(initial, buildSeed = 0x1234_5678, macKey = 0x3322_1100, anchor = 5, step = 64, dispatchDriftState = 0x4567_1357, pcAfterFetch = 9, stackDepth = 3)
        val differentSeed = rotateResidentDump(initial, buildSeed = 0x1234_5679, macKey = 0x3322_1100, anchor = 5, step = 64, dispatchDriftState = 0x4567_1357, pcAfterFetch = 9, stackDepth = 3)
        val differentDispatch = rotateResidentDump(initial, buildSeed = 0x1234_5678, macKey = 0x3322_1100, anchor = 5, step = 64, dispatchDriftState = 0x4567_1358, pcAfterFetch = 9, stackDepth = 3)

        assertEquals(first, repeat, "resident rotation must reproduce for same runtime state")
        assertTrue(first != initial, "resident rotation must change dumped resident opcode/epoch state")
        assertTrue(first != differentSeed, "resident rotation dump must diverge across resident build seeds")
        assertTrue(first != differentDispatch, "resident rotation dump must diverge across shared dispatch drift state")
    }
    private fun serializedLayout(seed: Int, contextSeed: Int = seed, nestedProfile: Int = 0, structureEntropy: ByteArray? = null): LayoutSnapshot {
        val context = fixedContext(contextSeed)
        return withVbc4BuildContext(context) {
            val serializer = if (structureEntropy == null) {
                VmBytecodeSerializer(
                    buildSeed = seed,
                    stateBinding = "structure-divergence-fixture",
                    entryMetadata = Vbc4EntryMetadata(methodLocalProfile = nestedProfile),
                    buildContext = context,
                )
            } else {
                VmBytecodeSerializer(
                    buildSeed = seed,
                    stateBinding = "structure-divergence-fixture",
                    entryMetadata = Vbc4EntryMetadata(methodLocalProfile = nestedProfile),
                    buildContext = context,
                    structureEntropy = structureEntropy,
                )
            }
            serializer.visitCode()
            repeat(128) { index ->
                serializer.visitLdcInsn(index xor (index shl 2))
                serializer.visitInsn(Opcodes.POP)
                serializer.visitInsn(Opcodes.ICONST_1)
                serializer.visitInsn(Opcodes.ICONST_2)
                serializer.visitInsn(Opcodes.IADD)
                serializer.visitInsn(Opcodes.POP)
            }
            serializer.visitInsn(Opcodes.ICONST_1)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitMaxs(8, 8)
            serializer.visitEnd()

            val bytes = serializer.serialize()
            val flags = readU2(bytes, 42)
            val blockCount = readU2(bytes, 44)
            val entries = readBlockIndex(bytes, blockCount)
            LayoutSnapshot(
                payload = bytes,
                seed = seed,
                context = context,
                effectiveSeed = effectiveBuildSeed(serializer),
                flags = flags,
                blockCount = blockCount,
                entries = entries,
                blockIds = entries.map { it.blockId },
                dispatchTokens = entries.map { it.token },
            )
        }
    }

    private fun controlFlowLayout(seed: Int): LayoutSnapshot {
        val context = fixedContext(seed)
        return withVbc4BuildContext(context) {
            val serializer = VmBytecodeSerializer(
                buildSeed = seed,
                stateBinding = "control-flow-structure-fixture",
                entryMetadata = Vbc4EntryMetadata(methodLocalProfile = 0),
                buildContext = context,
            )
            val start = org.objectweb.asm.Label()
            val handler = org.objectweb.asm.Label()
            val done = org.objectweb.asm.Label()
            val dflt = org.objectweb.asm.Label()
            val case0 = org.objectweb.asm.Label()
            val case1 = org.objectweb.asm.Label()
            serializer.visitCode()
            serializer.visitTryCatchBlock(start, done, handler, "java/lang/RuntimeException")
            serializer.visitLabel(start)
            serializer.visitVarInsn(Opcodes.ILOAD, 0)
            serializer.visitInsn(Opcodes.ICONST_1)
            serializer.visitInsn(Opcodes.IAND)
            serializer.visitLookupSwitchInsn(dflt, intArrayOf(0, 1), arrayOf(case0, case1))
            serializer.visitLabel(case0)
            serializer.visitIntInsn(Opcodes.BIPUSH, 7)
            serializer.visitJumpInsn(Opcodes.GOTO, done)
            serializer.visitLabel(case1)
            serializer.visitIntInsn(Opcodes.BIPUSH, 11)
            serializer.visitJumpInsn(Opcodes.GOTO, done)
            serializer.visitLabel(dflt)
            serializer.visitIntInsn(Opcodes.BIPUSH, 13)
            serializer.visitLabel(done)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitLabel(handler)
            serializer.visitInsn(Opcodes.POP)
            serializer.visitInsn(Opcodes.ICONST_M1)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitMaxs(4, 1)
            serializer.visitEnd()
            val bytes = serializer.serialize()
            val flags = readU2(bytes, 42)
            val blockCount = readU2(bytes, 44)
            val entries = readBlockIndex(bytes, blockCount)
            LayoutSnapshot(bytes, seed, context, effectiveBuildSeed(serializer), flags, blockCount, entries, entries.map { it.blockId }, entries.map { it.token })
        }
    }

    private fun fullChainSnapshot(seed: Int, contextSeed: Int): FullChainSnapshot {
        val layout = serializedLayout(seed = seed, contextSeed = contextSeed, nestedProfile = 0x1357_2468)
        val context = fixedContext(contextSeed)
        val resources = encodedOutlinedResources(context = context, seed = seed)
        val decoded = withVbc4BuildContext(context) {
            resources.mapNotNull { entry -> RuntimeResourceCodec.decode(entry.bytes)?.let { entry.name to it } }.toMap()
        }
        val manifestHeaders = decoded.values
            .mapNotNull { bytes -> bytes.decodeToString().trim().lines().firstOrNull()?.takeIf { it.startsWith("VBC4S|1|") } }
            .sorted()
        return FullChainSnapshot(
            blockIds = layout.blockIds,
            dispatchTokens = layout.dispatchTokens,
            nestedFlags = layout.flags and VBC4_FLAG_NESTED_VM_TEST,
            nestedDigest = sha256Hex(layout.payload),
            resourceNames = resources.map { it.name },
            resourceDigests = resources.map { sha256Hex(it.bytes) },
            manifestHeaders = manifestHeaders,
        )
    }

    private fun encodedOutlinedResources(context: Vbc4BuildContext, seed: Int) = withVbc4BuildContext(context) {
        val result = applyMethodVirtualization(
            artifact = outliningArtifact(),
            ruleMatches = outliningRuleMatches(),
            params = mapOf("maxInstructions" to Int.MAX_VALUE, "seed" to seed),
        )
        assertEquals(3, result.transformedMemberCount, "full-chain fixture must virtualize every selected method")
        result.artifact.jarEntries
            .filter { entry -> entry.name.isVmResourceName() || entry.name == "META-INF/.r/vm.idx" }
            .sortedBy { it.name }
    }

    private fun outliningArtifact() = testAttachedArtifact(
        classArtifacts = listOf(
            testClassArtifact(
                internalName = "e2e/FullChainStructureRoot",
                bytes = outliningFixtureClassBytes(),
                methodSummaries = listOf(
                    MemberSummary(MemberKind.METHOD, "seed", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    MemberSummary(MemberKind.METHOD, "fold", "(I)I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                    MemberSummary(MemberKind.METHOD, "verify", "()I", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC),
                ),
            ),
        ),
    )

    private fun outliningRuleMatches(): List<RuleMatch> = listOf(
        "seed" to "(I)I",
        "fold" to "(I)I",
        "verify" to "()I",
    ).map { (name, descriptor) ->
        RuleMatch(
            rule = RuleSpec(target = "e2e/FullChainStructureRoot#$name:$descriptor", action = "method-virtualization"),
            selector = TargetSelector(
                classPattern = "e2e/FullChainStructureRoot",
                memberPattern = name,
                memberDescriptorPattern = descriptor,
            ),
            matchedClassNames = listOf("e2e/FullChainStructureRoot"),
            matchedMembers = listOf(MatchedMember("e2e/FullChainStructureRoot", MemberKind.METHOD, name, descriptor)),
        )
    }

    private fun outliningFixtureClassBytes(): ByteArray {
        val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES or org.objectweb.asm.ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "e2e/FullChainStructureRoot", null, "java/lang/Object", null)
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
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/FullChainStructureRoot", "seed", "(I)I", false)
            visitVarInsn(Opcodes.ILOAD, 0)
            visitInsn(Opcodes.ICONST_1)
            visitInsn(Opcodes.IADD)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/FullChainStructureRoot", "seed", "(I)I", false)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(3, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "verify", "()I", null, null).apply {
            visitCode()
            visitInsn(Opcodes.ICONST_5)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/FullChainStructureRoot", "fold", "(I)I", false)
            visitInsn(Opcodes.ICONST_2)
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/FullChainStructureRoot", "seed", "(I)I", false)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(2, 0)
            visitEnd()
        }
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun String.isVmResourceName(): Boolean =
        startsWith("META-INF/") && !endsWith(".class") && !endsWith("/") && length > "META-INF/".length + 10

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }

    private fun fixedContext(seed: Int): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (seed ushr ((index and 3) * 8) xor index * 17).toByte() },
        nativeSeed = seed.toLong() xor 0x5A5A_1357L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (seed.rotateLeft(index and 31) xor index * 31).toByte() },
    )

    private data class FullChainSnapshot(
        val blockIds: List<Int>,
        val dispatchTokens: List<Int>,
        val nestedFlags: Int,
        val nestedDigest: String,
        val resourceNames: List<String>,
        val resourceDigests: List<String>,
        val manifestHeaders: List<String>,
    )

    private data class LayoutSnapshot(
        val payload: ByteArray,
        val seed: Int,
        val context: Vbc4BuildContext,
        val effectiveSeed: Int,
        val flags: Int,
        val blockCount: Int,
        val entries: List<BlockIndexEntry>,
        val blockIds: List<Int>,
        val dispatchTokens: List<Int>,
    )

    private data class BlockIndexEntry(val blockId: Int, val token: Int)

    private data class ResidentDump(
        val opcodes: List<Int>,
        val epochs: List<Int>,
        val residentEpoch: Int,
    )

    private fun residentDump(opcodes: List<Int>, epochs: List<Int>, residentEpoch: Int): ResidentDump {
        require(opcodes.size == epochs.size)
        return ResidentDump(opcodes = opcodes, epochs = epochs, residentEpoch = residentEpoch)
    }

    private fun rotateResidentDump(
        dump: ResidentDump,
        buildSeed: Int,
        macKey: Int,
        anchor: Int,
        step: Int,
        dispatchDriftState: Int,
        pcAfterFetch: Int,
        stackDepth: Int,
    ): ResidentDump {
        val count = dump.opcodes.size
        if (count <= 1) return dump
        var seed = buildSeed xor macKey xor dispatchDriftState
        seed = seed xor (step * 0x9E3779B1.toInt()) xor (pcAfterFetch * 0x85EBCA77.toInt()) xor (stackDepth * 0xC2B2AE3D.toInt())
        seed = seed xor (seed ushr 16)
        seed *= 0x7FEB352D
        seed = seed xor (seed ushr 15)
        val window = minOf(2 + (seed and 0x3), count)
        var start = anchor - ((seed ushr 8).floorMod(window))
        while (start < 0) start += count
        start %= count
        val nextResidentEpoch = dump.residentEpoch xor seed.rotateLeft((anchor + window) and 31) xor (window * 0x165667B1)
        val nextEpochs = dump.epochs.toMutableList()
        for (offset in 0 until window) {
            val index = (start + offset) % count
            nextEpochs[index] = residentNextOpcodeEpoch(
                buildSeed = buildSeed,
                macKey = macKey,
                oldEpoch = dump.epochs[index] xor (seed + offset * 0x45D9F3B),
                index = index,
                step = step + offset,
                pcAfterFetch = pcAfterFetch,
                stackDepth = stackDepth + offset,
            )
        }
        return dump.copy(epochs = nextEpochs, residentEpoch = nextResidentEpoch)
    }

    private fun residentNextOpcodeEpoch(
        buildSeed: Int,
        macKey: Int,
        oldEpoch: Int,
        index: Int,
        step: Int,
        pcAfterFetch: Int,
        stackDepth: Int,
    ): Int {
        var x = oldEpoch xor buildSeed xor (macKey shl 1)
        x = x xor (index * 0x27D4EB2D) xor (step * 0x165667B1) xor (pcAfterFetch * 0x85EBCA77.toInt()) xor (stackDepth * 0xC2B2AE3D.toInt())
        x = x xor (x ushr 16)
        x *= 0x7FEB352D
        x = x xor (x ushr 15)
        x *= 0x846CA68B.toInt()
        return x xor (x ushr 16)
    }

    private fun Int.floorMod(modulus: Int): Int = ((this % modulus) + modulus) % modulus

    private fun readBlockIndex(bytes: ByteArray, blockCount: Int): List<BlockIndexEntry> {
        val cpSectionSize = readU4(bytes, 50)
        var offset = 54 + cpSectionSize
        return (0 until blockCount).map {
            val entry = BlockIndexEntry(
                blockId = readU2(bytes, offset),
                token = readU4(bytes, offset + 6),
            )
            offset += 10
            entry
        }
    }

    private fun decodeDispatchNext(seed: Int, blockId: Int, blockCount: Int, token: Int): Int {
        val payload = token xor dispatchMask(seed, blockId, blockCount)
        val nextId = payload and 0xFFFF
        val state = (payload ushr 16) and 0xFFFF
        val expected = dispatchState(seed, blockId, nextId, blockCount)
        return if (state == expected) nextId else -1
    }

    private fun dispatchChain(snapshot: LayoutSnapshot): List<Int> {
        val effectiveSeed = snapshot.effectiveSeed
        val entriesByBlock = snapshot.entries.associateBy { it.blockId }
        val chain = mutableListOf<Int>()
        var blockId = 0
        repeat(snapshot.blockCount) {
            chain.add(blockId)
            val entry = entriesByBlock[blockId] ?: return chain
            blockId = decodeDispatchNext(effectiveSeed, blockId, snapshot.blockCount, entry.token)
        }
        return if (blockId == snapshot.blockCount) chain else chain + blockId
    }

    private fun dispatchMask(seed: Int, blockId: Int, blockCount: Int): Int =
        seed.rotateLeft((blockId * 5 + 7) and 31) xor
            (blockId * 0x45D9F3B) xor
            (blockCount * 0x119DE1F3)

    private fun dispatchState(seed: Int, blockId: Int, nextBlockId: Int, blockCount: Int): Int {
        val mixed = seed.rotateLeft((blockId * 3 + 11) and 31) xor
            (blockId * 0x632BE59B) xor
            (nextBlockId * 0x85157AF5.toInt()) xor
            (blockCount * 0x9E3779B9.toInt())
        val state = (mixed xor (mixed ushr 16)) and 0xFFFF
        return if (state == 0) 1 else state
    }

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    private fun effectiveBuildSeed(serializer: VmBytecodeSerializer): Int =
        serializer.javaClass.getDeclaredField("effectiveBuildSeed").apply { isAccessible = true }.getInt(serializer)

    private fun readU2(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU4(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

}
