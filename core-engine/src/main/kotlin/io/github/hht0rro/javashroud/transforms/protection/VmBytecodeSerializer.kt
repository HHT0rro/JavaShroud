package io.github.hht0rro.javashroud.transforms.protection

import org.objectweb.asm.*
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal data class Vbc4EntryMetadata(
    val entryToken: Long = 0L,
    val ownerToken: String = "",
    val methodToken: String = "",
    val returnDescriptor: String = "V",
    val methodLocalProfile: Int = 0,
    val originalOwner: String = "",
    val originalName: String = "",
    val originalDescriptor: String = "",
    val resourcePath: String = "",
    val originalAccess: Int = 0,
) {
    fun encode(): String = listOf(
        "vbc4-meta",
        entryToken.toULong().toString(16),
        ownerToken,
        methodToken,
        returnDescriptor,
        methodLocalProfile.toUInt().toString(16),
        originalOwner,
        originalName,
        originalDescriptor,
        resourcePath,
        originalAccess.toUInt().toString(16),
    ).joinToString("|")
}/**
 * VBC4 bytecode serializer.
 *
 * The Kotlin side is compile-time only: it captures JVM bytecode, builds a
 * logical register program for native validation/diversity, and emits an
 * encrypted VBC4 resource consumed exclusively by the C VM.
 */
internal class VmBytecodeSerializer(
    private val buildSeed: Int = 0,
    private val stateBinding: String = "",
    private val entryMetadata: Vbc4EntryMetadata = Vbc4EntryMetadata(),
    buildContext: Vbc4BuildContext,
    structureEntropy: ByteArray = randomVbc4StructureEntropy(),
) : MethodVisitor(Opcodes.ASM9) {

    private val serializationBuildContext: Vbc4BuildContext = buildContext
    private val structureEntropyDigest: ByteArray = structureEntropy.copyOf()
    private val effectiveBuildSeed: Int = deriveVbc4StructureSeed(buildContext, buildSeed, entryMetadata, structureEntropy)
    private val vbc4MasterKey: ByteArray = serializationBuildContext.copyMasterKey()
    private val vbc4LayoutDigest: ByteArray = serializationBuildContext.jarLayoutDigest.copyOf()
    private val opcodeDialectSalt: Int = vbc4OpcodeDialectSalt(effectiveBuildSeed, stateBinding, entryMetadata) xor readMacInt(structureEntropyDigest)
    private val structureSalt: Int = readMacInt(structureEntropyDigest)

    private val instructions = mutableListOf<VmInstruction>()
    private val constantPool = mutableListOf<Any>()
    private val constantPoolIndex = linkedMapOf<Any, Int>()
    private val exceptionEntries = mutableListOf<VmExceptionEntry>()
    private val labelToOffset = mutableMapOf<Label, Int>()
    private val labelRefs = mutableListOf<LabelRef>()
    private var currentOffset = 0

    data class VmInstruction(
        val offset: Int,
        val opcode: Int,
        val operands: List<Any> = emptyList(),
    )

    data class VmExceptionEntry(
        val start: Label,
        val end: Label,
        val handler: Label,
        val typeCpIndex: Int,
    )

    data class LabelRef(
        val instructionIndex: Int,
        val operandIndex: Int,
        val label: Label,
    )

    data class VmLogicalProgram(
        val registerCount: Int,
        val blocks: List<VmLogicalBlock>,
    )

    data class VmLogicalBlock(
        val blockId: Int,
        val entryToken: Int,
        val instructions: List<VmRegisterInstruction>,
    )

    data class VmRegisterInstruction(
        val opcode: Int,
        val flags: Int,
        val dst: Int,
        val srcA: Int,
        val srcB: Int,
        val operand: Int,
    )

    fun serialize(): ByteArray {
        return Vbc4CryptoScope.use(vbc4MasterKey, vbc4LayoutDigest) {
            try {
                serializeWithActiveKey()
            } finally {
                java.util.Arrays.fill(vbc4MasterKey, 0)
                java.util.Arrays.fill(vbc4LayoutDigest, 0)
            }
        }
    }

    private fun serializeWithActiveKey(): ByteArray {
        resolveLabelReferences()

        val metadataCpIndex = addConstant(entryMetadata.encode())
        val logicalProgram = lowerToLogicalProgram(metadataCpIndex)
        val constantPoolPlain = serializeConstantPool()

        val nestedVmFlag = if (nestedVmEnabled()) VBC4_FLAG_NESTED_VM else 0
        val flags = VBC4_FLAG_ENCRYPTED_CP or VBC4_FLAG_BLOCK_ENCRYPTED or VBC4_FLAG_MAC or VBC4_FLAG_STATE_BOUND or
            VBC4_FLAG_AUTHENTICATED or VBC4_FLAG_PER_ENTRY_CP or VBC4_FLAG_PADDED or VBC4_FLAG_PER_BLOCK_ENCRYPT or
            VBC4_FLAG_REGISTER_EXECUTABLE or VBC4_FLAG_SUPER_OPERATORS or VBC4_FLAG_ZSTD_SECTIONS or
            VBC4_FLAG_BLOCK_DISPATCH or nestedVmFlag
        val exceptionShape = intBytes(exceptionEntries.size)
        val nonce = vbc4Nonce(effectiveBuildSeed, flags, constantPoolPlain, exceptionShape, logicalProgram.blocks.size)
        val cryptoSeed = effectiveBuildSeed
        val wrappedSeed = vbc4WrappedSeed(cryptoSeed, nonce, stateBinding)
        val exceptionPlain = serializeExceptions(cryptoSeed)
        // Per-entry CP encryption: each constant pool entry encrypted independently
        val cpEntryPlainBuffers = serializeConstantPoolEntries()
        val cpEntryStoredSections = cpEntryPlainBuffers.map(::compressCpEntrySection)
        val cpEntryEncryptedBuffers = cpEntryStoredSections.mapIndexed { idx, section ->
            vbc4Crypt(section.bytes, cryptoSeed, nonce, VBC4_SECTION_CONSTANT_POOL_ENTRY, idx)
        }
        val exceptionStored = zstdCompressSection(exceptionPlain)
        val exceptionEncrypted = vbc4Crypt(exceptionStored, cryptoSeed, nonce, VBC4_SECTION_EXCEPTIONS, 0)

        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x56, 0x42, 0x43, 0x34))
        writeU2(out, VBC4_VERSION)
        out.write(nonce)
        writeU4(out, vbc4KeyId(cryptoSeed, nonce))
        out.write(wrappedSeed)
        writeU2(out, flags)
        writeU2(out, logicalProgram.blocks.size.coerceAtLeast(1))
        val storageBlocks = storageOrderedBlocks(logicalProgram.blocks)
        writeU4(out, constantPoolPlain.size)
        val cpSectionOut = java.io.ByteArrayOutputStream()
        writeU2(cpSectionOut, VBC4_CP_SECTION_VERSION)
        writeU2(cpSectionOut, constantPool.size)
        for ((idx, encEntry) in cpEntryEncryptedBuffers.withIndex()) {
            writeU4(cpSectionOut, cpEntryPlainBuffers[idx].size)
            writeU4(cpSectionOut, cpEntryStoredSections[idx].encodedLength)
            writeU4(cpSectionOut, encEntry.size)
            cpSectionOut.write(encEntry)
        }
        val cpSectionPlain = cpSectionOut.toByteArray()
        val cpSectionBytes = vbc4Crypt(cpSectionPlain, cryptoSeed, nonce, VBC4_SECTION_CONSTANT_POOL, 0)
        writeU4(out, cpSectionBytes.size)
        out.write(cpSectionBytes)
        // Write block index for multi-block programs in seed-diversified physical storage order.
        for (blk in storageBlocks) {
            writeU2(out, blk.blockId)
            writeU4(out, blk.entryToken)
            writeU4(out, vbc4BlockDispatchToken(cryptoSeed, blk.blockId, nextLogicalBlockId(blk.blockId, logicalProgram.blocks.size), logicalProgram.blocks.size))
        }
        for (blk in storageBlocks) {
            val blockPlain = serializeSingleBlock(blk, logicalProgram.registerCount, nestedVmFlag != 0)
            val blockStored = zstdCompressSection(blockPlain)
            val blockEncrypted = vbc4Crypt(blockStored, cryptoSeed, nonce, VBC4_SECTION_INSTRUCTIONS, blk.blockId)
            writeU4(out, blockPlain.size)
            writeU4(out, blockStored.size)
            writeU4(out, blockEncrypted.size)
            out.write(blockEncrypted)
        }
        writeU4(out, exceptionPlain.size)
        writeU4(out, exceptionStored.size)
        writeU4(out, exceptionEncrypted.size)
        out.write(exceptionEncrypted)
        // Authenticated size jitter: deterministic, MAC-covered random padding so two
        // methods (or builds) do not cluster by resource size. Padding lives inside the
        // MAC region, so tampering it fails verification; the native parser skips it.
        val padLength = vbc4PadLength(cryptoSeed, nonce)
        val padBytes = vbc4Crypt(ByteArray(padLength), cryptoSeed, nonce, VBC4_SECTION_PADDING, 0)
        writeU4(out, padLength)
        out.write(padBytes)
        val payload = out.toByteArray()
        out.write(vbc4Hmac(payload, cryptoSeed, nonce))
        out.write(32)
        return out.toByteArray()
    }

    private fun resolveLabelReferences() {
        for (ref in labelRefs) {
            val targetOffset = labelToOffset[ref.label] ?: continue
            val inst = instructions[ref.instructionIndex]
            val mutableOperands = inst.operands.toMutableList()
            mutableOperands[ref.operandIndex] = targetOffset
            instructions[ref.instructionIndex] = inst.copy(operands = mutableOperands)
        }
    }

    private fun lowerToLogicalProgram(metadataCpIndex: Int): VmLogicalProgram {
        val groups = mutableListOf<LogicalGroup>()
        groups.add(
            LogicalGroup(
                maskedOpcodeBase = VBC4_REG_META,
                primaryFlags = VBC4_REG_FLAG_EXECUTABLE,
                primaryDst = 0,
                primarySrcA = 0,
                primarySrcB = 0,
                primaryOperand = metadataCpIndex,
                continuations = emptyList(),
                maskSlots = 1,
            ),
        )
        val canFoldInstructionPairs = exceptionEntries.isEmpty()
        var index = 0
        while (index < instructions.size) {
            if (canFoldInstructionPairs) {
                when (superOperatorPlan(index)) {
                    SuperOperatorPlan.None -> Unit
                    SuperOperatorPlan.SemanticFold -> {
                        val foldedPredicate = foldedPredicateBranchGroup(index)
                        if (foldedPredicate != null) {
                            groups.add(foldedPredicate)
                            index += 2
                            continue
                        }
                        val folded = foldedSuperGroup(index)
                        if (folded != null) {
                            groups.add(folded)
                            index += 2
                            continue
                        }
                    }
                    SuperOperatorPlan.BinaryFold, SuperOperatorPlan.NestedMicroStream -> {
                        val folded = foldedSuperGroup(index)
                        if (folded != null) {
                            groups.add(folded)
                            index += 2
                            continue
                        }
                    }
                }
            }
            groups.add(registerGroup(instructions[index], index))
            index++
        }
        val partitions = partitionLogicalGroups(groups)
        var globalMaskIndex = 0
        val blocks = partitions.mapIndexed { blockId, blockGroups ->
            val rows = mutableListOf<VmRegisterInstruction>()
            for (group in blockGroups) {
                val maskIndex = globalMaskIndex
                rows.add(
                    VmRegisterInstruction(
                        opcode = group.maskedOpcodeBase xor vbc4OpcodeMask(effectiveBuildSeed, maskIndex),
                        flags = group.primaryFlags,
                        dst = group.primaryDst,
                        srcA = group.primarySrcA,
                        srcB = group.primarySrcB,
                        operand = group.primaryOperand,
                    ),
                )
                rows.addAll(group.continuations)
                globalMaskIndex += group.maskSlots
            }
            VmLogicalBlock(blockId, vbc4EntryToken(effectiveBuildSeed, blockId), rows)
        }
        return VmLogicalProgram(
            registerCount = instructions.maxOfOrNull { it.operands.size }?.coerceAtLeast(1) ?: 1,
            blocks = blocks,
        )
    }

    private data class LogicalGroup(
        val maskedOpcodeBase: Int,
        val primaryFlags: Int,
        val primaryDst: Int,
        val primarySrcA: Int,
        val primarySrcB: Int,
        val primaryOperand: Int,
        val continuations: List<VmRegisterInstruction>,
        val maskSlots: Int,
    )

    private enum class SuperOperatorPlan { None, BinaryFold, SemanticFold, NestedMicroStream }

    private fun superOperatorPlan(instructionIndex: Int): SuperOperatorPlan {
        val selector = structureSelector("super-plan", instructionIndex, opcodeDialectSalt, instructionIndex.rotateLeft(5))
        return SuperOperatorPlan.values()[(selector and 0x7FFFFFFF) % SuperOperatorPlan.values().size]
    }

    private fun storageOrderedBlocks(blocks: List<VmLogicalBlock>): List<VmLogicalBlock> {
        if (blocks.size <= 1) return blocks
        val mixed = structureSelector("block-storage-order", blocks.size, blocks.size * 0x7FEB352D.toInt())
        val storageBlocks = blocks.toMutableList()
        for (i in storageBlocks.lastIndex downTo 1) {
            val selector = structureSelector("block-storage-swap", i, mixed.rotateLeft(i and 31), i * 0x846CA68B.toInt())
            val j = selector % (i + 1)
            val tmp = storageBlocks[i]
            storageBlocks[i] = storageBlocks[j]
            storageBlocks[j] = tmp
        }
        return if (storageBlocks.map { it.blockId } == blocks.map { it.blockId }) {
            storageBlocks.drop(1) + storageBlocks.first()
        } else {
            storageBlocks
        }
    }


    private fun nextLogicalBlockId(blockId: Int, blockCount: Int): Int =
        if (blockId + 1 < blockCount) blockId + 1 else blockCount

    private fun vbc4BlockDispatchToken(seed: Int, blockId: Int, nextBlockId: Int, blockCount: Int): Int {
        val mask = seed.rotateLeft((blockId * 5 + 7) and 31) xor
            (blockId * 0x45D9F3B) xor
            (blockCount * 0x119DE1F3)
        val state = vbc4BlockDispatchState(seed, blockId, nextBlockId, blockCount)
        val payload = ((state and 0xFFFF) shl 16) or (nextBlockId and 0xFFFF)
        return payload xor mask
    }

    private fun vbc4BlockDispatchState(seed: Int, blockId: Int, nextBlockId: Int, blockCount: Int): Int {
        val mixed = seed.rotateLeft((blockId * 3 + 11) and 31) xor
            (blockId * 0x632BE59B) xor
            (nextBlockId * 0x85157AF5.toInt()) xor
            (blockCount * 0x9E3779B9.toInt())
        val state = (mixed xor (mixed ushr 16)) and 0xFFFF
        return if (state == 0) 1 else state
    }

    /**
     * Split the linear logical-group stream into multiple VM blocks. The serializer
     * stores blocks in seed-diversified physical order and writes a masked block-dispatch
     * edge for each logical block. The native VBC4 parser validates that opaque chain
     * and uses it to reassemble execution order before interpretation.
     * Correctness is preserved by treating blocks as storage/layout partitions only:
     * every group keeps its original absolute bytecode offset and branch targets remain
     * absolute VM offsets, so dominance/liveness relationships are unchanged by block
     * boundaries. Block 0 keeps metadata plus at least one real instruction.
     */
    private enum class BlockSplitStrategy {
        Stride,
        Weighted,
        Staggered,
    }

    private enum class BlockCoalesceStrategy {
        Pair,
        Window,
        Sparse,
    }

    private fun partitionLogicalGroups(groups: List<LogicalGroup>): List<List<LogicalGroup>> {
        val total = groups.size
        if (total <= 3) return listOf(groups)
        val ceiling = minOf(VBC4_MAX_LOGICAL_BLOCKS, total / 2).coerceAtLeast(1)
        if (ceiling <= 1) return listOf(groups)
        // Entropy-derived target block count so identical inputs and user seeds still
        // produce different block layouts across production builds.
        val seedHash = structureSelector("block-partition", total, total * 0x7FEB352D.toInt())
        val splitStrategy = selectBlockSplitStrategy(seedHash, total)
        val coalesceStrategy = selectBlockCoalesceStrategy(seedHash, total)
        // Range [2, ceiling]: methods large enough to split always produce >1 block,
        // and the exact count is seed-diversified across builds.
        val targetBlocks = seedDiversifiedBlockTarget(ceiling, seedHash, splitStrategy)
        if (targetBlocks <= 1) return listOf(groups)
        // Place (targetBlocks - 1) interior cut points, each at a group boundary >= 2
        // (META is group 0; block 0 must keep at least one real instruction). The
        // selected strategy changes both density and preferred cut positions, which
        // prevents a stable linear block-size fingerprint across builds.
        val cuts = cutCandidatesForStrategy(total, targetBlocks, seedHash, splitStrategy)
        if (cuts.isEmpty()) return listOf(groups)
        val partitions = mutableListOf<List<LogicalGroup>>()
        var start = 0
        for (cut in cuts) {
            if (cut <= start) continue
            partitions.add(groups.subList(start, cut).toList())
            start = cut
        }
        partitions.add(groups.subList(start, total).toList())
        return coalesceLogicalPartitions(groups, partitions, seedHash, coalesceStrategy)
    }

    private fun selectBlockSplitStrategy(seedHash: Int, total: Int): BlockSplitStrategy {
        val values = BlockSplitStrategy.values()
        val selector = (seedHash xor total.rotateLeft(3)) and 0x7FFFFFFF
        return values[selector % values.size]
    }

    private fun selectBlockCoalesceStrategy(seedHash: Int, total: Int): BlockCoalesceStrategy {
        val values = BlockCoalesceStrategy.values()
        val selector = (seedHash.rotateLeft(9) xor total.rotateLeft(1)) and 0x7FFFFFFF
        return values[selector % values.size]
    }

    private fun seedDiversifiedBlockTarget(ceiling: Int, seedHash: Int, strategy: BlockSplitStrategy): Int {
        if (ceiling < 2) return 1
        val minimum = if (ceiling >= 4) 3 else 2
        val range = ceiling - minimum + 1
        val bias = (when (strategy) {
            BlockSplitStrategy.Stride -> seedHash
            BlockSplitStrategy.Weighted -> seedHash.rotateLeft(5) xor 0x45D9F3B
            BlockSplitStrategy.Staggered -> seedHash.rotateLeft(11) xor 0x27D4EB2D
        }) and 0x7FFFFFFF
        return minimum + (bias % range)
    }

    private fun cutCandidatesForStrategy(total: Int, targetBlocks: Int, seedHash: Int, strategy: BlockSplitStrategy): Set<Int> {
        val cuts = sortedSetOf<Int>()
        val candidateCount = (targetBlocks - 1).coerceAtLeast(1)
        var attempt = 0
        while (cuts.size < candidateCount && attempt < total * 6) {
            val pos = when (strategy) {
                BlockSplitStrategy.Stride -> strideCutPosition(total, seedHash, attempt + 1)
                BlockSplitStrategy.Weighted -> weightedCutPosition(total, seedHash, attempt + 1, candidateCount)
                BlockSplitStrategy.Staggered -> staggeredCutPosition(total, seedHash, attempt + 1)
            }
            cuts.add(pos)
            attempt++
        }
        return cuts
    }

    private fun strideCutPosition(total: Int, seedHash: Int, stride: Int): Int {
        val mixed = (seedHash.rotateLeft(stride and 31) xor (stride * 0x846CA68B.toInt())) and 0x7FFFFFFF
        return 2 + (mixed % (total - 2))
    }

    private fun weightedCutPosition(total: Int, seedHash: Int, attempt: Int, targetCuts: Int): Int {
        val segment = (total - 2).coerceAtLeast(1)
        val coarse = ((segment * attempt) / (targetCuts + 1)).coerceIn(0, segment - 1)
        val jitterSpan = (segment / (targetCuts + 2)).coerceAtLeast(1)
        val jitter = ((seedHash.rotateLeft((attempt * 7) and 31) xor (attempt * 0x9E3779B9.toInt())) and 0x7FFFFFFF) % jitterSpan
        return 2 + ((coarse + jitter) % segment)
    }

    private fun staggeredCutPosition(total: Int, seedHash: Int, attempt: Int): Int {
        val segment = (total - 2).coerceAtLeast(1)
        val wave = seedHash.rotateLeft((attempt * 5 + 3) and 31) xor (attempt * attempt * 0x45D9F3B)
        val mirrored = if (attempt % 2 == 0) wave else wave.inv()
        return 2 + ((mirrored and 0x7FFFFFFF) % segment)
    }

    private fun coalesceLogicalPartitions(
        groups: List<LogicalGroup>,
        partitions: List<List<LogicalGroup>>,
        seedHash: Int,
        strategy: BlockCoalesceStrategy,
    ): List<List<LogicalGroup>> {
        val validated = validateLogicalPartitions(groups, partitions)
        if (validated.size <= 2) return validated
        val coalesced = mutableListOf<List<LogicalGroup>>()
        var index = 0
        while (index < validated.size) {
            val mergeWindow = coalesceWindow(strategy, seedHash, index, validated.size)
            val remainingAfterWindow = validated.size - index - mergeWindow
            val canMergeNext = mergeWindow > 1 && index + mergeWindow <= validated.size && coalesced.size + remainingAfterWindow >= 1
            val selector = (seedHash.rotateLeft((index * 3 + 5) and 31) xor (index * 0x27D4EB2D)) and 0x7FFFFFFF
            if (canMergeNext && selector % coalesceModulo(strategy) == 0) {
                coalesced.add(validated.subList(index, index + mergeWindow).flatten())
                index += mergeWindow
            } else {
                coalesced.add(validated[index])
                index++
            }
        }
        return validateLogicalPartitions(groups, coalesced)
    }

    private fun coalesceWindow(strategy: BlockCoalesceStrategy, seedHash: Int, index: Int, partitionCount: Int): Int = when (strategy) {
        BlockCoalesceStrategy.Pair -> 2
        BlockCoalesceStrategy.Window -> 2 + ((seedHash ushr ((index + partitionCount) and 15)) and 1)
        BlockCoalesceStrategy.Sparse -> if (((index + partitionCount + seedHash) and 1) == 0) 2 else 1
    }

    private fun coalesceModulo(strategy: BlockCoalesceStrategy): Int = when (strategy) {
        BlockCoalesceStrategy.Pair -> 3
        BlockCoalesceStrategy.Window -> 2
        BlockCoalesceStrategy.Sparse -> 5
    }

    private fun validateLogicalPartitions(groups: List<LogicalGroup>, partitions: List<List<LogicalGroup>>): List<List<LogicalGroup>> {
        if (partitions.isEmpty()) return listOf(groups)
        if (partitions.first().size < 2) return listOf(groups)
        val flattened = partitions.flatten()
        if (flattened.size != groups.size) return listOf(groups)
        for (index in groups.indices) {
            if (flattened[index] != groups[index]) return listOf(groups)
        }
        if (partitions.any { it.isEmpty() }) return listOf(groups)
        return partitions
    }

    private fun registerGroup(instruction: VmInstruction, instructionIndex: Int): LogicalGroup {
        requireSupportedVmOpcode(instruction.opcode, instruction.offset, "instruction")
        val operands = registerOperands(instruction)
        val baseOpcode = superOperatorOpcode(instruction, instructionIndex) ?: polymorphicOpcode(instruction.opcode, instructionIndex)
        requireSupportedVmOpcode(baseOpcode, instruction.offset, "encoded")
        val isSuperOperator = baseOpcode in VBC4_SUPER_BASE..VBC4_SUPER_INVOKE
        val flags = VBC4_REG_FLAG_EXECUTABLE or if (isSuperOperator) VBC4_REG_FLAG_SUPER else 0
        val continuations = if (operands.size > 1) {
            (1 until operands.size).map { extraIndex ->
                VmRegisterInstruction(
                    opcode = VBC4_REG_OPERAND_CONT,
                    flags = VBC4_REG_FLAG_CONTINUATION,
                    dst = extraIndex,
                    srcA = instruction.offset and 0xFFFF,
                    srcB = 0,
                    operand = operands[extraIndex],
                )
            }
        } else {
            emptyList()
        }
        return LogicalGroup(
            maskedOpcodeBase = baseOpcode,
            primaryFlags = flags,
            primaryDst = operands.size and 0xFFFF,
            primarySrcA = instruction.offset and 0xFFFF,
            primarySrcB = if (isSuperOperator) instruction.opcode else 0,
            primaryOperand = operands.firstOrNull() ?: 0,
            continuations = continuations,
            maskSlots = 1,
        )
    }

    private fun foldedPredicateBranchGroup(instructionIndex: Int): LogicalGroup? {
        if (instructionIndex + 1 >= instructions.size) return null
        val first = instructions[instructionIndex]
        val second = instructions[instructionIndex + 1]
        if (first.operands.isNotEmpty() || second.operands.size != 1) return null
        if (first.opcode !in VBC4_COMPARE_BUILDER_OPCODES || second.opcode !in VBC4_PREDICATE_BRANCH_OPCODES) return null
        val selector = structureSelector("folded-predicate", instructionIndex, first.opcode.rotateLeft(3), second.opcode)
        if (selector % 4 == 0) return null
        val branchTarget = registerOperands(second).firstOrNull() ?: return null
        return LogicalGroup(
            maskedOpcodeBase = VBC4_SUPER_CMP_BRANCH,
            primaryFlags = VBC4_REG_FLAG_EXECUTABLE or VBC4_REG_FLAG_SUPER or VBC4_REG_FLAG_FOLDED,
            primaryDst = 0,
            primarySrcA = domainSuperOperandOpcode(first.opcode, instructionIndex, 0),
            primarySrcB = domainSuperOperandOpcode(second.opcode, instructionIndex, 1),
            primaryOperand = branchTarget,
            continuations = emptyList(),
            maskSlots = 2,
        )
    }

    private fun foldedSuperGroup(instructionIndex: Int): LogicalGroup? {
        if (instructionIndex + 1 >= instructions.size) return null
        val first = instructions[instructionIndex]
        val second = instructions[instructionIndex + 1]
        if (first.operands.size != 1 || second.operands.isNotEmpty()) return null
        if (first.opcode !in VBC4_CONST_OPCODES || second.opcode !in VBC4_FOLDED_FUSION_OPCODES) return null
        val selector = structureSelector("folded-super", instructionIndex, first.opcode.rotateLeft(1), second.opcode)
        if (selector % 4 == 0) return null
        val constOperand = registerOperands(first).firstOrNull() ?: return null
        return LogicalGroup(
            maskedOpcodeBase = VBC4_SUPER_INT_ARITH,
            primaryFlags = VBC4_REG_FLAG_EXECUTABLE or VBC4_REG_FLAG_SUPER or VBC4_REG_FLAG_FOLDED,
            primaryDst = 0,
            primarySrcA = domainSuperOperandOpcode(first.opcode, instructionIndex, 0),
            primarySrcB = domainSuperOperandOpcode(second.opcode, instructionIndex, 1),
            primaryOperand = constOperand,
            continuations = emptyList(),
            maskSlots = 2,
        )
    }

    private fun domainSuperOperandOpcode(opcode: Int, instructionIndex: Int, role: Int): Int {
        requireSupportedVmOpcode(opcode, instructionIndex, "super operand")
        val encoded = polymorphicOpcode(opcode, instructionIndex + 0x51 + role * 0x1F)
        requireSupportedVmOpcode(encoded, instructionIndex, "encoded super operand")
        return encoded
    }

    private fun requireSupportedVmOpcode(opcode: Int, offset: Int, role: String) {
        if (opcode == VmOpcodes.VM_UNSUPPORTED) {
            throw UnsupportedOperationException(
                "VBC4 serializer produced unsupported $role opcode for ${entryMetadata.originalOwner}#${entryMetadata.originalName}${entryMetadata.originalDescriptor} at offset=$offset",
            )
        }
    }

    private fun registerOperands(instruction: VmInstruction): List<Int> = instruction.operands.map { operand ->
        when (operand) {
            is Int -> operand
            is Float -> java.lang.Float.floatToIntBits(operand)
            is String -> addConstant(operand)
            else -> operand.hashCode()
        }
    }
    private fun serializeConstantPool(): ByteArray {
        val out = java.io.ByteArrayOutputStream(estimateConstantPoolSize(includeCount = true))
        writeU2(out, constantPool.size)
        for (entry in constantPool) {
            writeConstantPoolEntry(out, entry)
        }
        return out.toByteArray()
    }

    private fun serializeConstantPoolEntries(): List<ByteArray> = constantPool.map { entry ->
        val out = java.io.ByteArrayOutputStream(estimateConstantPoolEntrySize(entry))
        writeConstantPoolEntry(out, entry)
        out.toByteArray()
    }

    private fun writeConstantPoolEntry(out: java.io.ByteArrayOutputStream, entry: Any) {
        when (entry) {
            is String -> {
                out.write(0x01)
                val bytes = entry.toByteArray(Charsets.UTF_8)
                writeU2(out, bytes.size)
                out.write(bytes)
            }
            is Int -> { out.write(0x02); writeU4(out, entry) }
            is Long -> { out.write(0x03); writeU8(out, entry) }
            is Float -> { out.write(0x04); writeU4(out, java.lang.Float.floatToIntBits(entry)) }
            is Double -> { out.write(0x05); writeU8(out, java.lang.Double.doubleToLongBits(entry)) }
            else -> {
                out.write(0x01)
                val bytes = entry.toString().toByteArray(Charsets.UTF_8)
                writeU2(out, bytes.size)
                out.write(bytes)
            }
        }
    }

    private fun estimateConstantPoolSize(includeCount: Boolean): Int =
        (if (includeCount) 2 else 0) + constantPool.sumOf(::estimateConstantPoolEntrySize)

    private fun estimateConstantPoolEntrySize(entry: Any): Int = when (entry) {
        is String -> 3 + entry.toByteArray(Charsets.UTF_8).size
        is Int -> 5
        is Long -> 9
        is Float -> 5
        is Double -> 9
        else -> 3 + entry.toString().toByteArray(Charsets.UTF_8).size
    }

    private fun polymorphicOpcode(opcode: Int, instructionIndex: Int): Int {
        val aliases = VM_OPCODE_ALIASES[opcode] ?: return opcode
        val selector = structureSelector("opcode-alias", instructionIndex, opcode)
        return aliases[selector % aliases.size]
    }


    private fun superOperatorOpcode(instruction: VmInstruction, instructionIndex: Int): Int? {
        val superOpcode = when (instruction.opcode) {
            VmOpcodes.VM_ICONST, VmOpcodes.VM_BIPUSH, VmOpcodes.VM_SIPUSH -> VBC4_SUPER_CONST
            VmOpcodes.VM_IADD, VmOpcodes.VM_ISUB, VmOpcodes.VM_IMUL,
            VmOpcodes.VM_IAND, VmOpcodes.VM_IOR, VmOpcodes.VM_IXOR,
            VmOpcodes.VM_ISHL, VmOpcodes.VM_ISHR, VmOpcodes.VM_IUSHR -> VBC4_SUPER_INT_ARITH
            VmOpcodes.VM_IFEQ, VmOpcodes.VM_IFNE, VmOpcodes.VM_IF_ICMPEQ, VmOpcodes.VM_IF_ICMPNE -> VBC4_SUPER_CMP_BRANCH
            VmOpcodes.VM_INVOKESTATIC, VmOpcodes.VM_INVOKEVIRTUAL, VmOpcodes.VM_INVOKESPECIAL, VmOpcodes.VM_INVOKEINTERFACE -> VBC4_SUPER_INVOKE
            else -> return null
        }
        val selector = structureSelector("super-opcode", instructionIndex, instruction.opcode.rotateLeft(3))
        return if (selector % 4 == 0) null else superOpcode
    }

    private fun serializeInstructionBlock(logicalProgram: VmLogicalProgram): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        writeU2(out, logicalProgram.registerCount)
        val registerInstructions = logicalProgram.blocks.flatMap { it.instructions }
        writeU2(out, registerInstructions.size)
        for (instruction in registerInstructions) {
            writeU2(out, instruction.opcode)
            writeU2(out, instruction.flags)
            writeU2(out, instruction.dst)
            writeU2(out, instruction.srcA)
            writeU2(out, instruction.srcB)
            writeU4(out, instruction.operand)
        }
        writeStackInstructionStream(out, registerInstructions.size)
        return out.toByteArray()
    }

    private fun serializeSingleBlock(block: VmLogicalBlock, registerCount: Int, nestedVm: Boolean): ByteArray {
        if (nestedVm) return serializeNestedBlock(block, registerCount)
        val out = java.io.ByteArrayOutputStream()
        writeU2(out, registerCount)
        writeU2(out, block.instructions.size)
        for (instruction in block.instructions) {
            writeU2(out, instruction.opcode)
            writeU2(out, instruction.flags)
            writeU2(out, instruction.dst)
            writeU2(out, instruction.srcA)
            writeU2(out, instruction.srcB)
            writeU4(out, instruction.operand)
        }
        writeU2(out, 0)
        return out.toByteArray()
    }

    private fun serializeNestedBlock(block: VmLogicalBlock, registerCount: Int): ByteArray {
        val profile = entryMetadata.methodLocalProfile
        require(profile != 0) { "Nested VBC4 block requires a method-local profile" }
        require(block.instructions.size * VBC4_NESTED_MICROS_PER_ROW <= 0xFFFF) {
            "Nested VBC4 micro stream is too large for one block"
        }
        val dialect = vbc4NestedDialect(effectiveBuildSeed, profile, block.blockId, block.instructions.size)
        val out = java.io.ByteArrayOutputStream()
        writeU2(out, registerCount)
        writeU2(out, VBC4_NESTED_MAGIC)
        writeU2(out, VBC4_NESTED_VERSION)
        writeU2(out, block.instructions.size)
        writeU4(out, profile)
        writeU4(out, dialect)
        writeU2(out, block.instructions.size * VBC4_NESTED_MICROS_PER_ROW)
        block.instructions.forEachIndexed { rowIndex, instruction ->
            val fields = intArrayOf(
                instruction.opcode and 0xFFFF,
                instruction.flags and 0xFFFF,
                instruction.dst and 0xFFFF,
                instruction.srcA and 0xFFFF,
                instruction.srcB and 0xFFFF,
                instruction.operand,
            )
            val fieldOrder = vbc4NestedFieldOrder(effectiveBuildSeed, profile, block.blockId, rowIndex, dialect)
            fieldOrder.forEachIndexed { slot, field ->
                val mix = vbc4NestedMix(effectiveBuildSeed, profile, block.blockId, rowIndex, slot, dialect)
                val valueMask = vbc4NestedMix(effectiveBuildSeed, profile, block.blockId, rowIndex, slot + 0x51, dialect)
                writeU2(out, VBC4_NESTED_FIELD_OPCODE_BASE or (mix and 0x0FFF))
                writeU2(out, field xor ((mix ushr 16) and 0xFFFF))
                writeU4(out, fields[field] xor valueMask)
            }
            val commitMix = vbc4NestedMix(effectiveBuildSeed, profile, block.blockId, rowIndex, VBC4_NESTED_COMMIT_SLOT, dialect)
            writeU2(out, VBC4_NESTED_COMMIT_OPCODE_BASE or (commitMix and 0x0FFF))
            writeU2(out, rowIndex xor ((commitMix ushr 16) and 0xFFFF))
            writeU4(out, vbc4NestedRowChecksum(effectiveBuildSeed, profile, block.blockId, rowIndex, dialect, fields))
        }
        return out.toByteArray()
    }

    private fun structureSelector(label: String, index: Int, vararg values: Int): Int {
        var x = effectiveBuildSeed xor opcodeDialectSalt.rotateLeft((index and 15) + 1) xor structureSalt.rotateRight(index and 31)
        x = x xor structureEntropyWord(index).rotateLeft(7) xor label.hashCode().rotateLeft(3) xor (index * 0x9E3779B9.toInt())
        values.forEachIndexed { valueIndex, value ->
            x = x xor value.rotateLeft((valueIndex * 5 + index) and 31) xor structureEntropyWord(index + valueIndex + 1)
            x = x xor (x ushr 16)
            x *= 0x7FEB352D
        }
        x = x xor (x ushr 15)
        x *= 0x846CA68B.toInt()
        return (x xor (x ushr 16)) and 0x7FFFFFFF
    }

    private fun structureEntropyWord(index: Int): Int {
        val normalized = ((index % structureEntropyDigest.size) + structureEntropyDigest.size) % structureEntropyDigest.size
        val offset = (normalized / 4 * 4).coerceAtMost(structureEntropyDigest.size - 4)
        return ((structureEntropyDigest[offset].toInt() and 0xFF) shl 24) or
            ((structureEntropyDigest[offset + 1].toInt() and 0xFF) shl 16) or
            ((structureEntropyDigest[offset + 2].toInt() and 0xFF) shl 8) or
            (structureEntropyDigest[offset + 3].toInt() and 0xFF)
    }

    private fun nestedVmEnabled(): Boolean = entryMetadata.methodLocalProfile != 0

    private fun writeStackInstructionStream(out: java.io.ByteArrayOutputStream, opcodeMaskBase: Int) {
        require(opcodeMaskBase >= 0)
        // VBC4 executes the register stream. Stack opcodes are no longer serialized as
        // an executable fallback; the native parser rejects any non-zero stack stream.
        writeU2(out, 0)
    }
    private fun serializeExceptions(cryptoSeed: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        // Add 1-3 decoy exception entries after real ones to confuse analysis tools.
        // Decoys use plausible but unreachable offsets within the instruction stream.
        val decoyCount = 1 + ((cryptoSeed ushr 16) and 0x3) % 3  // 1-3 decoys
        val totalEntries = exceptionEntries.size + decoyCount
        writeU2(out, totalEntries)
        for ((index, entry) in exceptionEntries.withIndex()) {
            val token = vbc4ExceptionToken(cryptoSeed, index)
            writeU4(out, token)
            writeU2(out, requireLabelOffset(entry.start, "start") xor vbc4ExceptionMask(cryptoSeed, index, 0, token))
            writeU2(out, requireLabelOffset(entry.end, "end") xor vbc4ExceptionMask(cryptoSeed, index, 1, token))
            writeU2(out, requireLabelOffset(entry.handler, "handler") xor vbc4ExceptionMask(cryptoSeed, index, 2, token))
            writeU2(out, entry.typeCpIndex xor vbc4ExceptionMask(cryptoSeed, index, 3, token))
        }
        // Emit decoy entries with crypto-derived plausible offsets.
        // Decoy ranges are placed BEYOND the real instruction count so they
        // never match any fault_pc during normal execution.
        val maxOffset = currentOffset.coerceAtLeast(16)
        for (di in 0 until decoyCount) {
            val decoyIndex = exceptionEntries.size + di
            val token = vbc4ExceptionToken(cryptoSeed, decoyIndex)
            writeU4(out, token)
            // Place decoy range beyond real instructions: start/end > maxOffset
            val decoyBase = maxOffset + 1 + ((cryptoSeed xor (di * 0x9E3779B9.toInt())) and 0x7FFF)
            val decoyStart = decoyBase
            val decoyEnd = decoyBase + 2 + ((cryptoSeed xor (di * 0x85EBCA6B.toInt())) and 0x1F)
            val decoyHandler = decoyEnd + 1  // handler also beyond range
            writeU2(out, decoyStart xor vbc4ExceptionMask(cryptoSeed, decoyIndex, 0, token))
            writeU2(out, decoyEnd xor vbc4ExceptionMask(cryptoSeed, decoyIndex, 1, token))
            writeU2(out, decoyHandler xor vbc4ExceptionMask(cryptoSeed, decoyIndex, 2, token))
            writeU2(out, 0 xor vbc4ExceptionMask(cryptoSeed, decoyIndex, 3, token))  // catch-all type
        }
        return out.toByteArray()
    }

    private fun requireLabelOffset(label: Label, role: String): Int =
        labelToOffset[label] ?: throw IllegalStateException("Unresolved VBC4 exception table $role label")

    private fun addConstant(value: Any): Int {
        constantPoolIndex[value]?.let { return it }
        val index = constantPool.size
        constantPool.add(value)
        constantPoolIndex[value] = index
        return index
    }

    private fun emit(opcode: Int, vararg operands: Any) {
        instructions.add(VmInstruction(currentOffset, opcode, operands.toList()))
        currentOffset++
    }

    private fun emitMbaIadd() {
        emit(polymorphicOpcode(VmOpcodes.VM_IADD, currentOffset))
    }

    private fun emitMbaIsub() {
        emit(polymorphicOpcode(VmOpcodes.VM_ISUB, currentOffset))
    }

    private fun emitMbaIxor() {
        emit(VmOpcodes.VM_IXOR)
    }

    private fun emitMbaIor() {
        emit(VmOpcodes.VM_IOR)
    }

    private fun unsupportedOpcode(kind: String, opcode: Int): Nothing {
        throw UnsupportedOperationException("VBC4 serializer does not support $kind opcode $opcode")
    }

    private fun emitLabel(label: Label) {
        labelToOffset[label] = currentOffset
    }

    private fun emitBranch(opcode: Int, label: Label) {
        val instIndex = instructions.size
        emit(opcode, 0)
        labelRefs.add(LabelRef(instIndex, 0, label))
    }

    // --- Constants ---
    override fun visitInsn(opcode: Int) {
        when (opcode) {
            Opcodes.NOP -> emit(VmOpcodes.VM_NOP)
            Opcodes.ACONST_NULL -> emit(VmOpcodes.VM_ACONST_NULL)
            Opcodes.ICONST_M1 -> emit(VmOpcodes.VM_ICONST, -1)
            Opcodes.ICONST_0 -> emit(VmOpcodes.VM_ICONST, 0)
            Opcodes.ICONST_1 -> emit(VmOpcodes.VM_ICONST, 1)
            Opcodes.ICONST_2 -> emit(VmOpcodes.VM_ICONST, 2)
            Opcodes.ICONST_3 -> emit(VmOpcodes.VM_ICONST, 3)
            Opcodes.ICONST_4 -> emit(VmOpcodes.VM_ICONST, 4)
            Opcodes.ICONST_5 -> emit(VmOpcodes.VM_ICONST, 5)
            Opcodes.LCONST_0 -> emit(VmOpcodes.VM_LCONST, addConstant(0L))
            Opcodes.LCONST_1 -> emit(VmOpcodes.VM_LCONST, addConstant(1L))
            Opcodes.FCONST_0 -> emit(VmOpcodes.VM_FCONST, 0.0f)
            Opcodes.FCONST_1 -> emit(VmOpcodes.VM_FCONST, 1.0f)
            Opcodes.FCONST_2 -> emit(VmOpcodes.VM_FCONST, 2.0f)
            Opcodes.DCONST_0 -> emit(VmOpcodes.VM_DCONST, addConstant(0.0))
            Opcodes.DCONST_1 -> emit(VmOpcodes.VM_DCONST, addConstant(1.0))
            Opcodes.POP -> emit(VmOpcodes.VM_POP)
            Opcodes.POP2 -> emit(VmOpcodes.VM_POP2)
            Opcodes.DUP -> emit(VmOpcodes.VM_DUP)
            Opcodes.DUP_X1 -> emit(VmOpcodes.VM_DUP_X1)
            Opcodes.DUP_X2 -> emit(VmOpcodes.VM_DUP_X2)
            Opcodes.DUP2 -> emit(VmOpcodes.VM_DUP2)
            Opcodes.DUP2_X1 -> emit(VmOpcodes.VM_DUP2_X1)
            Opcodes.DUP2_X2 -> emit(VmOpcodes.VM_DUP2_X2)
            Opcodes.SWAP -> emit(VmOpcodes.VM_SWAP)
            Opcodes.IADD -> emitMbaIadd()
            Opcodes.LADD -> emit(VmOpcodes.VM_LADD)
            Opcodes.FADD -> emit(VmOpcodes.VM_FADD)
            Opcodes.DADD -> emit(VmOpcodes.VM_DADD)
            Opcodes.ISUB -> emitMbaIsub()
            Opcodes.LSUB -> emit(VmOpcodes.VM_LSUB)
            Opcodes.FSUB -> emit(VmOpcodes.VM_FSUB)
            Opcodes.DSUB -> emit(VmOpcodes.VM_DSUB)
            Opcodes.IMUL -> emit(VmOpcodes.VM_IMUL)
            Opcodes.LMUL -> emit(VmOpcodes.VM_LMUL)
            Opcodes.FMUL -> emit(VmOpcodes.VM_FMUL)
            Opcodes.DMUL -> emit(VmOpcodes.VM_DMUL)
            Opcodes.IDIV -> emit(VmOpcodes.VM_IDIV)
            Opcodes.LDIV -> emit(VmOpcodes.VM_LDIV)
            Opcodes.FDIV -> emit(VmOpcodes.VM_FDIV)
            Opcodes.DDIV -> emit(VmOpcodes.VM_DDIV)
            Opcodes.IREM -> emit(VmOpcodes.VM_IREM)
            Opcodes.LREM -> emit(VmOpcodes.VM_LREM)
            Opcodes.FREM -> emit(VmOpcodes.VM_FREM)
            Opcodes.DREM -> emit(VmOpcodes.VM_DREM)
            Opcodes.INEG -> emit(VmOpcodes.VM_INEG)
            Opcodes.LNEG -> emit(VmOpcodes.VM_LNEG)
            Opcodes.FNEG -> emit(VmOpcodes.VM_FNEG)
            Opcodes.DNEG -> emit(VmOpcodes.VM_DNEG)
            Opcodes.ISHL -> emit(VmOpcodes.VM_ISHL)
            Opcodes.ISHR -> emit(VmOpcodes.VM_ISHR)
            Opcodes.IUSHR -> emit(VmOpcodes.VM_IUSHR)
            Opcodes.LSHL -> emit(VmOpcodes.VM_LSHL)
            Opcodes.LSHR -> emit(VmOpcodes.VM_LSHR)
            Opcodes.LUSHR -> emit(VmOpcodes.VM_LUSHR)
            Opcodes.IAND -> emit(VmOpcodes.VM_IAND)
            Opcodes.LAND -> emit(VmOpcodes.VM_LAND)
            Opcodes.IOR -> emitMbaIor()
            Opcodes.LOR -> emit(VmOpcodes.VM_LOR)
            Opcodes.IXOR -> emitMbaIxor()
            Opcodes.LXOR -> emit(VmOpcodes.VM_LXOR)
            Opcodes.I2L -> emit(VmOpcodes.VM_I2L)
            Opcodes.I2F -> emit(VmOpcodes.VM_I2F)
            Opcodes.I2D -> emit(VmOpcodes.VM_I2D)
            Opcodes.L2I -> emit(VmOpcodes.VM_L2I)
            Opcodes.L2F -> emit(VmOpcodes.VM_L2F)
            Opcodes.L2D -> emit(VmOpcodes.VM_L2D)
            Opcodes.F2I -> emit(VmOpcodes.VM_F2I)
            Opcodes.F2L -> emit(VmOpcodes.VM_F2L)
            Opcodes.F2D -> emit(VmOpcodes.VM_F2D)
            Opcodes.D2I -> emit(VmOpcodes.VM_D2I)
            Opcodes.D2L -> emit(VmOpcodes.VM_D2L)
            Opcodes.D2F -> emit(VmOpcodes.VM_D2F)
            Opcodes.I2B -> emit(VmOpcodes.VM_I2B)
            Opcodes.I2C -> emit(VmOpcodes.VM_I2C)
            Opcodes.I2S -> emit(VmOpcodes.VM_I2S)
            Opcodes.LCMP -> emit(VmOpcodes.VM_LCMP)
            Opcodes.FCMPL -> emit(VmOpcodes.VM_FCMPL)
            Opcodes.FCMPG -> emit(VmOpcodes.VM_FCMPG)
            Opcodes.DCMPL -> emit(VmOpcodes.VM_DCMPL)
            Opcodes.DCMPG -> emit(VmOpcodes.VM_DCMPG)
            Opcodes.IRETURN -> emit(VmOpcodes.VM_IRETURN)
            Opcodes.LRETURN -> emit(VmOpcodes.VM_LRETURN)
            Opcodes.FRETURN -> emit(VmOpcodes.VM_FRETURN)
            Opcodes.DRETURN -> emit(VmOpcodes.VM_DRETURN)
            Opcodes.ARETURN -> emit(VmOpcodes.VM_ARETURN)
            Opcodes.RETURN -> emit(VmOpcodes.VM_RETURN)
            Opcodes.ATHROW -> emit(VmOpcodes.VM_ATHROW)
            Opcodes.IALOAD -> emit(VmOpcodes.VM_IALOAD)
            Opcodes.LALOAD -> emit(VmOpcodes.VM_LALOAD)
            Opcodes.FALOAD -> emit(VmOpcodes.VM_FALOAD)
            Opcodes.DALOAD -> emit(VmOpcodes.VM_DALOAD)
            Opcodes.AALOAD -> emit(VmOpcodes.VM_AALOAD)
            Opcodes.BALOAD -> emit(VmOpcodes.VM_BALOAD)
            Opcodes.CALOAD -> emit(VmOpcodes.VM_CALOAD)
            Opcodes.SALOAD -> emit(VmOpcodes.VM_SALOAD)
            Opcodes.IASTORE -> emit(VmOpcodes.VM_IASTORE)
            Opcodes.LASTORE -> emit(VmOpcodes.VM_LASTORE)
            Opcodes.FASTORE -> emit(VmOpcodes.VM_FASTORE)
            Opcodes.DASTORE -> emit(VmOpcodes.VM_DASTORE)
            Opcodes.AASTORE -> emit(VmOpcodes.VM_AASTORE)
            Opcodes.BASTORE -> emit(VmOpcodes.VM_BASTORE)
            Opcodes.CASTORE -> emit(VmOpcodes.VM_CASTORE)
            Opcodes.SASTORE -> emit(VmOpcodes.VM_SASTORE)
            Opcodes.ARRAYLENGTH -> emit(VmOpcodes.VM_ARRAYLENGTH)
            Opcodes.MONITORENTER -> emit(VmOpcodes.VM_MONITORENTER)
            Opcodes.MONITOREXIT -> emit(VmOpcodes.VM_MONITOREXIT)
            else -> unsupportedOpcode("insn", opcode)
        }
    }

    override fun visitIntInsn(opcode: Int, operand: Int) {
        when (opcode) {
            Opcodes.BIPUSH -> emit(VmOpcodes.VM_BIPUSH, operand)
            Opcodes.SIPUSH -> emit(VmOpcodes.VM_SIPUSH, operand)
            Opcodes.NEWARRAY -> emit(VmOpcodes.VM_NEWARRAY, operand)
            else -> unsupportedOpcode("int", opcode)
        }
    }

    override fun visitVarInsn(opcode: Int, operand: Int) {
        when (opcode) {
            Opcodes.ILOAD -> emit(VmOpcodes.VM_ILOAD, operand)
            Opcodes.LLOAD -> emit(VmOpcodes.VM_LLOAD, operand)
            Opcodes.FLOAD -> emit(VmOpcodes.VM_FLOAD, operand)
            Opcodes.DLOAD -> emit(VmOpcodes.VM_DLOAD, operand)
            Opcodes.ALOAD -> emit(VmOpcodes.VM_ALOAD, operand)
            Opcodes.ISTORE -> emit(VmOpcodes.VM_ISTORE, operand)
            Opcodes.LSTORE -> emit(VmOpcodes.VM_LSTORE, operand)
            Opcodes.FSTORE -> emit(VmOpcodes.VM_FSTORE, operand)
            Opcodes.DSTORE -> emit(VmOpcodes.VM_DSTORE, operand)
            Opcodes.ASTORE -> emit(VmOpcodes.VM_ASTORE, operand)
            Opcodes.RET -> emit(VmOpcodes.VM_RET, operand)
            else -> unsupportedOpcode("var", opcode)
        }
    }

    override fun visitTypeInsn(opcode: Int, type: String?) {
        val t = type ?: "java/lang/Object"
        when (opcode) {
            Opcodes.NEW -> { val cp = addConstant(t); emit(VmOpcodes.VM_NEW, cp) }
            Opcodes.ANEWARRAY -> { val cp = addConstant(t); emit(VmOpcodes.VM_ANEWARRAY, cp) }
            Opcodes.CHECKCAST -> { val cp = addConstant(t); emit(VmOpcodes.VM_CHECKCAST, cp) }
            Opcodes.INSTANCEOF -> { val cp = addConstant(t); emit(VmOpcodes.VM_INSTANCEOF, cp) }
            else -> unsupportedOpcode("type", opcode)
        }
    }

    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
        val ref = "$owner.$name:$descriptor"
        val cp = addConstant(ref)
        when (opcode) {
            Opcodes.GETSTATIC -> emit(VmOpcodes.VM_GETSTATIC, cp)
            Opcodes.PUTSTATIC -> emit(VmOpcodes.VM_PUTSTATIC, cp)
            Opcodes.GETFIELD -> emit(VmOpcodes.VM_GETFIELD, cp)
            Opcodes.PUTFIELD -> emit(VmOpcodes.VM_PUTFIELD, cp)
            else -> unsupportedOpcode("field", opcode)
        }
    }

    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
        val ref = "$owner.$name:$descriptor"
        val cp = addConstant(ref)
        when (opcode) {
            Opcodes.INVOKEVIRTUAL -> emit(VmOpcodes.VM_INVOKEVIRTUAL, cp)
            Opcodes.INVOKESPECIAL -> emit(VmOpcodes.VM_INVOKESPECIAL, cp)
            Opcodes.INVOKESTATIC -> emit(VmOpcodes.VM_INVOKESTATIC, cp)
            Opcodes.INVOKEINTERFACE -> emit(VmOpcodes.VM_INVOKEINTERFACE, cp)
            else -> unsupportedOpcode("method", opcode)
        }
    }

    override fun visitInvokeDynamicInsn(name: String, descriptor: String, bootstrapMethodHandle: Handle, vararg bootstrapMethodArguments: Any) {
        val cp = addConstant(encodeInvokeDynamicConstant(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments))
        emit(VmOpcodes.VM_INVOKEDYNAMIC, cp)
    }

    private fun encodeInvokeDynamicConstant(
        name: String,
        descriptor: String,
        bootstrapMethodHandle: Handle,
        bootstrapMethodArguments: Array<out Any>,
    ): String {
        val normalized = normalizeNativeVmInvokeDynamic(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments)
        val staticTarget = methodHandleBackedStaticTarget(normalized)
        if (staticTarget != null) {
            return listOf(
                "mhstatic",
                normalized.name,
                normalized.descriptor,
                staticTarget.owner,
                staticTarget.name,
                staticTarget.desc,
            ).joinToString("|")
        }
        if (normalized.bootstrapMethodHandle.owner == "java/lang/invoke/LambdaMetafactory" &&
            normalized.bootstrapMethodHandle.name == "metafactory" &&
            normalized.bootstrapMethodArguments.size >= 3
        ) {
            val impl = normalized.bootstrapMethodArguments[1] as? Handle
            if (impl != null) {
                return listOf(
                    "lambda",
                    normalized.name,
                    normalized.descriptor,
                    impl.tag.toString(),
                    impl.owner,
                    impl.name,
                    impl.desc,
                ).joinToString("|")
            }
        }
        val bsmRef = "${normalized.bootstrapMethodHandle.owner}.${normalized.bootstrapMethodHandle.name}:${normalized.bootstrapMethodHandle.desc}"
        val callRef = "${normalized.name}:${normalized.descriptor}"
        val parts = mutableListOf(bsmRef, callRef)
        for (arg in normalized.bootstrapMethodArguments) {
            parts.add(arg.toString())
        }
        return parts.joinToString("|")
    }

    override fun visitJumpInsn(opcode: Int, label: Label?) {
        if (label == null) return unsupportedOpcode("jump", opcode)
        when (opcode) {
            Opcodes.IFEQ -> emitBranch(VmOpcodes.VM_IFEQ, label)
            Opcodes.IFNE -> emitBranch(VmOpcodes.VM_IFNE, label)
            Opcodes.IFLT -> emitBranch(VmOpcodes.VM_IFLT, label)
            Opcodes.IFGE -> emitBranch(VmOpcodes.VM_IFGE, label)
            Opcodes.IFGT -> emitBranch(VmOpcodes.VM_IFGT, label)
            Opcodes.IFLE -> emitBranch(VmOpcodes.VM_IFLE, label)
            Opcodes.IF_ICMPEQ -> emitBranch(VmOpcodes.VM_IF_ICMPEQ, label)
            Opcodes.IF_ICMPNE -> emitBranch(VmOpcodes.VM_IF_ICMPNE, label)
            Opcodes.IF_ICMPLT -> emitBranch(VmOpcodes.VM_IF_ICMPLT, label)
            Opcodes.IF_ICMPGE -> emitBranch(VmOpcodes.VM_IF_ICMPGE, label)
            Opcodes.IF_ICMPGT -> emitBranch(VmOpcodes.VM_IF_ICMPGT, label)
            Opcodes.IF_ICMPLE -> emitBranch(VmOpcodes.VM_IF_ICMPLE, label)
            Opcodes.IF_ACMPEQ -> emitBranch(VmOpcodes.VM_IF_ACMPEQ, label)
            Opcodes.IF_ACMPNE -> emitBranch(VmOpcodes.VM_IF_ACMPNE, label)
            Opcodes.GOTO -> emitBranch(VmOpcodes.VM_GOTO, label)
            Opcodes.JSR -> emitBranch(VmOpcodes.VM_JSR, label)
            Opcodes.IFNULL -> emitBranch(VmOpcodes.VM_IFNULL, label)
            Opcodes.IFNONNULL -> emitBranch(VmOpcodes.VM_IFNONNULL, label)
            else -> unsupportedOpcode("jump", opcode)
        }
    }

    override fun visitLdcInsn(value: Any) {
        when (value) {
            is Int -> { val cp = addConstant(value); emit(VmOpcodes.VM_LDC_INT, cp) }
            is Long -> { val cp = addConstant(value); emit(VmOpcodes.VM_LDC_LONG, cp) }
            is Float -> { val cp = addConstant(value); emit(VmOpcodes.VM_LDC_FLOAT, cp) }
            is Double -> { val cp = addConstant(value); emit(VmOpcodes.VM_LDC_DOUBLE, cp) }
            is String -> { val cp = addConstant(value); emit(VmOpcodes.VM_LDC_STRING, cp) }
            is Type -> { val cp = addConstant(value.descriptor); emit(VmOpcodes.VM_LDC_TYPE, cp) }
            is Handle -> { val cp = addConstant("handle|${value.tag}|${value.owner}|${value.name}|${value.desc}"); emit(VmOpcodes.VM_LDC_HANDLE, cp) }
            else -> unsupportedOpcode("ldc", -1)
        }
    }

    override fun visitIincInsn(`var`: Int, increment: Int) {
        emit(VmOpcodes.VM_IINC, `var`, increment)
    }

    override fun visitLabel(label: Label?) {
        if (label != null) emitLabel(label)
    }

    override fun visitTableSwitchInsn(min: Int, max: Int, dflt: Label?, vararg labels: Label?) {
        // Encoding: [min, max, defaultTarget, target0, target1, ..., targetN]
        val instIndex = instructions.size
        val operands = mutableListOf<Any>(min, max, 0) // 0 = placeholder for default
        for (i in labels.indices) operands.add(0) // placeholder for each case target
        instructions.add(VmInstruction(currentOffset, VmOpcodes.VM_TABLESWITCH, operands))
        currentOffset++
        if (dflt != null) labelRefs.add(LabelRef(instIndex, 2, dflt))
        for (i in labels.indices) {
            if (labels[i] != null) labelRefs.add(LabelRef(instIndex, 3 + i, labels[i]!!))
        }
    }

    override fun visitLookupSwitchInsn(dflt: Label?, keys: IntArray?, labels: Array<Label>?) {
        // Encoding: [npairs, defaultTarget, key0, target0, key1, target1, ...]
        val instIndex = instructions.size
        val npairs = keys?.size ?: 0
        val operands = mutableListOf<Any>(npairs, 0) // 0 = placeholder for default
        for (i in 0 until npairs) {
            operands.add(keys!![i])
            operands.add(0) // placeholder for target
        }
        instructions.add(VmInstruction(currentOffset, VmOpcodes.VM_LOOKUPSWITCH, operands))
        currentOffset++
        if (dflt != null) labelRefs.add(LabelRef(instIndex, 1, dflt))
        for (i in 0 until npairs) {
            if (labels != null && i < labels.size && labels[i] != null)
                labelRefs.add(LabelRef(instIndex, 3 + i * 2, labels[i]!!))
        }
    }

    override fun visitMultiANewArrayInsn(descriptor: String?, numDimensions: Int) {
        val cp = addConstant(descriptor ?: "java/lang/Object")
        emit(VmOpcodes.VM_MULTIANEWARRAY, cp, numDimensions)
    }

    override fun visitTryCatchBlock(start: Label?, end: Label?, handler: Label?, type: String?) {
        if (start == null || end == null || handler == null) return
        val typeCpIdx = if (type != null) addConstant(type) + 1 else 0
        exceptionEntries.add(VmExceptionEntry(start, end, handler, typeCpIdx))
    }

    override fun visitMaxs(maxStack: Int, maxLocals: Int) {
        emit(VmOpcodes.VM_MAXS, maxStack, maxLocals)
    }

    override fun visitEnd() {
    }
}

/**
 * VM opcode constants. These are the virtual opcodes used in the serialized
 * bytecode stream. They deliberately differ from JVM opcodes to make
 * static analysis harder.
 */
object VmOpcodes {
    const val VM_NOP = 0x00
    const val VM_ACONST_NULL = 0x01
    const val VM_ICONST = 0x02       // operand: int value
    const val VM_LCONST = 0x03       // operand: long value (via constant pool)
    const val VM_FCONST = 0x04       // operand: float value
    const val VM_DCONST = 0x05       // operand: double value
    const val VM_BIPUSH = 0x06
    const val VM_SIPUSH = 0x07
    const val VM_LDC_INT = 0x08
    const val VM_LDC_LONG = 0x09
    const val VM_LDC_FLOAT = 0x0A
    const val VM_LDC_DOUBLE = 0x0B
    const val VM_LDC_STRING = 0x0C
    const val VM_LDC_TYPE = 0x0D
    const val VM_LDC_HANDLE = 0x0E

    // Loads
    const val VM_ILOAD = 0x10
    const val VM_LLOAD = 0x11
    const val VM_FLOAD = 0x12
    const val VM_DLOAD = 0x13
    const val VM_ALOAD = 0x14

    // Stores
    const val VM_ISTORE = 0x20
    const val VM_LSTORE = 0x21
    const val VM_FSTORE = 0x22
    const val VM_DSTORE = 0x23
    const val VM_ASTORE = 0x24
    const val VM_IINC = 0x25
    const val VM_RET = 0x26

    // Stack
    const val VM_POP = 0x30
    const val VM_POP2 = 0x31
    const val VM_DUP = 0x32
    const val VM_DUP_X1 = 0x33
    const val VM_DUP_X2 = 0x34
    const val VM_DUP2 = 0x35
    const val VM_SWAP = 0x36
    const val VM_DUP2_X1 = 0xF6
    const val VM_DUP2_X2 = 0xF7

    // Arithmetic
    const val VM_IADD = 0x40
    const val VM_LADD = 0x41
    const val VM_FADD = 0x42
    const val VM_DADD = 0x43
    const val VM_ISUB = 0x44
    const val VM_LSUB = 0x45
    const val VM_FSUB = 0x46
    const val VM_DSUB = 0x47
    const val VM_IMUL = 0x48
    const val VM_LMUL = 0x49
    const val VM_FMUL = 0x4A
    const val VM_DMUL = 0x4B
    const val VM_IDIV = 0x4C
    const val VM_LDIV = 0x4D
    const val VM_FDIV = 0x4E
    const val VM_DDIV = 0x4F
    const val VM_IREM = 0x50
    const val VM_LREM = 0x51
    const val VM_FREM = 0xF2
    const val VM_DREM = 0xF3
    const val VM_INEG = 0x52
    const val VM_LNEG = 0x53
    const val VM_FNEG = 0x54
    const val VM_DNEG = 0x55

    // Shifts
    const val VM_ISHL = 0x56
    const val VM_ISHR = 0x57
    const val VM_IUSHR = 0x58
    const val VM_LSHL = 0x59
    const val VM_LSHR = 0x5A
    const val VM_LUSHR = 0x5B

    // Bitwise
    const val VM_IAND = 0x5C
    const val VM_LAND = 0x5D
    const val VM_IOR  = 0x5E
    const val VM_LOR  = 0x5F
    const val VM_IXOR = 0x68
    const val VM_LXOR = 0x69

    // Type conversions
    const val VM_I2L = 0x6A
    const val VM_I2F = 0x6B
    const val VM_I2D = 0x6C
    const val VM_L2I = 0x6D
    const val VM_L2F = 0x6E
    const val VM_L2D = 0x6F
    const val VM_F2I = 0x88
    const val VM_F2L = 0x89
    const val VM_F2D = 0x8A
    const val VM_D2I = 0x8B
    const val VM_D2L = 0x8C
    const val VM_D2F = 0x8D
    const val VM_I2B = 0x8E
    const val VM_I2C = 0x8F
    const val VM_I2S = 0x9A

    // Comparisons
    const val VM_LCMP = 0x60
    const val VM_FCMPL = 0x61
    const val VM_FCMPG = 0x62
    const val VM_DCMPL = 0x63
    const val VM_DCMPG = 0x64

    // Branches
    const val VM_IFEQ = 0x70
    const val VM_IFNE = 0x71
    const val VM_IFLT = 0x72
    const val VM_IFGE = 0x73
    const val VM_IFGT = 0x74
    const val VM_IFLE = 0x75
    const val VM_IF_ICMPEQ = 0x76
    const val VM_IF_ICMPNE = 0x77
    const val VM_IF_ICMPLT = 0x78
    const val VM_IF_ICMPGE = 0x79
    const val VM_IF_ICMPGT = 0x7A
    const val VM_IF_ICMPLE = 0x7B
    const val VM_IF_ACMPEQ = 0x7C
    const val VM_IF_ACMPNE = 0x7D
    const val VM_GOTO = 0x7E
    const val VM_JSR = 0x7F
    const val VM_IFNULL = 0x80
    const val VM_IFNONNULL = 0x81

    // Returns
    const val VM_IRETURN = 0x90
    const val VM_LRETURN = 0x91
    const val VM_FRETURN = 0x92
    const val VM_DRETURN = 0x93
    const val VM_ARETURN = 0x94
    const val VM_RETURN = 0x95
    const val VM_ATHROW = 0x96

    // Fields
    const val VM_GETSTATIC = 0xA0
    const val VM_PUTSTATIC = 0xA1
    const val VM_GETFIELD = 0xA2
    const val VM_PUTFIELD = 0xA3

    // Methods
    const val VM_INVOKEVIRTUAL = 0xB0
    const val VM_INVOKESPECIAL = 0xB1
    const val VM_INVOKESTATIC = 0xB2
    const val VM_INVOKEINTERFACE = 0xB3
    const val VM_INVOKEDYNAMIC = 0xB4

    // Objects
    const val VM_NEW = 0xC0
    const val VM_NEWARRAY = 0xC1
    const val VM_ANEWARRAY = 0xC2
    const val VM_ARRAYLENGTH = 0xC3
    const val VM_CHECKCAST = 0xC4
    const val VM_INSTANCEOF = 0xC5
    const val VM_MULTIANEWARRAY = 0xC6

    // Arrays
    const val VM_IALOAD = 0xD0
    const val VM_LALOAD = 0xD1
    const val VM_FALOAD = 0xD2
    const val VM_DALOAD = 0xD3
    const val VM_AALOAD = 0xD4
    const val VM_BALOAD = 0xD5
    const val VM_CALOAD = 0xD6
    const val VM_SALOAD = 0xD7
    const val VM_IASTORE = 0xD8
    const val VM_LASTORE = 0xD9
    const val VM_FASTORE = 0xDA
    const val VM_DASTORE = 0xDB
    const val VM_AASTORE = 0xDC
    const val VM_BASTORE = 0xDD
    const val VM_CASTORE = 0xDE
    const val VM_SASTORE = 0xDF

    // Monitor
    const val VM_MONITORENTER = 0xE0
    const val VM_MONITOREXIT = 0xE1

    // Polymorphic aliases for equivalent opcode semantics
    const val VM_ICONST_ALT = 0xE8
    const val VM_IADD_ALT = 0xE9
    const val VM_ISUB_ALT = 0xEA
    const val VM_ILOAD_ALT = 0xEB
    const val VM_ISTORE_ALT = 0xEC
    const val VM_IRETURN_ALT = 0xED
    const val VM_ICONST_ALT2 = 0xE2
    const val VM_IADD_ALT2 = 0xE3
    const val VM_ISUB_ALT2 = 0xE4
    const val VM_ILOAD_ALT2 = 0xE5
    const val VM_ISTORE_ALT2 = 0xE6
    const val VM_IRETURN_ALT2 = 0xE7

    // Extended polymorphic aliases (arithmetic/bitwise/load-store/array/field/branch families)
    const val VM_IMUL_ALT = 0x37
    const val VM_IXOR_ALT = 0x38
    const val VM_IAND_ALT = 0x39
    const val VM_IOR_ALT = 0x3A
    const val VM_ISHL_ALT = 0x3B
    const val VM_ISHR_ALT = 0x3C
    const val VM_IUSHR_ALT = 0x3D
    const val VM_INEG_ALT = 0x3E
    const val VM_LADD_ALT = 0x3F
    const val VM_ALOAD_ALT = 0x15
    const val VM_LLOAD_ALT = 0x16
    const val VM_FLOAD_ALT = 0x17
    const val VM_DLOAD_ALT = 0x18
    const val VM_ASTORE_ALT = 0x27
    const val VM_LSTORE_ALT = 0x28
    const val VM_FSTORE_ALT = 0x29
    const val VM_DSTORE_ALT = 0x2A
    const val VM_IALOAD_ALT = 0xA4
    const val VM_IASTORE_ALT = 0xA5
    const val VM_AALOAD_ALT = 0xA6
    const val VM_AASTORE_ALT = 0xA7
    const val VM_GETFIELD_ALT = 0xA8
    const val VM_PUTFIELD_ALT = 0xA9
    const val VM_GETSTATIC_ALT = 0xAA
    const val VM_PUTSTATIC_ALT = 0xAB
    const val VM_GOTO_ALT = 0x82
    const val VM_IFEQ_ALT = 0x83
    const val VM_IFNE_ALT = 0x84
    const val VM_IF_ICMPEQ_ALT = 0x85
    const val VM_IF_ICMPNE_ALT = 0x86
    const val VM_IFNULL_ALT = 0x87
    const val VM_IFNONNULL_ALT = 0x97
    const val VM_DUP_ALT = 0x98
    const val VM_POP_ALT = 0x99
    const val VM_SWAP_ALT = 0x9B

    const val VM_BIPUSH_ALT = 0x0F
    const val VM_SIPUSH_ALT = 0x19
    const val VM_LCONST_ALT = 0x1A
    const val VM_FCONST_ALT = 0x1B
    const val VM_DCONST_ALT = 0x1C
    const val VM_IREM_ALT = 0x1D
    const val VM_LREM_ALT = 0x1E
    const val VM_LAND_ALT = 0x1F
    const val VM_LOR_ALT = 0x2B
    const val VM_LXOR_ALT = 0x2C
    const val VM_IFLT_ALT = 0x2D
    const val VM_IFGE_ALT = 0x2E
    const val VM_IFGT_ALT = 0x2F
    const val VM_IFLE_ALT = 0xF4
    const val VM_IF_ICMPLT_ALT = 0xF5
    const val VM_IF_ICMPGE_ALT = 0x65
    const val VM_IF_ICMPGT_ALT = 0x66
    const val VM_IF_ICMPLE_ALT = 0x67
    const val VM_IF_ACMPEQ_ALT = 0x9C
    const val VM_IF_ACMPNE_ALT = 0x9D
    const val VM_LRETURN_ALT = 0x9E
    const val VM_FRETURN_ALT = 0x9F
    const val VM_DRETURN_ALT = 0xAC
    const val VM_ARETURN_ALT = 0xAD
    const val VM_RETURN_ALT = 0xAE
    const val VM_ATHROW_ALT = 0xAF
    const val VM_I2L_ALT = 0xB5
    const val VM_I2F_ALT = 0xB6
    const val VM_I2D_ALT = 0xB7
    const val VM_L2I_ALT = 0xB8
    const val VM_L2F_ALT = 0xB9
    const val VM_L2D_ALT = 0xBA
    const val VM_F2I_ALT = 0xBB
    const val VM_F2L_ALT = 0xBC
    const val VM_F2D_ALT = 0xBD
    const val VM_D2I_ALT = 0xBE
    const val VM_D2L_ALT = 0xBF
    const val VM_D2F_ALT = 0xC7
    const val VM_I2B_ALT = 0xC8
    const val VM_I2C_ALT = 0xC9
    const val VM_I2S_ALT = 0xCA
    const val VM_NEW_ALT = 0xCB
    const val VM_NEWARRAY_ALT = 0xCC
    const val VM_ANEWARRAY_ALT = 0xCD
    const val VM_ARRAYLENGTH_ALT = 0xCE
    const val VM_CHECKCAST_ALT = 0xCF
    const val VM_INSTANCEOF_ALT = 0xEE
    const val VM_MULTIANEWARRAY_ALT = 0xEF

    // Meta
    const val VM_TABLESWITCH = 0xF0
    const val VM_LOOKUPSWITCH = 0xF1
    const val VM_MAXS = 0xFE
    const val VM_UNSUPPORTED = 0xFF
}

private val VM_OPCODE_ALIASES = mapOf(
    VmOpcodes.VM_ICONST to intArrayOf(VmOpcodes.VM_ICONST, VmOpcodes.VM_ICONST_ALT, VmOpcodes.VM_ICONST_ALT2),
    VmOpcodes.VM_IADD to intArrayOf(VmOpcodes.VM_IADD, VmOpcodes.VM_IADD_ALT, VmOpcodes.VM_IADD_ALT2),
    VmOpcodes.VM_ISUB to intArrayOf(VmOpcodes.VM_ISUB, VmOpcodes.VM_ISUB_ALT, VmOpcodes.VM_ISUB_ALT2),
    VmOpcodes.VM_ILOAD to intArrayOf(VmOpcodes.VM_ILOAD, VmOpcodes.VM_ILOAD_ALT, VmOpcodes.VM_ILOAD_ALT2),
    VmOpcodes.VM_ISTORE to intArrayOf(VmOpcodes.VM_ISTORE, VmOpcodes.VM_ISTORE_ALT, VmOpcodes.VM_ISTORE_ALT2),
    VmOpcodes.VM_IRETURN to intArrayOf(VmOpcodes.VM_IRETURN, VmOpcodes.VM_IRETURN_ALT, VmOpcodes.VM_IRETURN_ALT2),
    VmOpcodes.VM_IMUL to intArrayOf(VmOpcodes.VM_IMUL, VmOpcodes.VM_IMUL_ALT),
    VmOpcodes.VM_IXOR to intArrayOf(VmOpcodes.VM_IXOR, VmOpcodes.VM_IXOR_ALT),
    VmOpcodes.VM_IAND to intArrayOf(VmOpcodes.VM_IAND, VmOpcodes.VM_IAND_ALT),
    VmOpcodes.VM_IOR to intArrayOf(VmOpcodes.VM_IOR, VmOpcodes.VM_IOR_ALT),
    VmOpcodes.VM_ISHL to intArrayOf(VmOpcodes.VM_ISHL, VmOpcodes.VM_ISHL_ALT),
    VmOpcodes.VM_ISHR to intArrayOf(VmOpcodes.VM_ISHR, VmOpcodes.VM_ISHR_ALT),
    VmOpcodes.VM_IUSHR to intArrayOf(VmOpcodes.VM_IUSHR, VmOpcodes.VM_IUSHR_ALT),
    VmOpcodes.VM_INEG to intArrayOf(VmOpcodes.VM_INEG, VmOpcodes.VM_INEG_ALT),
    VmOpcodes.VM_LADD to intArrayOf(VmOpcodes.VM_LADD, VmOpcodes.VM_LADD_ALT),
    VmOpcodes.VM_ALOAD to intArrayOf(VmOpcodes.VM_ALOAD, VmOpcodes.VM_ALOAD_ALT),
    VmOpcodes.VM_LLOAD to intArrayOf(VmOpcodes.VM_LLOAD, VmOpcodes.VM_LLOAD_ALT),
    VmOpcodes.VM_FLOAD to intArrayOf(VmOpcodes.VM_FLOAD, VmOpcodes.VM_FLOAD_ALT),
    VmOpcodes.VM_DLOAD to intArrayOf(VmOpcodes.VM_DLOAD, VmOpcodes.VM_DLOAD_ALT),
    VmOpcodes.VM_ASTORE to intArrayOf(VmOpcodes.VM_ASTORE, VmOpcodes.VM_ASTORE_ALT),
    VmOpcodes.VM_LSTORE to intArrayOf(VmOpcodes.VM_LSTORE, VmOpcodes.VM_LSTORE_ALT),
    VmOpcodes.VM_FSTORE to intArrayOf(VmOpcodes.VM_FSTORE, VmOpcodes.VM_FSTORE_ALT),
    VmOpcodes.VM_DSTORE to intArrayOf(VmOpcodes.VM_DSTORE, VmOpcodes.VM_DSTORE_ALT),
    VmOpcodes.VM_IALOAD to intArrayOf(VmOpcodes.VM_IALOAD, VmOpcodes.VM_IALOAD_ALT),
    VmOpcodes.VM_IASTORE to intArrayOf(VmOpcodes.VM_IASTORE, VmOpcodes.VM_IASTORE_ALT),
    VmOpcodes.VM_AALOAD to intArrayOf(VmOpcodes.VM_AALOAD, VmOpcodes.VM_AALOAD_ALT),
    VmOpcodes.VM_AASTORE to intArrayOf(VmOpcodes.VM_AASTORE, VmOpcodes.VM_AASTORE_ALT),
    VmOpcodes.VM_GETFIELD to intArrayOf(VmOpcodes.VM_GETFIELD, VmOpcodes.VM_GETFIELD_ALT),
    VmOpcodes.VM_PUTFIELD to intArrayOf(VmOpcodes.VM_PUTFIELD, VmOpcodes.VM_PUTFIELD_ALT),
    VmOpcodes.VM_GETSTATIC to intArrayOf(VmOpcodes.VM_GETSTATIC, VmOpcodes.VM_GETSTATIC_ALT),
    VmOpcodes.VM_PUTSTATIC to intArrayOf(VmOpcodes.VM_PUTSTATIC, VmOpcodes.VM_PUTSTATIC_ALT),
    VmOpcodes.VM_GOTO to intArrayOf(VmOpcodes.VM_GOTO, VmOpcodes.VM_GOTO_ALT),
    VmOpcodes.VM_IFEQ to intArrayOf(VmOpcodes.VM_IFEQ, VmOpcodes.VM_IFEQ_ALT),
    VmOpcodes.VM_IFNE to intArrayOf(VmOpcodes.VM_IFNE, VmOpcodes.VM_IFNE_ALT),
    VmOpcodes.VM_IF_ICMPEQ to intArrayOf(VmOpcodes.VM_IF_ICMPEQ, VmOpcodes.VM_IF_ICMPEQ_ALT),
    VmOpcodes.VM_IF_ICMPNE to intArrayOf(VmOpcodes.VM_IF_ICMPNE, VmOpcodes.VM_IF_ICMPNE_ALT),
    VmOpcodes.VM_IFNULL to intArrayOf(VmOpcodes.VM_IFNULL, VmOpcodes.VM_IFNULL_ALT),
    VmOpcodes.VM_IFNONNULL to intArrayOf(VmOpcodes.VM_IFNONNULL, VmOpcodes.VM_IFNONNULL_ALT),
    VmOpcodes.VM_DUP to intArrayOf(VmOpcodes.VM_DUP, VmOpcodes.VM_DUP_ALT),
    VmOpcodes.VM_POP to intArrayOf(VmOpcodes.VM_POP, VmOpcodes.VM_POP_ALT),
    VmOpcodes.VM_SWAP to intArrayOf(VmOpcodes.VM_SWAP, VmOpcodes.VM_SWAP_ALT),
    VmOpcodes.VM_BIPUSH to intArrayOf(VmOpcodes.VM_BIPUSH, VmOpcodes.VM_BIPUSH_ALT),
    VmOpcodes.VM_SIPUSH to intArrayOf(VmOpcodes.VM_SIPUSH, VmOpcodes.VM_SIPUSH_ALT),
    VmOpcodes.VM_LCONST to intArrayOf(VmOpcodes.VM_LCONST, VmOpcodes.VM_LCONST_ALT),
    VmOpcodes.VM_FCONST to intArrayOf(VmOpcodes.VM_FCONST, VmOpcodes.VM_FCONST_ALT),
    VmOpcodes.VM_DCONST to intArrayOf(VmOpcodes.VM_DCONST, VmOpcodes.VM_DCONST_ALT),
    VmOpcodes.VM_IREM to intArrayOf(VmOpcodes.VM_IREM, VmOpcodes.VM_IREM_ALT),
    VmOpcodes.VM_LREM to intArrayOf(VmOpcodes.VM_LREM, VmOpcodes.VM_LREM_ALT),
    VmOpcodes.VM_LAND to intArrayOf(VmOpcodes.VM_LAND, VmOpcodes.VM_LAND_ALT),
    VmOpcodes.VM_LOR to intArrayOf(VmOpcodes.VM_LOR, VmOpcodes.VM_LOR_ALT),
    VmOpcodes.VM_LXOR to intArrayOf(VmOpcodes.VM_LXOR, VmOpcodes.VM_LXOR_ALT),
    VmOpcodes.VM_IFLT to intArrayOf(VmOpcodes.VM_IFLT, VmOpcodes.VM_IFLT_ALT),
    VmOpcodes.VM_IFGE to intArrayOf(VmOpcodes.VM_IFGE, VmOpcodes.VM_IFGE_ALT),
    VmOpcodes.VM_IFGT to intArrayOf(VmOpcodes.VM_IFGT, VmOpcodes.VM_IFGT_ALT),
    VmOpcodes.VM_IFLE to intArrayOf(VmOpcodes.VM_IFLE, VmOpcodes.VM_IFLE_ALT),
    VmOpcodes.VM_IF_ICMPLT to intArrayOf(VmOpcodes.VM_IF_ICMPLT, VmOpcodes.VM_IF_ICMPLT_ALT),
    VmOpcodes.VM_IF_ICMPGE to intArrayOf(VmOpcodes.VM_IF_ICMPGE, VmOpcodes.VM_IF_ICMPGE_ALT),
    VmOpcodes.VM_IF_ICMPGT to intArrayOf(VmOpcodes.VM_IF_ICMPGT, VmOpcodes.VM_IF_ICMPGT_ALT),
    VmOpcodes.VM_IF_ICMPLE to intArrayOf(VmOpcodes.VM_IF_ICMPLE, VmOpcodes.VM_IF_ICMPLE_ALT),
    VmOpcodes.VM_IF_ACMPEQ to intArrayOf(VmOpcodes.VM_IF_ACMPEQ, VmOpcodes.VM_IF_ACMPEQ_ALT),
    VmOpcodes.VM_IF_ACMPNE to intArrayOf(VmOpcodes.VM_IF_ACMPNE, VmOpcodes.VM_IF_ACMPNE_ALT),
    VmOpcodes.VM_LRETURN to intArrayOf(VmOpcodes.VM_LRETURN, VmOpcodes.VM_LRETURN_ALT),
    VmOpcodes.VM_FRETURN to intArrayOf(VmOpcodes.VM_FRETURN, VmOpcodes.VM_FRETURN_ALT),
    VmOpcodes.VM_DRETURN to intArrayOf(VmOpcodes.VM_DRETURN, VmOpcodes.VM_DRETURN_ALT),
    VmOpcodes.VM_ARETURN to intArrayOf(VmOpcodes.VM_ARETURN, VmOpcodes.VM_ARETURN_ALT),
    VmOpcodes.VM_RETURN to intArrayOf(VmOpcodes.VM_RETURN, VmOpcodes.VM_RETURN_ALT),
    VmOpcodes.VM_ATHROW to intArrayOf(VmOpcodes.VM_ATHROW, VmOpcodes.VM_ATHROW_ALT),
    VmOpcodes.VM_I2L to intArrayOf(VmOpcodes.VM_I2L, VmOpcodes.VM_I2L_ALT),
    VmOpcodes.VM_I2F to intArrayOf(VmOpcodes.VM_I2F, VmOpcodes.VM_I2F_ALT),
    VmOpcodes.VM_I2D to intArrayOf(VmOpcodes.VM_I2D, VmOpcodes.VM_I2D_ALT),
    VmOpcodes.VM_L2I to intArrayOf(VmOpcodes.VM_L2I, VmOpcodes.VM_L2I_ALT),
    VmOpcodes.VM_L2F to intArrayOf(VmOpcodes.VM_L2F, VmOpcodes.VM_L2F_ALT),
    VmOpcodes.VM_L2D to intArrayOf(VmOpcodes.VM_L2D, VmOpcodes.VM_L2D_ALT),
    VmOpcodes.VM_F2I to intArrayOf(VmOpcodes.VM_F2I, VmOpcodes.VM_F2I_ALT),
    VmOpcodes.VM_F2L to intArrayOf(VmOpcodes.VM_F2L, VmOpcodes.VM_F2L_ALT),
    VmOpcodes.VM_F2D to intArrayOf(VmOpcodes.VM_F2D, VmOpcodes.VM_F2D_ALT),
    VmOpcodes.VM_D2I to intArrayOf(VmOpcodes.VM_D2I, VmOpcodes.VM_D2I_ALT),
    VmOpcodes.VM_D2L to intArrayOf(VmOpcodes.VM_D2L, VmOpcodes.VM_D2L_ALT),
    VmOpcodes.VM_D2F to intArrayOf(VmOpcodes.VM_D2F, VmOpcodes.VM_D2F_ALT),
    VmOpcodes.VM_I2B to intArrayOf(VmOpcodes.VM_I2B, VmOpcodes.VM_I2B_ALT),
    VmOpcodes.VM_I2C to intArrayOf(VmOpcodes.VM_I2C, VmOpcodes.VM_I2C_ALT),
    VmOpcodes.VM_I2S to intArrayOf(VmOpcodes.VM_I2S, VmOpcodes.VM_I2S_ALT),
    VmOpcodes.VM_NEW to intArrayOf(VmOpcodes.VM_NEW, VmOpcodes.VM_NEW_ALT),
    VmOpcodes.VM_NEWARRAY to intArrayOf(VmOpcodes.VM_NEWARRAY, VmOpcodes.VM_NEWARRAY_ALT),
    VmOpcodes.VM_ANEWARRAY to intArrayOf(VmOpcodes.VM_ANEWARRAY, VmOpcodes.VM_ANEWARRAY_ALT),
    VmOpcodes.VM_ARRAYLENGTH to intArrayOf(VmOpcodes.VM_ARRAYLENGTH, VmOpcodes.VM_ARRAYLENGTH_ALT),
    VmOpcodes.VM_CHECKCAST to intArrayOf(VmOpcodes.VM_CHECKCAST, VmOpcodes.VM_CHECKCAST_ALT),
    VmOpcodes.VM_INSTANCEOF to intArrayOf(VmOpcodes.VM_INSTANCEOF, VmOpcodes.VM_INSTANCEOF_ALT),
    VmOpcodes.VM_MULTIANEWARRAY to intArrayOf(VmOpcodes.VM_MULTIANEWARRAY, VmOpcodes.VM_MULTIANEWARRAY_ALT),
)

// --- Branch opcode set (used for block splitting) ---

private val VM_BRANCH_OPCODES = setOf(
    VmOpcodes.VM_GOTO, VmOpcodes.VM_JSR,
    VmOpcodes.VM_IFEQ, VmOpcodes.VM_IFNE, VmOpcodes.VM_IFLT, VmOpcodes.VM_IFGE, VmOpcodes.VM_IFGT, VmOpcodes.VM_IFLE,
    VmOpcodes.VM_IF_ICMPEQ, VmOpcodes.VM_IF_ICMPNE, VmOpcodes.VM_IF_ICMPLT, VmOpcodes.VM_IF_ICMPGE, VmOpcodes.VM_IF_ICMPGT, VmOpcodes.VM_IF_ICMPLE,
    VmOpcodes.VM_IF_ACMPEQ, VmOpcodes.VM_IF_ACMPNE, VmOpcodes.VM_IFNULL, VmOpcodes.VM_IFNONNULL,
    VmOpcodes.VM_TABLESWITCH, VmOpcodes.VM_LOOKUPSWITCH,
    VmOpcodes.VM_IRETURN, VmOpcodes.VM_LRETURN, VmOpcodes.VM_FRETURN, VmOpcodes.VM_DRETURN, VmOpcodes.VM_ARETURN, VmOpcodes.VM_RETURN, VmOpcodes.VM_ATHROW,
)

// --- VBC4 format helpers ---

private const val VBC4_VERSION = 4
private const val VBC4_FLAG_ENCRYPTED_CP = 0x0001
private const val VBC4_FLAG_BLOCK_ENCRYPTED = 0x0002
private const val VBC4_FLAG_MAC = 0x0004
private const val VBC4_FLAG_STATE_BOUND = 0x0008
private const val VBC4_FLAG_PER_BLOCK_ENCRYPT = 0x0010
private const val VBC4_FLAG_AUTHENTICATED = 0x0020
private const val VBC4_FLAG_PER_ENTRY_CP = 0x0040
private const val VBC4_FLAG_PADDED = 0x0080
private const val VBC4_FLAG_REGISTER_EXECUTABLE = 0x0100
private const val VBC4_FLAG_SUPER_OPERATORS = 0x0200
private const val VBC4_FLAG_ZSTD_SECTIONS = 0x0400
private const val VBC4_FLAG_BLOCK_DISPATCH = 0x0800
private const val VBC4_FLAG_NESTED_VM = 0x1000
private const val VBC4_NESTED_MAGIC = 0x4E56
private const val VBC4_NESTED_VERSION = 1
private const val VBC4_NESTED_FIELD_COUNT = 6
private const val VBC4_NESTED_MICROS_PER_ROW = VBC4_NESTED_FIELD_COUNT + 1
private const val VBC4_NESTED_FIELD_OPCODE_BASE = 0x7000
private const val VBC4_NESTED_COMMIT_OPCODE_BASE = 0x6000
private const val VBC4_NESTED_COMMIT_SLOT = 0x7F
private const val VBC4_SECTION_CONSTANT_POOL = 1
private const val VBC4_SECTION_CONSTANT_POOL_ENTRY = 9
private const val VBC4_CP_SECTION_VERSION = 1
private const val VBC4_SECTION_INSTRUCTIONS = 2
private const val VBC4_SECTION_EXCEPTIONS = 3
private const val VBC4_SECTION_PADDING = 8
private const val VBC4_STORED_ZSTD_FLAG = 0x80000000.toInt()
private const val VBC4_REG_FLAG_EXECUTABLE = 0x0001
private const val VBC4_REG_FLAG_SUPER = 0x0002
private const val VBC4_REG_FLAG_FOLDED = 0x0004
private const val VBC4_REG_FLAG_CONTINUATION = 0x8000
private const val VBC4_MAX_LOGICAL_BLOCKS = 12
private const val VBC4_REG_META = 0xFD
private const val VBC4_REG_OPERAND_CONT = 0xFC
private const val VBC4_SUPER_BASE = 0xF8
private const val VBC4_SUPER_CONST = 0xF8
private const val VBC4_SUPER_INT_ARITH = 0xF9
private const val VBC4_SUPER_CMP_BRANCH = 0xFA
private const val VBC4_SUPER_INVOKE = 0xFB
private val VBC4_CONST_OPCODES = setOf(VmOpcodes.VM_ICONST, VmOpcodes.VM_BIPUSH, VmOpcodes.VM_SIPUSH)
private val VBC4_INT_ARITH_OPCODES = setOf(VmOpcodes.VM_IADD, VmOpcodes.VM_ISUB, VmOpcodes.VM_IMUL)
private val VBC4_COMPARE_BUILDER_OPCODES = setOf(
    VmOpcodes.VM_LCMP, VmOpcodes.VM_FCMPL, VmOpcodes.VM_FCMPG, VmOpcodes.VM_DCMPL, VmOpcodes.VM_DCMPG,
)
private val VBC4_PREDICATE_BRANCH_OPCODES = setOf(
    VmOpcodes.VM_IFEQ, VmOpcodes.VM_IFNE, VmOpcodes.VM_IFLT, VmOpcodes.VM_IFGE, VmOpcodes.VM_IFGT, VmOpcodes.VM_IFLE,
)
// Item #7: semantic-fusion set for folded super-operators. Broader than the non-folded
// super set so more `const, <binop>` idioms (arithmetic + bitwise + shift) collapse into
// a single SUPER_INT_ARITH handler at rest, reducing one-to-one opcode mapping residue.
// Expansion reproduces the method's exact base ops, so semantics are preserved.
private val VBC4_FOLDED_FUSION_OPCODES = setOf(
    VmOpcodes.VM_IADD, VmOpcodes.VM_ISUB, VmOpcodes.VM_IMUL,
    VmOpcodes.VM_IAND, VmOpcodes.VM_IOR, VmOpcodes.VM_IXOR,
    VmOpcodes.VM_ISHL, VmOpcodes.VM_ISHR, VmOpcodes.VM_IUSHR,
)
private object Vbc4CryptoScope {
    private val activeSessionMaterial = ThreadLocal<ByteArray?>()

    fun <T> use(masterKey: ByteArray, layoutDigest: ByteArray, block: () -> T): T {
        val previous = activeSessionMaterial.get()
        val sessionMaterial = deriveSessionIntegrityMaterial(masterKey, layoutDigest)
        activeSessionMaterial.set(sessionMaterial)
        return try {
            block()
        } finally {
            java.util.Arrays.fill(sessionMaterial, 0)
            if (previous == null) activeSessionMaterial.remove() else activeSessionMaterial.set(previous)
        }
    }

    private fun deriveSessionIntegrityMaterial(masterKey: ByteArray, layoutDigest: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update("vbc4-session-integrity".toByteArray(Charsets.US_ASCII))
        digest.update(masterKey)
        digest.update(layoutDigest)
        digest.update(byteArrayOf(0x10, 0x42, 0x9F.toByte(), 0x6C))
        return digest.digest()
    }

    fun deriveScopedKey(label: ByteArray, seed: Int, vararg parts: ByteArray): ByteArray {
        val sessionMaterial = activeSessionMaterial.get()
            ?: error("VBC4 crypto operation outside Vbc4CryptoScope")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sessionMaterial, "HmacSHA256"))
        mac.update(intBytes(seed))
        for (part in parts) mac.update(part)
        mac.update(label)
        return mac.doFinal()
    }
}

private fun activeVbc4ScopedKey(label: ByteArray, seed: Int, vararg parts: ByteArray): ByteArray =
    Vbc4CryptoScope.deriveScopedKey(label, seed, *parts)

private fun vbc4Crypt(data: ByteArray, seed: Int, nonce: ByteArray, section: Int, blockId: Int): ByteArray {
    val key = vbc4AesKey(seed, nonce, section, blockId)
    val iv = vbc4AesIv(seed, nonce, section, blockId)
    return try {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        cipher.doFinal(data)
    } finally {
        java.util.Arrays.fill(key, 0)
        java.util.Arrays.fill(iv, 0)
    }
}

private fun zstdCompressSection(bytes: ByteArray): ByteArray {
    return Vbc4ZstdCodec.compress(bytes)
}

private data class Vbc4StoredSection(val bytes: ByteArray, val compressed: Boolean) {
    val encodedLength: Int get() = bytes.size or if (compressed) VBC4_STORED_ZSTD_FLAG else 0
}

private fun compressCpEntrySection(bytes: ByteArray): Vbc4StoredSection {
    val compressed = Vbc4ZstdCodec.compress(bytes)
    return if (compressed.size < bytes.size) {
        Vbc4StoredSection(compressed, compressed = true)
    } else {
        Vbc4StoredSection(bytes, compressed = false)
    }
}

private fun vbc4AesKey(seed: Int, nonce: ByteArray, section: Int, blockId: Int): ByteArray =
    withVbc4HmacMaterial(
        "vbc4-aes-key".toByteArray(Charsets.US_ASCII),
        seed,
        nonce,
        intBytes(section),
        intBytes(blockId),
    ) { material -> material.copyOfRange(0, 16) }

private fun vbc4AesIv(seed: Int, nonce: ByteArray, section: Int, blockId: Int): ByteArray =
    withVbc4HmacMaterial(
        "vbc4-aes-iv".toByteArray(Charsets.US_ASCII),
        seed,
        nonce,
        intBytes(section),
        intBytes(blockId),
    ) { material -> material.copyOfRange(0, 16) }

private fun vbc4MaskWord(seed: Int, section: Int, blockId: Int, offset: Int): Int =
    withVbc4HmacMaterial(
        "vbc4-opcode".toByteArray(Charsets.US_ASCII),
        seed,
        intBytes(section),
        intBytes(blockId),
        intBytes(offset),
    ) { material -> material[0].toInt() and 0xFF }

private fun vbc4OpcodeDialectSalt(seed: Int, stateBinding: String, entryMetadata: Vbc4EntryMetadata): Int {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    digest.update("vbc4-opcode-dialect".toByteArray(Charsets.US_ASCII))
    digest.update(intBytes(seed))
    digest.update(stateBinding.toByteArray(Charsets.UTF_8))
    digest.update(entryMetadata.encode().toByteArray(Charsets.UTF_8))
    return readMacInt(digest.digest())
}

private fun vbc4NestedDialect(seed: Int, profile: Int, blockId: Int, rowCount: Int): Int =
    vbc4NestedMix(seed, profile, blockId, rowCount, 0x23, seed.rotateLeft(9) xor profile.rotateLeft(3))

private fun vbc4NestedFieldOrder(seed: Int, profile: Int, blockId: Int, rowIndex: Int, dialect: Int): IntArray {
    val order = IntArray(VBC4_NESTED_FIELD_COUNT) { it }
    for (index in order.lastIndex downTo 1) {
        val mix = vbc4NestedMix(seed, profile, blockId, rowIndex, index + 0x31, dialect)
        val swapIndex = (mix and 0x7FFFFFFF) % (index + 1)
        val tmp = order[index]
        order[index] = order[swapIndex]
        order[swapIndex] = tmp
    }
    return order
}

private fun vbc4NestedRowChecksum(
    seed: Int,
    profile: Int,
    blockId: Int,
    rowIndex: Int,
    dialect: Int,
    fields: IntArray,
): Int {
    var x = vbc4NestedMix(seed, profile, blockId, rowIndex, VBC4_NESTED_COMMIT_SLOT, dialect)
    fields.forEachIndexed { index, field ->
        x = vbc4NestedMix(x xor field, profile, blockId, rowIndex, index + 0x91, dialect)
    }
    return x
}

private fun vbc4NestedMix(seed: Int, profile: Int, blockId: Int, rowIndex: Int, slot: Int, dialect: Int): Int {
    var x = seed
    x = x xor profile xor dialect xor (blockId * 0x45D9F3B) xor
        (rowIndex * 0x7FEB352D) xor (slot * 0x846CA68B.toInt())
    x = x xor (x ushr 16)
    x *= 0x7FEB352D
    x = x xor (x ushr 13)
    x *= 0x846CA68B.toInt()
    return x xor (x ushr 16)
}

private const val VBC4_DERIVE_LABEL_VM_STRUCTURE = "javashroud-vbc4-vm-structure-v1"

private fun deriveVbc4StructureSeed(
    context: Vbc4BuildContext,
    buildSeed: Int,
    entryMetadata: Vbc4EntryMetadata,
    structureEntropy: ByteArray,
): Int {
    val derived = context.deriveSubKey(
        VBC4_DERIVE_LABEL_VM_STRUCTURE,
        16,
        intBytes(buildSeed),
        entryMetadata.encode().toByteArray(Charsets.UTF_8),
        structureEntropy.copyOf(),
    )
    return try {
        readMacInt(derived) xor buildSeed
    } finally {
        java.util.Arrays.fill(derived, 0)
    }
}

private fun randomVbc4StructureEntropy(): ByteArray =
    ByteArray(32).also { SecureRandom().nextBytes(it) }

private fun vbc4EntryToken(seed: Int, blockId: Int): Int =
    withVbc4HmacMaterial(
        "vbc4-entry-token".toByteArray(Charsets.US_ASCII),
        seed,
        intBytes(blockId),
    ) { material -> readMacInt(material) }

private fun vbc4OpcodeMask(seed: Int, index: Int): Int = vbc4MaskWord(seed, 7, index, index) and 0xFF

private fun vbc4ExceptionToken(seed: Int, index: Int): Int =
    withVbc4HmacMaterial(
        "vbc4-exception-token".toByteArray(Charsets.US_ASCII),
        seed,
        intBytes(index),
    ) { material -> readMacInt(material) }

private fun vbc4ExceptionMask(seed: Int, index: Int, field: Int, token: Int): Int =
    withVbc4HmacMaterial(
        "vbc4-exception-mask".toByteArray(Charsets.US_ASCII),
        seed,
        intBytes(index),
        intBytes(field),
        intBytes(token),
    ) { material -> readMacInt(material) and 0xFFFF }

private fun vbc4Nonce(seed: Int, flags: Int, constantPoolPlain: ByteArray, exceptionPlain: ByteArray, blockCount: Int): ByteArray =
    withVbc4HmacMaterial(
        "vbc4-nonce".toByteArray(Charsets.US_ASCII),
        seed,
        intBytes(flags),
        intBytes(blockCount),
        constantPoolPlain,
        exceptionPlain,
    ) { material -> material.copyOfRange(0, 16) }

private fun vbc4WrappedSeed(seed: Int, nonce: ByteArray, stateBinding: String = ""): ByteArray {
    val bindingBytes = stateBinding.toByteArray(Charsets.UTF_8)
    val mask = vbc4Hmac("vbc4-seed-wrap".toByteArray(Charsets.US_ASCII), 0, nonce, bindingBytes)
    val token = vbc4Hmac("vbc4-seed-token".toByteArray(Charsets.US_ASCII), seed, nonce, bindingBytes)
    return try {
        val seedBytes = intBytes(seed)
        val wrapped = ByteArray(16)
        for (index in 0 until 4) wrapped[index] = (seedBytes[index].toInt() xor mask[index].toInt()).toByte()
        System.arraycopy(token, 0, wrapped, 4, 12)
        wrapped
    } finally {
        java.util.Arrays.fill(mask, 0)
        java.util.Arrays.fill(token, 0)
    }
}

private fun vbc4PadLength(seed: Int, nonce: ByteArray): Int =
    withVbc4HmacMaterial("vbc4-pad-length".toByteArray(Charsets.US_ASCII), seed, nonce) { material ->
        8 + ((material[0].toInt() and 0x3F))
    }

private fun vbc4KeyId(seed: Int, nonce: ByteArray): Int =
    withVbc4HmacMaterial("vbc4-key-id".toByteArray(Charsets.US_ASCII), seed, nonce) { material ->
        readMacInt(material)
    }

private inline fun <T> withVbc4HmacMaterial(data: ByteArray, seed: Int, vararg parts: ByteArray, block: (ByteArray) -> T): T {
    val material = vbc4Hmac(data, seed, *parts)
    return try {
        block(material)
    } finally {
        java.util.Arrays.fill(material, 0)
    }
}

private fun readMacInt(bytes: ByteArray): Int =
    ((bytes[0].toInt() and 0xFF) shl 24) or
        ((bytes[1].toInt() and 0xFF) shl 16) or
        ((bytes[2].toInt() and 0xFF) shl 8) or
        (bytes[3].toInt() and 0xFF)

private fun vbc4Hmac(data: ByteArray, seed: Int, vararg parts: ByteArray): ByteArray {
    val scopedKey = activeVbc4ScopedKey(data, seed, *parts)
    return try {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(scopedKey, "HmacSHA256"))
        mac.update(intBytes(seed))
        for (part in parts) mac.update(part)
        mac.update(data)
        mac.doFinal()
    } finally {
        java.util.Arrays.fill(scopedKey, 0)
    }
}

private fun intBytes(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)

private fun writeU4(out: ByteArray, offset: Int, value: Int) {
    out[offset] = ((value ushr 24) and 0xFF).toByte()
    out[offset + 1] = ((value ushr 16) and 0xFF).toByte()
    out[offset + 2] = ((value ushr 8) and 0xFF).toByte()
    out[offset + 3] = (value and 0xFF).toByte()
}

// --- Helper for writing binary data ---

private fun writeU2(out: java.io.ByteArrayOutputStream, value: Int) {
    out.write((value shr 8) and 0xFF)
    out.write(value and 0xFF)
}

private fun writeU4(out: java.io.ByteArrayOutputStream, value: Int) {
    out.write((value shr 24) and 0xFF)
    out.write((value shr 16) and 0xFF)
    out.write((value shr 8) and 0xFF)
    out.write(value and 0xFF)
}

private fun writeU8(out: java.io.ByteArrayOutputStream, value: Long) {
    writeU4(out, (value shr 32).toInt())
    writeU4(out, value.toInt())
}
