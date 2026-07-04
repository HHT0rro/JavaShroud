# Polymorphic CP + Register Row Envelope 实现补丁

$file = "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"
$content = Get-Content $file -Encoding UTF8

# 1. 添加标志常量（在 VBC4_FLAG_NESTED_VM 之后）
$lineNum = 0
foreach ($line in $content) {
    $lineNum++
    if ($line -match "^private const val VBC4_FLAG_NESTED_VM = 0x1000") {
        $newContent = @($content[0..($lineNum-1)])
        $newContent += "private const val VBC4_FLAG_POLYMORPHIC_CP = 0x2000"
        $newContent += "private const val VBC4_FLAG_REGISTER_ROW_ENVELOPE = 0x4000"
        $newContent += $content[$lineNum..($content.Length-1)]
        $content = $newContent
        Write-Host "✓ Added VBC4 flags"
        break
    }
}

# 2. 在 serializeConstantPool 之前添加辅助函数
$lineNum = 0
foreach ($line in $content) {
    $lineNum++
    if ($line -match "^\s+private fun serializeConstantPool\(\): ByteArray") {
        $helpers = @(
            "    private fun polymorphicConstantPoolIndexMap(): IntArray {",
            "        val size = constantPool.size",
            "        if (size == 0) return IntArray(0)",
            "        val physicalOrder = (0 until size)",
            "            .sortedWith(compareBy<Int> { ",
            "                structureSelector(`"cp-physical-order`", it, constantPool[it].hashCode(), size)",
            "            }.thenBy { it })",
            "        val logicalToPhysical = IntArray(size)",
            "        physicalOrder.forEachIndexed { physicalIndex, logicalIndex -> ",
            "            logicalToPhysical[logicalIndex] = physicalIndex ",
            "        }",
            "        return logicalToPhysical",
            "    }",
            "",
            "    private fun remapLogicalProgramCpIndexes(program: VmLogicalProgram, cpIndexMap: IntArray): VmLogicalProgram {",
            "        if (cpIndexMap.isEmpty()) return program",
            "        val remappedBlocks = program.blocks.map { block ->",
            "            val remappedInsns = block.instructions.map { insn ->",
            "                val newOperand = if ((insn.flags and 0x0002) != 0 && insn.operand > 0 && (insn.operand - 1) < cpIndexMap.size) {",
            "                    cpIndexMap[insn.operand - 1] + 1",
            "                } else {",
            "                    insn.operand",
            "                }",
            "                insn.copy(operand = newOperand)",
            "            }",
            "            block.copy(instructions = remappedInsns)",
            "        }",
            "        return program.copy(blocks = remappedBlocks)",
            "    }",
            ""
        )
        $newContent = @($content[0..($lineNum-2)])
        $newContent += $helpers
        $newContent += $content[($lineNum-1)..($content.Length-1)]
        $content = $newContent
        Write-Host "✓ Added polymorphic CP functions"
        break
    }
}

$content | Set-Content $file -Encoding UTF8
Write-Host "✓ Patch applied successfully"
