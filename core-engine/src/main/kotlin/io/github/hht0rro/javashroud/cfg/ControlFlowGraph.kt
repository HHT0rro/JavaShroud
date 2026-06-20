package io.github.hht0rro.javashroud.cfg

/**
 * A control flow graph for a single method.
 *
 * Provides access to basic blocks, edges, and exception ranges.
 * The entry block is the first block in the method.
 */
data class ControlFlowGraph(
    val blocks: List<BasicBlock>,
    val edges: List<CfgEdge>,
    val entryBlock: BasicBlock?,
) {
    val blockCount: Int get() = blocks.size
    val edgeCount: Int get() = edges.size

    /** Get all successor blocks of a given block. */
    fun successors(block: BasicBlock): List<BasicBlock> =
        edges.filter { it.source == block }.map { it.target }

    /** Get all predecessor blocks of a given block. */
    fun predecessors(block: BasicBlock): List<BasicBlock> =
        edges.filter { it.target == block }.map { it.source }

    /** Get all exception handler blocks. */
    fun exceptionHandlers(): List<BasicBlock> =
        edges.filter { it.type == EdgeType.EXCEPTION }.map { it.target }.distinct()

    /** Get blocks in topological order (entry first). */
    fun blocksInOrder(): List<BasicBlock> = blocks
}
