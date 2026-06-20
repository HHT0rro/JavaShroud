package io.github.hht0rro.javashroud.cfg

/**
 * An edge in the control flow graph.
 *
 * Edge types:
 * - NORMAL: sequential flow or unconditional jump
 * - CONDITIONAL_TRUE: taken branch when condition is true
 * - CONDITIONAL_FALSE: fall-through when condition is false
 * - EXCEPTION: exception handler edge
 */
enum class EdgeType {
    NORMAL,
    CONDITIONAL_TRUE,
    CONDITIONAL_FALSE,
    EXCEPTION,
}

data class CfgEdge(
    val source: BasicBlock,
    val target: BasicBlock,
    val type: EdgeType,
    val exceptionType: String? = null, // null means catch-all
)
