package io.github.hht0rro.javashroud.bytecode

/**
 * Configuration for control flow obfuscation, extracted from pass params.
 */
data class ControlFlowConfig(
    val density: Int = 5,
    val dispatchMode: String = "if-chain",
    val algebraicFamily: String = "mixed",
    val handlerComplexity: String = "nop",
    val pattern: String = "dead-branch",
    val mode: String = "mixed",
    val frequency: Int = 8,
    val seed: Long? = null,
)

fun buildControlFlowConfig(params: Map<String, Any>): ControlFlowConfig = ControlFlowConfig(
    density = (params["density"] as? Int)?.coerceIn(1, 10) ?: 5,
    dispatchMode = (params["dispatchMode"] as? String) ?: "if-chain",
    algebraicFamily = (params["algebraicFamily"] as? String) ?: "mixed",
    handlerComplexity = (params["handlerComplexity"] as? String) ?: "nop",
    pattern = (params["pattern"] as? String) ?: "dead-branch",
    mode = (params["mode"] as? String) ?: "mixed",
    frequency = (params["frequency"] as? Int) ?: 8,
    seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long),
)
