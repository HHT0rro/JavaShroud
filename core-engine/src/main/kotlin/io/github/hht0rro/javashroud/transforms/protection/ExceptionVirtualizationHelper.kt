package io.github.hht0rro.javashroud.transforms.protection

/**
 * Runtime helper for exception semantic virtualization.
 */
object ExceptionVirtualizationHelper {

    private var enabled = true

    @JvmStatic
    fun shouldVirtualize(): Boolean = enabled
}

/**
 * Custom exception used for control flow virtualization.
 * This exception is used as a message passing mechanism.
 */
class FlowControlException : RuntimeException("Flow control") {
    companion object {
        private const val serialVersionUID = 1L
    }
}
