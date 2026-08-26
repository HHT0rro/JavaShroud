package io.github.hht0rro.javashroud.model.config

/** JDK versions used by the hardened release matrix. */
object HardenedJdkMatrix {
    val BLOCKING: Set<Int> = setOf(17, 21)
    val OBSERVATIONAL: Set<Int> = setOf(8, 11)

    fun currentFeature(): Int = Runtime.version().feature()

    fun isBlockingRuntime(feature: Int = currentFeature()): Boolean = feature in BLOCKING
}
