package io.github.hht0rro.javashroud.bytecode

import java.util.Random
import java.util.concurrent.atomic.AtomicLong

/**
 * Generates randomized helper method/field names for injected bytecode.
 *
 * Fixed prefixes like `__javashroud_*` are fingerprinting risks.
 * This generator produces short, non-obvious names that are still
 * valid JVM identifiers.
 */
internal object HelperNameGenerator {
    private val globalCounter = AtomicLong(System.nanoTime())

    /**
     * Generate a short random helper name.
     * Uses lowercase letters and digits to stay unobtrusive.
     */
    fun generateName(prefix: String = "", seed: Long? = null): String {
        val rng = if (seed != null) Random(seed) else Random(globalCounter.incrementAndGet())
        val len = 4 + rng.nextInt(4) // 4-7 chars
        val body = buildString {
            repeat(len) {
                val c = 'a' + rng.nextInt(26)
                append(c)
            }
        }
        return if (prefix.isEmpty()) body else "${prefix}_$body"
    }

    /**
     * Generate a sequential helper name like `a0000`, `a0001`, etc.
     */
    fun generateSequentialName(prefix: String = "a"): String {
        val idx = globalCounter.incrementAndGet()
        return "${prefix}${idx.toString().padStart(4, '0')}"
    }

    /**
     * Generate a per-class unique helper name using the class name as context.
     */
    fun generateClassScopedName(className: String, role: String): String {
        val hash = ((className + "#" + role).hashCode().toLong() and 0xffffffffL).toString(36)
        val nonce = globalCounter.incrementAndGet().toString(36)
        return "h${hash}${nonce}"
    }

    fun generateReservedHelperMethodName(className: String, role: String): String {
        return "\$_${generateClassScopedName(className, role)}"
    }
}
