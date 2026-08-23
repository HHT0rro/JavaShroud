package io.github.hht0rro.javashroud.transforms.protection

/**
 * Compile-only compatibility boundary for NativeRecompilationTransforms. It
 * carries configuration identity only and performs no packing, loading,
 * extraction, or fallback.
 */
@Deprecated("Use AkenR1PackingLevel")
internal object NativeKernelShellPacker {
    enum class Level(private val r1Level: AkenR1PackingLevel) {
        OFF(AkenR1PackingLevel.OFF),
        STANDARD(AkenR1PackingLevel.STANDARD),
        MAX(AkenR1PackingLevel.MAX),
        MAX_HARDENING(AkenR1PackingLevel.MAX_HARDENING);

        val configValue: String
            get() = r1Level.configValue

        internal fun toR1(): AkenR1PackingLevel = r1Level

        companion object {
            fun parse(value: String): Level = valueOf(AkenR1PackingLevel.parse(value).name)
        }
    }
}
