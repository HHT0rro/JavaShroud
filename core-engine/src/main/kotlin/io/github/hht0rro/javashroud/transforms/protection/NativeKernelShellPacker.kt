package io.github.hht0rro.javashroud.transforms.protection

/**
 * Compile-only compatibility boundary for QpNativeCompilerPass. It
 * carries configuration identity only and performs no packing, loading,
 * extraction, or fallback.
 */
@Deprecated("Use QpPackingLevel")
internal object NativeKernelShellPacker {
    enum class Level(private val r1Level: QpPackingLevel) {
        OFF(QpPackingLevel.OFF),
        STANDARD(QpPackingLevel.STANDARD),
        MAX(QpPackingLevel.MAX),
        MAX_HARDENING(QpPackingLevel.MAX_HARDENING);

        val configValue: String
            get() = r1Level.configValue

        internal fun toR1(): QpPackingLevel = r1Level

        companion object {
            fun parse(value: String): Level = valueOf(QpPackingLevel.parse(value).name)
        }
    }
}
