package io.github.hht0rro.javashroud.transforms.protection

/**
 * Compile-only compatibility boundary for QpNativeCompilerPass. It
 * carries configuration identity only and performs no packing, loading,
 * extraction, or fallback.
 */
@Deprecated("Use QpPackingLevel")
internal object NativeKernelShellPacker {
    enum class Level(private val nativeLevel: QpPackingLevel) {
        OFF(QpPackingLevel.OFF),
        STANDARD(QpPackingLevel.STANDARD),
        MAX(QpPackingLevel.MAX),
        MAX_HARDENING(QpPackingLevel.MAX_HARDENING);

        val configValue: String
            get() = nativeLevel.configValue

        internal fun toNative(): QpPackingLevel = nativeLevel

        companion object {
            fun parse(value: String): Level = valueOf(QpPackingLevel.parse(value).name)
        }
    }
}
