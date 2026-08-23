package io.github.hht0rro.javashroud.transforms.protection

import java.util.Locale

/** Configuration identity for the direct AKEN-R1 Rust cdylib route. */
internal enum class AkenR1PackingLevel(
    val configValue: String,
    val hardened: Boolean,
) {
    OFF("off", false),
    STANDARD("standard", false),
    MAX("max", false),
    MAX_HARDENING("max-hardening", true);

    companion object {
        fun parse(value: String): AkenR1PackingLevel = when (value.trim().lowercase(Locale.ROOT)) {
            "off" -> OFF
            "standard" -> STANDARD
            "max" -> MAX
            "max-hardening" -> MAX_HARDENING
            else -> throw IllegalArgumentException(
                "jni-microkernel-loader nativePackingLevel '$value' is not supported",
            )
        }
    }
}
