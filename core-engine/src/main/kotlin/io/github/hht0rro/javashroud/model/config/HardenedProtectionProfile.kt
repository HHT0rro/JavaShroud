package io.github.hht0rro.javashroud.model.config

/**
 * Build protection profile. Default is [RELEASE_HARDENED].
 * [MINIMAL] must be selected explicitly and is reported as low protection.
 * [ANALYSIS_ONLY] artifacts must not enter release tasks.
 */
enum class HardenedProtectionProfile(val wireValue: String) {
    RELEASE_HARDENED("release-hardened"),
    ANALYSIS_ONLY("analysis-only"),
    MINIMAL("minimal"),
    ;

    val requiresReleaseScan: Boolean
        get() = this == RELEASE_HARDENED || this == ANALYSIS_ONLY

    val allowsDiagnostics: Boolean
        get() = this != RELEASE_HARDENED

    val isLowProtection: Boolean
        get() = this == MINIMAL

    companion object {
        fun fromWireValue(value: String): HardenedProtectionProfile {
            val normalized = value.trim().lowercase()
            return values().firstOrNull { it.wireValue == normalized }
                ?: throw IllegalArgumentException(
                    "Config validation failed: protectionProfile '" + value + "' is not supported; " +
                        "supported values: " + values().joinToString(", ") { it.wireValue },
                )
        }
    }
}
