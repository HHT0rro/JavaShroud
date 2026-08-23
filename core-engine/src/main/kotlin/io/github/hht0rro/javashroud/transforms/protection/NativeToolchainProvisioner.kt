package io.github.hht0rro.javashroud.transforms.protection

/**
 * Diagnostic message type consumed by the current recompilation API.
 * RustToolchainProvisioner owns all AKEN-R1 toolchain resolution; this type
 * performs no discovery, download, extraction, or fallback.
 */
@Deprecated("AKEN-R1 uses RustToolchainProvisioner for all toolchain resolution")
object NativeToolchainProvisioner {
    data class ResolutionMessage(
        val level: String,
        val message: String,
        val progress: Int? = null,
    )
}
