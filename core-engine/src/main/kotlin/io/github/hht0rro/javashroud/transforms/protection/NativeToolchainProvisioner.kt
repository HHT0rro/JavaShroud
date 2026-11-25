package io.github.hht0rro.javashroud.transforms.protection

/**
 * Diagnostic message type consumed by the current recompilation API.
 * RustToolchainProvisioner owns all Qp toolchain resolution; this type
 * performs no discovery, download, extraction, or fallback.
 */
@Deprecated("Qp uses RustToolchainProvisioner for all toolchain resolution")
object NativeToolchainProvisioner {
    data class ResolutionMessage(
        val level: String,
        val message: String,
        val progress: Int? = null,
    )
}
