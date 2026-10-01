package io.github.hht0rro.javashroud.transforms.protection

/**
 * Build-only description of the locked Qp Rust compilation routes selected
 * for one `jni-microkernel-loader` invocation.
 *
 * This contract deliberately stops at the pre-seal JAR entry names. It models
 * stable compilation metadata only; compiler inputs, emitted payloads, sealing
 * output names, and execution state remain outside this request.
 */
internal class QpNativeCompilerRequest private constructor(
    val nativeProtectionLevel: String,
    routes: List<NativeRecompilationRoute>,
) {
    val routes: List<NativeRecompilationRoute> = routes.toList()

    init {
        require(nativeProtectionLevel in supportedNativeProtectionLevels) {
            "jni-microkernel-loader nativeProtectionLevel '$nativeProtectionLevel' is not supported"
        }
        require(this.routes.isNotEmpty()) { "native recompilation requires at least one target platform" }
        require(this.routes.map(NativeRecompilationRoute::platform).distinct().size == this.routes.size) {
            "native recompilation routes must have unique platforms"
        }
        require(this.routes.map(NativeRecompilationRoute::preSealResourcePath).distinct().size == this.routes.size) {
            "native recompilation routes must have unique pre-seal resource paths"
        }
    }

    companion object {
        private val supportedNativeProtectionLevels = setOf("standard", "aggressive")

        /** Resolve only the two locked Qp Rust routes in caller order. */
        internal fun forTargets(
            nativeProtectionLevel: String,
            targetPlatforms: Collection<String> = NativeRecompilationRoute.canonicalPlatformOrder,
        ): QpNativeCompilerRequest {
            val requestedPlatforms = targetPlatforms.map(NativeRecompilationRoute::normalizePlatform)
            require(requestedPlatforms.isNotEmpty()) { "native recompilation requires at least one target platform" }
            require(requestedPlatforms.distinct().size == requestedPlatforms.size) {
                "native recompilation target platforms must be unique"
            }
            return QpNativeCompilerRequest(
                nativeProtectionLevel = nativeProtectionLevel,
                routes = requestedPlatforms.map(NativeRecompilationRoute::forPlatform),
            )
        }
    }
}

/**
 * One locked Rust target route before RuntimeArtifactSealing assigns a final
 * artifact-specific resource name.
 */
internal class NativeRecompilationRoute private constructor(
    val platform: String,
    val rustTarget: String,
    val outputName: String,
    val loadSuffix: String,
    val shellLoaderProfile: String,
) {
    val preSealResourcePath: String
        get() = "${io.github.hht0rro.javashroud.transforms.protection.qp.qpResourceDir()}/$platform/$outputName"

    companion object {

        private val canonicalRoutes = listOf(
            route(
                platform = RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                outputName = "qp_ffi.dll",
                loadSuffix = ".dll",
                shellLoaderProfile = "rust-ffi-windows-x64-v1",
            ),
            route(
                platform = RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
                rustTarget = RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
                outputName = "libqp_ffi.so",
                loadSuffix = ".so",
                shellLoaderProfile = "rust-ffi-linux-x64-v1",
            ),
        )

        private val routesByPlatform = canonicalRoutes.associateBy(NativeRecompilationRoute::platform)

        internal val canonicalPlatformOrder: List<String> = canonicalRoutes.map(NativeRecompilationRoute::platform)

        internal fun normalizePlatform(value: String): String {
            val normalized = value.trim()
            return when (normalized) {
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET -> RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
                RustToolchainProvisioner.LINUX_RUNTIME_TARGET -> RustToolchainProvisioner.RUNTIME_TARGET_LINUX
                else -> throw IllegalArgumentException(
                    "Qp Rust target platform is unsupported: $value; " +
                        "only Windows x64 and Linux x64 glibc 2.17 are accepted",
                )
            }
        }

        internal fun forPlatform(platform: String): NativeRecompilationRoute =
            requireNotNull(routesByPlatform[platform]) {
                "Qp Rust target platform is unsupported: $platform"
            }

        private fun route(
            platform: String,
            rustTarget: String,
            outputName: String,
            loadSuffix: String,
            shellLoaderProfile: String,
        ): NativeRecompilationRoute {
            require(outputName.endsWith(loadSuffix)) {
                "Rust output '$outputName' must end with '$loadSuffix'"
            }
            require(platform in setOf(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
            )) {
                "unsupported Qp Rust route platform: $platform"
            }
            require(rustTarget == when (platform) {
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS -> RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX -> RustToolchainProvisioner.LINUX_RUNTIME_TARGET
                else -> error("unsupported Qp Rust route platform: $platform")
            }) {
                "Rust target does not match route platform: $platform/$rustTarget"
            }
            return NativeRecompilationRoute(
                platform = platform,
                rustTarget = rustTarget,
                outputName = outputName,
                loadSuffix = loadSuffix,
                shellLoaderProfile = shellLoaderProfile,
            )
        }
    }
}
