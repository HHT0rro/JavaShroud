package io.github.hht0rro.javashroud.transforms.protection

/**
 * Build-only description of the locked AKEN-R1 Rust compilation routes selected
 * for one `jni-microkernel-loader` invocation.
 *
 * This contract deliberately stops at the pre-seal JAR entry names. It models
 * stable compilation metadata only; compiler inputs, emitted payloads, sealing
 * output names, and execution state remain outside this request.
 */
internal class NativeRecompilationRequest private constructor(
    val nativeProtectionLevel: String,
    val nativePackingProfile: NativeRecompilationPackingProfile,
    routes: List<NativeRecompilationRoute>,
) {
    val nativePackingLevel: AkenR1PackingLevel
        get() = nativePackingProfile.level

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

        /** Resolve only the two locked AKEN-R1 Rust routes in caller order. */
        internal fun forTargets(
            nativeProtectionLevel: String,
            nativePackingLevel: AkenR1PackingLevel,
            targetPlatforms: Collection<String> = NativeRecompilationRoute.canonicalPlatformOrder,
        ): NativeRecompilationRequest {
            val requestedPlatforms = targetPlatforms.map(NativeRecompilationRoute::normalizePlatform)
            require(requestedPlatforms.isNotEmpty()) { "native recompilation requires at least one target platform" }
            require(requestedPlatforms.distinct().size == requestedPlatforms.size) {
                "native recompilation target platforms must be unique"
            }

            return NativeRecompilationRequest(
                nativeProtectionLevel = nativeProtectionLevel,
                nativePackingProfile = NativeRecompilationPackingProfile.forLevel(nativePackingLevel),
                routes = requestedPlatforms.map(NativeRecompilationRoute::forPlatform),
            )
        }

        /** Compatibility bridge for the current recompilation API. */
        @Deprecated("Use AkenR1PackingLevel")
        internal fun forTargets(
            nativeProtectionLevel: String,
            nativePackingLevel: NativeKernelShellPacker.Level,
            targetPlatforms: Collection<String> = NativeRecompilationRoute.canonicalPlatformOrder,
        ): NativeRecompilationRequest {
            val requestedPlatforms = targetPlatforms.map { value ->
                runCatching { NativeRecompilationRoute.normalizePlatform(value) }
                    .getOrElse { value.trim().ifEmpty { "<blank>" } }
            }
            require(requestedPlatforms.isNotEmpty()) { "native recompilation requires at least one target platform" }
            require(requestedPlatforms.distinct().size == requestedPlatforms.size) {
                "native recompilation target platforms must have unique values"
            }
            return NativeRecompilationRequest(
                nativeProtectionLevel = nativeProtectionLevel,
                nativePackingProfile = NativeRecompilationPackingProfile.forLevel(nativePackingLevel.toR1()),
                routes = requestedPlatforms.map { platform ->
                    if (NativeRecompilationRoute.isKnownPlatform(platform)) {
                        NativeRecompilationRoute.forPlatform(platform)
                    } else {
                        NativeRecompilationRoute.rejected(platform)
                    }
                },
            )
        }
    }
}

/** Direct Rust artifact policy selected by the retained configuration value. */
internal class NativeRecompilationPackingProfile private constructor(
    val level: AkenR1PackingLevel,
    val outputForm: AkenR1OutputForm,
) {
    init {
        require(level.hardened == outputForm.hardened) {
            "AKEN-R1 packing level does not match its direct Rust output policy"
        }
    }

    companion object {
        internal fun forLevel(level: AkenR1PackingLevel): NativeRecompilationPackingProfile =
            NativeRecompilationPackingProfile(
                level = level,
                outputForm = if (level.hardened) {
                    AkenR1OutputForm.HARDENED_DIRECT_RUST_CDYLIB
                } else {
                    AkenR1OutputForm.DIRECT_RUST_CDYLIB
                },
            )
    }
}

internal enum class AkenR1OutputForm(
    val hardened: Boolean,
) {
    DIRECT_RUST_CDYLIB(false),
    HARDENED_DIRECT_RUST_CDYLIB(true),
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
    val preSealResourcePath: String,
    val shellLoaderProfile: String,
) {
    companion object {
        private const val preSealResourceRoot = "META-INF/jsrt"

        private val canonicalRoutes = listOf(
            route(
                platform = RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                rustTarget = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                outputName = "jsrt_ffi.dll",
                loadSuffix = ".dll",
                shellLoaderProfile = "rust-ffi-windows-x64-v1",
            ),
            route(
                platform = RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
                rustTarget = RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
                outputName = "libjsrt_ffi.so",
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
                    "AKEN-R1 Rust target platform is unsupported: $value; " +
                        "only Windows x64 and Linux x64 glibc 2.17 are accepted",
                )
            }
        }

        internal fun isKnownPlatform(platform: String): Boolean = platform in routesByPlatform

        internal fun forPlatform(platform: String): NativeRecompilationRoute =
            requireNotNull(routesByPlatform[platform]) {
                "AKEN-R1 Rust target platform is unsupported: $platform"
            }

        /** Preserve diagnostic failure categories for the raw compatibility adapter. */
        internal fun rejected(platform: String): NativeRecompilationRoute = NativeRecompilationRoute(
            platform = platform,
            rustTarget = "unsupported",
            outputName = "rejected.unsupported",
            loadSuffix = ".unsupported",
            preSealResourcePath = "$preSealResourceRoot/rejected/$platform",
            shellLoaderProfile = "r1-rejected-route",
        )

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
                "unsupported AKEN-R1 Rust route platform: $platform"
            }
            require(rustTarget == when (platform) {
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS -> RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX -> RustToolchainProvisioner.LINUX_RUNTIME_TARGET
                else -> error("unsupported AKEN-R1 Rust route platform: $platform")
            }) {
                "Rust target does not match route platform: $platform/$rustTarget"
            }
            return NativeRecompilationRoute(
                platform = platform,
                rustTarget = rustTarget,
                outputName = outputName,
                loadSuffix = loadSuffix,
                preSealResourcePath = "$preSealResourceRoot/$platform/$outputName",
                shellLoaderProfile = shellLoaderProfile,
            )
        }
    }
}
