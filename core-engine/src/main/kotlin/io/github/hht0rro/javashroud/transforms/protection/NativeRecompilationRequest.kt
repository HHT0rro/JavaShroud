package io.github.hht0rro.javashroud.transforms.protection

/**
 * Build-only description of the native compilation routes selected for one
 * `jni-microkernel-loader` invocation.
 *
 * This contract deliberately stops at the pre-seal JAR entry names. It models
 * stable public compilation metadata only; compiler inputs, emitted payloads,
 * sealing output names, and execution state remain outside this request.
 */
internal class NativeRecompilationRequest private constructor(
    val nativeProtectionLevel: String,
    val nativePackingProfile: NativeRecompilationPackingProfile,
    routes: List<NativeRecompilationRoute>,
) {
    val nativePackingLevel: NativeKernelShellPacker.Level
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

        /**
         * Resolves selected platforms in caller order. The default is the current
         * canonical cross-platform order used by native recompilation.
         */
        internal fun forTargets(
            nativeProtectionLevel: String,
            nativePackingLevel: NativeKernelShellPacker.Level,
            targetPlatforms: Collection<String> = NativeRecompilationRoute.canonicalPlatformOrder,
        ): NativeRecompilationRequest {
            val requestedPlatforms = targetPlatforms.toList()
            require(requestedPlatforms.isNotEmpty()) { "native recompilation requires at least one target platform" }
            require(requestedPlatforms.distinct().size == requestedPlatforms.size) {
                "native recompilation target platforms must be unique"
            }

            val unknownPlatforms = requestedPlatforms.filterNot(NativeRecompilationRoute::isKnownPlatform)
            require(unknownPlatforms.isEmpty()) {
                "native recompilation target platform is unsupported: ${unknownPlatforms.joinToString(",")}"
            }

            return NativeRecompilationRequest(
                nativeProtectionLevel = nativeProtectionLevel,
                nativePackingProfile = NativeRecompilationPackingProfile.forLevel(nativePackingLevel),
                routes = requestedPlatforms.map(NativeRecompilationRoute::forPlatform),
            )
        }
    }
}

/**
 * Typed projection of the four existing native packing branches. The actual
 * compiler remains the sole owner of how these branches produce a native image.
 */
internal class NativeRecompilationPackingProfile private constructor(
    val level: NativeKernelShellPacker.Level,
    val outputForm: NativeRecompilationOutputForm,
) {
    init {
        require(level.usesStubShell == outputForm.usesStubShell) {
            "native packing profile does not match its shell form"
        }
    }

    companion object {
        internal fun forLevel(level: NativeKernelShellPacker.Level): NativeRecompilationPackingProfile =
            NativeRecompilationPackingProfile(
                level = level,
                outputForm = when (level) {
                    NativeKernelShellPacker.Level.OFF -> NativeRecompilationOutputForm.DIRECT_SECTION_SEALED
                    NativeKernelShellPacker.Level.STANDARD -> NativeRecompilationOutputForm.AUTHENTICATED_OVERLAY
                    NativeKernelShellPacker.Level.MAX -> NativeRecompilationOutputForm.OUTER_STUB_SHELL
                    NativeKernelShellPacker.Level.MAX_HARDENING -> NativeRecompilationOutputForm.HARDENED_OUTER_STUB_SHELL
                },
            )
    }
}

internal enum class NativeRecompilationOutputForm(
    val usesStubShell: Boolean,
) {
    DIRECT_SECTION_SEALED(false),
    AUTHENTICATED_OVERLAY(false),
    OUTER_STUB_SHELL(true),
    HARDENED_OUTER_STUB_SHELL(true),
}

/**
 * One known native target route before RuntimeArtifactSealing assigns a final
 * artifact-specific resource name.
 */
internal class NativeRecompilationRoute private constructor(
    val platform: String,
    val zigTarget: String,
    val outputName: String,
    val loadSuffix: String,
    val preSealResourcePath: String,
    val shellLoaderProfile: String,
) {
    companion object {
        private const val preSealResourceRoot = "META-INF/js-native"

        private val canonicalRoutes = listOf(
            route(
                platform = "windows-x64",
                zigTarget = "x86_64-windows-gnu",
                outputName = "js_kernel_windows-x64.dll",
                loadSuffix = ".dll",
                shellLoaderProfile = "pe64-memory-loader-headerdir-reloc-import-export-tlsrange-execbounds-v22",
            ),
            route(
                platform = "linux-x64",
                zigTarget = "x86_64-linux-gnu",
                outputName = "js_kernel_linux-x64.so",
                loadSuffix = ".so",
                shellLoaderProfile = "elf64-anonymous-loader-dynnull-hashbounds-strbounds-rela-init-execbounds-v6",
            ),
            route(
                platform = "macos-x64",
                zigTarget = "x86_64-macos-none",
                outputName = "js_kernel_macos-x64.dylib",
                loadSuffix = ".dylib",
                shellLoaderProfile = "macho64-validated-fail-closed-v2",
            ),
            route(
                platform = "macos-arm64",
                zigTarget = "aarch64-macos-none",
                outputName = "js_kernel_macos-arm64.dylib",
                loadSuffix = ".dylib",
                shellLoaderProfile = "macho64-validated-fail-closed-v2",
            ),
        )

        private val routesByPlatform = canonicalRoutes.associateBy(NativeRecompilationRoute::platform)

        internal val canonicalPlatformOrder: List<String> = canonicalRoutes.map(NativeRecompilationRoute::platform)

        internal fun isKnownPlatform(platform: String): Boolean = platform in routesByPlatform

        internal fun forPlatform(platform: String): NativeRecompilationRoute =
            requireNotNull(routesByPlatform[platform]) { "native recompilation target platform is unsupported: $platform" }

        private fun route(
            platform: String,
            zigTarget: String,
            outputName: String,
            loadSuffix: String,
            shellLoaderProfile: String,
        ): NativeRecompilationRoute {
            require(outputName.endsWith(loadSuffix)) {
                "native output '$outputName' must end with '$loadSuffix'"
            }
            return NativeRecompilationRoute(
                platform = platform,
                zigTarget = zigTarget,
                outputName = outputName,
                loadSuffix = loadSuffix,
                preSealResourcePath = "$preSealResourceRoot/$outputName",
                shellLoaderProfile = shellLoaderProfile,
            )
        }
    }
}
