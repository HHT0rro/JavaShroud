package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.config.loadValidatedConfig
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Arrays
import java.util.HexFormat

internal data class EngineRunRequest(
    val configPath: Path,
    val config: ObfuscationConfig,
)

internal data class AutoBootSecret(
    val secret: ByteArray,
    val sidecar: Path?,
    val artifactBinding: ByteArray?,
    val delivery: String,
)

internal fun buildRunRequest(args: Array<String>): EngineRunRequest {
    val configPath: Path = parseConfigPath(args)
    return loadRunRequest(configPath)
}

internal fun loadRunRequest(configPath: Path): EngineRunRequest = EngineRunRequest(
    configPath = configPath,
    config = loadValidatedConfig(configPath),
)

/**
 * Generates a random Boot KEK when the configuration enables the JNI microkernel
 * loader but no external KEK is supplied. Depending on bootKeyDelivery, the
 * generated secret is either written to a sidecar file or retained only in
 * memory so the output builder can embed it in the final JAR.
 */
internal fun installAutoBootSecretIfNeeded(
    config: ObfuscationConfig,
    getenv: (String) -> String? = System::getenv,
): AutoBootSecret? {
    val hasJniLoader = config.passes.any { it.id == JNI_MICROKERNEL_LOADER_ID && it.enabled }
    if (!hasJniLoader) return null

    if (NativeKernelShellPacker.buildBootSecretProvider != null) return null
    // Treat an explicitly present environment variable (including an empty or
    // whitespace-only value) as caller-supplied. The runtime loader must report
    // that invalid value instead of silently replacing it with an auto-generated
    // secret or falling back to the embedded resource.
    if (getenv(NativeKernelShellPacker.BOOT_SECRET_ENV) != null) return null
    if (getenv(NativeKernelShellPacker.BOOT_SECRET_FILE_ENV) != null) return null

    val delivery = configuredBootKeyDelivery(config)
    val secret = ByteArray(BOOT_KEK_SIZE).also { SecureRandom().nextBytes(it) }
    val maxHardening = config.passes.any { pass ->
        pass.enabled && pass.id == JNI_MICROKERNEL_LOADER_ID &&
            pass.params["nativePackingLevel"]?.asText() == "max-hardening"
    }
    val artifactBinding = if (maxHardening) ByteArray(BOOT_KEK_SIZE).also { SecureRandom().nextBytes(it) } else null
    val outputPath = Path.of(config.outputJarPath)
    val suffix = if (maxHardening) HARDENED_BOOT_KEK_SIDECAR_SUFFIX else BOOT_KEK_SIDECAR_SUFFIX
    val sidecar = if (delivery == BootKekSidecar.DELIVERY_EXTERNAL_FILE) {
        outputPath.resolveSibling(outputPath.fileName.toString() + suffix)
    } else {
        null
    }

    if (sidecar != null) {
        // Machine binding remains an independent runtime gate. It must not alter the
        // externally supplied Boot KEK before the authenticated bindings catalog is loaded.
        val sidecarBytes = artifactBinding?.let { BootKekSidecar.encodeText(secret, it) }
            ?: HexFormat.of().formatHex(secret)
        sidecar.parent?.let(Files::createDirectories)
        Files.writeString(sidecar, sidecarBytes, Charsets.UTF_8)
    }

    NativeKernelShellPacker.buildBootSecretProvider = { secret.copyOf() }
    BootKekSidecar.buildArtifactBindingProvider = artifactBinding?.let { binding -> { binding.copyOf() } }
    return AutoBootSecret(secret, sidecar, artifactBinding, delivery)
}

internal fun wipeAutoBootSecret(generated: AutoBootSecret) {
    NativeKernelShellPacker.buildBootSecretProvider = null
    BootKekSidecar.buildArtifactBindingProvider = null
    Arrays.fill(generated.secret, 0)
    generated.artifactBinding?.let { Arrays.fill(it, 0) }
}

internal fun configuredBootKeyDelivery(config: ObfuscationConfig): String {
    val loaderPass = config.passes.firstOrNull { it.id == JNI_MICROKERNEL_LOADER_ID && it.enabled }
        ?: return BootKekSidecar.DELIVERY_EXTERNAL_FILE
    val delivery = loaderPass.params["bootKeyDelivery"]?.asText() ?: BootKekSidecar.DELIVERY_EXTERNAL_FILE
    require(delivery == BootKekSidecar.DELIVERY_EXTERNAL_FILE || delivery == BootKekSidecar.DELIVERY_EMBEDDED) {
        "jni-microkernel-loader bootKeyDelivery '$delivery' is not supported"
    }
    return delivery
}

internal fun cleanupEmbeddedBootSecretSidecars(config: ObfuscationConfig) {
    if (configuredBootKeyDelivery(config) != BootKekSidecar.DELIVERY_EMBEDDED) return
    val outputPath = Path.of(config.outputJarPath)
    for (suffix in listOf(BOOT_KEK_SIDECAR_SUFFIX, HARDENED_BOOT_KEK_SIDECAR_SUFFIX)) {
        Files.deleteIfExists(outputPath.resolveSibling(outputPath.fileName.toString() + suffix))
    }
}

private const val JNI_MICROKERNEL_LOADER_ID = "jni-microkernel-loader"
private const val BOOT_KEK_SIZE = 32
private const val BOOT_KEK_SIDECAR_SUFFIX = ".boot-secret.hex"
private const val HARDENED_BOOT_KEK_SIDECAR_SUFFIX = ".boot-kek.jsbk"
