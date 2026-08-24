package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import java.nio.file.Path
import kotlin.io.path.absolutePathString

internal object HardenedDefaultPipeline {
    val RELEASE_PASSES: List<String> = listOf(
        "rename-packages",
        "rename-classes",
        "rename-methods",
        "rename-fields",
        "string-encryption",
        "invoke-dynamic-indirection",
        "callsite-rotation-protection",
        "jni-microkernel-loader",
        "os-anti-debug",
        "os-anti-vm",
        "method-virtualization",
        "strip-compile-debug-info",
        "control-flow-flattening",
    )

    val COSMETIC_PASSES: Set<String> = setOf(
        "anti-decompiler-structure",
    )

    fun defaultPassSpecs(): List<PassSpec> =
        RELEASE_PASSES.map { id -> PassSpec(id = id, enabled = true, params = emptyMap()) }

    fun validate(config: ObfuscationConfig, passes: List<PassSpec>, configPath: Path) {
        if (config.protectionProfile != HardenedProtectionProfile.RELEASE_HARDENED) return
        val enabledPasses = passes.filter { it.enabled }
        val enabled = enabledPasses.map { it.id }.toSet()
        val stringCodec = enabledPasses.firstOrNull { it.id == "string-encryption" }?.params?.get("payloadCodec")?.asText()
        val numericCodec = enabledPasses.firstOrNull { it.id == "integer-constant-obfuscation" }?.params?.get("resolverCodec")?.asText()
        if (numericCodec == "des") {
            throw IllegalArgumentException(
                "Config validation failed: integer-constant-obfuscation resolverCodec=des is retired; use xor, path=" +
                    configPath.absolutePathString(),
            )
        }
        val cosmetic = enabled.intersect(COSMETIC_PASSES)
        if (cosmetic.isNotEmpty() && !config.allowIncomplete && !config.allowOptInPasses) {
            throw IllegalArgumentException(
                "Config validation failed: RELEASE_HARDENED rejects cosmetic passes " + cosmetic.joinToString(", ") +
                    "; mark them opt-in via MINIMAL or allowIncomplete, path=" + configPath.absolutePathString(),
            )
        }
        if (stringCodec == "des") {
            throw IllegalArgumentException(
                "Config validation failed: payloadCodec=des is retired under RELEASE_HARDENED; use aes-gcm or native-kernel, path=" +
                    configPath.absolutePathString(),
            )
        }
        if ("method-virtualization" in enabled && "jni-microkernel-loader" !in enabled && !config.allowIncomplete) {
            throw IllegalArgumentException(
                "Config validation failed: protectionProfile=" + config.protectionProfile.wireValue +
                    " requires jni-microkernel-loader whenever method-virtualization is enabled, path=" +
                    configPath.absolutePathString(),
            )
        }
        val defensePasses = enabled.intersect(setOf("os-anti-debug", "os-anti-vm"))
        if (defensePasses.isNotEmpty() && "jni-microkernel-loader" !in enabled && !config.allowIncomplete) {
            throw IllegalArgumentException(
                "Config validation failed: protectionProfile=" + config.protectionProfile.wireValue +
                    " requires jni-microkernel-loader for unified defense passes " +
                    defensePasses.sorted().joinToString(", ") + ", path=" +
                    configPath.absolutePathString(),
            )
        }
        if (config.protectionProfile == HardenedProtectionProfile.ANALYSIS_ONLY) return
        if ("js-native-cfg-evidence" in enabled || enabled.any { it.contains("analysis-only") }) {
            throw IllegalArgumentException(
                "Config validation failed: ANALYSIS_ONLY passes cannot enter RELEASE_HARDENED, path=" +
                    configPath.absolutePathString(),
            )
        }
    }
}
