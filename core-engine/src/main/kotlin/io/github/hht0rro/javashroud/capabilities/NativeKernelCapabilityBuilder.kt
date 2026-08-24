package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ModuleTargetingCapability
import io.github.hht0rro.javashroud.model.schema.ParamSchema

private val jniMicrokernelAnchorPassIds = listOf(
    "os-anti-debug",
    "os-anti-vm",
    "callsite-rotation-protection",
    "exception-semantic-virtualization",
    "method-virtualization",
    "string-encryption",
)

private val nativeKernelClassTargeting = ModuleTargetingCapability(
    supported = true,
    targetKinds = listOf("class"),
)

/** Current-format JNI microkernel capability. */
internal fun nativeKernelCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        targeting = nativeKernelClassTargeting,
        id = "jni-microkernel-loader",
        name = "JNI Microkernel Loader",
        description = "Build and embed the current AKEN-R1 Rust native runtime for protected string, page, VM, and unified-defense routes.",
        tagIds = listOf("native-kernel"),
        stability = "experimental",
        risk = "high",
        platformConstraints = listOf("Windows x64", "Linux x64"),
        compatibilityNotes = "The current format requires a verified Rust native image. Toolchain, ABI, registration, image validation, and runtime load failure are fail-closed. Retired loader, environment-binding, and delayed-decryption formats are not accepted.",
        requiresAnyPassIds = jniMicrokernelAnchorPassIds,
        defaultEnabled = false,
        params = listOf(
            ParamSchema(
                key = "kernelComponents",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("loader"),
                options = listOf("loader", "decrypt", "vm", "guards", "all"),
                description = "Native capability subset.",
            ),
            ParamSchema(
                key = "targetPlatform",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode("auto"),
                options = null,
                description = "auto, all, windows-x64, linux-x64, or a comma-separated supported target list.",
            ),
            ParamSchema(
                key = "diversifiedVirtualization",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(true),
                options = null,
                description = "Enable diversified VM serialization.",
                hidden = true,
            ),
            ParamSchema(
                key = "nativeRecompilation",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(true),
                options = null,
                description = "Rebuild and validate the bundled Rust runtime for this artifact.",
            ),
            ParamSchema(
                key = "nativeProtectionLevel",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("standard"),
                options = listOf("standard", "aggressive"),
                description = "Native runtime hardening level.",
                hidden = true,
            ),
            ParamSchema(
                key = "nativePackingLevel",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("max"),
                options = listOf("off", "standard", "max", "max-hardening"),
                description = "AKEN-R1 Rust cdylib hardening level.",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic native diversification seed.",
            ),
        ),
    ),
)

fun buildNativeKernelCapabilityDefinitions(): List<ModuleDefinition> =
    nativeKernelCapabilityBindings().map { binding ->
        ModuleDefinition(
            id = binding.id,
            name = binding.name,
            description = binding.description,
            tagIds = binding.tagIds,
            params = binding.params,
            stability = binding.stability,
            risk = binding.risk,
            requiresRuntimeFlags = binding.requiresRuntimeFlags,
            platformConstraints = binding.platformConstraints,
            compatibilityNotes = binding.compatibilityNotes,
            requiredPassIds = binding.requiredPassIds,
            requiresAnyPassIds = binding.requiresAnyPassIds,
            variantRequirements = binding.variantRequirements,
            defaultEnabled = binding.defaultEnabled,
            requiresOptIn = binding.requiresOptIn || binding.risk == "high",
            targeting = binding.targeting,
        )
    }