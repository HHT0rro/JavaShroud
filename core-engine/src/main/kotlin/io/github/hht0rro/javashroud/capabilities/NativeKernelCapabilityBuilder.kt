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
        description = "Build and embed the current Qp Rust native runtime for protected string, page, VM, and unified-defense routes.",
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
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic native diversification seed.",
            ),
        ),
    ),
    CapabilityBinding(
        targeting = nativeKernelClassTargeting,
        id = "nativeshroud",
        name = "Custom packing",
        description = "After JSIM measurement, pack the compiled Qp native images externally: spawn the bundled/installed Xenolith CLI (cliPath + profile), or pause so the user can pack them manually (VMP / NativeShroud / etc.) and select the packed file back. Missing file, failed spawn, or cancel fails closed.",
        tagIds = listOf("native-kernel"),
        stability = "experimental",
        risk = "high",
        platformConstraints = listOf("Windows x64", "Linux x64"),
        compatibilityNotes = "The only spawned process is the external Xenolith CLI (spawn-only contract; no packer code is linked in-process). Windows requires a non-empty packed PE64 DLL that preserves the JS measurement sections (.jsms/.jsmk) and the JNI/qp_r1 bridge exports; Linux may reply SKIP to ship the unpacked .so. cliPath applies to windows-x64 only. Cancel, failed Xenolith run, or missing packedPath fails closed when this pass is enabled.",
        requiredPassIds = listOf("jni-microkernel-loader"),
        defaultEnabled = false,
        params = listOf(
            ParamSchema(
                key = "cliPath",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode(""),
                options = null,
                description = "Absolute path to the Xenolith CLI executable; when set, the engine runs `xenolith pack` on the unpacked Windows qp_ffi.dll before JSIM binding.",
                hidden = true,
            ),
            ParamSchema(
                key = "profile",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("standard"),
                options = listOf("fast", "standard", "max"),
                description = "Xenolith pack profile (fast/standard/max).",
                hidden = true,
            ),
            ParamSchema(
                key = "vmExports",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode(""),
                options = null,
                description = "Comma-separated export names to virtualize via `--vm-export`. JVM/CRT ABI names (JNI_OnLoad/JNI_OnUnload/Java_*/qp_r1_*/DllMain/*crt*/leading _) are refused; the fast profile rejects vmExports.",
                hidden = true,
            ),
            ParamSchema(
                key = "selectRva",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode(""),
                options = null,
                description = "Comma-separated explicit function ranges `RVA:LEN` (hex or decimal) passed as repeatable `--select-rva`. Fail-closed if unliftable.",
                hidden = true,
            ),
            ParamSchema(
                key = "selectFunction",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode(""),
                options = null,
                description = "Comma-separated symbol/export names selected after metadata discovery via `--select-function`.",
                hidden = true,
            ),
            ParamSchema(
                key = "selectAll",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Select every discoverable function (`--select-all`); discovery is never implicit without it.",
                hidden = true,
            ),
            ParamSchema(
                key = "strictCoverage",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Fail the pack when no function is selected or a selected function cannot be fully transformed (`--strict-coverage`). Mutually exclusive with allowNativeFallback.",
                hidden = true,
            ),
            ParamSchema(
                key = "allowNativeFallback",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Let unliftable selected functions stay native, reported as mixed_native (`--allow-native-fallback`). Mutually exclusive with strictCoverage.",
                hidden = true,
            ),
            ParamSchema(
                key = "lazyRegions",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Rejected: the VEH wake cannot run under the loader lock, so a lazily-sealed qp_ffi.dll fails its initialization routine. Kept in the schema only as a named fail-closed error.",
                hidden = true,
            ),
            ParamSchema(
                key = "protectImports",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Seal import name records in the envelope (`--protect-imports`; TLS/Fast targets keep the loader directory).",
                hidden = true,
            ),
            ParamSchema(
                key = "strictConstants",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Refuse to pack when read-only constants keep native references (`--strict-constants`).",
                hidden = true,
            ),
            ParamSchema(
                key = "traceDiverge",
                type = "boolean",
                defaultValue = JsonNodeFactory.instance.booleanNode(false),
                options = null,
                description = "Two semantically equal paths per block with a TEB^heap^RSP selector (`--trace-diverge`).",
                hidden = true,
            ),
            ParamSchema(
                key = "packedPath",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode(""),
                options = null,
                description = "Absolute path to a pre-packed Windows qp_ffi.dll for non-interactive CLI/tests.",
                hidden = true,
            ),
            ParamSchema(
                key = "packedPathLinux",
                type = "string",
                defaultValue = JsonNodeFactory.instance.textNode(""),
                options = null,
                description = "Absolute path to a pre-packed Linux libqp_ffi.so for non-interactive CLI/tests.",
                hidden = true,
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
