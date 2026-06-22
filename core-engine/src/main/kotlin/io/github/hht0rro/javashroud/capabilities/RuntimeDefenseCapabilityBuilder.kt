package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun runtimeDefenseCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "callsite-rotation-protection",
        name = "Callsite Rotation Protection",
        description = "Switch real call targets at runtime with MutableCallSite, epoch, counter, thread-local, or random signals to make static callsite recovery harder.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "Changes callsite linking and runtime dispatch paths; verify performance, debugging, and framework proxy scenarios.",
        params = listOf(
            ParamSchema(
                key = "rotationStrategy",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("epoch"),
                options = listOf("epoch", "counter", "thread-local", "random"),
                description = "Rotation strategy.",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic seed.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "environment-bound-keys",
        name = "Environment Bound Keys",
        description = "Derive decryption keys from hardware, JVM parameters, certificate, license, or remote authorization material through a KDF so output binds to the target environment.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = "Requires runtime binding material; environment changes directly affect decryption and startup behavior.",
        requiredPassIds = listOf("jni-microkernel-loader"),
        params = listOf(
            ParamSchema(
                key = "bindingSource",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("jvm-params"),
                options = listOf("hardware-id", "jvm-params", "certificate-fingerprint", "combined"),
                description = "Key binding source.",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic seed.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "anti-symbolic-execution",
        name = "Anti Symbolic Execution",
        description = "Inject runtime-data-driven opaque predicates so symbolic execution tools cannot remove branches through constant constraint solving alone.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = RUNTIME_HELPER_COMPATIBILITY_NOTE,
        params = listOf(
            ParamSchema(
                key = "trapDensity",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(5),
                options = null,
                description = "Inject one symbolic execution trap every N methods.",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic seed.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "exception-semantic-virtualization",
        name = "Exception Semantic Virtualization",
        description = "Convert normal control flow to exception-driven flow using custom exception types.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "May impact performance and debugging.",
        params = listOf(
            ParamSchema(key = "virtualizationLevel", type = "enum", defaultValue = JsonNodeFactory.instance.textNode("selective"), options = listOf("selective", "aggressive"), description = "Virtualization level."),
            ParamSchema(key = "seed", type = "number", defaultValue = JsonNodeFactory.instance.nullNode(), options = null, description = "Deterministic seed."),
        ),
    ),
)

fun buildRuntimeDefenseCapabilityDefinitions() = capabilityDefinitions(runtimeDefenseCapabilityBindings())
