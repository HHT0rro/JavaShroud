package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun runtimeDefenseCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "callsite-rotation-protection",
        name = "Callsite Rotation Protection",
        description = "Experimental medium-strength callsite perturbation: switch call targets at runtime with MutableCallSite, epoch, counter, thread-local, or random signals to raise static recovery cost. It is observable at runtime and is not a VM-level protection by itself.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "Changes callsite linking and runtime dispatch paths; verify performance, debugging, and framework proxy scenarios. Treat as cost-raising dispatch indirection, not a hard anti-hook boundary.",
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
        description = "Bind runtime key derivation to normalized hardware, JVM parameter, certificate fingerprint, or combined environment material through the sealed native KDF. Missing required material or binding mismatch is fail-closed.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = "Requires jni-microkernel-loader and stable runtime binding material; environment changes directly affect decryption and startup behavior. Combined mode requires all configured material to be present.",
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
        description = "Experimental semantic transformation that converts selected normal control flow to exception-driven flow using custom exception types. It raises decompiler and debugging cost but is not a complete VM-level virtualization layer.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "May impact performance, stack traces, and debugging; verify exception-sensitive code paths carefully.",
        params = listOf(
            ParamSchema(key = "virtualizationLevel", type = "enum", defaultValue = JsonNodeFactory.instance.textNode("selective"), options = listOf("selective", "aggressive"), description = "Virtualization level."),
            ParamSchema(key = "seed", type = "number", defaultValue = JsonNodeFactory.instance.nullNode(), options = null, description = "Deterministic seed."),
        ),
    ),
)

fun buildRuntimeDefenseCapabilityDefinitions() = capabilityDefinitions(runtimeDefenseCapabilityBindings())
