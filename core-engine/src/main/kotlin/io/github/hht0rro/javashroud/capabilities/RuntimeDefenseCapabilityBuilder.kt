package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun runtimeDefenseCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        targeting = CLASS_TARGETING,
        id = "callsite-rotation-protection",
        name = "Callsite Rotation Protection",
        description = "Experimental medium-strength callsite perturbation: switch call targets at runtime with MutableCallSite, epoch, counter, thread-local, or random signals to raise static recovery cost. It is observable at runtime and is not a VM-level protection by itself.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "Changes callsite linking and runtime dispatch paths; generated helper/callsite surfaces target Java 11+ runtime behavior. Verify performance, debugging, framework proxy, and older runtime scenarios.",
        params = listOf(
            ParamSchema(
                key = "rotationStrategy",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("mixed"),
                options = listOf(
                    "mixed",
                    "mutable",
                    "guarded",
                    "table",
                    "thread-slot",
                    "oneshot",
                    "epoch",
                    "counter",
                    "thread-local",
                    "random",
                ),
                description = "Per-site dispatch strategy. mixed selects a shuffled pool per artifact.",
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
    unifiedDefenseCapabilityBinding(
        id = "os-anti-debug",
        name = "OS Anti Debug",
        description = "Unified native defense for Windows x64 debugger checks, Linux TracerPid, JVM agent arguments, JVMTI, Instrumentation, ByteBuddy transformer, and attach surfaces. Every startup and distributed probe is authenticated and fail-closed.",
    ),
    unifiedDefenseCapabilityBinding(
        id = "os-anti-vm",
        name = "OS Anti VM",
        description = "Unified native defense for CPUID, hypervisor, firmware, DMI, sysfs, evaluator-bound predicate-share, and protected field-material signals. High-confidence evidence fails closed; weak evidence requires independent corroboration.",
    ),
    CapabilityBinding(
        targeting = CLASS_TARGETING,
        id = "exception-semantic-virtualization",
        name = "Exception Semantic Virtualization",
        description = "Experimental semantic transformation that converts selected normal control flow to exception-driven flow using custom exception types.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "Changes exception semantics, stack shapes, and performance characteristics; verify exception-sensitive paths.",
        params = listOf(
            ParamSchema(
                key = "virtualizationLevel",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("selective"),
                options = listOf("selective", "aggressive"),
                description = "Virtualization level.",
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
)

private fun unifiedDefenseCapabilityBinding(
    id: String,
    name: String,
    description: String,
): CapabilityBinding = CapabilityBinding(
    targeting = CLASS_TARGETING,
    id = id,
    name = name,
    description = description,
    tagIds = listOf("runtime-defense", "native-kernel"),
    stability = "experimental",
    risk = "medium",
    defaultEnabled = false,
    requiredPassIds = listOf("jni-microkernel-loader"),
    platformConstraints = listOf("Windows x64", "Linux x64"),
    compatibilityNotes = "Current protected-artifact format requires the bundled native defense kernel. Missing native registration, ABI mismatch, failed probe authentication, or a hardened signal match terminates the protected route.",
    params = listOf(
        ParamSchema(
            key = "profile",
            type = "enum",
            defaultValue = JsonNodeFactory.instance.textNode("hardened"),
            options = listOf("balanced", "hardened"),
            description = "Native defense signal policy.",
        ),
        ParamSchema(
            key = "distributedProbeCount",
            type = "number",
            defaultValue = JsonNodeFactory.instance.numberNode(2),
            options = null,
            description = "Authenticated method-entry probes per protected class (1-4).",
        ),
    ),
)

fun buildRuntimeDefenseCapabilityDefinitions() = capabilityDefinitions(runtimeDefenseCapabilityBindings())