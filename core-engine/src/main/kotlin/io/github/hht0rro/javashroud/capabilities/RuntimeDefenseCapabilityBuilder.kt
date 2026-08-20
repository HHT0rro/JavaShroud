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
        compatibilityNotes = "Changes callsite linking and runtime dispatch paths; generated helper/callsite surfaces target Java 11+ runtime behavior. Verify performance, debugging, framework proxy, and older runtime scenarios. Treat as cost-raising dispatch indirection, not a hard anti-hook boundary.",
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
        targeting = CLASS_TARGETING,
        id = "environment-bound-keys",
        name = "Environment Bound Keys",
        description = "Bind runtime key derivation to normalized hardware, JVM parameter, certificate fingerprint, or combined environment material through the sealed native KDF. Missing required material or binding mismatch is fail-closed.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = "Requires jni-microkernel-loader, Java 11+ runtime, and stable runtime binding material; environment changes directly affect decryption and startup behavior. Combined mode requires all configured material to be present.",
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
        targeting = CLASS_TARGETING,
        id = "anti-symbolic-execution",
        name = "Anti Symbolic Execution",
        description = "Inject runtime-data-driven opaque predicates so symbolic execution tools cannot remove branches through constant constraint solving alone.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "会注入 Java 11/classfile 55 runtime helper；目标运行时需 Java 11+。会插入运行时数据相关分支，请验证性能、监控工具和符号执行/测试环境兼容性。",
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
        targeting = CLASS_TARGETING,
        id = "exception-semantic-virtualization",
        name = "Exception Semantic Virtualization",
        description = "Experimental semantic transformation that converts selected normal control flow to exception-driven flow using custom exception types. It raises decompiler and debugging cost but is not a complete VM-level virtualization layer.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "会注入 Java 11/classfile 55 runtime helper；目标运行时需 Java 11+。会改变异常语义、堆栈形态和性能特征，需验证异常敏感路径。",
        params = listOf(
            ParamSchema(key = "virtualizationLevel", type = "enum", defaultValue = JsonNodeFactory.instance.textNode("selective"), options = listOf("selective", "aggressive"), description = "Virtualization level."),
            ParamSchema(key = "seed", type = "number", defaultValue = JsonNodeFactory.instance.nullNode(), options = null, description = "Deterministic seed."),
        ),
    ),
)

fun buildRuntimeDefenseCapabilityDefinitions() = capabilityDefinitions(runtimeDefenseCapabilityBindings())
