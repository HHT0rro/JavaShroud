package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun runtimeDefenseCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "callsite-rotation-protection",
        name = "调用点轮换保护",
        description = "基于 MutableCallSite、epoch、线程、计数器或运行态信号切换真实 target。" +
            " 运行时动态重绑定方法调用目标，阻止静态解析。",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = "会改变调用点链接和运行时分派路径；请重点验证性能、调试和框架代理场景。",
        params = listOf(
            ParamSchema(
                key = "rotationStrategy",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("epoch"),
                options = listOf("epoch", "counter", "thread-local", "random"),
                description = "轮换策略。",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "确定性种子。",
            ),
        ),
    ),
    CapabilityBinding(
        id = "environment-bound-keys",
        name = "环境绑定密钥",
        description = "选择硬件/JVM 参数/签名证书/license/远程授权材料做 KDF 派生解密密钥。" +
            " 脱离目标环境后解密材料不可用。",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "ultra-high",
        defaultEnabled = false,
        compatibilityNotes = "需要运行时环境提供绑定材料；环境变更会直接影响解密和启动行为。",
        requiredPassIds = listOf("jni-microkernel-loader"),
        params = listOf(
            ParamSchema(
                key = "bindingSource",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("jvm-params"),
                options = listOf("hardware-id", "jvm-params", "certificate-fingerprint", "combined"),
                description = "密钥绑定源。",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "确定性种子。",
            ),
        ),
    ),
    CapabilityBinding(
        id = "anti-symbolic-execution",
        name = "反符号执行陷阱",
        description = "使用运行时数据驱动的非线性 opaque predicate 而非纯常量恒真式，" +
            "使符号执行引擎无法通过约束求解消除分支。",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = RUNTIME_HELPER_COMPATIBILITY_NOTE,
        params = listOf(
            ParamSchema(
                key = "trapDensity",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(5),
                options = null,
                description = "每 N 个方法注入一个符号执行陷阱。",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "确定性种子。",
            ),
        ),
    ),
    CapabilityBinding(
        id = "exception-semantic-virtualization",
        name = "Exception Semantic Virtualization",
        description = "Convert normal control flow to exception-driven flow using custom exception types.",
        tagIds = listOf("runtime-defense"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = "May impact performance and debugging.",
        params = listOf(
            ParamSchema(key = "virtualizationLevel", type = "enum", defaultValue = JsonNodeFactory.instance.textNode("selective"), options = listOf("selective", "aggressive"), description = "Virtualization level."),
            ParamSchema(key = "seed", type = "number", defaultValue = JsonNodeFactory.instance.nullNode(), options = null, description = "Deterministic seed."),
        ),
    ),
)

fun buildRuntimeDefenseCapabilityDefinitions() = capabilityDefinitions(runtimeDefenseCapabilityBindings())
