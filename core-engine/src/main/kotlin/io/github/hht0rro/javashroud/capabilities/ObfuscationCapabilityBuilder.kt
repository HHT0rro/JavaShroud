package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun obfuscationCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "integer-constant-obfuscation",
        name = "Integer Constant Obfuscation",
        description = "Replace integer constant loads with arithmetic equivalent expressions to break pattern matching.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
        params = listOf(
            ParamSchema(
                key = "rewriteMode",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("arithmetic"),
                options = listOf("arithmetic", "resolver"),
                description = "Rewriting mode: arithmetic preserves arithmetic-equivalent rewriting; resolver replaces constants with class-local resolver call sites.",
            ),
            ParamSchema(
                key = "intCoverage",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("none"),
                options = listOf("none", "normal", "aggressive"),
                description = "Integer constant coverage level for resolver mode: none disables, aggressive is the highest level.",
            ),
            ParamSchema(
                key = "longCoverage",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("none"),
                options = listOf("none", "normal"),
                description = "Long constant coverage level for resolver mode: none disables, normal is the highest level.",
            ),
            ParamSchema(
                key = "resolverCodec",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("xor"),
                options = listOf("xor", "des"),
                description = "Resolver payload codec for resolver mode.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "static-init-perturbation",
        name = "Static Init Perturbation",
        description = "Move compile-time static field constants into runtime clinit initialization and inject noise assignments.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "anti-decompiler-structure",
        name = "Anti-Decompiler Structure",
        description = "Insert bogus exception handlers and dead code blocks that confuse decompilers without affecting runtime behavior.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "invoke-dynamic-indirection",
        name = "InvokeDynamic Indirection",
        description = "Replace INVOKESTATIC method calls with INVOKEDYNAMIC instructions backed by a per-class bootstrap lookup table.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "Java 8 classfile 兼容：输出可包含 invokedynamic，但不应抬升 classfile major version。会改变调用点链接形态，请验证反射、agent、AOT 和安全管理策略。",
        params = listOf(
            ParamSchema(
                key = "callSiteForm",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("bootstrap-table"),
                options = listOf("bootstrap-table", "constant-resolver"),
                description = "Call-site form: bootstrap-table rewrites static calls through a per-class bootstrap lookup table; constant-resolver wraps class-local resolver members in first-resolve constant call sites.",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic seed for the constant-resolver call-site layout. Null or absent means random.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "control-flow-obfuscation",
        name = "Control Flow Obfuscation",
        description = "Restructure method control flow with parameterized opaque predicates, dispatch modes, " +
            "and algebraic families to confuse CFG reconstruction.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
        params = listOf(
            ParamSchema(
                key = "branchInjection",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("none"),
                options = listOf("none", "light", "normal", "aggressive"),
                description = "Conditional-edge injection level based on state-field perturbation, combined with predicate and dispatch rewriting: none disables, aggressive is the highest level.",
            ),
            ParamSchema(
                key = "handlerSplit",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("none"),
                options = listOf("none", "light", "heavy"),
                description = "Same-type exception handler split and relay level, combined with predicate and dispatch rewriting: none disables, heavy is the highest level.",
            ),
            ParamSchema(
                key = "density",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(5),
                options = null,
                description = "Obfuscation density level from 1 (minimal) to 10 (aggressive). " +
                    "Higher values insert more opaque predicates and dispatch nodes.",
            ),
            ParamSchema(
                key = "dispatchMode",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("if-chain"),
                options = listOf("lookupswitch", "if-chain", "tableswitch-hybrid"),
                description = "Dispatch mechanism for control flow restructuring: lookupswitch (table-driven), " +
                    "if-chain (conditional branch chains), tableswitch-hybrid (combined approach).",
            ),
            ParamSchema(
                key = "algebraicFamily",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("mixed"),
                options = listOf("quadratic-residue", "bitwise-identity", "modular-arithmetic", "mixed"),
                description = "Algebraic identity family for guard conditions.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "reference-proxy",
        name = "Reference Proxy",
        description = "Create synthetic static forwarders that reroute direct INVOKESTATIC call sites through proxy methods.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "control-flow-flattening",
        name = "Control Flow Flattening",
        description = "Medium-strength control-flow perturbation that flattens selected method control flow using configurable density, handler complexity, and insertion patterns. It raises CFG recovery cost but is not a complete VM-level protection.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "会重写异常区域和分发结构；Java 8 classfile 输入不应被抬升 major version。请重点验证异常敏感路径和性能表现。当前为中等强度扰动，不能替代 native/VM 级保护。",
        params = listOf(
            ParamSchema(
                key = "density",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(5),
                options = null,
                description = "Flattening density from 1 (minimal) to 10 (aggressive).",
            ),
            ParamSchema(
                key = "handlerComplexity",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("nop"),
                options = listOf("nop", "field-write", "method-call"),
                description = "Handler body complexity: nop, field-write (synthetic field writes), " +
                    "method-call (insert synthetic no-op handler probes).",
            ),
            ParamSchema(
                key = "pattern",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("dead-branch"),
                options = listOf("arithmetic-nop", "dead-branch", "unreachable-method", "field-noise"),
                description = "Insertion pattern for dispatch blocks: arithmetic-nop (NOP sequences), " +
                    "dead-branch (unreachable code blocks), unreachable-method (synthetic dead methods), " +
                    "field-noise (synthetic field read/writes).",
            ),
        ),
    ),
    // --- Novel JVMS edge-behavior techniques ---
    CapabilityBinding(
        id = "condy-constant-indirection",
        name = "ConstantDynamic Constant Indirection",
        description = "Replace LDC string and integer constants with CONSTANT_Dynamic bootstrap resolution. Exploits JVMS 4.4.10 (CONSTANT_Dynamic_info) which most decompilers lack full support for.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = "Java 11+/classfile 55+ 特性：只应对 Java 11 及以上 classfile 写入 CONSTANT_Dynamic；Java 8/classfile 52 输入必须跳过或回退，不能写入 CONSTANT_Dynamic，也不应抬升 major version。",
    ),
)

fun buildObfuscationCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(obfuscationCapabilityBindings())
