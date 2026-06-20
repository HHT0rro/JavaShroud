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
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "static-init-perturbation",
        name = "Static Init Perturbation",
        description = "Move compile-time static field constants into runtime clinit initialization and inject noise assignments.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "anti-decompiler-structure",
        name = "Anti-Decompiler Structure",
        description = "Insert bogus exception handlers and dead code blocks that confuse decompilers without affecting runtime behavior.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "invoke-dynamic-indirection",
        name = "InvokeDynamic Indirection",
        description = "Replace INVOKESTATIC method calls with INVOKEDYNAMIC instructions backed by a per-class bootstrap lookup table.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "control-flow-obfuscation",
        name = "Control Flow Obfuscation",
        description = "Restructure method control flow with parameterized opaque predicates, dispatch modes, " +
            "and algebraic families to confuse CFG reconstruction.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
        params = listOf(
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
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
    CapabilityBinding(
        id = "control-flow-flattening",
        name = "Control Flow Flattening",
        description = "Flatten method control flow using configurable density, handler complexity, and insertion patterns.",
        tagIds = listOf("obfuscation"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = "会重写异常区域和分发结构；请重点验证异常敏感路径和性能表现。",
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
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
)

fun buildObfuscationCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(obfuscationCapabilityBindings())
