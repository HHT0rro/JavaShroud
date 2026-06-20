package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal fun encryptionCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "string-encryption",
        name = "String Encryption",
        description = "Replace string constants with native-backed, per-literal payload decoding and per-class String[] caching. " +
            "The transform removes plaintext LDC strings, uses randomized synthetic callsites, and requires the JNI microkernel loader.",
        tagIds = listOf("encryption", "native-kernel"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
        requiredPassIds = listOf("jni-microkernel-loader"),
        params = listOf(
            ParamSchema(
                key = "scope",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("all-strings"),
                options = listOf("all-strings", "annotated", "length-threshold"),
                description = "Which strings to encrypt: all-strings (every LDC string), " +
                    "annotated (only strings in methods with @ShroudEncrypt), " +
                    "length-threshold (only strings >= lengthThreshold characters).",
            ),
            ParamSchema(
                key = "lengthThreshold",
                type = "number",
                defaultValue = JsonNodeFactory.instance.numberNode(3),
                options = null,
                description = "Minimum string length to encrypt when scope=length-threshold.",
            ),
            ParamSchema(
                key = "seed",
                type = "number",
                defaultValue = JsonNodeFactory.instance.nullNode(),
                options = null,
                description = "Deterministic seed for callsite and payload layout. Null or absent means random.",
            ),
        ),
    ),
    CapabilityBinding(
        id = "field-string-encryption",
        name = "Field String Encryption",
        description = "Encrypt static final String field constant values with AES, injecting clinit decrypt stubs. Prevents string constants from appearing in the constant pool as plaintext. Fusion from jar-obfuscator.",
        tagIds = listOf("encryption"),
        stability = "experimental",
        risk = "high",
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
)

fun buildEncryptionCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(encryptionCapabilityBindings())
