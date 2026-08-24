package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema
import io.github.hht0rro.javashroud.model.schema.VariantRequirement

internal fun encryptionCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        targeting = CLASS_TARGETING,
        id = "string-encryption",
        name = "String Encryption",
        description = "Replace string constants with native-backed or JVM-only resolver decoding and per-class caching. " +
            "The native-kernel decoder backend requires the JNI microkernel loader; the jvm-resolver backend emits a self-contained JVM resolver.",
        tagIds = listOf("encryption", "native-kernel"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
        variantRequirements = listOf(
            VariantRequirement(
                whenParam = "decoderBackend",
                equals = "native-kernel",
                requiredPassIds = listOf("jni-microkernel-loader"),
            ),
        ),
        params = listOf(
            ParamSchema(
                key = "decoderBackend",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("native-kernel"),
                options = listOf("native-kernel", "jvm-resolver"),
                description = "Decoder backend: native-kernel preserves the JNI-backed decoder and auto-enables the JNI microkernel loader; jvm-resolver uses a self-contained JVM resolver with no native dependency.",
            ),
            ParamSchema(
                key = "strength",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("max"),
                options = listOf("standard", "strong", "flow-guarded", "max"),
                description = "String protection level for the jvm-resolver backend, from standard up to the highest level max.",
            ),
            ParamSchema(
                key = "payloadCodec",
                type = "enum",
                defaultValue = JsonNodeFactory.instance.textNode("auto"),
                options = listOf("auto", "xor", "indexed", "aes-gcm"),
                description = "Resolver payload codec for the jvm-resolver backend. auto derives the codec from strength.",
            ),
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
        targeting = CLASS_TARGETING,
        id = "field-string-encryption",
        name = "Field String Encryption",
        description = "Encrypt static final String field constant values with AES, injecting clinit decrypt stubs. Prevents string constants from appearing in the constant pool as plaintext. Fusion from jar-obfuscator.",
        tagIds = listOf("encryption"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
)

fun buildEncryptionCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(encryptionCapabilityBindings())
