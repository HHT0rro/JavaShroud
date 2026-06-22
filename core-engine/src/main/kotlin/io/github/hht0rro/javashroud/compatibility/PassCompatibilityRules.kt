package io.github.hht0rro.javashroud.compatibility

import io.github.hht0rro.javashroud.model.schema.OrderingConstraint

import io.github.hht0rro.javashroud.model.schema.PassCompatibilityRule

val hardConflictPairs: Set<Pair<String, String>> = setOf(
    // Class encryption freezes already-transformed class bytes into encrypted resources.
    // Runtime artifact sealing cannot safely rewrite helper references inside those
    // encrypted payloads, so VM/JNI virtualization combinations must be rejected
    // until encrypted payload remapping is implemented.
    "class-encryption-loader" to "method-virtualization",
    // Delayed method body resources are embedded into runtime decryption stubs.
    // Method virtualization moves those stubs and resource path constants into
    // VBC4 resources, where sealing cannot safely rewrite delayed resource names.
    "method-body-delayed-decryption" to "method-virtualization",
)
val softConflictPairs: Set<Pair<String, String>> = emptySet()

fun buildPassCompatibilityRules(): List<PassCompatibilityRule> =

    (hardConflictPairs.map { (a, b) ->

        PassCompatibilityRule(

            passIds = listOf(a, b),

            severity = "hard",

            description = "These passes rewrite the same bytecode surface and cannot run together.",

        )

    } + softConflictPairs.map { (a, b) ->

        PassCompatibilityRule(

            passIds = listOf(a, b),

            severity = "soft",

            description = "These passes overlap in effect. Avoid running both unless allowRedundantPasses is true.",

        )

    }).sortedWith(compareBy<PassCompatibilityRule> { it.severity }.thenBy { it.passIds.joinToString("|") })

fun buildOrderingConstraints(): List<OrderingConstraint> = listOf(
    OrderingConstraint(before = "rename-classes", after = "class-encryption-loader", reason = "Class renaming must complete before class encryption loader packages encrypted classes."),
    OrderingConstraint(before = "rename-packages", after = "class-encryption-loader", reason = "Package renaming must complete before class encryption loader records package names."),
    OrderingConstraint(before = "rename-methods", after = "method-body-delayed-decryption", reason = "Method renaming must complete before delayed decryption packages method bodies."),
    OrderingConstraint(before = "rename-classes", after = "method-body-delayed-decryption", reason = "Class renaming must complete before delayed decryption embeds class references."),
    OrderingConstraint(before = "rename-packages", after = "method-body-delayed-decryption", reason = "Package renaming must complete before delayed decryption embeds package names."),
    OrderingConstraint(before = "rename-classes", after = "method-virtualization", reason = "Class renaming must complete before virtualization embeds class references."),
    OrderingConstraint(before = "rename-packages", after = "method-virtualization", reason = "Package renaming must complete before virtualization embeds owner names."),
    OrderingConstraint(before = "rename-methods", after = "method-virtualization", reason = "Method renaming must complete before virtualization rewrites method bodies."),
    OrderingConstraint(before = "rename-fields", after = "method-virtualization", reason = "Field renaming must complete before virtualization embeds field references in VBC4 resources."),
    OrderingConstraint(before = "rename-methods", after = "string-encryption", reason = "Method renaming must see plaintext reflection string constants before string encryption hides them."),
    OrderingConstraint(before = "rename-methods", after = "field-string-encryption", reason = "Method renaming must see plaintext reflection string constants before field string encryption rewrites storage."),
    OrderingConstraint(before = "rename-classes", after = "string-encryption", reason = "Class renaming must see plaintext class-name and class-resource string constants before string encryption hides them."),
    OrderingConstraint(before = "rename-packages", after = "string-encryption", reason = "Package renaming must see plaintext package resource string constants before string encryption hides them."),
    OrderingConstraint(before = "rename-fields", after = "string-encryption", reason = "Field renaming must see plaintext reflection string constants before string encryption hides them."),
    OrderingConstraint(before = "rename-fields", after = "field-string-encryption", reason = "Field renaming must see plaintext reflection string constants before field string encryption rewrites storage."),
    OrderingConstraint(before = "string-encryption", after = "field-string-encryption", reason = "LDC string encryption must complete before field string encryption to avoid encrypting decrypt stub strings."),
    OrderingConstraint(before = "field-string-encryption", after = "class-encryption-loader", reason = "Field string encryption must complete before class encryption loader packages classes."),
    OrderingConstraint(before = "string-encryption", after = "method-virtualization", reason = "String encryption must complete before virtualization so dispatcher LDC strings are not encrypted."),
    OrderingConstraint(before = "integer-constant-obfuscation", after = "method-virtualization", reason = "Integer constant rewriting must complete before virtualization so arithmetic surfaces are captured inside VBC4 resources."),
    OrderingConstraint(before = "static-init-perturbation", after = "method-virtualization", reason = "Static initialization perturbation must complete before virtualization so changed method bodies are captured inside VBC4 resources."),
    OrderingConstraint(before = "anti-decompiler-structure", after = "method-virtualization", reason = "Anti-decompiler body structure must complete before virtualization so inserted bytecode is not left visible after VM lowering."),
    OrderingConstraint(before = "invoke-dynamic-indirection", after = "method-virtualization", reason = "InvokeDynamic callsite rewriting must complete before virtualization so call indirection is captured inside VBC4 resources."),
    OrderingConstraint(before = "control-flow-obfuscation", after = "method-virtualization", reason = "Control-flow obfuscation must complete before virtualization so final control flow is captured inside VBC4 resources."),
    OrderingConstraint(before = "reference-proxy", after = "method-virtualization", reason = "Reference proxy callsite rewriting must complete before virtualization so proxy dispatch is captured inside VBC4 resources."),
    OrderingConstraint(before = "control-flow-flattening", after = "method-virtualization", reason = "Control-flow flattening must complete before virtualization so flattened dispatch is captured inside VBC4 resources."),
    OrderingConstraint(before = "condy-constant-indirection", after = "method-virtualization", reason = "ConstantDynamic indirection must complete before virtualization so constant resolution surfaces are captured inside VBC4 resources or fail closed if unsupported."),
    OrderingConstraint(before = "rename-classes", after = "exception-semantic-virtualization", reason = "Class renaming must complete before exception virtualization embeds owner names."),
    OrderingConstraint(before = "rename-packages", after = "exception-semantic-virtualization", reason = "Package renaming must complete before exception virtualization embeds owner names."),
    OrderingConstraint(before = "rename-methods", after = "exception-semantic-virtualization", reason = "Method renaming must complete before exception virtualization rewrites handlers."),
    OrderingConstraint(before = "rename-classes", after = "callsite-rotation-protection", reason = "Class renaming must complete before callsite protection records call owners."),
    OrderingConstraint(before = "rename-methods", after = "callsite-rotation-protection", reason = "Method renaming must complete before callsite protection records call targets."),
    OrderingConstraint(before = "rename-packages", after = "callsite-rotation-protection", reason = "Package renaming must complete before callsite rotation records owner names."),
    OrderingConstraint(before = "string-encryption", after = "class-encryption-loader", reason = "String encryption must run before class encryption loader packages classes."),
    OrderingConstraint(before = "field-string-encryption", after = "class-encryption-loader", reason = "Field string encryption must complete before class encryption loader packages classes."),
    OrderingConstraint(before = "class-encryption-loader", after = "jni-microkernel-loader", reason = "Class encryption loader must run before JNI microkernel loader so the final class initializer retains loadKernel wiring."),
    OrderingConstraint(before = "string-encryption", after = "method-body-delayed-decryption", reason = "String encryption must complete before method body delayed decryption encrypts method bodies."),
    OrderingConstraint(before = "string-encryption", after = "control-flow-obfuscation", reason = "String encryption should finish before control-flow obfuscation adds branch scaffolding around method bodies."),
    OrderingConstraint(before = "field-string-encryption", after = "member-hide", reason = "Field string encryption should finish before member access flags are hidden."),
    OrderingConstraint(before = "member-hide", after = "reference-proxy", reason = "Member access-flag hiding should complete before reference proxy rewrites call and field references."),
    OrderingConstraint(before = "method-virtualization", after = "class-encryption-loader", reason = "Method virtualization must complete before class encryption loader packages classes, so VM dispatchers are included in the encrypted class."),
    OrderingConstraint(before = "anti-instrumentation", after = "method-virtualization", reason = "Anti-instrumentation direct native checks must be visible before method virtualization."),
    OrderingConstraint(before = "anti-dump-protection", after = "method-virtualization", reason = "Anti-dump direct native checks must be visible before method virtualization."),
    OrderingConstraint(before = "invoke-dynamic-indirection", after = "callsite-rotation-protection", reason = "Indy callsites should be established before callsite rotation wraps dispatch."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "method-virtualization", reason = "JNI kernel must load before method virtualization switches to the native VM interpreter."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "anti-instrumentation", reason = "JNI kernel must load before native runtime defenses."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "anti-dump-protection", reason = "JNI kernel must load before anti-dump initialization."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "environment-bound-keys", reason = "JNI kernel must load before environment-bound initialization."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "method-body-delayed-decryption", reason = "JNI kernel must load before method body decryption stubs."),
)
