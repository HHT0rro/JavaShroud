package io.github.hht0rro.javashroud.compatibility

import io.github.hht0rro.javashroud.model.schema.OrderingConstraint
import io.github.hht0rro.javashroud.model.schema.PassCompatibilityRule

/** Current protected-artifact format has no compatibility conflict paths. */
val hardConflictPairs: Set<Pair<String, String>> = emptySet()
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
    OrderingConstraint(before = "rename-classes", after = "method-virtualization", reason = "Class renaming must complete before VBC4 captures owner references."),
    OrderingConstraint(before = "rename-packages", after = "method-virtualization", reason = "Package renaming must complete before VBC4 captures owner references."),
    OrderingConstraint(before = "rename-methods", after = "method-virtualization", reason = "Method renaming must complete before VBC4 lowers selected method bodies."),
    OrderingConstraint(before = "rename-fields", after = "method-virtualization", reason = "Field renaming must complete before VBC4 captures field references."),
    OrderingConstraint(before = "rename-methods", after = "string-encryption", reason = "Method renaming must see supported reflection string constants before string encryption."),
    OrderingConstraint(before = "rename-classes", after = "string-encryption", reason = "Class renaming must see supported reflection class-name strings before string encryption."),
    OrderingConstraint(before = "rename-packages", after = "string-encryption", reason = "Package renaming must see supported reflection package strings before string encryption."),
    OrderingConstraint(before = "rename-fields", after = "string-encryption", reason = "Field renaming must see supported reflection field strings before string encryption."),
    OrderingConstraint(before = "string-encryption", after = "field-string-encryption", reason = "LDC string encryption must finish before field string storage rewriting."),
    OrderingConstraint(before = "string-encryption", after = "method-virtualization", reason = "String encryption must complete before VBC4 captures selected methods."),
    OrderingConstraint(before = "integer-constant-obfuscation", after = "method-virtualization", reason = "Integer rewriting must complete before VBC4 captures arithmetic."),
    OrderingConstraint(before = "static-init-perturbation", after = "method-virtualization", reason = "Static initialization changes must complete before VBC4 lowering."),
    OrderingConstraint(before = "anti-decompiler-structure", after = "method-virtualization", reason = "Anti-decompiler bytecode must be captured before VBC4 lowering."),
    OrderingConstraint(before = "invoke-dynamic-indirection", after = "method-virtualization", reason = "InvokeDynamic indirection must complete before VBC4 lowering."),
    OrderingConstraint(before = "control-flow-obfuscation", after = "method-virtualization", reason = "Control-flow rewriting must complete before VBC4 lowering."),
    OrderingConstraint(before = "reference-proxy", after = "method-virtualization", reason = "Reference-proxy rewriting must complete before VBC4 lowering."),
    OrderingConstraint(before = "control-flow-flattening", after = "method-virtualization", reason = "Flattened control flow must complete before VBC4 lowering."),
    OrderingConstraint(before = "condy-constant-indirection", after = "method-virtualization", reason = "ConstantDynamic indirection must complete before VBC4 lowering."),
    OrderingConstraint(before = "rename-classes", after = "exception-semantic-virtualization", reason = "Class renaming must complete before exception virtualization embeds owners."),
    OrderingConstraint(before = "rename-packages", after = "exception-semantic-virtualization", reason = "Package renaming must complete before exception virtualization embeds owners."),
    OrderingConstraint(before = "rename-methods", after = "exception-semantic-virtualization", reason = "Method renaming must complete before exception virtualization rewrites handlers."),
    OrderingConstraint(before = "rename-classes", after = "callsite-rotation-protection", reason = "Class renaming must complete before callsite rotation records owners."),
    OrderingConstraint(before = "rename-packages", after = "callsite-rotation-protection", reason = "Package renaming must complete before callsite rotation records owners."),
    OrderingConstraint(before = "rename-methods", after = "callsite-rotation-protection", reason = "Method renaming must complete before callsite rotation records targets."),
    OrderingConstraint(before = "invoke-dynamic-indirection", after = "callsite-rotation-protection", reason = "Indy callsites must exist before callsite rotation wraps them."),
    OrderingConstraint(before = "method-virtualization", after = "callsite-rotation-protection", reason = "VBC4 lowering completes before callsite rotation introduces Java helper invokedynamic sites."),
    OrderingConstraint(before = "callsite-rotation-protection", after = "jni-microkernel-loader", reason = "Callsite rotation completes before the current native runtime is sealed."),
    OrderingConstraint(before = "method-virtualization", after = "jni-microkernel-loader", reason = "VBC4 pages must exist before current native runtime sealing."),
    OrderingConstraint(before = "method-virtualization", after = "os-anti-debug", reason = "VBC4 lowering completes before unified defense probes are injected."),
    OrderingConstraint(before = "method-virtualization", after = "os-anti-vm", reason = "VBC4 lowering completes before unified defense probes are injected."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "os-anti-debug", reason = "The typed native runtime must be sealed before debugger-defense probes are injected."),
    OrderingConstraint(before = "jni-microkernel-loader", after = "os-anti-vm", reason = "The typed native runtime must be sealed before virtual-machine-defense probes are injected."),
)
