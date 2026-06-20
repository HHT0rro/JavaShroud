package io.github.hht0rro.javashroud.naming

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind

fun buildMethodRenameMap(
    matchedMembers: List<MatchedMember>,
    config: RenameConfig = RenameConfig(),
): Map<MemberKey, MemberRename> {
    val eligible = matchedMembers
        .filter { it.kind == MemberKind.METHOD }
        .filter { canRenameMethod(it.name) }
        .distinctBy { MemberKey(it.owner, it.name, it.descriptor) }

    // Group by (name, parameter descriptor) so interface methods and their implementations
    // get the same renamed name, and return-type-only bridge pairs keep one reflected
    // lookup name. Java reflection getDeclaredMethod resolves by name and parameter
    // types, not by return type.
    data class MethodSig(val name: String, val parameterDescriptor: String)
    val groups = eligible.groupBy { MethodSig(it.name, methodParameterDescriptor(it.descriptor)) }

    val generator = NameGenerator(config)
    val result = mutableMapOf<MemberKey, MemberRename>()

    for ((_, members) in groups.entries.sortedBy { it.key.name + it.key.parameterDescriptor }) {
        val renamedName = generator.generateSimpleName("m")
        for (member in members) {
            val key = MemberKey(member.owner, member.name, member.descriptor)
            result[key] = MemberRename(
                owner = member.owner,
                originalName = member.name,
                descriptor = member.descriptor,
                renamedName = renamedName,
            )
        }
    }
    return result
}

private fun methodParameterDescriptor(methodDescriptor: String): String {
    val closeIndex = methodDescriptor.indexOf(')')
    return if (closeIndex >= 0) methodDescriptor.substring(0, closeIndex + 1) else methodDescriptor
}

fun buildFieldRenameMap(
    matchedMembers: List<MatchedMember>,
    config: RenameConfig = RenameConfig(),
): Map<MemberKey, MemberRename> {
    val generator = NameGenerator(config)
    return matchedMembers
        .filter { it.kind == MemberKind.FIELD }
        .distinctBy { MemberKey(it.owner, it.name, it.descriptor) }
        .sortedWith(compareBy<MatchedMember> { it.owner }.thenBy { it.name }.thenBy { it.descriptor })
        .map { member: MatchedMember ->
            val key = MemberKey(member.owner, member.name, member.descriptor)
            key to MemberRename(
                owner = member.owner,
                originalName = member.name,
                descriptor = member.descriptor,
                renamedName = generator.generateSimpleName("f"),
            )
        }
        .toMap()
}
