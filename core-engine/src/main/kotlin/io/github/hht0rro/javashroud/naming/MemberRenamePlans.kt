package io.github.hht0rro.javashroud.naming

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind

fun buildMethodRenameMap(
    matchedMembers: List<MatchedMember>,
    config: RenameConfig = RenameConfig(),
    returnSensitive: Boolean = false,
    occupiedMethodKeys: Set<MemberKey> = emptySet(),
): Map<MemberKey, MemberRename> {
    val eligible = matchedMembers
        .filter { it.kind == MemberKind.METHOD }
        .filter { canRenameMethod(it.name) }
        .distinctBy { MemberKey(it.owner, it.name, it.descriptor) }

    // Default mode groups by Java reflection's name-and-parameters identity.
    // Return-sensitive mode partitions by the final JVM descriptor, including
    // return type, so compatible overloads can intentionally share a short name.
    data class MethodSig(val name: String, val descriptorKey: String)
    val groups = eligible.groupBy { member ->
        MethodSig(member.name, if (returnSensitive) member.descriptor else methodParameterDescriptor(member.descriptor))
    }

    val generator = NameGenerator(config)
    val result = mutableMapOf<MemberKey, MemberRename>()
    val reusableNames = mutableListOf<String>()
    val namesByOwnerAndDescriptor = mutableMapOf<Pair<String, String>, MutableSet<String>>()

    fun isAvailable(candidate: String, members: List<MatchedMember>): Boolean = members.all { member ->
        MemberKey(member.owner, candidate, member.descriptor) !in occupiedMethodKeys &&
            (!returnSensitive || candidate !in namesByOwnerAndDescriptor[member.owner to member.descriptor].orEmpty())
    }

    fun nextAvailableName(members: List<MatchedMember>): String {
        while (true) {
            val candidate = generator.generateSimpleName("m")
            if (isAvailable(candidate, members)) return candidate
            // A rejected name can still be reused by a different complete descriptor.
            if (returnSensitive && candidate !in reusableNames) reusableNames += candidate
        }
    }

    for ((_, members) in groups.entries.sortedBy { it.key.name + it.key.descriptorKey }) {
        val renamedName = if (returnSensitive) {
            reusableNames.firstOrNull { candidate -> isAvailable(candidate, members) }
                ?: nextAvailableName(members).also(reusableNames::add)
        } else {
            nextAvailableName(members)
        }
        for (member in members) {
            val key = MemberKey(member.owner, member.name, member.descriptor)
            result[key] = MemberRename(
                owner = member.owner,
                originalName = member.name,
                descriptor = member.descriptor,
                renamedName = renamedName,
            )
            if (returnSensitive) {
                namesByOwnerAndDescriptor.getOrPut(member.owner to member.descriptor) { linkedSetOf() } += renamedName
            }
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
