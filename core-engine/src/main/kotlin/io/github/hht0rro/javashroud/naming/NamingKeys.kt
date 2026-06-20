package io.github.hht0rro.javashroud.naming

import io.github.hht0rro.javashroud.model.analysis.MemberKind

fun buildMethodKey(name: String, descriptor: String): String {
    return name + ":" + descriptor
}

fun buildMemberKey(kind: MemberKind, name: String, descriptor: String): String {
    return kind.name + ":" + name + ":" + descriptor
}
