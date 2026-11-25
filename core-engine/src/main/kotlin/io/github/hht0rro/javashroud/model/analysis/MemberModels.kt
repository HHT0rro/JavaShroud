package io.github.hht0rro.javashroud.model.analysis

enum class MemberKind {
    FIELD,
    METHOD,
}

data class MemberSummary(
    val kind: MemberKind,
    val name: String,
    val descriptor: String,
    val accessFlags: Int,
)

data class MatchedMember(
    val owner: String,
    val kind: MemberKind,
    val name: String,
    val descriptor: String,
)
