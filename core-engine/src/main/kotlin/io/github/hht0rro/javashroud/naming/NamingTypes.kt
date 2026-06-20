package io.github.hht0rro.javashroud.naming

data class MemberKey(
    val owner: String,
    val name: String,
    val descriptor: String,
)

data class MemberRename(
    val owner: String,
    val originalName: String,
    val descriptor: String,
    val renamedName: String,
)
