package io.github.hht0rro.javashroud.passes

internal fun buildUnknownPassMessage(passId: String): String {
    val availablePassIds = executablePassRegistry.keys.sorted().joinToString(",")
    return "Unknown pass id=" + passId + ", availablePassIds=" + availablePassIds
}
