package io.github.hht0rro.javashroud.adapters.protocol

fun buildCommandUsageErrorMessage(): String {
    val supportedArguments = supportedCommandSpecs.joinToString(separator = ", ") { spec: EngineCommandSpec ->
        "'${spec.usageSuffix}'"
    }
    return "Missing required arguments: expected $supportedArguments"
}

internal fun buildCommandUsageErrorMessage(spec: EngineCommandSpec, args: Array<String> = emptyArray()): String {
    val received = if (args.isEmpty()) "" else args.joinToString(separator = " ")
    return "Missing required arguments: expected '${spec.usageSuffix}', received='$received'"
}