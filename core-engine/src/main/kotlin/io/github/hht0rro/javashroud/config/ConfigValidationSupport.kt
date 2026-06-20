package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
import java.nio.file.Path
import kotlin.io.path.absolutePathString

fun requiredRootText(node: JsonNode, fieldName: String, configPath: Path): String {
    return requiredNestedText(node, fieldName, configPath, "root")
}

fun optionalRootBoolean(node: JsonNode, fieldName: String, configPath: Path): Boolean {
    val valueNode = node.get(fieldName) ?: return false
    if (!valueNode.isBoolean) {
        throw IllegalArgumentException(
            "Config validation failed: root.$fieldName must be a boolean, path=${configPath.absolutePathString()}"
        )
    }
    return valueNode.booleanValue()
}

fun requiredNestedText(node: JsonNode, fieldName: String, configPath: Path, parentPath: String): String {
    val valueNode = node.get(fieldName)
    if (valueNode == null || !valueNode.isTextual) {
        throw IllegalArgumentException(
            "Config validation failed: $parentPath.$fieldName must be a string, path=${configPath.absolutePathString()}"
        )
    }
    val value = valueNode.textValue()
    if (value.isBlank()) {
        throw IllegalArgumentException(
            "Config validation failed: $parentPath.$fieldName must not be blank, path=${configPath.absolutePathString()}"
        )
    }
    return value
}
