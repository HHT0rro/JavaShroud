package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
import io.github.hht0rro.javashroud.model.config.PassSpec
import java.nio.file.Path
import kotlin.io.path.absolutePathString

internal fun decodePasses(passesNode: JsonNode, configPath: Path): List<PassSpec> {
    if (!passesNode.isArray) {
        throw IllegalArgumentException("Config validation failed: passes must be an array, path=${configPath.absolutePathString()}")
    }

    val result = mutableListOf<PassSpec>()
    var index = 0
    for (passNode in passesNode) {
        val id = requiredNestedText(passNode, "id", configPath, "passes[$index]")
        val enabledNode = passNode.get("enabled")
        if (enabledNode == null || !enabledNode.isBoolean) {
            throw IllegalArgumentException(
                "Config validation failed: passes[$index].enabled must be a boolean, path=${configPath.absolutePathString()}"
            )
        }
        val params = decodePassParams(passNode.path("params"), configPath, index)
        result.add(PassSpec(id = id, enabled = enabledNode.booleanValue(), params = params))
        index += 1
    }

    return result
}

internal fun decodePassParams(paramsNode: JsonNode, configPath: Path, passIndex: Int): Map<String, JsonNode> {
    if (paramsNode.isMissingNode || paramsNode.isNull) {
        return emptyMap()
    }

    if (!paramsNode.isObject) {
        throw IllegalArgumentException("Config validation failed: passes[$passIndex].params must be an object, path=${configPath.absolutePathString()}")
    }

    return paramsNode.properties().associate { entry: Map.Entry<String, JsonNode> -> entry.key to entry.value }
}
