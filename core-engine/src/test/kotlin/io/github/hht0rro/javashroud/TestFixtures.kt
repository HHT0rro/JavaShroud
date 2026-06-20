package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.analysis.attachAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.nio.file.Files
import java.nio.file.Path

internal fun testConfig(
    inputJarPath: String = "C:/tmp/input.jar",
    outputJarPath: String = "C:/tmp/output.jar",
    passes: List<PassSpec> = emptyList(),
    allowOptInPasses: Boolean = false,
    allowRedundantPasses: Boolean = false,
    ruleSet: RuleSet = RuleSet(rules = emptyList()),
): ObfuscationConfig = ObfuscationConfig(
    inputJarPath = inputJarPath,
    outputJarPath = outputJarPath,
    passes = passes,
    allowOptInPasses = allowOptInPasses,
    allowRedundantPasses = allowRedundantPasses,
    ruleSet = ruleSet,
)

internal fun testPassSpec(
    id: String = "strip-compile-debug-info",
    enabled: Boolean = true,
    params: Map<String, JsonNode> = emptyMap(),
): PassSpec = PassSpec(id = id, enabled = enabled, params = params)

internal fun writeTestRunConfigToml(
    configPath: Path,
    inputJar: Path,
    outputJar: Path,
    passIds: List<String>,
    rules: List<RuleSpec> = emptyList(),
    allowIncomplete: Boolean = true,
    allowOptInPasses: Boolean = true,
    allowRedundantPasses: Boolean = false,
    passParams: Map<String, Map<String, JsonNode>> = emptyMap(),
) {
    val builder = StringBuilder()
    builder.appendLine("inputJarPath = ${tomlString(inputJar.toAbsolutePath().normalize().toString().replace('\\', '/'))}")
    builder.appendLine("outputJarPath = ${tomlString(outputJar.toAbsolutePath().normalize().toString().replace('\\', '/'))}")
    builder.appendLine("allowIncomplete = $allowIncomplete")
    builder.appendLine("allowOptInPasses = $allowOptInPasses")
    builder.appendLine("allowRedundantPasses = $allowRedundantPasses")
    builder.appendLine()
    for (passId in passIds) {
        builder.appendLine("[[passes]]")
        builder.appendLine("id = ${tomlString(passId)}")
        builder.appendLine("enabled = true")
        val params = passParams[passId].orEmpty()
        if (params.isNotEmpty()) {
            builder.appendLine()
            builder.appendLine("[passes.params]")
            for ((key, value) in params.toSortedMap()) {
                builder.appendLine("$key = ${tomlScalar(value)}")
            }
        }
        builder.appendLine()
    }
    builder.appendLine("[ruleSet]")
    if (rules.isEmpty()) {
        builder.appendLine("rules = []")
    } else {
        for (rule in rules) {
            builder.appendLine("[[ruleSet.rules]]")
            builder.appendLine("target = ${tomlString(rule.target)}")
            builder.appendLine("action = ${tomlString(rule.action)}")
            builder.appendLine()
        }
    }
    Files.writeString(configPath, builder.toString())
}

private fun tomlScalar(value: JsonNode): String = when {
    value.isBoolean -> value.booleanValue().toString()
    value.isNumber -> value.numberValue().toString()
    value.isTextual -> tomlString(value.textValue())
    else -> error("Unsupported TOML scalar test param: $value")
}

private fun tomlString(value: String): String = ObjectMapper().writeValueAsString(value)

internal fun testClassSummary(
    internalName: String,
    accessFlags: Int = 0,
    fieldSummaries: List<MemberSummary> = emptyList(),
    methodSummaries: List<MemberSummary> = emptyList(),
    superName: String? = "java/lang/Object",
    interfaceNames: List<String> = emptyList(),
): ClassAnalysisSummary = ClassAnalysisSummary(
    internalName = internalName,
    superName = superName,
    interfaceNames = interfaceNames,
    accessFlags = accessFlags,
    fieldCount = fieldSummaries.size,
    methodCount = methodSummaries.size,
    fieldSummaries = fieldSummaries,
    methodSummaries = methodSummaries,
)


/**
 * Convenience: build a BytecodeArtifact with a single class from raw bytes.
 * Used by tests that generate bytecode at runtime (e.g., classes without <clinit>).
 */
internal fun singleClassArtifact(classBytes: ByteArray, internalName: String): io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact {
    val classArtifact = testClassArtifact(internalName = internalName, bytes = classBytes)
    return testAttachedArtifact(classArtifacts = listOf(classArtifact))
}

internal fun testClassArtifact(
    internalName: String,
    entryName: String = "$internalName.class",
    bytes: ByteArray = byteArrayOf(1),
    accessFlags: Int = 0,
    fieldSummaries: List<MemberSummary> = emptyList(),
    methodSummaries: List<MemberSummary> = emptyList(),
    superName: String? = "java/lang/Object",
    interfaceNames: List<String> = emptyList(),
): ClassArtifact = ClassArtifact(
    entryName = entryName,
    summary = testClassSummary(
        internalName = internalName,
        accessFlags = accessFlags,
        fieldSummaries = fieldSummaries,
        methodSummaries = methodSummaries,
        superName = superName,
        interfaceNames = interfaceNames,
    ),
    bytes = bytes,
)

internal fun testAttachedArtifact(
    classArtifacts: List<ClassArtifact>,
    jarEntries: List<JarEntryData> = classArtifacts.map { classArtifact: ClassArtifact ->
        JarEntryData(classArtifact.entryName, classArtifact.bytes)
    },
    config: ObfuscationConfig = testConfig(),
    manifestPresent: Boolean = false,
): BytecodeArtifact = attachAnalysisSummary(
    config = config,
    jarEntries = jarEntries,
    classArtifacts = classArtifacts,
    manifestPresent = manifestPresent,
)

internal fun emptyTestArtifact(config: ObfuscationConfig = testConfig()): BytecodeArtifact =
    testAttachedArtifact(classArtifacts = emptyList(), jarEntries = emptyList(), config = config)

internal fun buildTargetedRuleSet(
    passIds: List<String>,
    targetedClasses: Set<String> = emptySet(),
    targetedMembers: Set<String> = emptySet(),
    excludeClasses: Set<String> = emptySet(),
): RuleSet {
    val rules = mutableListOf<RuleSpec>()
    for (passId in passIds) {
        for (target in targetedClasses) {
            rules += RuleSpec(target = target, action = passId)
        }
        for (target in targetedMembers) {
            rules += RuleSpec(target = target, action = passId)
        }
    }
    for (target in excludeClasses) {
        rules += RuleSpec(target = target, action = "exclude")
    }
    return RuleSet(rules = rules)
}
