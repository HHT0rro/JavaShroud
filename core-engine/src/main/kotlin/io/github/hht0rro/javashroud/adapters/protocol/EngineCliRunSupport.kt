package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.apk.ApkLogSupport
import io.github.hht0rro.javashroud.config.loadValidatedConfig
import io.github.hht0rro.javashroud.config.parseConfig
import io.github.hht0rro.javashroud.config.protectedRunFilePaths
import io.github.hht0rro.javashroud.config.sameArtifactPath
import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_AUTO
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_APK
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.RuleSet
import java.nio.file.Path
import kotlin.io.path.absolutePathString

internal data class EngineRunRequest(
    val configPath: Path,
    val config: ObfuscationConfig,
    val cliLogFilePath: Path? = null,
)

internal fun buildRunRequest(args: Array<String>): EngineRunRequest {
    val flags = parseRunFlags(args)
    try {
        if (flags.directInput != null) {
            return buildDirectRunRequest(
                input = flags.directInput!!,
                output = flags.directOutput!!,
                logFilePath = flags.logFilePath,
            )
        }
        return EngineRunRequest(
            configPath = flags.configPath,
            config = loadValidatedConfig(
                configPath = flags.configPath,
                forceApk = flags.forceApk,
                cliLogFilePath = flags.logFilePath,
            ),
            cliLogFilePath = flags.logFilePath,
        )
    } catch (error: Throwable) {
        // Config parsing/validation runs before the pipeline opens its own log;
        // mirror the requested --log-file (or the TOML-declared one, when the
        // file parsed that far) so every failed run leaves a detailed log.
        ApkLogSupport.appendFailure(runFailureLogPath(flags), error)
        throw error
    }
}

/** Only write a failure log if its path can be checked against all run files. */
private fun runFailureLogPath(flags: RunCommandFlags): String? {
    return runCatching {
        val config = if (flags.directInput == null) {
            val parsed = parseConfig(flags.configPath)
            if (flags.forceApk) parsed.copy(artifactFormat = ARTIFACT_FORMAT_APK) else parsed
        } else ObfuscationConfig(
            inputJarPath = flags.directInput!!.toString(),
            outputJarPath = requireNotNull(flags.directOutput).toString(),
            passes = emptyList(),
            ruleSet = RuleSet(emptyList()),
            artifactFormat = ARTIFACT_FORMAT_AUTO,
        )
        val log = flags.logFilePath ?: config.logFilePath.takeIf { it.isNotBlank() }?.let { Path.of(it) }
            ?: return null
        if (protectedRunFilePaths(config, flags.configPath).any { sameArtifactPath(it, log) }) return null
        log.absolutePathString()
    }.getOrNull()
}

/**
 * Config-less direct run (`--input <artifact> --output <artifact>`): the
 * configuration is synthesized from engine defaults — artifactFormat=auto
 * (zip sniffing picks the APK pipeline for .apk inputs), the default pass
 * pipeline, and the APK-visible MINIMAL profile default, exactly as a TOML
 * without those keys would resolve.
 */
internal fun buildDirectRunRequest(input: Path, output: Path, logFilePath: Path?): EngineRunRequest {
    val direct = ObfuscationConfig(
        inputJarPath = input.absolutePathString(),
        outputJarPath = output.absolutePathString(),
        passes = emptyList(),
        ruleSet = RuleSet(emptyList()),
        artifactFormat = ARTIFACT_FORMAT_AUTO,
        protectionProfileExplicit = false,
        logFilePath = logFilePath?.absolutePathString() ?: "",
    )
    return EngineRunRequest(
        configPath = input,
        config = validateConfig(direct, input),
        cliLogFilePath = logFilePath,
    )
}

internal fun loadRunRequest(configPath: Path): EngineRunRequest = EngineRunRequest(
    configPath = configPath,
    config = loadValidatedConfig(configPath),
)
