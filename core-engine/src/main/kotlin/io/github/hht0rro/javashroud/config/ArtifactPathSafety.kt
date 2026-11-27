package io.github.hht0rro.javashroud.config

import io.github.hht0rro.javashroud.apk.ApkFormatDetector
import io.github.hht0rro.javashroud.apk.ApkSignerService
import io.github.hht0rro.javashroud.apk.apkSidecarPaths
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_APK
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_AUTO
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.CandidateProductionBuildEvidence
import io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

internal fun runOutputSidecarPaths(config: ObfuscationConfig): List<Path> {
    val output = Path.of(config.outputJarPath).toAbsolutePath().normalize()
    val apk = config.artifactFormat == ARTIFACT_FORMAT_APK ||
        config.artifactFormat == ARTIFACT_FORMAT_AUTO && ApkFormatDetector.looksLikeApk(Path.of(config.inputJarPath))
    if (apk) return apkSidecarPaths(output)
    val stem = output.fileName.toString().removeSuffix(".jar")
    return listOf(
        output.resolveSibling(stem + ".release-scan.txt"),
        SignedDebugMap.sidecarPath(output),
        CandidateProductionBuildEvidence.evidencePath(output),
    )
}

internal fun protectedRunFilePaths(config: ObfuscationConfig, configPath: Path): List<Path> = listOf(
    Path.of(config.inputJarPath),
    Path.of(config.outputJarPath),
    configPath,
    ApkSignerService.keystorePath(config.apk.signing),
) + runOutputSidecarPaths(config)

internal fun requireSafeRunFilePaths(config: ObfuscationConfig, configPath: Path) {
    val protected = listOf(Path.of(config.inputJarPath), configPath, ApkSignerService.keystorePath(config.apk.signing))
    val destinations = listOf(Path.of(config.outputJarPath)) + runOutputSidecarPaths(config)
    for (destination in destinations) {
        for (source in protected) {
            require(!sameArtifactPath(source, destination)) { "Output or sidecar path refers to a protected run file: $destination ($source)" }
        }
    }
    if (config.logFilePath.isNotBlank()) {
        val log = Path.of(config.logFilePath)
        for (file in protected + destinations) {
            require(!sameArtifactPath(file, log)) { "Log path refers to a protected run file: $log ($file)" }
        }
    }
}

internal fun sameArtifactPath(left: Path, right: Path): Boolean {
    val a = left.toAbsolutePath().normalize()
    val b = right.toAbsolutePath().normalize()
    if (a == b) return true
    if (Files.exists(a) && Files.exists(b)) return Files.isSameFile(a, b)
    return resolveExistingAncestor(a) == resolveExistingAncestor(b)
}

private fun resolveExistingAncestor(path: Path): Path {
    if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return path.toRealPath()
    val parent = path.parent ?: return path
    return resolveExistingAncestor(parent).resolve(path.fileName)
}
