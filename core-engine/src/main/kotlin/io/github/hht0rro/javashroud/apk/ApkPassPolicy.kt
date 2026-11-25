package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.model.config.APK_FORBIDDEN_PASS_IDS
import io.github.hht0rro.javashroud.model.config.ApkConfig
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.schema.requiredPassIdsFor
import io.github.hht0rro.javashroud.transforms.protection.hardening.HardenedDefaultPipeline
import java.nio.file.Path

/**
 * APK-mode pass policy: forbidden-pass blacklist, RELEASE_HARDENED default
 * pipeline fill, and min-api gates. Every check is fail-closed and only ever
 * runs on the APK branch of config validation; jar-mode behavior is untouched.
 */
object ApkPassPolicy {

    const val MIN_API_FLOOR = 21
    const val MIN_API_FOR_INVOKE_CUSTOM = 26
    const val INDY_PASS_ID = "invoke-dynamic-indirection"

    /** Passes that may never be enabled in APK mode (Qp runtime is desktop x64 only). */
    val forbiddenPassIds: Set<String> = APK_FORBIDDEN_PASS_IDS

    /**
     * Default APK pipeline: RELEASE_PASSES minus the blacklist, from the single
     * source of truth. Passes whose static dependency closure (as the pipeline
     * would inject it) still pulls in a forbidden pass are dropped too, so the
     * dependency injector cannot reintroduce desktop-only passes by surprise.
     * When the effective minApi cannot verify invoke-custom bytecodes
     * (API < 26), invoke-dynamic-indirection is omitted as well.
     */
    fun defaultApkPassSpecs(minApi: Int = MIN_API_FOR_INVOKE_CUSTOM): List<PassSpec> {
        val modulesById = buildEngineSchemaPayload().modules.associateBy { it.id }
        val floorIds = buildSet {
            addAll(forbiddenPassIds)
            if (minApi < MIN_API_FOR_INVOKE_CUSTOM) add(INDY_PASS_ID)
        }
        val candidates = HardenedDefaultPipeline.RELEASE_PASSES
            .filter { it !in floorIds }
            .toMutableList()
        var changed = true
        while (changed) {
            changed = false
            val rejected = candidates.firstOrNull { id ->
                closureOf(id, modulesById, emptyMap()).any { it in floorIds }
            }
            if (rejected != null) {
                candidates.remove(rejected)
                changed = true
            }
        }
        return candidates.map { id -> PassSpec(id = id, enabled = true, params = emptyMap()) }
    }

    /**
     * Effective minApi: an explicit value always wins (and keeps the strict
     * manifest cross-check); an unspecified one is derived from the manifest
     * minSdkVersion, floored at the API-21 native-multidex minimum, so a
     * config-less direct run on any minSdk >= 21 app stays valid. A manifest
     * without uses-sdk keeps the 26 default.
     */
    fun deriveEffectiveMinApi(apk: ApkConfig, manifestMinSdk: Int?): Int {
        if (apk.minApiExplicit || manifestMinSdk == null) return apk.minApi
        return maxOf(MIN_API_FLOOR, manifestMinSdk)
    }

    private fun closureOf(
        passId: String,
        modulesById: Map<String, io.github.hht0rro.javashroud.model.schema.ModuleDefinition>,
        params: Map<String, com.fasterxml.jackson.databind.JsonNode>,
    ): Set<String> {
        val closure = mutableSetOf<String>()
        val queue = ArrayDeque<String>()
        queue += passId
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            if (!closure.add(current)) continue
            val module = modulesById[current] ?: continue
            for (required in module.requiredPassIdsFor(params)) {
                if (required !in closure) queue += required
            }
        }
        return closure
    }

    /**
     * Applies the APK default-pipeline fill for empty pass lists under
     * RELEASE_HARDENED, mirroring the jar-mode fill in ConfigLoadSupport
     * (including the mandatory allowOptInPasses=true opt-in unlock).
     */
    fun fillDefaultPipeline(config: ObfuscationConfig): ObfuscationConfig {
        if (config.passes.isNotEmpty()) return config
        if (config.protectionProfile != HardenedProtectionProfile.RELEASE_HARDENED) return config
        return config.copy(passes = defaultApkPassSpecs(), allowOptInPasses = true)
    }

    /** True when invoke-custom (invokedynamic) bytecodes may reach the output dex. */
    fun invokeCustomActive(config: ObfuscationConfig): Boolean {
        val enabledIds = config.passes.filter { it.enabled }.map { it.id }.toSet()
        if (INDY_PASS_ID in enabledIds) return true
        return config.protectionProfile != HardenedProtectionProfile.MINIMAL
    }

    fun validatePassBlacklist(config: ObfuscationConfig, configPath: Path) {
        val enabledIds = config.passes.filter { it.enabled }.map { it.id }.toSet()
        val used = enabledIds.intersect(forbiddenPassIds)
        if (used.isNotEmpty()) {
            throw IllegalArgumentException(
                "Config validation failed: APK mode rejects passes that need the desktop Qp native runtime: " +
                    used.sorted().joinToString(", ") + ", path=${configPath}",
            )
        }
    }

    fun validateMinApi(apk: ApkConfig, configPath: Path) {
        if (apk.minApi < MIN_API_FLOOR) {
            throw IllegalArgumentException(
                "Config validation failed: apk.minApi=${apk.minApi} is below the supported floor $MIN_API_FLOOR " +
                    "(native multidex requires API >= 21), path=${configPath}",
            )
        }
    }

    fun validateInvokeCustomGate(config: ObfuscationConfig, configPath: Path) {
        if (!invokeCustomActive(config)) return
        if (config.apk.minApi < MIN_API_FOR_INVOKE_CUSTOM) {
            throw IllegalArgumentException(
                "Config validation failed: APK mode with invoke-dynamic-indirection (or any non-MINIMAL profile, " +
                    "which wraps indy targets) requires apk.minApi >= $MIN_API_FOR_INVOKE_CUSTOM; " +
                    "got=${config.apk.minApi}. Disable the indy pass / use protectionProfile=minimal, or raise minApi, " +
                    "path=${configPath}",
            )
        }
    }

    /**
     * The dangerous direction is manifest minSdk below the effective minApi:
     * devices between the two would load invoke-custom dex bytecodes their ART
     * cannot verify. An EXPLICIT apk.minApi above the manifest keeps failing
     * closed — the user asked for something the input contradicts. When minApi
     * was derived (the engine floor plus the manifest value), the pipeline
     * instead raises the OUTPUT manifest's minSdkVersion to the effective
     * minApi with a warning: the produced dex genuinely requires that floor,
     * and raising the manifest is the only sound output for inputs like
     * minSdk 9-20 apps.
     */
    fun validateManifestMinSdk(manifestMinSdk: Int?, config: ObfuscationConfig, configPath: Path) {
        require(manifestMinSdk != null && manifestMinSdk > 0) {
            "AndroidManifest.xml must declare a numeric minSdkVersion in <uses-sdk>. " +
                "Rebuild the input APK with an explicit minSdkVersion before repacking: $configPath"
        }
        if (!config.apk.minApiExplicit) return
        if (manifestMinSdk < config.apk.minApi) {
            throw IllegalArgumentException(
                "Config validation failed: AndroidManifest minSdkVersion=$manifestMinSdk is below the explicit " +
                    "apk.minApi=${config.apk.minApi}; API ${manifestMinSdk}-${config.apk.minApi - 1} devices would fail " +
                    "dex verification. Raise the manifest minSdkVersion to at least apk.minApi, or lower apk.minApi " +
                    "(and drop invoke-dynamic passes if below $MIN_API_FOR_INVOKE_CUSTOM), path=${configPath}",
            )
        }
    }
}
