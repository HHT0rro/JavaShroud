package io.github.hht0rro.javashroud.model.config

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.databind.JsonNode

data class PassSpec(
    val id: String,
    val enabled: Boolean,
    val params: Map<String, JsonNode>,
)

data class RuleSpec(
    val target: String,
    val action: String,
)

/**
 * Runtime provenance for a rule view.
 *
 * Global configuration and all legacy callers use [GLOBAL]. [SELECTED_ONLY] is
 * attached only to the ephemeral effective RuleSet compiled for one enabled
 * pass, so it is never serialized as user configuration.
 */
enum class RuleSetScope {
    GLOBAL,
    SELECTED_ONLY,
}

data class RuleSet(
    val rules: List<RuleSpec>,
    @get:JsonIgnore
    val scope: RuleSetScope = RuleSetScope.GLOBAL,
)

/**
 * Controls how a pass obtains its target rules.
 *
 * [INHERIT_GLOBAL] preserves the legacy ruleSet behavior. [SELECTED_ONLY]
 * is an independent range with an implicit all-targets-enabled baseline; local
 * class or method rules exclude targets or recover more-specific children.
 */
enum class PassSelectionMode(val wireValue: String) {
    INHERIT_GLOBAL("inherit-global"),
    SELECTED_ONLY("selected-only"),
    ;

    companion object {
        fun fromWireValue(value: String): PassSelectionMode = values().firstOrNull { it.wireValue == value }
            ?: throw IllegalArgumentException(
                "Config validation failed: pass selection mode '$value' is not supported; " +
                    "supported values: ${values().joinToString(", ") { it.wireValue }}",
            )
    }
}

/**
 * Per-pass target selection. Rules use the same selector syntax as the global
 * ruleSet, but selected-only selections are limited to class and JVM-method
 * selectors by configuration validation.
 */
data class PassSelectionSpec(
    val passId: String,
    val mode: PassSelectionMode = PassSelectionMode.INHERIT_GLOBAL,
    val rules: List<RuleSpec> = emptyList(),
)

data class ObfuscationConfig(
    val inputJarPath: String,
    val outputJarPath: String,
    val passes: List<PassSpec>,
    val ruleSet: RuleSet,
    val passSelections: List<PassSelectionSpec> = emptyList(),
    val allowIncomplete: Boolean = false,
    val allowOptInPasses: Boolean = false,
    val allowRedundantPasses: Boolean = false,
    val allowAnnotationPasses: Boolean = false,
    val protectionProfile: HardenedProtectionProfile = HardenedProtectionProfile.RELEASE_HARDENED,
    /**
     * False when the config file did not carry an explicit protectionProfile
     * key. APK mode uses this to resolve the profile default to MINIMAL with
     * a visible announcement; an explicitly requested profile is never
     * silently downgraded.
     */
    val protectionProfileExplicit: Boolean = true,
    /**
     * Input artifact format: "auto" (sniff zip for Android manifest + dex),
     * "jar", or "apk". Always resolved to a concrete "jar"/"apk" by
     * [io.github.hht0rro.javashroud.config.validateConfig].
     */
    val artifactFormat: String = ARTIFACT_FORMAT_AUTO,
    /** Optional verbose log file for APK pipeline diagnostics; CLI --log-file overrides. */
    val logFilePath: String = "",
    /** APK-mode toolchain and signing options; ignored in jar mode. */
    val apk: ApkConfig = ApkConfig(),
)

const val ARTIFACT_FORMAT_AUTO = "auto"
const val ARTIFACT_FORMAT_JAR = "jar"
const val ARTIFACT_FORMAT_APK = "apk"

/** Passes that may not run in APK mode: Qp native runtime is x64 desktop only. */
val APK_FORBIDDEN_PASS_IDS: Set<String> = setOf(
    "jni-microkernel-loader",
    "nativeshroud",
    "method-virtualization",
    "os-anti-debug",
    "os-anti-vm",
)

/** Serialized methods whose member names must survive any rename in APK mode. */
data class ApkSerializedMemberKeeps(
    val owner: String,
    val name: String,
    val descriptor: String,
    val kind: String,
)

data class ApkConfig(
    val minApi: Int = 26,
    /**
     * False when the config carried no apk.minApi key. An unspecified minApi is
     * derived from the manifest minSdkVersion (floored at the API-21 multidex
     * minimum) instead of failing closed against the 26 default; an explicit
     * value keeps the strict minSdk cross-check.
     */
    val minApiExplicit: Boolean = false,
    val androidJarPath: String = "",
    val d8JarPath: String = "",
    val dex2jarDirPath: String = "",
    val extraKeepPrefixes: List<String> = emptyList(),
    val soPageSize: Int = 4096,
    val signing: ApkSigningConfig = ApkSigningConfig(),
)

data class ApkSigningConfig(
    val keystorePath: String = "",
    val storePassword: String = "",
    val keyAlias: String = "",
    val keyPassword: String = "",
    val v1Enabled: Boolean = true,
    val v2Enabled: Boolean = true,
)
