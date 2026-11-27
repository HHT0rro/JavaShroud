package io.github.hht0rro.javashroud.config

import io.github.hht0rro.javashroud.apk.ApkBinaryXmlReader
import io.github.hht0rro.javashroud.apk.ApkFormatDetector
import io.github.hht0rro.javashroud.apk.ApkPassPolicy
import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.compatibility.hardConflictPairs
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_APK
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_AUTO
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_JAR
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.hardening.HardenedDefaultPipeline
import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.schema.requiredPassIdsFor
import io.github.hht0rro.javashroud.model.schema.requiresAnyPassIdsFor
import java.nio.file.Path
import kotlin.io.path.absolutePathString

fun loadValidatedConfig(
    configPath: Path,
    forceApk: Boolean = false,
    cliLogFilePath: Path? = null,
): ObfuscationConfig {
    ensureReadableFile(configPath)
    val parsed = parseConfig(configPath)
    val withOverrides = parsed.copy(
        artifactFormat = if (forceApk) ARTIFACT_FORMAT_APK else parsed.artifactFormat,
        logFilePath = cliLogFilePath?.absolutePathString() ?: parsed.logFilePath,
    )
    return validateConfig(withOverrides, configPath)
}

fun validateConfig(config: ObfuscationConfig, configPath: Path): ObfuscationConfig {
    val normalizedConfig = config.copy(
        inputJarPath = config.inputJarPath.trim(),
        outputJarPath = config.outputJarPath.trim(),
        passes = config.passes.map { pass -> pass.copy(id = pass.id.trim()) },
        ruleSet = config.ruleSet.copy(
            rules = config.ruleSet.rules.map { rule -> rule.copy(target = rule.target.trim(), action = rule.action.trim()) },
        ),
        passSelections = config.passSelections.map { selection ->
            selection.copy(
                passId = selection.passId.trim(),
                rules = selection.rules.map { rule -> rule.copy(target = rule.target.trim(), action = rule.action.trim()) },
            )
        },
    )
    rejectRemovedCurrentFormatParameters(normalizedConfig.passes)
    rejectRetiredCurrentFormatPassIds(
        passes = normalizedConfig.passes,
        globalRules = normalizedConfig.ruleSet.rules,
        passSelections = normalizedConfig.passSelections,
    )
    if (normalizedConfig.inputJarPath.isBlank()) {
        throw IllegalArgumentException("Config validation failed: inputJarPath is blank, path=${configPath.absolutePathString()}")
    }

    if (normalizedConfig.outputJarPath.isBlank()) {
        throw IllegalArgumentException("Config validation failed: outputJarPath is blank, path=${configPath.absolutePathString()}")
    }

    // Resolve the artifact format before pipeline selection: "auto" sniffs the
    // input for Android markers; explicit formats cross-checked fail-closed.
    val formatResolved = resolveArtifactFormat(normalizedConfig, configPath)

    val apkConfigured = formatResolved.artifactFormat == ARTIFACT_FORMAT_APK

    // APK profile default: an absent protectionProfile resolves to MINIMAL
    // (the desktop-native passes the RELEASE_HARDENED scan requires are
    // blacklisted on Android). An explicitly requested profile is never
    // downgraded — explicit RELEASE_HARDENED keeps its fail-closed scan.
    val profileResolved = if (
        apkConfigured &&
        !formatResolved.protectionProfileExplicit &&
        formatResolved.protectionProfile == HardenedProtectionProfile.RELEASE_HARDENED
    ) {
        formatResolved.copy(protectionProfile = HardenedProtectionProfile.MINIMAL)
    } else {
        formatResolved
    }
    require(!apkConfigured || profileResolved.protectionProfile != HardenedProtectionProfile.RELEASE_HARDENED) {
        "APK mode does not support protectionProfile=release-hardened because it requires the desktop Qp runtime. " +
            "Use protectionProfile=minimal with Android-compatible passes: $configPath"
    }
    val profileDefaultedToMinimal =
        apkConfigured &&
            !profileResolved.protectionProfileExplicit &&
            profileResolved.protectionProfile == HardenedProtectionProfile.MINIMAL

    // APK minApi: read the manifest up front so an unspecified apk.minApi can
    // be derived from minSdkVersion (floored at 21) before any gate or default
    // pipeline fill runs. Explicit values are untouched and keep the strict
    // cross-checks below.
    val apkManifestMinSdk = if (apkConfigured) {
        readManifestMinSdk(Path.of(profileResolved.inputJarPath))
    } else {
        null
    }
    val minApiResolved = if (apkConfigured) {
        profileResolved.copy(
            apk = profileResolved.apk.copy(
                minApi = ApkPassPolicy.deriveEffectiveMinApi(profileResolved.apk, apkManifestMinSdk),
            ),
        )
    } else {
        profileResolved
    }

    if (apkConfigured) {
        ApkPassPolicy.validateMinApi(minApiResolved.apk, configPath)
    }

    val pipelineFilled = when {
        minApiResolved.passes.isNotEmpty() -> minApiResolved
        profileDefaultedToMinimal -> minApiResolved.copy(
            passes = ApkPassPolicy.defaultApkPassSpecs(minApi = minApiResolved.apk.minApi),
            allowOptInPasses = true,
        )
        minApiResolved.protectionProfile == HardenedProtectionProfile.RELEASE_HARDENED -> minApiResolved.copy(
            passes = HardenedDefaultPipeline.defaultPassSpecs(),
            allowOptInPasses = true,
        )
        else -> minApiResolved
    }

    if (apkConfigured) {
        // Dependency-injected forbidden passes are caught here too (the
        // injector runs further below, so also re-check after normalize).
        ApkPassPolicy.validatePassBlacklist(pipelineFilled, configPath)
        ApkPassPolicy.validateInvokeCustomGate(pipelineFilled, configPath)
        ApkPassPolicy.validateManifestMinSdk(apkManifestMinSdk, pipelineFilled, configPath)
    }

    val profileFilled = pipelineFilled
    if (profileFilled.passes.isEmpty()) {
        throw IllegalArgumentException("Config validation failed: passes is empty, path=${configPath.absolutePathString()}")
    }

    val executablePasses = profileFilled.passes.filterNot { it.id == PASS_ORDERING_PLANNER_ID }
    val enabledIds = executablePasses.filter { it.enabled }.map { it.id }
    val duplicateIds = enabledIds.groupBy { it }.filter { it.value.size > 1 }.keys
    if (duplicateIds.isNotEmpty()) {
        throw IllegalArgumentException(
            "Config validation failed: duplicate pass IDs found: ${duplicateIds.joinToString(", ")}, path=${configPath.absolutePathString()}"
        )
    }

    val inputJarPath = Path.of(normalizedConfig.inputJarPath).toAbsolutePath().normalize()
    val outputJarPath = Path.of(normalizedConfig.outputJarPath).toAbsolutePath().normalize()
    requireSafeRunFilePaths(profileFilled, configPath)
    ensureReadableFile(inputJarPath)

    if (executablePasses.isEmpty()) {
        throw IllegalArgumentException("Config validation failed: passes is empty, path=${configPath.absolutePathString()}")
    }

    validateKnownPassIds(executablePasses, configPath)
    val normalizedPasses = normalizePassDependencies(executablePasses)
    if (apkConfigured) {
        // The dependency injector above may add forbidden passes after the
        // earlier blacklist check; re-check the injected list fail-closed.
        ApkPassPolicy.validatePassBlacklist(
            profileFilled.copy(passes = normalizedPasses),
            configPath,
        )
    }
    validatePassSelections(profileFilled.passSelections, normalizedPasses, configPath)
    validateRequiredPassDependencies(normalizedPasses, configPath)
    validatePassCompatibility(normalizedPasses, configPath, profileFilled.allowIncomplete)
    validateRequiresAnyPassDependencies(normalizedPasses, configPath)
    validateOptInPasses(normalizedPasses, configPath, profileFilled.allowOptInPasses)
    validateRedundantPasses(normalizedPasses, configPath, profileFilled.allowRedundantPasses)
    HardenedDefaultPipeline.validate(profileFilled, normalizedPasses, configPath)

    return profileFilled.copy(
        passes = normalizedPasses,
        inputJarPath = inputJarPath.absolutePathString(),
        outputJarPath = outputJarPath.absolutePathString(),
    )
}

internal fun rejectRemovedCurrentFormatParameters(passes: List<PassSpec>) {
    if (passes.any { pass ->
            pass.id == JNI_MICROKERNEL_LOADER_ID && pass.params.containsKey(REMOVED_BOOT_KEY_DELIVERY_PARAM)
        }) {
        throw IllegalArgumentException(REMOVED_BOOT_KEY_DELIVERY_MESSAGE)
    }
}

/**
 * Resolves artifactFormat="auto" by sniffing the input zip for Android
 * markers. Explicit formats are cross-checked fail-closed: explicit "apk"
 * without dex entries and explicit "jar" on APK-shaped input both reject
 * with both facts in the message.
 */
internal fun resolveArtifactFormat(config: ObfuscationConfig, configPath: Path): ObfuscationConfig {
    val inputPath = Path.of(config.inputJarPath).toAbsolutePath().normalize()
    return when (config.artifactFormat.trim().lowercase()) {
        ARTIFACT_FORMAT_JAR -> {
            if (ApkFormatDetector.looksLikeApk(inputPath)) {
                throw IllegalArgumentException(
                    "Config validation failed: artifactFormat=jar but the input has Android markers " +
                        "(root AndroidManifest.xml + classes*.dex); use artifactFormat=\"apk\", path=${configPath.absolutePathString()}",
                )
            }
            config
        }
        ARTIFACT_FORMAT_APK -> {
            if (!ApkFormatDetector.looksLikeApk(inputPath)) {
                throw IllegalArgumentException(
                    "Config validation failed: artifactFormat=apk but the input is not an APK " +
                        "(no root AndroidManifest.xml + classes*.dex pair), path=${configPath.absolutePathString()}",
                )
            }
            config
        }
        ARTIFACT_FORMAT_AUTO -> {
            val isApk = ApkFormatDetector.looksLikeApk(inputPath)
            config.copy(artifactFormat = if (isApk) ARTIFACT_FORMAT_APK else ARTIFACT_FORMAT_JAR)
        }
        else -> throw IllegalArgumentException(
            "Config validation failed: artifactFormat '${config.artifactFormat}' is not supported; " +
                "supported values: $ARTIFACT_FORMAT_AUTO, $ARTIFACT_FORMAT_JAR, $ARTIFACT_FORMAT_APK, " +
                "path=${configPath.absolutePathString()}",
        )
    }
}

internal fun readManifestMinSdk(inputApk: Path): Int? {
    val manifestBytes = ApkFormatDetector.readRootEntry(inputApk, "AndroidManifest.xml")
        ?: throw IllegalArgumentException(
            "APK input is missing the root AndroidManifest.xml entry: $inputApk",
        )
    val manifest = runCatching { ApkBinaryXmlReader.parse(manifestBytes) }.getOrElse { error ->
        throw IllegalArgumentException(
            "APK AndroidManifest.xml is not parseable: ${error.message}, path=$inputApk",
        )
    }
    return manifest.minSdkVersion
}

internal val RETIRED_CURRENT_FORMAT_PASS_IDS = setOf(
    "bootstrap-table-encryption",
    "environment-bound-keys",
    "method-body-delayed-decryption",
    "class-encryption-loader",
    "anti-instrumentation",
    "anti-jvmti-agent",
    "anti-bytebuddy-transform",
    "anti-dump-protection",
    "anti-symbolic-execution",
)

internal fun rejectRetiredCurrentFormatPassIds(
    passes: List<PassSpec>,
    globalRules: List<io.github.hht0rro.javashroud.model.config.RuleSpec> = emptyList(),
    passSelections: List<io.github.hht0rro.javashroud.model.config.PassSelectionSpec>,
) {
    val configuredIds = buildList {
        addAll(passes.map(PassSpec::id))
        addAll(globalRules.map { it.action })
        passSelections.forEach { selection ->
            add(selection.passId)
            addAll(selection.rules.map { it.action })
        }
    }
    val retired = configuredIds
        .filter { it in RETIRED_CURRENT_FORMAT_PASS_IDS }
        .distinct()
        .sorted()
    if (retired.isNotEmpty()) {
        throw IllegalArgumentException(
            "Config validation failed: retired/unsupported current-format pass IDs found: " +
                retired.joinToString(", ") { "'$it'" },
        )
    }
}

/**
 * Auto-inject missing required dependency passes.
 *
 * Static and parameter-selected requiredPassIds are inserted into the
 * configuration before downstream validation. This allows users to specify only
 * the pass they want without manually including all required dependencies.
 */
private const val PASS_ORDERING_PLANNER_ID = "pass-ordering-planner"
private const val JNI_MICROKERNEL_LOADER_ID = "jni-microkernel-loader"
private const val REMOVED_BOOT_KEY_DELIVERY_PARAM = "bootKeyDelivery"
private const val REMOVED_BOOT_KEY_DELIVERY_MESSAGE =
    "jni-microkernel-loader bootKeyDelivery 已由当前格式移除；删除该配置项后重新构建。"

private fun validateKnownPassIds(passes: List<PassSpec>, configPath: Path) {
    val knownPassIds = buildEngineSchemaPayload().modules.map { it.id }.toSet()
    val unknownPassIds = passes
        .map { it.id }
        .filter { it !in knownPassIds }
        .distinct()
        .sorted()

    if (unknownPassIds.isNotEmpty()) {
        val renderedIds = unknownPassIds.joinToString(", ") { passId ->
            if (passId.isBlank()) "<blank>" else "'$passId'"
        }
        throw IllegalArgumentException(
            "Config validation failed: unknown pass IDs found: $renderedIds, " +
                "path=${configPath.absolutePathString()}",
        )
    }
}

private fun normalizePassDependencies(passes: List<PassSpec>): List<PassSpec> {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toMutableSet()
    val result = passes.toMutableList()
    val schema = buildEngineSchemaPayload()
    val modulesById = schema.modules.associateBy { it.id }

    var changed = true
    while (changed) {
        changed = false
        for (passSpec in result.toList()) {
            if (!passSpec.enabled) continue
            val module = modulesById[passSpec.id] ?: continue
            for (requiredId in module.requiredPassIdsFor(passSpec.params)) {
                if (requiredId !in enabledIds) {
                    result.add(PassSpec(id = requiredId, enabled = true, params = emptyMap()))
                    enabledIds += requiredId
                    changed = true
                }
            }
        }
    }
    return result
}

private fun validatePassCompatibility(passes: List<PassSpec>, configPath: Path, allowIncomplete: Boolean = false) {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()

    for ((a, b) in hardConflictPairs) {
        if (a in enabledIds && b in enabledIds) {
            throw IllegalArgumentException(
                "Config validation failed: incompatible passes '$a' and '$b' cannot be enabled together, " +
                    "path=${configPath.absolutePathString()}"
            )
        }
    }
}

private fun validateRequiredPassDependencies(passes: List<PassSpec>, configPath: Path) {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()
    val modulesById = buildEngineSchemaPayload().modules.associateBy { it.id }
    val missingDependencies = passes
        .filter { passSpec -> passSpec.enabled }
        .mapNotNull { passSpec ->
            val module = modulesById[passSpec.id] ?: return@mapNotNull null
            val missingRequiredPassIds = module.requiredPassIdsFor(passSpec.params).filterNot(enabledIds::contains)
            if (missingRequiredPassIds.isEmpty()) {
                null
            } else {
                module.id to missingRequiredPassIds
            }
        }
        .sortedBy { (passId, _) -> passId }

    if (missingDependencies.isNotEmpty()) {
        val dependencySummary = missingDependencies.joinToString("; ") { (passId, requiredPassIds) ->
            "$passId requires ${requiredPassIds.sorted()}"
        }
        throw IllegalArgumentException(
            "Config validation failed: missing required passes: $dependencySummary, " +
                "path=${configPath.absolutePathString()}"
        )
    }
}

private fun validateRequiresAnyPassDependencies(passes: List<PassSpec>, configPath: Path) {
    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()
    val modulesById = buildEngineSchemaPayload().modules.associateBy { it.id }
    val missingAnyDependencies = passes
        .filter { passSpec -> passSpec.enabled }
        .mapNotNull { passSpec ->
            val module = modulesById[passSpec.id] ?: return@mapNotNull null
            val requiredAnyPassIds = module.requiresAnyPassIdsFor(passSpec.params)
            if (requiredAnyPassIds.isEmpty() || requiredAnyPassIds.any(enabledIds::contains)) null else module to requiredAnyPassIds
        }
        .sortedBy { (module, _) -> module.id }

    if (missingAnyDependencies.isNotEmpty()) {
        val dependencySummary = missingAnyDependencies.joinToString("; ") { (module, requiredAnyPassIds) ->
            "${module.id} requires any of ${requiredAnyPassIds.sorted()}"
        }
        throw IllegalArgumentException(
            "Config validation failed: missing companion passes: $dependencySummary, " +
                "path=${configPath.absolutePathString()}"
        )
    }
}

/**
 * Reject opt-in passes unless explicitly allowed.
 * Opt-in passes require explicit user consent because they may change runtime
 * behavior, have significant performance impact, or require specific runtime support.
 */
private fun validateOptInPasses(passes: List<PassSpec>, configPath: Path, allowOptInPasses: Boolean = false) {
    if (allowOptInPasses) return

    val enabledIds = passes.filter { it.enabled }.map { it.id }.toSet()
    val schema = buildEngineSchemaPayload()
    val optInModuleIds = schema.modules.filter { it.requiresOptIn }.map { it.id }.toSet()

    val usedOptIn = enabledIds.intersect(optInModuleIds)
    if (usedOptIn.isNotEmpty()) {
        throw IllegalArgumentException(
            "Config validation failed: passes $usedOptIn require explicit opt-in. " +
                "These passes may change runtime behavior, have significant performance impact, " +
                "or require specific runtime support. Set \"allowOptInPasses\": true to use them. " +
                "path=${configPath.absolutePathString()}"
        )
    }
}

private fun validatePassSelections(
    selections: List<io.github.hht0rro.javashroud.model.config.PassSelectionSpec>,
    normalizedPasses: List<PassSpec>,
    configPath: Path,
) {
    val duplicateIds = selections.groupBy { it.passId }.filterValues { it.size > 1 }.keys.sorted()
    if (duplicateIds.isNotEmpty()) {
        throw IllegalArgumentException(
            "Config validation failed: duplicate pass selection IDs found: ${duplicateIds.joinToString(", ")}, " +
                "path=${configPath.absolutePathString()}",
        )
    }

    val schemaModules = buildEngineSchemaPayload().modules.associateBy { it.id }
    val configuredPasses = normalizedPasses.associateBy { it.id }
    for (selection in selections) {
        val module = schemaModules[selection.passId]
            ?: throw IllegalArgumentException(
                "Config validation failed: passSelections references unknown pass '${selection.passId}', " +
                    "path=${configPath.absolutePathString()}",
            )
        val pass = configuredPasses[selection.passId]
            ?: throw IllegalArgumentException(
                "Config validation failed: passSelections references pass '${selection.passId}' that is not configured, " +
                    "path=${configPath.absolutePathString()}",
            )
        if (!pass.enabled) {
            throw IllegalArgumentException(
                "Config validation failed: passSelections references disabled pass '${selection.passId}', " +
                    "path=${configPath.absolutePathString()}",
            )
        }
        if (!module.targeting.supported) {
            throw IllegalArgumentException(
                "Config validation failed: pass '${selection.passId}' does not support class/method target selection, " +
                    "path=${configPath.absolutePathString()}",
            )
        }
        val duplicateTargets = selection.rules.groupBy { it.target }.filterValues { it.size > 1 }.keys.sorted()
        if (duplicateTargets.isNotEmpty()) {
            throw IllegalArgumentException(
                "Config validation failed: pass selection '${selection.passId}' has duplicate rule targets: " +
                    "${duplicateTargets.joinToString(", ")}, path=${configPath.absolutePathString()}",
            )
        }
        for ((index, rule) in selection.rules.withIndex()) {
            if (rule.target.isBlank()) {
                throw IllegalArgumentException(
                    "Config validation failed: passSelections '${selection.passId}' rule[$index] target is blank, " +
                        "path=${configPath.absolutePathString()}",
                )
            }
            if (rule.action !in setOf("obfuscate", "exclude")) {
                throw IllegalArgumentException(
                    "Config validation failed: passSelections '${selection.passId}' rule[$index] action '${rule.action}' is invalid; " +
                        "supported values: obfuscate, exclude, path=${configPath.absolutePathString()}",
                )
            }
            val targetKind = passSelectionTargetKindOrThrow(
                target = rule.target,
                passId = selection.passId,
                ruleIndex = index,
                configPath = configPath,
            )
            if (targetKind !in module.targeting.targetKinds) {
                throw IllegalArgumentException(
                    "Config validation failed: pass '${selection.passId}' does not support $targetKind target selection, " +
                        "target=${rule.target}, supported targetKinds=${module.targeting.targetKinds.joinToString(", ")}, " +
                        "path=${configPath.absolutePathString()}",
                )
            }
        }
        if (selection.mode == PassSelectionMode.INHERIT_GLOBAL && selection.rules.isNotEmpty()) {
            throw IllegalArgumentException(
                "Config validation failed: inherit-global pass selection '${selection.passId}' must not contain local rules, " +
                    "path=${configPath.absolutePathString()}",
            )
        }
    }
}

/**
 * Pass selections deliberately do not share the permissive legacy global-rule
 * grammar. They are persisted from class-tree canonical selectors and must stay
 * concrete after passing through TOML/JSON and the desktop bridge.
 */
private fun passSelectionTargetKindOrThrow(
    target: String,
    passId: String,
    ruleIndex: Int,
    configPath: Path,
): String {
    fun concreteTargetError(): Nothing = throw IllegalArgumentException(
        "Config validation failed: passSelections '$passId' rule[$ruleIndex] must target one concrete class or method, " +
            "target=$target, path=${configPath.absolutePathString()}",
    )
    fun canonicalTargetError(): Nothing = throw IllegalArgumentException(
        "Config validation failed: passSelections '$passId' rule[$ruleIndex] must use a canonical class or JVM method selector, " +
            "target=$target, path=${configPath.absolutePathString()}",
    )

    if ('*' in target) concreteTargetError()

    val memberSeparator = target.indexOf('#')
    if (memberSeparator < 0) {
        if (!isCanonicalInternalClassName(target)) canonicalTargetError()
        return "class"
    }
    if (memberSeparator != target.lastIndexOf('#')) canonicalTargetError()

    val owner = target.substring(0, memberSeparator)
    val memberWithDescriptor = target.substring(memberSeparator + 1)
    val descriptorSeparator = memberWithDescriptor.indexOf(':')
    if (
        !isCanonicalInternalClassName(owner) ||
        descriptorSeparator <= 0 ||
        descriptorSeparator != memberWithDescriptor.lastIndexOf(':')
    ) {
        canonicalTargetError()
    }

    val memberName = memberWithDescriptor.substring(0, descriptorSeparator)
    val descriptor = memberWithDescriptor.substring(descriptorSeparator + 1)
    if (!isCanonicalMethodName(memberName)) canonicalTargetError()
    if (!descriptor.startsWith("(")) {
        throw IllegalArgumentException(
            "Config validation failed: passSelections '$passId' supports JVM method selectors only; " +
                "field selectors are not supported, target=$target, path=${configPath.absolutePathString()}",
        )
    }
    if (!isJvmMethodDescriptor(descriptor)) canonicalTargetError()
    if (!isCanonicalConstructorSelector(memberName, descriptor)) canonicalTargetError()

    return "method"
}

private fun isCanonicalInternalClassName(value: String): Boolean {
    if (value.isBlank() || value.endsWith('/') || value.endsWith('.')) return false
    return value.split('/').all { segment ->
        segment.isNotBlank() && segment.none { character ->
            character == '\\' ||
                character in setOf('.', '#', ':', ';', '[', ']', '(', ')', '*', '<', '>') ||
                character.isWhitespace()
        }
    }
}

private fun isCanonicalMethodName(value: String): Boolean {
    if (value == "<init>" || value == "<clinit>") return true
    if (value.isBlank()) return false
    return value.none { character ->
        character in setOf('#', '.', ':', ';', '[', ']', '(', ')', '/', '*', '<', '>') || character.isWhitespace()
    }
}

/**
 * JVM descriptor syntax is intentionally reusable for ordinary methods, but
 * constructor and class-initializer selectors have stricter JVM invariants.
 * The class tree never emits any other shape; rejecting them here prevents an
 * imported selected-only independent-scope rule from being non-empty yet unmatchable.
 */
private fun isCanonicalConstructorSelector(memberName: String, descriptor: String): Boolean =
    (memberName != "<init>" || descriptor.endsWith('V')) &&
        (memberName != "<clinit>" || descriptor == "()V")

private fun isJvmMethodDescriptor(descriptor: String): Boolean {
    if (!descriptor.startsWith("(")) return false

    var index = 1
    while (index < descriptor.length && descriptor[index] != ')') {
        index = consumeJvmFieldDescriptor(descriptor, index) ?: return false
    }
    if (index >= descriptor.length || descriptor[index] != ')') return false

    index += 1
    if (index < descriptor.length && descriptor[index] == 'V') return index + 1 == descriptor.length
    return consumeJvmFieldDescriptor(descriptor, index) == descriptor.length
}

private fun consumeJvmFieldDescriptor(descriptor: String, start: Int): Int? {
    var index = start
    while (index < descriptor.length && descriptor[index] == '[') index += 1
    if (index >= descriptor.length) return null

    return when (descriptor[index]) {
        'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z' -> index + 1
        'L' -> {
            val end = descriptor.indexOf(';', startIndex = index + 1)
            if (end < 0 || !isCanonicalInternalClassName(descriptor.substring(index + 1, end))) null else end + 1
        }
        else -> null
    }
}
