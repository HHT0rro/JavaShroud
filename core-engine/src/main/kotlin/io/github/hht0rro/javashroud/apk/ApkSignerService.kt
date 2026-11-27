package io.github.hht0rro.javashroud.apk

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import com.android.apksig.apk.ApkFormatException
import io.github.hht0rro.javashroud.model.config.ApkSigningConfig
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * In-process apksig signing + fail-closed verification. Keystores come from
 * the config or from the auto-generated debug keystore under
 * ~/.javashroud/apk/debug.keystore (created by spawning the JDK's own
 * keytool; no BouncyCastle dependency). Output is written to a .tmp sibling,
 * verified with ApkVerifier for every enabled scheme, and only then atomically
 * moved into place.
 */
object ApkSignerService {

    private const val DEBUG_KEYSTORE_PASSWORD = "javashroud"
    private const val DEBUG_KEY_ALIAS = "javashroud-debug"
    private const val DEBUG_VALIDITY_DAYS = 10950

    data class SigningOutcome(
        val signedApk: Path,
        val usedDebugKeystore: Boolean,
        val v1Enabled: Boolean,
        val v2Enabled: Boolean,
        val signerCertificateSha256: String?,
    )

    fun sign(
        unsignedApk: Path,
        finalApk: Path,
        signing: ApkSigningConfig,
        minApi: Int,
        soPageSize: Int,
        log: (String) -> Unit,
    ): SigningOutcome {
        checkApkCancellation()
        requireSigningSchemes(signing, minApi)
        val source = unsignedApk.toAbsolutePath().normalize()
        val destination = finalApk.toAbsolutePath().normalize()
        val keystore = keystorePath(signing)
        requireSeparateApkPaths(source, destination)
        requireSeparateApkPaths(keystore, destination)
        require(Files.isRegularFile(source)) { "Unsigned APK is not a regular file: $source" }
        existingRegularApkFile(destination)
        val keyMaterial = loadOrCreateKeyMaterial(signing, keystore, log)
        val signerConfig = ApkSigner.SignerConfig.Builder(
            keyMaterial.alias,
            keyMaterial.privateKey,
            keyMaterial.certificateChain,
        ).build()

        Files.createDirectories(destination.parent)
        val tmpApk = Files.createTempFile(destination.parent, ".javashroud-signing-", ".apk")
        try {
            val signer = ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(source.toFile())
                .setOutputApk(tmpApk.toFile())
                .setV1SigningEnabled(signing.v1Enabled)
                .setV2SigningEnabled(signing.v2Enabled)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setMinSdkVersion(minApi)
                .setAlignmentPreserved(true)
                .setLibraryPageAlignmentBytes(soPageSize)
                .build()
            signer.sign()
            log("apksig signed v1=${signing.v1Enabled} v2=${signing.v2Enabled} minSdk=$minApi soPageAlign=$soPageSize")

            verifyWithCertificate(tmpApk, signing, minApi, keyMaterial.certificateSha256, log)

            checkApkCancellation()
            moveApkFile(tmpApk, destination)
            return SigningOutcome(
                signedApk = finalApk,
                usedDebugKeystore = keyMaterial.fromDebugKeystore,
                v1Enabled = signing.v1Enabled,
                v2Enabled = signing.v2Enabled,
                signerCertificateSha256 = keyMaterial.certificateSha256,
            )
        } finally {
            Files.deleteIfExists(tmpApk)
        }
    }

    fun verify(apk: Path, signing: ApkSigningConfig, minApi: Int, log: (String) -> Unit) =
        verifyWithCertificate(apk, signing, minApi, expectedSha256 = null, log = log)

    internal fun verifyWithCertificate(
        apk: Path,
        signing: ApkSigningConfig,
        minApi: Int,
        expectedSha256: String?,
        log: (String) -> Unit,
    ) {
        requireSigningSchemes(signing, minApi)
        fun checkedResult(builder: ApkVerifier.Builder, label: String): ApkVerifier.Result {
            val result = try {
                builder.build().verify()
            } catch (error: ApkFormatException) {
                throw IllegalArgumentException("APK $label signature verification failed: ${error.message}", error)
            }
            require(result.isVerified) {
                "APK $label signature verification failed: ${summarize(result.allErrors.map { it.toString() })}"
            }
            if (expectedSha256 != null) {
                require(result.signerCertificates.map(::certificateSha256) == listOf(expectedSha256)) {
                    "APK $label signer certificate does not match the expected fingerprint"
                }
            }
            return result
        }

        // Force pre-N verification even when the APK's supported range starts after API 23.
        if (signing.v1Enabled) {
            val legacy = checkedResult(
                ApkVerifier.Builder(apk.toFile())
                    .setMinCheckedPlatformVersion(minApi.coerceAtMost(23))
                    .setMaxCheckedPlatformVersion(23),
                "v1",
            )
            require(legacy.isVerifiedUsingV1Scheme) { "APK v1 signature was not verified" }
        }
        val supported = checkedResult(ApkVerifier.Builder(apk.toFile()).setMinCheckedPlatformVersion(minApi), "supported SDK")
        require(supported.isVerifiedUsingV2Scheme == signing.v2Enabled) { "APK v2 signature does not match signing configuration" }
        log("ApkVerifier passed v1=${signing.v1Enabled} v2=${supported.isVerifiedUsingV2Scheme}")
    }

    private fun summarize(errors: List<String>): String =
        if (errors.isEmpty()) "<no errors reported>" else errors.take(8).joinToString("; ")

    private fun requireSigningSchemes(signing: ApkSigningConfig, minApi: Int) {
        require(signing.v1Enabled || signing.v2Enabled) { "APK signing requires v1 or v2" }
        require(signing.v1Enabled || minApi >= 24) { "APK signing requires v1 below API 24" }
    }

    internal fun keystorePath(signing: ApkSigningConfig): Path =
        (if (signing.keystorePath.isNotBlank()) Path.of(signing.keystorePath)
        else Path.of(System.getProperty("user.home"), ".javashroud/apk/debug.keystore"))
            .toAbsolutePath().normalize()

    private class KeyMaterial(
        val alias: String,
        val privateKey: PrivateKey,
        val certificateChain: List<X509Certificate>,
        val fromDebugKeystore: Boolean,
        val certificateSha256: String,
    )

    private fun loadOrCreateKeyMaterial(signing: ApkSigningConfig, keystorePath: Path, log: (String) -> Unit): KeyMaterial {
        if (signing.keystorePath.isNotBlank()) {
            require(Files.isRegularFile(keystorePath)) { "apk.signing.keystorePath does not exist: $keystorePath" }
            val storePassword = signing.storePassword.toCharArray()
            val alias = signing.keyAlias.ifBlank { singleAlias(keystorePath, storePassword) }
            val keyPassword = if (signing.keyPassword.isBlank()) storePassword else signing.keyPassword.toCharArray()
            val keyStore = loadKeyStore(keystorePath, storePassword)
            val entry = keyStore.getEntry(alias, KeyStore.PasswordProtection(keyPassword)) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalArgumentException(
                    "keystore $keystorePath has no private-key entry for alias '$alias' (wrong keyPassword?)",
                )
            log("signing keystore=$keystorePath alias=$alias")
            return materialFrom(entry.privateKey, entry.certificateChain, alias, fromDebugKeystore = false)
        }
        val debugKeystore = keystorePath
        if (!existingRegularApkFile(debugKeystore)) {
            createDebugKeystore(debugKeystore, log)
        }
        val storePassword = DEBUG_KEYSTORE_PASSWORD.toCharArray()
        val keyStore = loadKeyStore(debugKeystore, storePassword)
        val entry = keyStore.getEntry(DEBUG_KEY_ALIAS, KeyStore.PasswordProtection(storePassword)) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("auto-generated debug keystore is unusable: $debugKeystore")
        log("signing with auto-generated debug keystore (CN=JavaShroud Debug) at $debugKeystore")
        return materialFrom(entry.privateKey, entry.certificateChain, DEBUG_KEY_ALIAS, fromDebugKeystore = true)
    }

    private fun materialFrom(
        privateKey: PrivateKey,
        chain: Array<out java.security.cert.Certificate>,
        alias: String,
        fromDebugKeystore: Boolean,
    ): KeyMaterial {
        val certificates = chain.map { it as X509Certificate }
        return KeyMaterial(
            alias = alias,
            privateKey = privateKey,
            certificateChain = certificates,
            fromDebugKeystore = fromDebugKeystore,
            certificateSha256 = certificateSha256(certificates.first()),
        )
    }

    private fun certificateSha256(certificate: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString("") { "%02x".format(it) }

    private fun singleAlias(keystorePath: Path, storePassword: CharArray): String {
        val keyStore = loadKeyStore(keystorePath, storePassword)
        val aliases = keyStore.aliases().toList()
        val keyAliases = aliases.filter { alias -> keyStore.isKeyEntry(alias) }
        require(keyAliases.isNotEmpty()) { "keystore $keystorePath contains no private-key entries" }
        require(keyAliases.size == 1) {
            "keystore $keystorePath has multiple key aliases ${keyAliases.sorted()}; set apk.signing.keyAlias"
        }
        return keyAliases.single()
    }

    private fun loadKeyStore(path: Path, storePassword: CharArray): KeyStore {
        val buffer = Files.readAllBytes(path)
        for (type in listOf("PKCS12", "JKS")) {
            val keyStore = KeyStore.getInstance(type)
            try {
                keyStore.load(buffer.inputStream(), storePassword)
                return keyStore
            } catch (_: Exception) {
                // try the next store type
            }
        }
        throw IllegalArgumentException(
            "keystore $path is neither a loadable PKCS12 nor JKS store (or the storePassword is wrong)",
        )
    }

    /**
     * Spawns the JDK's own keytool binary; no security provider dependencies.
     * Transient Windows failures (AV scanners or a concurrent engine process
     * racing the same freshly-created staging file report "path not found" /
     * "file in use") are retried on fresh staging files; a keystore that
     * appeared meanwhile (a concurrent run won the race) ends the retry loop
     * early.
     */
    private fun createDebugKeystore(target: Path, log: (String) -> Unit) {
        val keytool = resolveKeytool()
        val attempts = 3
        var lastFailure: IllegalStateException? = null
        for (attempt in 1..attempts) {
            if (attempt > 1 && Files.isRegularFile(target)) {
                log("debug keystore appeared concurrently at $target; skipping keytool generation")
                return
            }
            Files.createDirectories(target.parent)
            val staging = Files.createTempFile(target.parent, "debug-keystore-", ".p12")
            // keytool refuses to write into an existing (empty) keystore file.
            Files.deleteIfExists(staging)
            try {
                val command = listOf(
                    keytool.toAbsolutePath().toString(),
                    "-genkeypair",
                    "-keystore", staging.toAbsolutePath().toString(),
                    "-storetype", "PKCS12",
                    "-storepass", DEBUG_KEYSTORE_PASSWORD,
                    "-keypass", DEBUG_KEYSTORE_PASSWORD,
                    "-alias", DEBUG_KEY_ALIAS,
                    "-keyalg", "RSA",
                    "-keysize", "2048",
                    "-sigalg", "SHA256withRSA",
                    "-validity", DEBUG_VALIDITY_DAYS.toString(),
                    "-dname", "CN=JavaShroud Debug, O=JavaShroud",
                )
                val result = ApkProcessSupport.runProcess(command, ApkProcessSupport.DEFAULT_TIMEOUT_MILLIS)
                if (result.exitCode == 0) {
                    checkApkCancellation()
                    try {
                        Files.move(staging, target)
                    } catch (_: java.nio.file.FileAlreadyExistsException) {
                        require(existingRegularApkFile(target)) { "Debug keystore disappeared: $target" }
                        return
                    }
                    log("generated debug keystore via keytool at $target")
                    return
                }
                lastFailure = IllegalStateException(
                    "keytool failed to generate the debug keystore (exit=${result.exitCode}): " +
                        ApkProcessSupport.preview(result.output),
                )
                if (result.timedOut) throw lastFailure
            } finally {
                Files.deleteIfExists(staging)
            }
            if (Files.isRegularFile(target)) {
                log("debug keystore appeared concurrently at $target; skipping keytool generation")
                return
            }
            Thread.sleep(500L * attempt)
        }
        throw lastFailure ?: IllegalStateException("keytool failed to generate the debug keystore after $attempts attempts")
    }

    private fun resolveKeytool(): Path {
        val javaHome = System.getProperty("java.home")
        if (!javaHome.isNullOrBlank()) {
            val candidate = Path.of(javaHome, "bin", if (isWindows()) "keytool.exe" else "keytool")
            if (Files.isRegularFile(candidate)) return candidate
        }
        val envJavaHome = System.getenv("JAVA_HOME")
        if (!envJavaHome.isNullOrBlank()) {
            val candidate = Path.of(envJavaHome, "bin", if (isWindows()) "keytool.exe" else "keytool")
            if (Files.isRegularFile(candidate)) return candidate
        }
        throw IllegalStateException("keytool not found next to the resolved java runtime")
    }

    private fun isWindows(): Boolean =
        System.getProperty("os.name").lowercase(Locale.ROOT).startsWith("windows")
}
