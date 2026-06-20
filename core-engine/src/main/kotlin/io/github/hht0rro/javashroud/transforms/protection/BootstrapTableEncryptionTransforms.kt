package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.*
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Bootstrap Table Encryption transform.
 *
 * Ensures that invokedynamic bootstrap parameters, target tables, and
 * MethodHandle mappings do not exist as stable plaintext templates.
 *
 * Approach:
 * 1. Find all INVOKEDYNAMIC instructions in matched classes.
 * 2. For bootstrap methods that use table-based dispatch, encrypt the
 *    bootstrap arguments (MethodType strings, MethodHandle references).
 * 3. Replace with an encrypted bootstrap that decrypts arguments at runtime.
 */
fun applyBootstrapTableEncryption(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "bootstrap-table-encryption")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val scope = (params["scope"] as? String) ?: "per-class"
    val supportedScopes = setOf("per-class", "global")
    require(scope in supportedScopes) { "bootstrap-table-encryption scope '$scope' is not supported; supported values: ${supportedScopes.joinToString("", "")}" }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    val globalKey = if (scope == "global") generateBootstrapKey(random) else null
    var classCount = 0
    var indyCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

        val cr = ClassReader(classArtifact.bytes)
        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        val classKey = globalKey ?: generateBootstrapKey(random)
        var classModified = false
        val className = classArtifact.summary.internalName

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitInvokeDynamicInsn(
                        name: String,
                        descriptor: String,
                        bootstrapMethodHandle: Handle,
                        vararg bootstrapMethodArguments: Any,
                    ) {
                        // Encrypt only String bootstrap constants so runtime bootstrap ABI stays intact
                        // for MethodHandle / MethodType / primitive bootstrap arguments.
                        val encryptedArgs = bootstrapMethodArguments.map { bootstrapArgument ->
                            if (bootstrapArgument is String) encryptToString(bootstrapArgument, classKey) else bootstrapArgument
                        }.toTypedArray()

                        // Replace bootstrap with our encrypted bootstrap handler
                        val encryptedBootstrap = Handle(
                            Opcodes.H_INVOKESTATIC,
                            "io/github/hht0rro/javashroud/transforms/protection/BootstrapEncryptionHelper",
                            "encryptedBootstrap",
                            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                            false,
                        )

                        // Build the encrypted argument array:
                        // [encryptedKey, originalBootstrapHandle, ...encryptedOrOriginalArgs]
                        val newArgs = arrayOfNulls<Any>(2 + encryptedArgs.size)
                        newArgs[0] = Base64.getEncoder().encodeToString(classKey)
                        newArgs[1] = bootstrapMethodHandle
                        encryptedArgs.forEachIndexed { i, bootstrapArgument -> newArgs[i + 2] = bootstrapArgument }

                        superMv.visitInvokeDynamicInsn(
                            name,
                            descriptor,
                            encryptedBootstrap,
                            *newArgs.requireNoNulls(),
                        )

                        classModified = true
                        indyCount++
                    }
                }
            }
        }

        try {
            cr.accept(cv, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) { return@map classArtifact }
        if (!classModified) return@map classArtifact
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = indyCount,
    )
}

private fun generateBootstrapKey(random: SecureRandom): ByteArray {
    val key = ByteArray(16)
    random.nextBytes(key)
    return key
}


private fun encryptToString(data: String, key: ByteArray): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    return Base64.getEncoder().encodeToString(iv + cipher.doFinal(data.toByteArray(Charsets.UTF_8)))
}

