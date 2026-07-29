package io.github.hht0rro.javashroud.transforms.protection

import org.objectweb.asm.Handle
import org.objectweb.asm.Type
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal data class NormalizedInvokeDynamic(
    val name: String,
    val descriptor: String,
    val bootstrapMethodHandle: Handle,
    val bootstrapMethodArguments: Array<Any>,
)

internal data class SamLambdaMetafactoryRecipe(
    val impl: Handle,
    val samType: Type,
    val instantiatedType: Type,
    val flags: Int,
    val markerInterfaces: List<Type>,
    val bridgeTypes: List<Type>,
)

private const val LAMBDA_FLAG_SERIALIZABLE = 1
private const val LAMBDA_FLAG_MARKERS = 2
private const val LAMBDA_FLAG_BRIDGES = 4
private const val LAMBDA_SUPPORTED_FLAGS = LAMBDA_FLAG_SERIALIZABLE or LAMBDA_FLAG_MARKERS or LAMBDA_FLAG_BRIDGES

internal fun normalizeNativeVmInvokeDynamic(
    name: String,
    descriptor: String,
    bootstrapMethodHandle: Handle,
    bootstrapMethodArguments: Array<out Any>,
): NormalizedInvokeDynamic = if (isEncryptedBootstrapWrapper(bootstrapMethodHandle)) {
    decodeEncryptedBootstrapWrapper(name, descriptor, bootstrapMethodArguments)
} else {
    NormalizedInvokeDynamic(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments.toList().toTypedArray())
}

internal fun isNativeVmSupportedInvokeDynamicCall(
    name: String,
    descriptor: String,
    bootstrapMethodHandle: Handle,
    bootstrapMethodArguments: Array<out Any>,
): Boolean {
    val normalized = try {
        normalizeNativeVmInvokeDynamic(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments)
    } catch (_: RuntimeException) {
        return false
    }
    if (normalized.bootstrapMethodHandle.owner == "java/lang/invoke/StringConcatFactory") return true
    if (methodHandleBackedStaticTarget(normalized) != null) return true
    return isSupportedSamLambdaMetafactory(normalized)
}

internal fun methodHandleBackedStaticTarget(indy: NormalizedInvokeDynamic): Handle? {
    val target = indy.bootstrapMethodArguments.firstOrNull { it is Handle } as? Handle ?: return null
    if (target.tag != org.objectweb.asm.Opcodes.H_INVOKESTATIC) return null
    return target.takeIf { it.desc == indy.descriptor }
}

private fun isEncryptedBootstrapWrapper(bootstrapMethodHandle: Handle): Boolean =
    bootstrapMethodHandle.owner == "io/github/hht0rro/javashroud/transforms/protection/BootstrapEncryptionHelper" &&
        bootstrapMethodHandle.name == "encryptedBootstrap" &&
        bootstrapMethodHandle.desc == "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"

private fun decodeEncryptedBootstrapWrapper(
    name: String,
    descriptor: String,
    bootstrapMethodArguments: Array<out Any>,
): NormalizedInvokeDynamic {
    require(bootstrapMethodArguments.size >= 2) { "encrypted bootstrap missing original bootstrap arguments" }
    val keyBase64 = bootstrapMethodArguments[0] as? String
        ?: throw IllegalArgumentException("encrypted bootstrap key argument is not a string")
    val originalBootstrap = bootstrapMethodArguments[1] as? Handle
        ?: throw IllegalArgumentException("encrypted bootstrap original handle argument is not a MethodHandle")
    val decodedArguments = bootstrapMethodArguments.drop(2).map { argument ->
        if (argument is String) decryptBootstrapString(argument, keyBase64) else argument
    }.toTypedArray()
    return NormalizedInvokeDynamic(name, descriptor, originalBootstrap, decodedArguments)
}

private fun decryptBootstrapString(encryptedBase64: String, keyBase64: String): String {
    val encrypted = Base64.getDecoder().decode(encryptedBase64)
    val key = Base64.getDecoder().decode(keyBase64)
    require(encrypted.size >= 16 && (encrypted.size - 16) % 16 == 0) { "invalid encrypted bootstrap payload" }
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(key, "AES"),
        IvParameterSpec(encrypted.copyOfRange(0, 16)),
    )
    return cipher.doFinal(encrypted.copyOfRange(16, encrypted.size)).toString(Charsets.UTF_8)
}

internal fun extractSamLambdaMetafactoryRecipe(indy: NormalizedInvokeDynamic): SamLambdaMetafactoryRecipe? {
    if (indy.bootstrapMethodHandle.owner != "java/lang/invoke/LambdaMetafactory") return null
    if (indy.bootstrapMethodArguments.size < 3) return null
    val samType = indy.bootstrapMethodArguments[0] as? Type ?: return null
    val impl = indy.bootstrapMethodArguments[1] as? Handle ?: return null
    val instantiatedType = indy.bootstrapMethodArguments[2] as? Type ?: return null
    if (indy.bootstrapMethodHandle.name == "metafactory") {
        if (indy.bootstrapMethodArguments.size != 3) return null
        return SamLambdaMetafactoryRecipe(impl, samType, instantiatedType, 0, emptyList(), emptyList())
    }
    if (indy.bootstrapMethodHandle.name != "altMetafactory" || indy.bootstrapMethodArguments.size < 4) return null
    val flags = indy.bootstrapMethodArguments[3] as? Int ?: return null
    if (flags and LAMBDA_SUPPORTED_FLAGS.inv() != 0) return null
    var cursor = 4
    val markers = mutableListOf<Type>()
    if (flags and LAMBDA_FLAG_MARKERS != 0) {
        val markerCount = indy.bootstrapMethodArguments.getOrNull(cursor++) as? Int ?: return null
        if (markerCount < 0 || markerCount > 64 || cursor + markerCount > indy.bootstrapMethodArguments.size) return null
        repeat(markerCount) {
            val marker = indy.bootstrapMethodArguments[cursor++] as? Type ?: return null
            if (marker.sort != Type.OBJECT) return null
            markers += marker
        }
    }
    val bridges = mutableListOf<Type>()
    if (flags and LAMBDA_FLAG_BRIDGES != 0) {
        val bridgeCount = indy.bootstrapMethodArguments.getOrNull(cursor++) as? Int ?: return null
        if (bridgeCount < 0 || bridgeCount > 64 || cursor + bridgeCount > indy.bootstrapMethodArguments.size) return null
        repeat(bridgeCount) {
            val bridge = indy.bootstrapMethodArguments[cursor++] as? Type ?: return null
            if (bridge.sort != Type.METHOD) return null
            bridges += bridge
        }
    }
    if (cursor != indy.bootstrapMethodArguments.size) return null
    return SamLambdaMetafactoryRecipe(impl, samType, instantiatedType, flags, markers, bridges)
}

internal fun encodeSamLambdaMetafactoryConstant(
    name: String,
    descriptor: String,
    recipe: SamLambdaMetafactoryRecipe,
): String = listOf(
    "lambda",
    name,
    descriptor,
    recipe.impl.tag.toString(),
    recipe.impl.owner,
    recipe.impl.name,
    recipe.impl.desc,
    recipe.samType.descriptor,
    recipe.instantiatedType.descriptor,
    encodeSamLambdaOptions(recipe),
).joinToString("|")

private fun encodeSamLambdaOptions(recipe: SamLambdaMetafactoryRecipe): String {
    fun encodeDescriptor(type: Type): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(type.descriptor.toByteArray(Charsets.US_ASCII))
    return listOf(
        recipe.flags.toString(16),
        recipe.markerInterfaces.joinToString(",") { encodeDescriptor(it) },
        recipe.bridgeTypes.joinToString(",") { encodeDescriptor(it) },
    ).joinToString(";")
}

private fun isSupportedSamLambdaMetafactory(indy: NormalizedInvokeDynamic): Boolean {
    val recipe = extractSamLambdaMetafactoryRecipe(indy) ?: return false
    val samType = recipe.samType
    val instantiatedType = recipe.instantiatedType
    val returnType = Type.getReturnType(indy.descriptor)
    if (returnType.sort != Type.OBJECT) return false
    if (indy.name.isBlank() || samType.sort != Type.METHOD || instantiatedType.sort != Type.METHOD) return false
    if (Type.getArgumentTypes(samType.descriptor).size != Type.getArgumentTypes(instantiatedType.descriptor).size) return false
    if (recipe.bridgeTypes.any { Type.getArgumentTypes(it.descriptor).size != Type.getArgumentTypes(samType.descriptor).size }) return false
    return recipe.impl.tag in setOf(
        org.objectweb.asm.Opcodes.H_INVOKEVIRTUAL,
        org.objectweb.asm.Opcodes.H_INVOKESTATIC,
        org.objectweb.asm.Opcodes.H_INVOKESPECIAL,
        org.objectweb.asm.Opcodes.H_NEWINVOKESPECIAL,
        org.objectweb.asm.Opcodes.H_INVOKEINTERFACE,
    )
}
