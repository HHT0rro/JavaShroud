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

private fun isSupportedSamLambdaMetafactory(indy: NormalizedInvokeDynamic): Boolean {
    if (indy.bootstrapMethodHandle.owner != "java/lang/invoke/LambdaMetafactory" || indy.bootstrapMethodHandle.name != "metafactory") return false
    val returnType = Type.getReturnType(indy.descriptor)
    if (indy.bootstrapMethodArguments.size < 3 || indy.bootstrapMethodArguments[1] !is Handle) return false
    val samType = indy.bootstrapMethodArguments[0] as? Type ?: return false
    val instantiatedType = indy.bootstrapMethodArguments[2] as? Type ?: return false
    if (returnType.sort != Type.OBJECT) return false
    return when (returnType.internalName) {
        "java/lang/Runnable" -> indy.name == "run" && samType.descriptor == "()V" && instantiatedType.descriptor == "()V"
        "java/util/function/IntUnaryOperator" -> indy.name == "applyAsInt" && samType.descriptor == "(I)I" && Type.getArgumentTypes(instantiatedType.descriptor).size == 1 && Type.getReturnType(instantiatedType.descriptor).sort == Type.INT
        "java/util/function/Function" -> indy.name == "apply" && samType.descriptor == "(Ljava/lang/Object;)Ljava/lang/Object;" && Type.getArgumentTypes(instantiatedType.descriptor).size == 1
        else -> false
    }
}
