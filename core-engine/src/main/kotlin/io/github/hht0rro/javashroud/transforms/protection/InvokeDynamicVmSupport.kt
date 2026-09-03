package io.github.hht0rro.javashroud.transforms.protection

import org.objectweb.asm.Handle

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
): NormalizedInvokeDynamic = NormalizedInvokeDynamic(
    name = name,
    descriptor = descriptor,
    bootstrapMethodHandle = bootstrapMethodHandle,
    bootstrapMethodArguments = bootstrapMethodArguments.toList().toTypedArray(),
)

internal fun isNativeVmSupportedInvokeDynamicCall(
    name: String,
    descriptor: String,
    bootstrapMethodHandle: Handle,
    bootstrapMethodArguments: Array<out Any>,
): Boolean {
    val normalized = normalizeNativeVmInvokeDynamic(
        name,
        descriptor,
        bootstrapMethodHandle,
        bootstrapMethodArguments,
    )
    if (normalized.bootstrapMethodHandle.owner == "java/lang/invoke/LambdaMetafactory") return false
    if (normalized.bootstrapMethodHandle.owner == "java/lang/invoke/StringConcatFactory") return true
    return methodHandleBackedStaticTarget(normalized) != null
}

internal fun methodHandleBackedStaticTarget(indy: NormalizedInvokeDynamic): Handle? {
    val target = indy.bootstrapMethodArguments.firstOrNull { it is Handle } as? Handle ?: return null
    if (target.tag != org.objectweb.asm.Opcodes.H_INVOKESTATIC) return null
    return target.takeIf { it.desc == indy.descriptor }
}
