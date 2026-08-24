package io.github.hht0rro.javashroud.bytecode

fun stripCompileDebug(classBytes: ByteArray): ByteArray {
    return ClassfileAttributeWhitelist.apply(classBytes)
}
