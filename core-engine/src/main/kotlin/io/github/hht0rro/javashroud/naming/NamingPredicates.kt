package io.github.hht0rro.javashroud.naming

import org.objectweb.asm.Opcodes

fun isEnumClass(accessFlags: Int): Boolean {
    return accessFlags and Opcodes.ACC_ENUM != 0
}

fun canRenameMethod(methodName: String): Boolean {
    return methodName != "<init>" && methodName != "<clinit>" && !methodName.matches(JAVA_SYNTHETIC_ACCESSOR_REGEX)
}

private val JAVA_SYNTHETIC_ACCESSOR_REGEX = Regex("access\\$\\d+")

