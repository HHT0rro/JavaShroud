package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.Opcodes
import org.objectweb.asm.commons.Remapper

internal fun createRemapper(
    mapInternalName: ((String) -> String)? = null,
    mapResourcePath: ((String) -> String)? = null,
    mapMethodName: ((String, String, String) -> String)? = null,
    mapFieldName: ((String, String, String) -> String)? = null,
    mapStringValue: ((String) -> String)? = null,
): Remapper {
    return object : Remapper(Opcodes.ASM9) {
        override fun map(internalName: String?): String? {
            if (internalName == null || mapInternalName == null) {
                return internalName
            }
            return mapInternalName(internalName)
        }

        override fun mapValue(value: Any?): Any? {
            if (value is String && mapStringValue != null) {
                val mappedValue = mapStringValue(value)
                if (mappedValue != value) {
                    return mappedValue
                }
            }
            if (value is String && mapInternalName != null) {
                if (value.endsWith(".class")) {
                    val internalName = value.removeSuffix(".class")
                    val mappedName = mapInternalName(internalName)
                    if (mappedName != internalName) {
                        return "$mappedName.class"
                    }
                }
                if (mapResourcePath != null && value.indexOf('/') >= 0) {
                    val mappedPath = mapResourcePath(value)
                    if (mappedPath != value) {
                        return mappedPath
                    }
                }
                if (value.indexOf('.') >= 0 && value.indexOf('/') < 0) {
                    val internalName = value.replace('.', '/')
                    val mappedName = mapInternalName(internalName)
                    if (mappedName != internalName) {
                        return mappedName.replace('/', '.')
                    }
                }
            }
            return super.mapValue(value)
        }

        override fun mapMethodName(owner: String?, name: String?, descriptor: String?): String? {
            if (owner == null || name == null || descriptor == null || mapMethodName == null) {
                return name
            }
            return mapMethodName(owner, name, descriptor)
        }

        override fun mapFieldName(owner: String?, name: String?, descriptor: String?): String? {
            if (owner == null || name == null || descriptor == null || mapFieldName == null) {
                return name
            }
            return mapFieldName(owner, name, descriptor)
        }
    }
}
