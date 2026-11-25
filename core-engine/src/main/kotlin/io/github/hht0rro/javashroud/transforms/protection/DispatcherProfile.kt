package io.github.hht0rro.javashroud.transforms.protection

import kotlin.math.absoluteValue

enum class DispatcherProfile {
    SWITCH,
    DIRECT_THREADED,
    INDIRECT_THREADED,
    CALL_THREADED,
    IF_NEST,
    INTERPOLATION;
    
    companion object {
        fun selectFromAuth(
            entryToken: ByteArray,
            resourcePath: String,
            manifestMesh: ByteArray
        ): DispatcherProfile {
            val hash = (entryToken + resourcePath.toByteArray() + manifestMesh)
                .fold(0L) { acc, b -> acc * 31 + b.toLong() }
            return values()[(hash % values().size).toInt().absoluteValue]
        }
        
        fun encode(profile: DispatcherProfile): Byte = profile.ordinal.toByte()
        
        fun decode(value: Byte): DispatcherProfile = values()[value.toInt()]
    }
}
