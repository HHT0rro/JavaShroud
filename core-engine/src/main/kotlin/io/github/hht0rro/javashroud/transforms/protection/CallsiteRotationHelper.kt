package io.github.hht0rro.javashroud.transforms.protection

import java.lang.invoke.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Runtime helper for callsite rotation protection.
 *
 * Creates MutableCallSite instances that rotate their binding target
 * based on epoch, thread, counter, or random signals.
 */
object CallsiteRotationHelper {

    private val epoch = AtomicLong(0)
    private val callSites = ConcurrentHashMap<String, MutableCallSite>()

    @JvmStatic
    fun createRotatingCallSite(
        lookup: MethodHandles.Lookup,
        name: String,
        type: MethodType,
        owner: String,
        strategy: String,
    ): CallSite {
        val ownerClass = Class.forName(owner.replace('/', '.'))
        val targetType = type.dropParameterTypes(0, 1)
        val target = lookup.findVirtual(ownerClass, name, targetType)

        val ms = MutableCallSite(type)

        // Create a method handle that dispatches through the MutableCallSite
        ms.target = target

        val key = "$owner::$name"
        callSites[key] = ms
        return ms
    }
}
