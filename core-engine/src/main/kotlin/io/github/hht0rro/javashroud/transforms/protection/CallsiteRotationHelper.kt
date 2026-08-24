package io.github.hht0rro.javashroud.transforms.protection

import java.lang.invoke.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * Runtime helper for callsite rotation protection.
 *
 * Creates MutableCallSite instances that rotate their binding target
 * based on epoch, thread, counter, or random signals.
 */
object CallsiteRotationHelper {

    private val epoch = AtomicLong(0)
    private val callSites = ConcurrentHashMap<String, RotatingSite>()
    private val threadSlot = ThreadLocal.withInitial { 0 }

    @JvmStatic
    fun createRotatingCallSite(
        lookup: MethodHandles.Lookup,
        name: String,
        type: MethodType,
        owner: String,
        strategy: String,
    ): CallSite {
        val target = resolveTarget(lookup, name, type, owner)
        val site = RotatingSite(MutableCallSite(type), strategy, equivalentTargets(target, type))
        val key = "$owner::$name${type.toMethodDescriptorString()}#${System.identityHashCode(site)}"
        callSites[key] = site
        site.installInitialTarget()
        return site.callSite
    }

    @JvmStatic
    fun dispatch(site: RotatingSite, args: Array<Any?>): Any? {
        val target = site.nextTarget()
        return try {
            target.invokeWithArguments(*args)
        } finally {
            if (site.rotationDue()) {
                site.rotateMutableTarget()
            }
        }
    }

    private fun resolveTarget(
        lookup: MethodHandles.Lookup,
        name: String,
        type: MethodType,
        ownerOrToken: String,
    ): MethodHandle {
        if (ownerOrToken.length >= 24) {
            try {
                return IndyTargetBootstrap.resolveHandle(lookup, ownerOrToken).asType(type)
            } catch (ex: SecurityException) {
                throw ex
            } catch (_: Exception) {
                throw SecurityException("callsite target token authentication failed")
            }
        }
        throw SecurityException("callsite target token is required")
    }

    private fun equivalentTargets(target: MethodHandle, type: MethodType): Array<MethodHandle> {
        val adapted = target.asType(type)
        val identityPermutation = IntArray(type.parameterCount()) { it }
        val permuted = MethodHandles.permuteArguments(adapted, type, *identityPermutation)
        val cast = MethodHandles.explicitCastArguments(adapted, type)
        return arrayOf(adapted, permuted, cast)
    }

    class RotatingSite(
        val callSite: MutableCallSite,
        private val strategy: String,
        private val targets: Array<MethodHandle>,
    ) {
        private val counter = AtomicLong(0)
        @Volatile private var slot = 0

        fun installInitialTarget() {
            callSite.target = dispatcher().asCollector(Array<Any?>::class.java, callSite.type().parameterCount()).asType(callSite.type())
        }

        fun nextTarget(): MethodHandle {
            val nextSlot = when (strategy) {
                "epoch" -> ((System.nanoTime() / 50_000_000L) % targets.size).toInt()
                "counter" -> ((counter.incrementAndGet() / 32L) % targets.size).toInt()
                "thread-local" -> {
                    val value = (threadSlot.get() + 1) % targets.size
                    threadSlot.set(value)
                    value
                }
                "random" -> ThreadLocalRandom.current().nextInt(targets.size)
                else -> 0
            }
            slot = nextSlot
            return targets[nextSlot]
        }

        fun rotationDue(): Boolean = when (strategy) {
            "epoch" -> epoch.incrementAndGet() and 15L == 0L
            "counter" -> counter.get() and 31L == 0L
            "thread-local", "random" -> true
            else -> false
        }

        fun rotateMutableTarget() {
            callSite.target = dispatcher().asCollector(Array<Any?>::class.java, callSite.type().parameterCount()).asType(callSite.type())
            MutableCallSite.syncAll(arrayOf(callSite))
        }

        private fun dispatcher(): MethodHandle = DISPATCH.bindTo(this)
    }

    private val DISPATCH: MethodHandle = MethodHandles.lookup().findStatic(
        CallsiteRotationHelper::class.java,
        "dispatch",
        MethodType.methodType(Any::class.java, RotatingSite::class.java, Array<Any?>::class.java),
    )
}
