package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import io.github.hht0rro.javashroud.transforms.protection.encodeSamLambdaMetafactoryConstant
import io.github.hht0rro.javashroud.transforms.protection.extractSamLambdaMetafactoryRecipe
import io.github.hht0rro.javashroud.transforms.protection.isNativeVmSupportedInvokeDynamicCall
import io.github.hht0rro.javashroud.transforms.protection.normalizeNativeVmInvokeDynamic
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.Serializable
import java.util.Base64
import java.util.function.Consumer
import java.util.function.Function
import java.util.function.IntUnaryOperator
import java.util.function.Supplier
import java.util.concurrent.Callable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LambdaRecipeFidelityTest {

    @Test
    fun generic_sam_recipe_preserves_reference_primitive_void_and_capture_shapes() {
        val owner = LambdaRecipeFidelityTest::class.java.name.replace('.', '/')

        val runnable = JniMicrokernelHelper.createSamLambda(
            "run", "(Ljava/lang/String;)Ljava/lang/Runnable;", owner, "record",
            "(Ljava/lang/String;)V", Opcodes.H_INVOKESTATIC, "()V", "()V", "0;;", arrayOf("ran"),
        ) as Runnable
        assertFalse(runnable is Serializable)
        runnable.run()
        assertEquals("ran", lastValue)

        @Suppress("UNCHECKED_CAST")
        val function = JniMicrokernelHelper.createSamLambda(
            "apply", "(Ljava/lang/String;)Ljava/util/function/Function;", owner, "decorate",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", Opcodes.H_INVOKESTATIC,
            "(Ljava/lang/Object;)Ljava/lang/Object;", "(Ljava/lang/String;)Ljava/lang/String;", "0;;", arrayOf("pre-"),
        ) as Function<String, String>
        assertEquals("pre-value", function.apply("value"))

        val consumer = JniMicrokernelHelper.createSamLambda(
            "accept", "(Ljava/lang/String;)Ljava/util/function/Consumer;", owner, "recordPair",
            "(Ljava/lang/String;Ljava/lang/String;)V", Opcodes.H_INVOKESTATIC,
            "(Ljava/lang/Object;)V", "(Ljava/lang/String;)V", "0;;", arrayOf("seen:"),
        ) as Consumer<String>
        consumer.accept("item")
        assertEquals("seen:item", lastValue)

        val intOperator = JniMicrokernelHelper.createSamLambda(
            "applyAsInt", "()Ljava/util/function/IntUnaryOperator;", owner, "doubleValue",
            "(I)I", Opcodes.H_INVOKESTATIC, "(I)I", "(I)I", "0;;", emptyArray(),
        ) as IntUnaryOperator
        assertEquals(42, intOperator.applyAsInt(21))
    }

    @Test
    fun alt_metafactory_without_serializable_flag_preserves_marker_and_bridge_only() {
        val owner = LambdaRecipeFidelityTest::class.java.name.replace('.', '/')
        val markerOwner = Marker::class.java.name.replace('.', '/')
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val bridgeDescriptor = "(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;"
        val options = listOf(
            "6",
            encoder.encodeToString("L$markerOwner;".toByteArray(Charsets.US_ASCII)),
            encoder.encodeToString(bridgeDescriptor.toByteArray(Charsets.US_ASCII)),
        ).joinToString(";")

        @Suppress("UNCHECKED_CAST")
        val function = JniMicrokernelHelper.createSamLambda(
            "apply", "(Ljava/lang/String;)Ljava/util/function/Function;", owner, "decorate",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", Opcodes.H_INVOKESTATIC,
            "(Ljava/lang/Object;)Ljava/lang/Object;", "(Ljava/lang/String;)Ljava/lang/String;",
            options, arrayOf("plain-"),
        ) as Function<String, String>

        assertTrue(function is Marker)
        assertFalse(function is Serializable)
        assertEquals("plain-value", function.apply("value"))
        val bridge = function.javaClass.getMethod("apply", CharSequence::class.java)
        assertEquals("plain-bridge", bridge.invoke(function, "bridge"))
    }

    @Test
    fun generic_sam_recipe_preserves_bound_unbound_interface_special_and_constructor_handles() {
        val owner = LambdaRecipeFidelityTest::class.java.name.replace('.', '/')

        @Suppress("UNCHECKED_CAST")
        val bound = JniMicrokernelHelper.createSamLambda(
            "apply", "(L$owner;)Ljava/util/function/Function;", owner, "suffix",
            "(Ljava/lang/String;)Ljava/lang/String;", Opcodes.H_INVOKEVIRTUAL,
            "(Ljava/lang/Object;)Ljava/lang/Object;", "(Ljava/lang/String;)Ljava/lang/String;", "0;;", arrayOf(this),
        ) as Function<String, String>
        assertEquals("value-bound", bound.apply("value"))

        @Suppress("UNCHECKED_CAST")
        val unbound = JniMicrokernelHelper.createSamLambda(
            "apply", "()Ljava/util/function/Function;", owner, "suffixValue",
            "()Ljava/lang/String;", Opcodes.H_INVOKEVIRTUAL,
            "(Ljava/lang/Object;)Ljava/lang/Object;", "(L$owner;)Ljava/lang/String;", "0;;", emptyArray(),
        ) as Function<LambdaRecipeFidelityTest, String>
        assertEquals("value-bound", unbound.apply(this))

        @Suppress("UNCHECKED_CAST")
        val interfaceCall = JniMicrokernelHelper.createSamLambda(
            "apply", "(Ljava/lang/CharSequence;I)Ljava/util/function/Function;", "java/lang/CharSequence", "subSequence",
            "(II)Ljava/lang/CharSequence;", Opcodes.H_INVOKEINTERFACE,
            "(Ljava/lang/Object;)Ljava/lang/Object;", "(Ljava/lang/Integer;)Ljava/lang/CharSequence;", "0;;", arrayOf("abcd", 1),
        ) as Function<Int, CharSequence>
        assertEquals("bc", interfaceCall.apply(3).toString())

        @Suppress("UNCHECKED_CAST")
        val special = JniMicrokernelHelper.createSamLambda(
            "apply", "(L$owner;)Ljava/util/function/Function;", owner, "specialSuffix",
            "(Ljava/lang/String;)Ljava/lang/String;", Opcodes.H_INVOKESPECIAL,
            "(Ljava/lang/Object;)Ljava/lang/Object;", "(Ljava/lang/String;)Ljava/lang/String;", "0;;", arrayOf(this),
        ) as Function<String, String>
        assertEquals("value-special", special.apply("value"))

        @Suppress("UNCHECKED_CAST")
        val constructor = JniMicrokernelHelper.createSamLambda(
            "get", "(Ljava/lang/String;)Ljava/util/function/Supplier;", "java/lang/StringBuilder", "<init>",
            "(Ljava/lang/String;)V", Opcodes.H_NEWINVOKESPECIAL,
            "()Ljava/lang/Object;", "()Ljava/lang/StringBuilder;", "0;;", arrayOf("built"),
        ) as Supplier<StringBuilder>
        assertEquals("built", constructor.get().toString())
    }

    @Test
    fun generic_sam_recipe_preserves_checked_exceptions_and_non_public_interfaces() {
        val owner = LambdaRecipeFidelityTest::class.java.name.replace('.', '/')
        @Suppress("UNCHECKED_CAST")
        val checked = JniMicrokernelHelper.createSamLambda(
            "call", "()Ljava/util/concurrent/Callable;", owner, "checkedFailure",
            "()Ljava/lang/String;", Opcodes.H_INVOKESTATIC,
            "()Ljava/lang/Object;", "()Ljava/lang/String;", "0;;", emptyArray(),
        ) as Callable<String>
        assertFailsWith<IOException> { checked.call() }

        val hiddenOwner = HiddenSupplier::class.java.name.replace('.', '/')
        val hidden = JniMicrokernelHelper.createSamLambda(
            "get", "()L$hiddenOwner;", owner, "hiddenValue",
            "()Ljava/lang/String;", Opcodes.H_INVOKESTATIC,
            "()Ljava/lang/String;", "()Ljava/lang/String;", "0;;", emptyArray(),
        ) as HiddenSupplier
        assertEquals("hidden", hidden.get())
    }

    @Test
    fun alt_metafactory_recipe_preserves_serializable_marker_and_callable_bridges() {
        val owner = LambdaRecipeFidelityTest::class.java.name.replace('.', '/')
        val markerOwner = Marker::class.java.name.replace('.', '/')
        val samType = Type.getMethodType("(Ljava/lang/Object;)Ljava/lang/Object;")
        val instantiatedType = Type.getMethodType("(Ljava/lang/String;)Ljava/lang/String;")
        val bridgeType = Type.getMethodType("(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;")
        val impl = Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "decorate",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            false,
        )
        val altMetafactory = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/LambdaMetafactory",
            "altMetafactory",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false,
        )
        val factoryDescriptor = "(Ljava/lang/String;)Ljava/util/function/Function;"
        val arguments = arrayOf<Any>(
            samType,
            impl,
            instantiatedType,
            7,
            1,
            Type.getObjectType(markerOwner),
            1,
            bridgeType,
        )
        assertTrue(isNativeVmSupportedInvokeDynamicCall("apply", factoryDescriptor, altMetafactory, arguments))
        val recipe = extractSamLambdaMetafactoryRecipe(
            normalizeNativeVmInvokeDynamic("apply", factoryDescriptor, altMetafactory, arguments)
        ) ?: error("missing altMetafactory recipe")
        val encoded = encodeSamLambdaMetafactoryConstant("apply", factoryDescriptor, recipe)
        val encodedParts = encoded.split('|')
        assertEquals(10, encodedParts.size)
        assertEquals(7, recipe.flags)
        assertEquals(listOf(Type.getObjectType(markerOwner)), recipe.markerInterfaces)
        assertEquals(listOf(bridgeType), recipe.bridgeTypes)

        val markerDescriptor = "L$markerOwner;"
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val options = listOf(
            "7",
            encoder.encodeToString(markerDescriptor.toByteArray(Charsets.US_ASCII)),
            encoder.encodeToString(bridgeType.descriptor.toByteArray(Charsets.US_ASCII)),
        ).joinToString(";")
        assertEquals(options, encodedParts[9])
        @Suppress("UNCHECKED_CAST")
        val function = JniMicrokernelHelper.createSamLambda(
            "apply", factoryDescriptor, owner, "decorate",
            impl.desc, Opcodes.H_INVOKESTATIC, samType.descriptor, instantiatedType.descriptor,
            options, arrayOf("alt-"),
        ) as Function<String, String>
        assertTrue(function is Marker)
        assertTrue(function is Serializable)
        assertEquals("alt-value", function.apply("value"))
        val bridge = function.javaClass.getMethod("apply", CharSequence::class.java)
        assertEquals("alt-bridge", bridge.invoke(function, "bridge"))

        val serialized = ByteArrayOutputStream().use { bytes ->
            ObjectOutputStream(bytes).use { it.writeObject(function) }
            bytes.toByteArray()
        }
        @Suppress("UNCHECKED_CAST")
        val restored = ObjectInputStream(ByteArrayInputStream(serialized)).use { it.readObject() } as Function<String, String>
        assertEquals("alt-restored", restored.apply("restored"))
        val restoredBridge = restored.javaClass.getMethod("apply", CharSequence::class.java)
        assertEquals("alt-restored-bridge", restoredBridge.invoke(restored, "restored-bridge"))
    }

    fun suffix(value: String): String = "$value-bound"

    fun suffixValue(): String = "value-bound"

    private fun specialSuffix(value: String): String = "$value-special"

    private fun interface HiddenSupplier {
        fun get(): String
    }

    interface Marker

    companion object {
        @Volatile private var lastValue: String = ""

        @JvmStatic fun record(value: String) { lastValue = value }
        @JvmStatic fun recordPair(prefix: String, value: String) { lastValue = prefix + value }
        @JvmStatic fun decorate(prefix: String, value: String): String = prefix + value
        @JvmStatic fun doubleValue(value: Int): Int = value * 2
        @JvmStatic fun checkedFailure(): String = throw IOException("checked")
        @JvmStatic fun hiddenValue(): String = "hidden"
    }
}
