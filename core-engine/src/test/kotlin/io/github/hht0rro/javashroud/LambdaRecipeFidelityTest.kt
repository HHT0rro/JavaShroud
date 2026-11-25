package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.isNativeVmSupportedInvokeDynamicCall
import io.github.hht0rro.javashroud.transforms.protection.normalizeNativeVmInvokeDynamic
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LambdaRecipeFidelityTest {
    @Test
    fun generic_target_entrypoints_are_absent_from_the_runtime_helper() {
        val methods = QpBridge::class.java.declaredMethods.map { it.name }.toSet()
        assertFalse("createRunnableLambda" in methods)
        assertFalse("createSamLambda" in methods)
        assertFalse("resolveVmMethodHandle" in methods)
    }

    @Test
    fun lambda_metafactory_recipe_is_selected_only_with_a_replayable_handle() {
        val factoryDescriptor = "()Ljava/util/function/Supplier;"
        val bootstrap = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/LambdaMetafactory",
            "metafactory",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
                "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)" +
                "Ljava/lang/invoke/CallSite;",
            false,
        )
        val arguments = arrayOf<Any>(
            Type.getMethodType("()Ljava/lang/Object;"),
            Handle(Opcodes.H_INVOKESTATIC, "example/Target", "value", "()Ljava/lang/String;", false),
            Type.getMethodType("()Ljava/lang/String;"),
        )
        assertTrue(
            isNativeVmSupportedInvokeDynamicCall("get", factoryDescriptor, bootstrap, arguments),
            "Current lambda replay requires the explicit implementation handle",
        )
        val virtualTarget = arguments.copyOf().also {
            it[1] = Handle(Opcodes.H_INVOKEVIRTUAL, "example/Target", "value", "()Ljava/lang/String;", false)
        }
        assertFalse(isNativeVmSupportedInvokeDynamicCall("get", factoryDescriptor, bootstrap, virtualTarget))
        assertFalse(isNativeVmSupportedInvokeDynamicCall("get", factoryDescriptor, bootstrap, emptyArray()))
    }
}
