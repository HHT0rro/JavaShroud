package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.isNativeVmSupportedInvokeDynamicCall
import io.github.hht0rro.javashroud.transforms.protection.normalizeNativeVmInvokeDynamic
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import kotlin.test.Test
import kotlin.test.assertFalse

class LambdaRecipeFidelityTest {
    @Test
    fun generic_target_entrypoints_are_absent_from_the_runtime_helper() {
        val methods = QpBridge::class.java.declaredMethods.map { it.name }.toSet()
        assertFalse("createRunnableLambda" in methods)
        assertFalse("createSamLambda" in methods)
        assertFalse("resolveVmMethodHandle" in methods)
    }

    @Test
    fun lambda_metafactory_recipe_is_not_selected_for_native_vm() {
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
        assertFalse(
            isNativeVmSupportedInvokeDynamicCall("get", factoryDescriptor, bootstrap, arguments),
            "LambdaMetafactory recipes stay on the JVM boundary until an opaque native route exists",
        )
    }
}
