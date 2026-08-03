package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.insertAntiDecompilerStructures
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import java.lang.reflect.InvocationTargetException
import org.objectweb.asm.ClassWriter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertFailsWith

class ClassWriterSupportRegressionTest {
    @Test
    fun common_super_class_preserves_throwable_parent() {
        val writer = computeFramesWriter()
        val resolver = ClassWriter::class.java.getDeclaredMethod(
            "getCommonSuperClass",
            String::class.java,
            String::class.java,
        ).apply { isAccessible = true }

        val common = resolver.invoke(
            writer,
            "java/lang/IllegalArgumentException",
            "java/lang/IllegalStateException",
        ) as String

        assertEquals("java/lang/RuntimeException", common)
    }

    @Test
    fun anti_decompiler_preserves_throwable_frames_in_embedded_jni_helper() {
        val resourceName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class"
        val original = requireNotNull(javaClass.classLoader.getResourceAsStream(resourceName)).use { it.readBytes() }
        val transformed = insertAntiDecompilerStructures(original)

        val loaded = VerifyingClassLoader(javaClass.classLoader).defineAndResolve(transformed)

        assertEquals("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper", loaded.name)
        assertNotNull(loaded.getDeclaredMethod("createSamLambda", String::class.java, String::class.java, String::class.java,
            String::class.java, String::class.java, Int::class.javaPrimitiveType, String::class.java, String::class.java,
            String::class.java, Array<Any>::class.java))
    }

    @Test
    fun anti_decompiler_preserves_shared_multicatch_athrow_frames() {
        val resourceName = "io/github/hht0rro/javashroud/MultiCatchAthrowFixture.class"
        val original = requireNotNull(javaClass.classLoader.getResourceAsStream(resourceName)).use { it.readBytes() }
        val transformed = insertAntiDecompilerStructures(original)

        val loaded = VerifyingClassLoader(javaClass.classLoader).defineAndResolve(transformed)
        val run = loaded.getDeclaredMethod("run", Int::class.javaPrimitiveType)
        val thrown = assertFailsWith<InvocationTargetException> { run.invoke(null, 0) }.targetException

        assertIs<IllegalArgumentException>(thrown)
    }

    private class VerifyingClassLoader(parent: ClassLoader) : ClassLoader(parent) {
        fun defineAndResolve(bytes: ByteArray): Class<*> {
            val defined = defineClass(null, bytes, 0, bytes.size)
            resolveClass(defined)
            return defined
        }
    }
}
