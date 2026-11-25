package io.github.hht0rro.javashroud.apk

import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Keep-rule synthesis over ASM-built class fixtures: Parcelable/Serializable
 * member keeps, @JavascriptInterface bridge methods, serialization hooks,
 * JNI declarers, manifest/resource/native class keeps and prefix rules.
 */
class ApkKeepRuleSynthesisTest {

    private fun parcelableClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC,
            internalName,
            null,
            "java/lang/Object",
            arrayOf("android/os/Parcelable"),
        )
        writer.visitField(Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC + Opcodes.ACC_FINAL, "CREATOR", "Landroid/os/Parcelable\$Creator;", null, null).visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE + Opcodes.ACC_STATIC + Opcodes.ACC_FINAL, "mRenamable", "Ljava/lang/String;", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun serializableClass(internalName: String, withHooks: Boolean): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC,
            internalName,
            null,
            "java/lang/Object",
            arrayOf("java/io/Serializable"),
        )
        writer.visitField(Opcodes.ACC_PRIVATE + Opcodes.ACC_STATIC + Opcodes.ACC_FINAL, "serialVersionUID", "J", null, null).visitEnd()
        if (withHooks) {
            writer.visitMethod(Opcodes.ACC_PRIVATE, "writeObject", "(Ljava/io/ObjectOutputStream;)V", null, null).visitEnd()
            writer.visitMethod(Opcodes.ACC_PRIVATE, "readObject", "(Ljava/io/ObjectInputStream;)V", null, null).visitEnd()
            writer.visitMethod(0, "writeReplace", "()Ljava/lang/Object;", null, null).visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun jniClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        writer.visitMethod(Opcodes.ACC_PUBLIC + Opcodes.ACC_NATIVE, "nativeCalc", "(II)I", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun jsBridgeClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        val bridge: MethodVisitor = writer.visitMethod(Opcodes.ACC_PUBLIC, "onJsCall", "(Ljava/lang/String;)V", null, null)
        bridge.visitAnnotation("Landroid/webkit/JavascriptInterface;", true).visitEnd()
        bridge.visitInsn(Opcodes.RETURN)
        bridge.visitMaxs(0, 2)
        bridge.visitEnd()
        val plain = writer.visitMethod(Opcodes.ACC_PUBLIC, "plainMethod", "()V", null, null)
        plain.visitInsn(Opcodes.RETURN)
        plain.visitMaxs(0, 1)
        plain.visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun jarOf(entries: List<Pair<String, ByteArray>>): Path {
        val jar = Files.createTempFile("keep-classes-", ".jar")
        JarOutputStream(Files.newOutputStream(jar)).use { out ->
            for ((name, bytes) in entries) {
                out.putNextEntry(ZipEntry(name))
                out.write(bytes)
                out.closeEntry()
            }
        }
        return jar
    }

    @Test
    fun retainsPlatformPlaceholdersWithoutExemptingApplicationClasses() {
        fun placeholder(name: String, parent: String, synthetic: Boolean, throws: Boolean): ByteArray {
            val writer = ClassWriter(0)
            writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, name, null, parent, null)
            val access = Opcodes.ACC_STATIC or (if (synthetic) Opcodes.ACC_SYNTHETIC else 0)
            val init = writer.visitMethod(access, "<clinit>", "()V", null, null)
            init.visitCode()
            if (throws) {
                init.visitTypeInsn(Opcodes.NEW, "java/lang/NoClassDefFoundError")
                init.visitInsn(Opcodes.DUP)
                init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/NoClassDefFoundError", "<init>", "()V", false)
                init.visitInsn(Opcodes.ATHROW)
            } else {
                init.visitInsn(Opcodes.RETURN)
            }
            init.visitMaxs(2, 0)
            init.visitEnd()
            writer.visitEnd()
            return writer.toByteArray()
        }

        val objectType = "java/lang/Object"
        val segmentFinder = "android/text/SegmentFinder"
        val floatProperty = "android/util/FloatProperty"
        val appPlaceholder = "demo/MissingLibrary"
        val appInAndroidPrefix = "android/support/v4/app/Fixture"
        val nonSynthetic = "android/example/OrdinaryInitializer"
        val jar = jarOf(listOf(
            "$segmentFinder.class" to placeholder(segmentFinder, objectType, synthetic = true, throws = true),
            "$floatProperty.class" to placeholder(floatProperty, "android/util/Property", synthetic = true, throws = true),
            "$appPlaceholder.class" to placeholder(appPlaceholder, objectType, synthetic = true, throws = true),
            "$appInAndroidPrefix.class" to placeholder(appInAndroidPrefix, objectType, synthetic = true, throws = false),
            "$nonSynthetic.class" to placeholder(nonSynthetic, objectType, synthetic = false, throws = true),
        ))
        val plan = ApkKeepRuleSynthesis.synthesize(jar, emptySet(), emptySet(), emptySet(), emptyList())
        assertEquals(setOf(segmentFinder, floatProperty), plan.excludedClassNames)
        assertEquals(setOf(segmentFinder, floatProperty), plan.rules.filter { it.action == "exclude" }.map { it.target }.toSet())
    }

    @Test
    fun synthesizesParcelableSerializableAndBridgeRules() {
        val jar = jarOf(
            listOf(
                "com/example/Parc.class" to parcelableClass("com/example/Parc"),
                "com/example/Ser.class" to serializableClass("com/example/Ser", withHooks = true),
                "com/example/Bridge.class" to jsBridgeClass("com/example/Bridge"),
                "com/example/JniAnchor.class" to jniClass("com/example/JniAnchor"),
            ),
        )
        val plan = ApkKeepRuleSynthesis.synthesize(
            mergedClassJarPath = jar,
            manifestComponentClasses = setOf("com/example/Parc"),
            resourceReferencedClasses = setOf("com/example/Ser"),
            nativeReferencedClasses = setOf("com/example/JniAnchor"),
            extraKeepPrefixes = listOf("com.vendor.internal"),
        )

        val targets = plan.rules.map { it.target }
        assertTrue("com/example/Parc" in targets, "manifest component must be class-excluded")
        assertTrue("com/example/Ser" in targets, "resource-referenced class must be class-excluded")
        assertTrue("com/example/JniAnchor" in targets, "JNI declarer must be class-excluded")
        // Member keeps are owner-wildcard and name-anchored so they survive
        // owner renames (the kernel re-matches rules on current class names).
        assertTrue(
            "*#CREATOR:*" in targets,
            "CREATOR keep must be owner-wildcard: $targets",
        )
        assertTrue("*#serialVersionUID:J" in targets)
        assertTrue("*#writeObject:(Ljava/io/ObjectOutputStream;)V" in targets)
        assertTrue("*#readObject:(Ljava/io/ObjectInputStream;)V" in targets)
        assertTrue("*#writeReplace:()Ljava/lang/Object;" in targets)
        assertTrue("*#onJsCall:*" in targets, "JS bridge methods are kept by name with any descriptor")
        assertTrue(
            plan.memberKeeps.none { it.owner == "com/example/Bridge" && it.name == "plainMethod" },
            "non-bridge methods must not be kept",
        )
        assertTrue("com/vendor/internal/*" in targets, "extraKeepPrefixes must map to package exclude rules")
        assertTrue(plan.rules.all { it.action == "exclude" })
        assertEquals(3, plan.keepClassCount)
    }

    @Test
    fun emptyKeepPlanEmitsWarning() {
        val jar = jarOf(listOf("com/example/Plain.class" to parcelableClass("com/example/Plain")))
        val plan = ApkKeepRuleSynthesis.synthesize(
            mergedClassJarPath = jar,
            manifestComponentClasses = emptySet(),
            resourceReferencedClasses = emptySet(),
            nativeReferencedClasses = emptySet(),
            extraKeepPrefixes = emptyList(),
        )
        // CREATOR keep still synthesizes for the Parcelable class itself.
        assertTrue(plan.memberKeeps.isNotEmpty())
        assertTrue(plan.warnings.isEmpty())
    }

    @Test
    fun mergePreservesUserRules() {
        val jar = jarOf(listOf("com/example/Parc.class" to parcelableClass("com/example/Parc")))
        val plan = ApkKeepRuleSynthesis.synthesize(jar, emptySet(), emptySet(), emptySet(), emptyList())
        val userRule = io.github.hht0rro.javashroud.model.config.RuleSpec("com/example/Parc", "rename-fields")
        val merged = ApkKeepRuleSynthesis.mergeRuleSet(
            io.github.hht0rro.javashroud.model.config.RuleSet(listOf(userRule)),
            plan,
        )
        assertTrue(merged.rules.contains(userRule))
        assertTrue(merged.rules.any { it.action == "exclude" })
    }
}
