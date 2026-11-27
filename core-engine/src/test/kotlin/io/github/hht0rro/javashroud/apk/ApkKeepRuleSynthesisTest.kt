package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.bytecode.remapClasses
import io.github.hht0rro.javashroud.bytecode.remapMethods
import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.naming.MemberRename
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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

    @Test
    fun externalMemberDescriptorsRetainLoadedTypesAndTheirParentInterfaces() {
        fun interfaceBytes(name: String, vararg parents: String): ByteArray = ClassWriter(0).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
                name, null, "java/lang/Object", parents)
            visitEnd()
        }.toByteArray()

        val parser = "android/content/res/XmlResourceParser"
        val pullParser = "org/xmlpull/v1/XmlPullParser"
        val attributes = "android/util/AttributeSet"
        val fieldType = "fixture/FieldType"
        val resources = "android/content/res/Resources"
        val caller = "fixture/Caller"
        val unrelated = "android/sun/Unrelated"
        val descriptor = "(I)L$parser;"
        val external = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, resources, null, "java/lang/Object", null)
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "parsers", "[[L$fieldType;", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC, "getXml", descriptor, null, null).apply {
                visitCode()
                visitInsn(Opcodes.ACONST_NULL)
                visitInsn(Opcodes.ARETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitEnd()
        }.toByteArray()
        val client = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, caller, null, "java/lang/Object", null)
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "probe", "(L$resources;)I", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitInsn(Opcodes.ICONST_0)
                visitMethodInsn(Opcodes.INVOKEVIRTUAL, resources, "getXml", descriptor, false)
                visitInsn(Opcodes.POP)
                visitFieldInsn(Opcodes.GETSTATIC, resources, "parsers", "[[L$fieldType;")
                visitInsn(Opcodes.POP)
                visitIntInsn(Opcodes.BIPUSH, 42)
                visitInsn(Opcodes.IRETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitEnd()
        }.toByteArray()
        val input = listOf(
            parser to interfaceBytes(parser, pullParser, attributes),
            pullParser to interfaceBytes(pullParser),
            attributes to interfaceBytes(attributes),
            fieldType to interfaceBytes(fieldType),
            unrelated to interfaceBytes(unrelated),
            caller to client,
        )
        val jar = jarOf(input.map { (name, bytes) -> "$name.class" to bytes })
        val plan = ApkKeepRuleSynthesis.synthesize(jar, emptySet(), emptySet(), emptySet(), emptyList())
        val mapping = input.map { it.first }.filter { it !in plan.excludedClassNames }
            .associateWith { "moved/${it.substringAfterLast('/')}" }
        val output = input.associate { (name, bytes) -> (mapping[name] ?: name) to remapClasses(bytes, mapping) } +
            (resources to external)
        val loader = object : ClassLoader(null) {
            override fun findClass(name: String): Class<*> {
                val bytes = output[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
                return defineClass(name, bytes, 0, bytes.size)
            }
        }
        val api = loader.loadClass(resources.replace('/', '.'))
        val entry = loader.loadClass(mapping.getValue(caller).replace('/', '.'))
        assertEquals(42, entry.getMethod("probe", api).invoke(null, api.getConstructor().newInstance()))
        assertEquals(setOf(parser, pullParser, attributes, fieldType), plan.excludedClassNames)
        assertTrue(unrelated in mapping)
    }

    @Test
    fun androidFrameworkInterfaceCallbacksKeepTheirRuntimeNames() {
        val interfaceName = "android/media/AudioManager\$OnModeChangedListener"
        val listenerName = "fixture/AudioModeListener"
        val relocatedListenerName = "moved/AudioModeListener"

        val placeholderInterface = ClassWriter(0).apply {
            visit(
                Opcodes.V1_8,
                Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT or Opcodes.ACC_SYNTHETIC,
                interfaceName,
                null,
                "java/lang/Object",
                null,
            )
            visitMethod(Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, "<clinit>", "()V", null, null).apply {
                visitCode()
                visitTypeInsn(Opcodes.NEW, "java/lang/NoClassDefFoundError")
                visitInsn(Opcodes.DUP)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/NoClassDefFoundError", "<init>", "()V", false)
                visitInsn(Opcodes.ATHROW)
                visitMaxs(2, 0)
                visitEnd()
            }
            visitEnd()
        }.toByteArray()
        val listener = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, listenerName, null, "java/lang/Object", arrayOf(interfaceName))
            visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "observedMode", "I", null, null).visitEnd()
            visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC, "onModeChanged", "(I)V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ILOAD, 1)
                visitFieldInsn(Opcodes.PUTSTATIC, listenerName, "observedMode", "I")
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "getObservedMode", "()I", null, null).apply {
                visitCode()
                visitFieldInsn(Opcodes.GETSTATIC, listenerName, "observedMode", "I")
                visitInsn(Opcodes.IRETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(Opcodes.ACC_PRIVATE, "appHelper", "()V", null, null).apply {
                visitCode()
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitEnd()
        }.toByteArray()
        val plan = ApkKeepRuleSynthesis.synthesize(
            jarOf(
                listOf(
                    "$interfaceName.class" to placeholderInterface,
                    "$listenerName.class" to listener,
                ),
            ),
            emptySet(),
            emptySet(),
            emptySet(),
            emptyList(),
        )

        val callbackKeep = plan.memberKeeps.singleOrNull {
            it.owner == listenerName && it.name == "onModeChanged" && it.descriptor == "(I)V"
        }
        assertTrue(callbackKeep != null, "the Android callback signature must be kept")
        assertFalse(listenerName in plan.excludedClassNames, "the app listener class can still be relocated")
        assertTrue(plan.rules.any { it.action == "exclude" && it.target == "*#onModeChanged:*" })

        val methodRenameMap = mapOf(
            MemberKey(relocatedListenerName, "appHelper", "()V") to MemberRename(
                owner = relocatedListenerName,
                originalName = "appHelper",
                descriptor = "()V",
                renamedName = "mAppHelper",
            ),
        )
        val relocatedBytes = remapClasses(listener, mapOf(listenerName to relocatedListenerName))
        val remappedListener = remapMethods(relocatedBytes, methodRenameMap)
        val validationJar = jarOf(
            listOf(
                "$interfaceName.class" to placeholderInterface,
                "$relocatedListenerName.class" to remappedListener,
            ),
        )
        ApkValidation.validateKeepRetention(validationJar, plan)
        val runtimeInterface = ClassWriter(0).apply {
            visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT, interfaceName, null, "java/lang/Object", null)
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT, "onModeChanged", "(I)V", null, null).visitEnd()
            visitEnd()
        }.toByteArray()
        val definitions = mapOf(interfaceName to runtimeInterface, relocatedListenerName to remappedListener)
        val loader = object : ClassLoader(null) {
            override fun findClass(name: String): Class<*> {
                val bytes = definitions[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
                return defineClass(name, bytes, 0, bytes.size)
            }
        }
        val api = loader.loadClass(interfaceName.replace('/', '.'))
        val listenerClass = loader.loadClass(relocatedListenerName.replace('/', '.'))
        val instance = listenerClass.getConstructor().newInstance()
        api.getMethod("onModeChanged", Int::class.javaPrimitiveType).invoke(instance, 42)

        assertEquals(42, listenerClass.getMethod("getObservedMode").invoke(null))
        assertTrue(listenerClass.declaredMethods.any { it.name == "mAppHelper" })
        assertFalse(listenerClass.declaredMethods.any { it.name == "appHelper" })
    }

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
