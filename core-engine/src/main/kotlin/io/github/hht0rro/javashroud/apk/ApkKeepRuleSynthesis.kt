package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.io.InputStream
import java.util.jar.JarInputStream
import java.util.zip.ZipEntry
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.Handle
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TypeInsnNode

/**
 * Synthesizes the Android-semantics keep rules that must accompany every APK
 * run: without them the rename passes would rename manifest components,
 * JNI anchors, Parcelable.CREATOR, serialVersionUID, serialization hooks and
 * @JavascriptInterface bridges, which crashes typical apps at runtime.
 */
object ApkKeepRuleSynthesis {

    const val PARCELABLE_INTERNAL = "android/os/Parcelable"
    const val PARCELABLE_CREATOR_INTERNAL = "android/os/Parcelable\$Creator"
    const val SERIALIZABLE_INTERNAL = "java/io/Serializable"
    const val JAVASCRIPT_INTERFACE_DESC = "Landroid/webkit/JavascriptInterface;"

    internal val SERIALIZATION_HOOKS = setOf(
        "writeObject:(Ljava/io/ObjectOutputStream;)V",
        "readObject:(Ljava/io/ObjectInputStream;)V",
        "readObjectNoData:()V",
        "writeReplace:()Ljava/lang/Object;",
        "readResolve:()Ljava/lang/Object;",
    )

    /**
     * Member-level keeps are anchored by member name with a wildcard owner
     * (`*#CREATOR:*`): the kernel re-matches rules against the CURRENT class
     * names on every pass, so owner-anchored member rules go stale as soon as
     * rename-packages/rename-classes relocate the owner. Name anchoring keeps
     * protecting the member across any owner rename.
     */
    private const val WILDCARD_OWNER = "*"

    data class ApkKeepPlan(
        val rules: List<RuleSpec>,
        val excludedClassNames: Set<String>,
        val memberKeeps: List<ApkMemberKeep>,
        val keepClassCount: Int,
        val warnings: List<String>,
    )

    data class ApkMemberKeep(
        val owner: String,
        val name: String,
        val descriptor: String,
        val kind: String,
        val reason: String,
    ) {
        val selector: String get() = "$owner#$name:$descriptor"
    }

    internal class LoadedClassInfo(
        val internalName: String,
        val superName: String?,
        val interfaces: List<String>,
        val hasNativeMethod: Boolean,
        val fields: List<Pair<String, String>>,
        val methods: List<Pair<String, String>>,
        val javascriptInterfaceMethods: List<Pair<String, String>>,
        val isAndroidFrameworkPlaceholder: Boolean,
    )

    internal fun classInfosFromBytes(classBytes: List<Pair<String, ByteArray>>): List<LoadedClassInfo> =
        classBytes.map { (_, bytes) -> readClassInfo(bytes) }

    internal fun readClassInfo(bytes: ByteArray): LoadedClassInfo {
        lateinit var internalName: String
        var superName: String? = null
        val interfaces = mutableListOf<String>()
        var hasNativeMethod = false
        val fields = mutableListOf<Pair<String, String>>()
        val methods = mutableListOf<Pair<String, String>>()
        val javascriptInterfaceMethods = mutableListOf<Pair<String, String>>()

        val reader = ClassReader(bytes)
        reader.accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visit(
                version: Int,
                access: Int,
                name: String?,
                signature: String?,
                superClass: String?,
                implemented: Array<out String>?,
            ) {
                internalName = name ?: ""
                superName = superClass
                interfaces += implemented.orEmpty()
            }

            override fun visitField(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                value: Any?,
            ): FieldVisitor? {
                if (name != null && descriptor != null) fields += name to descriptor
                return null
            }

            override fun visitMethod(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                exceptions: Array<out String>?,
            ): MethodVisitor? {
                if (name == null || descriptor == null) return null
                methods += name to descriptor
                if (access and Opcodes.ACC_NATIVE != 0) hasNativeMethod = true
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitAnnotation(annotationDescriptor: String?, visible: Boolean): org.objectweb.asm.AnnotationVisitor? {
                        if (annotationDescriptor == JAVASCRIPT_INTERFACE_DESC) {
                            javascriptInterfaceMethods += name to descriptor
                        }
                        return null
                    }
                }
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)

        return LoadedClassInfo(
            internalName = internalName,
            superName = superName,
            interfaces = interfaces.toList(),
            hasNativeMethod = hasNativeMethod,
            fields = fields.toList(),
            methods = methods.toList(),
            javascriptInterfaceMethods = javascriptInterfaceMethods.toList(),
            isAndroidFrameworkPlaceholder = internalName.startsWith("android/") && fields.isEmpty() &&
                methods.singleOrNull() == ("<clinit>" to "()V") && hasMissingFrameworkTypeInitializer(reader),
        )
    }

    private fun hasMissingFrameworkTypeInitializer(reader: ClassReader): Boolean {
        val node = ClassNode()
        reader.accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        val init = node.methods.singleOrNull() ?: return false
        val requiredFlags = Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC
        if (init.access and requiredFlags != requiredFlags || !init.tryCatchBlocks.isNullOrEmpty()) return false
        val code = init.instructions.filter { it.opcode >= 0 }
        if (code.size != 4) return false
        val allocation = code[0] as? TypeInsnNode ?: return false
        val constructor = code[2] as? MethodInsnNode ?: return false
        val error = "java/lang/NoClassDefFoundError"
        return allocation.opcode == Opcodes.NEW && allocation.desc == error && code[1].opcode == Opcodes.DUP &&
            constructor.opcode == Opcodes.INVOKESPECIAL && constructor.owner == error && constructor.name == "<init>" &&
            constructor.desc == "()V" && !constructor.itf && code[3].opcode == Opcodes.ATHROW
    }

    fun synthesize(
        mergedClassJarPath: java.nio.file.Path,
        manifestComponentClasses: Set<String>,
        resourceReferencedClasses: Set<String>,
        nativeReferencedClasses: Set<String>,
        extraKeepPrefixes: List<String>,
        layoutClickMethods: Set<String> = emptySet(),
    ): ApkKeepPlan {
        val loaded = readClassInfos(mergedClassJarPath)
        val loadedNames = loaded.map { it.internalName }.toSet()
        val warnings = mutableListOf<String>()

        val classKeeps = sortedSetOf<String>()
        val memberKeeps = mutableListOf<ApkMemberKeep>()

        // On a supporting Android version the boot class loader resolves these names to the SDK classes.
        // Moving the packaged placeholder would also rewrite platform method descriptors and superclass names.
        for (info in loaded) {
            // Keep the desugared library's namespace intact for existing references and the D8 partition.
            if (info.isAndroidFrameworkPlaceholder || info.internalName.startsWith("j\$/")) classKeeps += info.internalName
        }

        classKeeps += externalSignatureClasses(mergedClassJarPath, loaded)

        // 1. Manifest components (intersected with actually loaded classes).
        val manifestHits = manifestComponentClasses.intersect(loadedNames)
        classKeeps += manifestHits

        // 2/3. JNI declaring classes and native-code reverse callbacks.
        val jniDeclarers = loaded.filter { it.hasNativeMethod }.map { it.internalName }.toSet()
        classKeeps += jniDeclarers
        classKeeps += nativeReferencedClasses.intersect(loadedNames)

        // 6. Resource string-pool references.
        classKeeps += resourceReferencedClasses.intersect(loadedNames)

        // 6b. Name-convention implementations resolved by reflection at
        // runtime: Room looks up "<databaseClass>_Impl" via Class.forName on
        // the canonical-name + suffix. Renaming either side breaks the
        // pairing, so every *_Impl class whose base class is also loaded
        // keeps its name.
        val implConventionClasses = loadedNames.filterTo(sortedSetOf()) { name ->
            name.endsWith("_Impl") && loadedNames.contains(name.removeSuffix("_Impl"))
        }
        classKeeps += implConventionClasses
        // The lookup string is built from the DATABASE class's own name, so
        // the base class must keep its name too — pinning only the generated
        // side still breaks the pairing.
        classKeeps += implConventionClasses.map { it.removeSuffix("_Impl") }

        // 4. Parcelable CREATOR / Serializable serialVersionUID member keeps.
        val parcelableClasses = implementorsOf(loaded, PARCELABLE_INTERNAL)
        val serializableClasses = implementorsOf(loaded, SERIALIZABLE_INTERNAL)
        for (info in loaded) {
            if (info.internalName in parcelableClasses) {
                info.fields.firstOrNull { it.first == "CREATOR" }?.let { (_, descriptor) ->
                    memberKeeps += ApkMemberKeep(
                        owner = info.internalName,
                        name = "CREATOR",
                        descriptor = descriptor,
                        kind = "field",
                        reason = "parcelable-creator",
                    )
                }
            }
            if (info.internalName in serializableClasses) {
                info.fields.firstOrNull { it.first == "serialVersionUID" }?.let { (_, descriptor) ->
                    memberKeeps += ApkMemberKeep(
                        owner = info.internalName,
                        name = "serialVersionUID",
                        descriptor = descriptor,
                        kind = "field",
                        reason = "serial-version-uid",
                    )
                }
                // 5. Serialization hook methods that actually exist.
                for ((name, descriptor) in info.methods) {
                    if ("$name:$descriptor" in SERIALIZATION_HOOKS) {
                        memberKeeps += ApkMemberKeep(
                            owner = info.internalName,
                            name = name,
                            descriptor = descriptor,
                            kind = "method",
                            reason = "serialization-hook",
                        )
                    }
                }
            }
            // 5b. @JavascriptInterface bridge methods (JS looks them up by name).
            for ((name, descriptor) in info.javascriptInterfaceMethods) {
                memberKeeps += ApkMemberKeep(
                    owner = info.internalName,
                    name = name,
                    descriptor = descriptor,
                    kind = "method",
                    reason = "javascript-interface",
                )
            }
            for ((name, descriptor) in info.methods) {
                if (descriptor == "(Landroid/view/View;)V" && name in layoutClickMethods) {
                    classKeeps += info.internalName
                    memberKeeps += ApkMemberKeep(info.internalName, name, descriptor, "method", "layout-on-click")
                }
            }
        }

        // 7. User extraKeepPrefixes -> class rules.
        val prefixRules = extraKeepPrefixes
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { prefix -> RuleSpec(target = normalizePrefix(prefix), action = "exclude") }

        if (classKeeps.isEmpty() && memberKeeps.isEmpty() && prefixRules.isEmpty()) {
            warnings += "APK keep synthesis matched no loaded classes; default rename fallback applies to everything."
        }

        val classRules = classKeeps.map { name -> RuleSpec(target = name, action = "exclude") }
        // Owner-wildcard, name-anchored selectors: see WILDCARD_OWNER note above.
        val memberRules = memberKeeps
            .distinctBy { it.selector }
            .map { keep ->
                val descriptorPattern = when (keep.reason) {
                    "parcelable-creator", "javascript-interface" -> "*"
                    else -> keep.descriptor
                }
                RuleSpec(target = "$WILDCARD_OWNER#${keep.name}:$descriptorPattern", action = "exclude")
            }
            .distinctBy { it.target }

        return ApkKeepPlan(
            rules = classRules + memberRules + prefixRules,
            excludedClassNames = classKeeps,
            memberKeeps = memberKeeps.distinctBy { it.selector },
            keepClassCount = classKeeps.size,
            warnings = warnings,
        )
    }

    fun mergeRuleSet(userRuleSet: RuleSet, keepPlan: ApkKeepPlan): RuleSet =
        RuleSet(rules = userRuleSet.rules + keepPlan.rules)

    private fun normalizePrefix(prefix: String): String {
        val slash = prefix.replace('.', '/')
        return if (slash.endsWith("/*")) slash else "$slash/*"
    }

    private fun externalSignatureClasses(
        jarPath: java.nio.file.Path,
        loaded: List<LoadedClassInfo>,
    ): Set<String> {
        val byName = loaded.associateBy { it.internalName }
        val methods = loaded.associate { it.internalName to it.methods.toSet() }
        val fields = loaded.associate { it.internalName to it.fields.toSet() }
        val retained = mutableSetOf<String>()

        fun declaredInLoadedHierarchy(
            owner: String,
            name: String,
            descriptor: String,
            field: Boolean,
            visited: MutableSet<String>,
        ): Boolean {
            if (!visited.add(owner)) return false
            val info = byName[owner] ?: return false
            val declarations = if (field) fields else methods
            if ((name to descriptor) in declarations.getValue(owner)) return true
            return info.interfaces.any { declaredInLoadedHierarchy(it, name, descriptor, field, visited) } ||
                (info.superName?.let { declaredInLoadedHierarchy(it, name, descriptor, field, visited) } ?: false)
        }

        fun retainType(name: String) {
            val info = byName[name] ?: return
            if (!retained.add(name)) return
            info.superName?.let { retainType(it) }
            info.interfaces.forEach { retainType(it) }
        }

        fun referencedTypes(type: Type, names: MutableSet<String>) {
            when (type.sort) {
                Type.OBJECT -> if (type.internalName in byName) names += type.internalName
                Type.ARRAY -> referencedTypes(type.elementType, names)
                Type.METHOD -> {
                    type.argumentTypes.forEach { referencedTypes(it, names) }
                    referencedTypes(type.returnType, names)
                }
            }
        }

        fun memberReference(owner: String, name: String, descriptor: String, field: Boolean) {
            val names = mutableSetOf<String>()
            referencedTypes(Type.getType(descriptor), names)
            if (names.isEmpty() || declaredInLoadedHierarchy(owner, name, descriptor, field, mutableSetOf())) return
            // The external declaration cannot follow our class renames. This also covers packaged SDK
            // interfaces resolved by Android's boot loader and inherited external member references.
            names.forEach { retainType(it) }
        }

        fun handleReference(handle: Handle) {
            memberReference(handle.owner, handle.name, handle.desc, handle.tag in Opcodes.H_GETFIELD..Opcodes.H_PUTSTATIC)
        }

        fun constantReference(value: Any) {
            when (value) {
                is Handle -> handleReference(value)
                is ConstantDynamic -> {
                    handleReference(value.bootstrapMethod)
                    repeat(value.bootstrapMethodArgumentCount) { constantReference(value.getBootstrapMethodArgument(it)) }
                }
            }
        }

        JarInputStream(java.nio.file.Files.newInputStream(jarPath).buffered()).use { jar ->
            while (true) {
                val entry = jar.nextEntry ?: break
                if (entry.isDirectory || !entry.name.endsWith(".class")) continue
                ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                    override fun visitMethod(
                        access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?,
                    ): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                        override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                            memberReference(owner, name, descriptor, false)
                        }

                        override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
                            memberReference(owner, name, descriptor, true)
                        }

                        override fun visitLdcInsn(value: Any) = constantReference(value)

                        override fun visitInvokeDynamicInsn(name: String, descriptor: String, bootstrap: Handle, vararg arguments: Any) {
                            handleReference(bootstrap)
                            arguments.forEach { constantReference(it) }
                        }
                    }
                }, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            }
        }
        return retained
    }

    /** Direct-or-transitive implementors of [interfaceInternal] within the loaded closure. */
    private fun implementorsOf(loaded: List<LoadedClassInfo>, interfaceInternal: String): Set<String> {
        val byName = loaded.associateBy { it.internalName }
        val memo = HashMap<String, Boolean>()

        fun resolvesInterfaceChain(name: String): Boolean {
            memo[name]?.let { return it }
            memo[name] = false // cycle guard
            val info = byName[name]
            val result = when {
                info == null -> name == interfaceInternal // framework interface referenced but not loaded
                name == interfaceInternal -> true
                else -> info.interfaces.any { interfaceName ->
                    interfaceName == interfaceInternal || resolvesInterfaceChain(interfaceName)
                } || (info.superName?.let { resolvesInterfaceChain(it) } ?: false)
            }
            memo[name] = result
            return result
        }

        return loaded
            .filter { info -> info.interfaces.any { resolvesInterfaceChain(it) } || (info.superName?.let { s -> resolvesInterfaceChain(s) } ?: false) }
            .map { it.internalName }
            .toSet()
    }

    private fun readClassInfos(jarPath: java.nio.file.Path): List<LoadedClassInfo> {
        val infos = mutableListOf<LoadedClassInfo>()
        JarInputStream(java.nio.file.Files.newInputStream(jarPath).buffered()).use { jar: JarInputStream ->
            while (true) {
                val entry: ZipEntry = jar.nextEntry ?: break
                if (entry.isDirectory || !entry.name.endsWith(".class")) continue
                infos += readClassInfo(jar.readBytes())
            }
        }
        return infos
    }
}
