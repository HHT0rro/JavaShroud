package io.github.hht0rro.javashroud.apk

import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TypeInsnNode

/**
 * Real dex2jar + D8 round trip over ASM-built fixtures. Runs by default in
 * Gradle/CI (the toolchain is always present there); set
 * JAVASHROUD_APK_REAL_TOOLS=skip to bypass on restricted runners.
 */
class ApkRealToolchainRoundTripTest {

    @Test
    fun allocationIndexIncludesPreciseNewWhoseConstructorBelongsToItsParent() {
        val parent = "fixture/Base"
        val first = "fixture/First"
        val second = "fixture/Second"
        val host = "fixture/PartlyRecovered"
        fun classBytes(owner: String, superName: String, methods: (ClassWriter) -> Unit = {}): ByteArray {
            val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
            writer.visit(Opcodes.V1_6, Opcodes.ACC_PUBLIC, owner, null, superName, null)
            methods(writer)
            writer.visitEnd()
            return writer.toByteArray()
        }
        val bytes = classBytes(host, "java/lang/Object") { writer ->
            writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "make", "()V", null, null).apply {
                visitCode()
                for (owner in listOf(first, parent)) {
                    visitTypeInsn(Opcodes.NEW, owner)
                    visitInsn(Opcodes.DUP)
                    visitMethodInsn(Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false)
                    visitInsn(Opcodes.POP)
                }
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        val classes = listOf(
            "$host.class" to bytes,
            "$parent.class" to classBytes(parent, "java/lang/Object"),
            "$first.class" to classBytes(first, parent),
            "$second.class" to classBytes(second, parent),
        )
        val sites = listOf(first, second).map { ApkDexNewInstanceIndex.Site(it, parent) }
        for (declaredStack in listOf(2, 0)) {
            val input = ClassNode()
            ClassReader(bytes).accept(input, 0)
            input.methods.single().maxStack = declaredStack
            val writer = ClassWriter(0)
            input.accept(writer)
            val convertedClasses = classes.map { (name, body) -> name to if (name == "$host.class") writer.toByteArray() else body }
            val result = ApkNewTypeRepair.repair(convertedClasses, mapOf(host to mapOf("make()V" to sites)))
            val node = ClassNode()
            ClassReader(result.classes.first().second).accept(node, 0)
            assertEquals(listOf(first, second), node.methods.single().instructions.filterIsInstance<TypeInsnNode>()
                .filter { it.opcode == Opcodes.NEW }.map { it.desc }, "declared maxStack=$declaredStack")
            assertEquals(1, result.dexRecoveredSites)
        }
    }

    @Test
    fun reorderedAllocationUsesItsFieldReceiverRatherThanTheDexOrdinal() {
        val parent = "java/lang/Object"
        val host = "fixture/AllocationOrder"
        val counter = "fixture/Counter"
        val reference = "fixture/Reference"
        fun classBytes(name: String, block: (ClassWriter) -> Unit): ByteArray =
            ClassWriter(ClassWriter.COMPUTE_MAXS).also { writer ->
                writer.visit(Opcodes.V1_6, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, name, null, parent, null)
                block(writer)
                writer.visitEnd()
            }.toByteArray()

        val make = classBytes(host) { writer ->
            writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "make", "()V", null, null).apply {
                visitCode()
                fun allocate() {
                    visitTypeInsn(Opcodes.NEW, parent)
                    visitInsn(Opcodes.DUP)
                    visitMethodInsn(Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false)
                }
                allocate()
                visitInsn(Opcodes.POP)
                allocate()
                visitVarInsn(Opcodes.ASTORE, 0)
                visitVarInsn(Opcodes.ALOAD, 0)
                visitInsn(Opcodes.FCONST_1)
                visitFieldInsn(Opcodes.PUTFIELD, counter, "value", "F")
                allocate()
                visitInsn(Opcodes.POP)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        val classes = listOf(
            "$host.class" to make,
            "$counter.class" to classBytes(counter) { it.visitField(Opcodes.ACC_PUBLIC, "value", "F", null, null).visitEnd() },
            "$reference.class" to classBytes(reference) {},
        )
        val source = listOf(reference, reference, counter, reference).map { ApkDexNewInstanceIndex.Site(it, parent) }
        val repaired = ApkNewTypeRepair.repair(classes, mapOf(host to mapOf("make()V" to source)))
        val output = ClassNode()
        ClassReader(repaired.classes.first().second).accept(output, 0)
        assertEquals(listOf(reference, counter, reference), output.methods.single().instructions
            .filterIsInstance<TypeInsnNode>().filter { it.opcode == Opcodes.NEW }.map { it.desc })
    }

    @Test
    fun packagedDesugaredLibraryAndApplicationProduceSeparateDexGroups(@TempDir work: Path) {
        Assumptions.assumeTrue(System.getenv(ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV) != "skip")
        val app = "fixture/App"
        val provider = "j\$/nio/file/spi/FixtureProvider"
        fun classWithMarker(owner: String): ByteArray {
            val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
            writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
            val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "marker", "()I", null, null)
            method.visitCode()
            if (owner == app) method.visitMethodInsn(Opcodes.INVOKESTATIC, provider, "marker", "()I", false)
            else method.visitIntInsn(Opcodes.BIPUSH, 42)
            method.visitInsn(Opcodes.IRETURN)
            method.visitMaxs(0, 0)
            method.visitEnd()
            writer.visitEnd()
            return writer.toByteArray()
        }
        val input = work.resolve("app-and-library.jar")
        JarOutputStream(Files.newOutputStream(input)).use { jar ->
            for (owner in listOf(app, provider)) {
                jar.putNextEntry(ZipEntry("$owner.class"))
                jar.write(classWithMarker(owner))
                jar.closeEntry()
            }
        }
        val toolchain = ApkToolchainProvisioner.ensure(dex2jarDirOverride = "", d8JarOverride = "")
        val dex = ApkD8Runner().compile(toolchain, input, work.resolve("dex"), minApi = 23, androidJarPath = "") {}
        assertEquals(listOf("classes.dex", "classes2.dex"), dex.map { it.first })
        val duplicate = assertFailsWith<IllegalArgumentException> {
            ApkValidation.validateDisjointDexClasses(dex + ("classes3.dex" to dex[1].second))
        }
        assertTrue(duplicate.message.orEmpty().contains("defined more than once"))
        val converted = dex.mapIndexed { i, (name, bytes) ->
            ApkValidation.validateDexHeader(name, bytes)
            ApkDex2JarRunner().convert(toolchain, ApkInputUnpacker.ApkDexInput(name, i + 1, bytes), work) {}
        }
        assertEquals(listOf("$app.class"), converted[0].classNames)
        assertEquals(listOf("$provider.class"), converted[1].classNames)
        val node = ClassNode()
        java.util.jar.JarFile(converted[0].jarPath.toFile()).use { jar ->
            jar.getInputStream(jar.getJarEntry("$app.class")).use { ClassReader(it).accept(node, 0) }
        }
        val call = node.methods.single().instructions.filterIsInstance<MethodInsnNode>().single()
        assertEquals(provider, call.owner)
        assertEquals("marker", call.name)
    }

    @Test
    fun toolOutputKeepsTheFailureAmongVerboseWarnings() {
        val output = "Info: first hint\n" + "Info: noisy build hint\n".repeat(600) +
            "Error: packaged library classes cannot be merged\n" + "Info: more build hints\n".repeat(600) + "Final tool status\n"
        val preview = ApkProcessSupport.preview(output)
        assertTrue(preview.length <= 8_000)
        assertTrue("Info: first hint" in preview && "Final tool status" in preview)
        assertTrue("Error: packaged library classes cannot be merged" in preview)
    }

    @Test
    fun desugaredCompanionNameKeepsItsDexAllocationIdentity(@TempDir work: Path) {
        Assumptions.assumeTrue(System.getenv(ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV) != "skip")
        val companion = "demo/Query\$-CC"
        val descriptor = "make()Ldemo/Result;"
        val query = Files.writeString(work.resolve("Query.smali"), """
            .class public L$companion;
            .super Ljava/lang/Object;

            .method public static $descriptor
                .registers 2
                new-instance v0, Ldemo/Result;
                invoke-direct {v0}, Ljava/lang/Object;-><init>()V
                const/4 v1, 0x2
                iput v1, v0, Ldemo/Result;->value:I
                return-object v0
            .end method
        """.trimIndent())
        val result = Files.writeString(work.resolve("Result.smali"), """
            .class public Ldemo/Result;
            .super Ljava/lang/Object;
            .field public value:I
        """.trimIndent())
        val toolchain = ApkToolchainProvisioner.ensure(dex2jarDirOverride = "", d8JarOverride = "")
        val dex = work.resolve("classes.dex")
        val assembler = listOf(
            toolchain.javaExecutable.toString(), "-Xmx256m", "-cp",
            ApkDex2JarRunner.wildcardClasspath(toolchain.dex2jarDirectory),
            "com.googlecode.d2j.smali.SmaliCmd", "--output", dex.toString(), query.toString(), result.toString(),
        )
        ApkProcessSupport.requireSuccess("assemble allocation fixture", assembler, ApkProcessSupport.runProcess(assembler, 60_000))
        val dexBytes = Files.readAllBytes(dex)
        ApkValidation.validateDexHeader(dex.fileName.toString(), dexBytes)
        val sites = ApkDexNewInstanceIndex.build(listOf(dexBytes))
        val sourceSite = ApkDexNewInstanceIndex.Site("demo/Result", "java/lang/Object")
        assertEquals(listOf(sourceSite), sites[companion]?.get(descriptor))

        val converted = ApkDex2JarRunner().convert(
            toolchain, ApkInputUnpacker.ApkDexInput(dex.fileName.toString(), 1, dexBytes), work,
        ) {}
        assertTrue("$companion.class" in converted.classNames, "DEX owner changed: ${converted.classNames}")
        val classes = java.util.jar.JarFile(converted.jarPath.toFile()).use { jar ->
            converted.classNames.map { name -> name to jar.getInputStream(jar.getJarEntry(name)).use { it.readBytes() } }
        }
        fun allocationType(classBytes: ByteArray): String {
            val node = ClassNode()
            ClassReader(classBytes).accept(node, 0)
            return node.methods.single { it.name + it.desc == descriptor }.instructions
                .filterIsInstance<TypeInsnNode>().single { it.opcode == Opcodes.NEW }.desc
        }
        assertEquals("java/lang/Object", allocationType(classes.single { it.first == "$companion.class" }.second))
        val repaired = ApkNewTypeRepair.repair(classes, sites)
        assertEquals(1, repaired.dexRecoveredSites)
        assertEquals("demo/Result", allocationType(repaired.classes.single { it.first == "$companion.class" }.second))

        val repairedJar = work.resolve("repaired.jar")
        JarOutputStream(Files.newOutputStream(repairedJar)).use { jar ->
            for ((name, bytes) in repaired.classes) {
                jar.putNextEntry(ZipEntry(name))
                jar.write(bytes)
                jar.closeEntry()
            }
        }
        val roundTrip = ApkD8Runner().compile(toolchain, repairedJar, work.resolve("round-trip"), minApi = 26, androidJarPath = "") {}
        assertEquals(listOf(sourceSite), ApkDexNewInstanceIndex.build(roundTrip.map { it.second })[companion]?.get(descriptor))
    }

    @Test
    fun allocationIndexFindsConstructorsAfterACheckCast() {
        Assumptions.assumeTrue(System.getenv(ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV) != "skip")
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "demo/AllocationProbe", null, "java/lang/Object", null)
        val method = writer.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "make", "(Ljava/lang/Object;)Ljava/lang/StringBuilder;", null, null,
        )
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String")
        method.visitVarInsn(Opcodes.ASTORE, 0)
        method.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
        method.visitInsn(Opcodes.DUP)
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false)
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()

        val toolchain = ApkToolchainProvisioner.ensure(dex2jarDirOverride = "", d8JarOverride = "")
        val work = Files.createTempDirectory("apk-allocation-index-")
        val jarPath = work.resolve("classes.jar")
        JarOutputStream(Files.newOutputStream(jarPath)).use { jar ->
            jar.putNextEntry(ZipEntry("demo/AllocationProbe.class"))
            jar.write(writer.toByteArray())
            jar.closeEntry()
        }
        val dex = ApkD8Runner().compile(toolchain, jarPath, work.resolve("dex"), minApi = 26, androidJarPath = "") {}
        val sites = ApkDexNewInstanceIndex.build(dex.map { it.second })
        assertEquals(
            listOf(ApkDexNewInstanceIndex.Site("java/lang/StringBuilder", "java/lang/StringBuilder")),
            sites["demo/AllocationProbe"]?.get("make(Ljava/lang/Object;)Ljava/lang/StringBuilder;"),
        )
    }

    private fun classBytes(internalName: String, withCreator: Boolean): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC,
            internalName,
            null,
            "java/lang/Object",
            if (withCreator) arrayOf("android/os/Parcelable") else null,
        )
        if (withCreator) {
            writer.visitField(
                Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC + Opcodes.ACC_FINAL,
                "CREATOR",
                "Landroid/os/Parcelable\$Creator;",
                null,
                null,
            ).visitEnd()
        }
        val main = writer.visitMethod(Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        main.visitCode()
        main.visitInsn(Opcodes.RETURN)
        main.visitMaxs(0, 1)
        main.visitEnd()
        // D8 rejects methods without a Code attribute: every declared method
        // gets an explicit empty body.
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(0, 1)
        init.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    @Test
    fun classToDexAndBackKeepsNamesAndCreators() {
        Assumptions.assumeTrue(
            System.getenv(ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV) != "skip",
            "JAVASHROUD_APK_REAL_TOOLS=skip",
        )

        val toolchain = ApkToolchainProvisioner.ensure(dex2jarDirOverride = "", d8JarOverride = "")
        val work = Files.createTempDirectory("apk-roundtrip-")

        // class -> dex (real D8).
        val classJar = work.resolve("classes.jar")
        JarOutputStream(Files.newOutputStream(classJar)).use { jar ->
            listOf(
                "demo/Keep.class" to classBytes("demo/Keep", withCreator = true),
                "demo/Other.class" to classBytes("demo/Other", withCreator = false),
            ).forEach { (name, bytes) ->
                jar.putNextEntry(ZipEntry(name))
                jar.write(bytes)
                jar.closeEntry()
            }
        }
        val dexDir = work.resolve("dex-out")
        val dexes = ApkD8Runner().compile(toolchain, classJar, dexDir, minApi = 26, androidJarPath = "") {}
        assertEquals(1, dexes.size, "two small classes must fit into one dex")
        val (dexName, dexBytes) = dexes.single()
        assertEquals("classes.dex", dexName)
        ApkValidation.validateDexHeader(dexName, dexBytes)
        assertTrue(ApkValidation.dexClassCount(dexBytes) >= 2, "both fixture classes must be defined")

        // dex -> class (real dex2jar): names and CREATOR survive the trip.
        val converted = ApkDex2JarRunner().convert(
            toolchain = toolchain,
            dex = ApkInputUnpacker.ApkDexInput(entryName = dexName, index = 1, bytes = dexBytes),
            workDirectory = work,
        ) {}
        val convertedNames = converted.classNames.toSet()
        assertTrue("demo/Keep.class" in convertedNames, "keep class name must survive: $convertedNames")
        assertTrue("demo/Other.class" in convertedNames)

        val keepInfo = ApkKeepRuleSynthesis.readClassInfo(
            java.util.jar.JarInputStream(Files.newInputStream(converted.jarPath)).use { jar ->
                var bytes: ByteArray? = null
                while (true) {
                    val entry: ZipEntry = jar.nextEntry ?: break
                    if (entry.name == "demo/Keep.class") bytes = jar.readBytes()
                }
                bytes!!
            },
        )
        assertEquals(true, keepInfo.interfaces.contains("android/os/Parcelable"))
        assertTrue(
            keepInfo.fields.any { (name, descriptor) ->
                name == "CREATOR" && descriptor == "Landroid/os/Parcelable\$Creator;"
            },
            "CREATOR must survive the dex round trip with its descriptor: ${keepInfo.fields}",
        )
    }
}
