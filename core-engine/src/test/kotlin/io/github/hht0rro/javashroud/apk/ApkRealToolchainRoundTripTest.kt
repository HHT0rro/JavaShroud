package io.github.hht0rro.javashroud.apk

import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.TypeInsnNode

/**
 * Real dex2jar + D8 round trip over ASM-built fixtures. Runs by default in
 * Gradle/CI (the toolchain is always present there); set
 * JAVASHROUD_APK_REAL_TOOLS=skip to bypass on restricted runners.
 */
class ApkRealToolchainRoundTripTest {

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
