package io.github.hht0rro.javashroud.apk

import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class ApkValidationTest {

    /** Minimal structurally valid dex: header + map_list with one class-def. */
    private fun minimalDex(classDefs: Int = 1, version: String = "035"): ByteArray {
        val mapOffset = 0x70
        val mapSize = 2
        val total = mapOffset + 4 + mapSize * 12
        val bytes = ByteArray(total)
        fun u16(offset: Int, value: Int) {
            bytes[offset] = (value and 0xFF).toByte()
            bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        }
        fun u32(offset: Int, value: Long) {
            bytes[offset] = (value and 0xFF).toByte()
            bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
            bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
            bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
        }
        System.arraycopy(byteArrayOf(0x64, 0x65, 0x78, 0x0A), 0, bytes, 0, 4)
        System.arraycopy(version.toByteArray(), 0, bytes, 4, 3)
        bytes[7] = 0
        u32(8, 1L) // adler placeholder, fixed below
        u32(32, total.toLong()) // file_size
        u32(36, 0x70L) // header_size
        u32(40, 0x12345678L) // endian tag
        u32(52, mapOffset.toLong()) // map_off
        u32(56, 1L) // string_ids_size
        u32(96, 1L) // data_size (arbitrary)
        u32(100, mapOffset.toLong()) // data_off
        // map_list: items of {type(2), unused(2), size(4), offset(4)} per the
        // dex spec — size precedes offset (verified against real D8 output).
        u32(mapOffset, mapSize.toLong())
        u16(mapOffset + 4, 0x0002) // TYPE_STRING_ID_ITEM
        u32(mapOffset + 8, 1L) // size
        u32(mapOffset + 12, 0x70L) // offset
        u16(mapOffset + 16, 0x0006) // TYPE_CLASS_DEF_ITEM
        u32(mapOffset + 20, classDefs.toLong()) // size
        u32(mapOffset + 24, 0x70L) // offset
        val signature = java.security.MessageDigest.getInstance("SHA-1").apply {
            update(bytes, 32, total - 32)
        }.digest()
        signature.copyInto(bytes, 12)
        // adler32 over bytes from offset 12
        var a = 1
        var b = 0
        for (index in 12 until total) {
            a = (a + (bytes[index].toInt() and 0xFF)) % 65521
            b = (b + a) % 65521
        }
        u32(8, ((b.toLong() shl 16) or a.toLong()))
        return bytes
    }

    @Test
    fun acceptsValidDexHeaderAndCountsClassDefs() {
        val dex = minimalDex(classDefs = 3)
        ApkValidation.validateDexHeader("classes.dex", dex)
        assertEquals(3, ApkValidation.dexClassCount(dex))
    }

    @Test
    fun rejectsCorruptMagicSizeAndAdler() {
        val badMagic = minimalDex().also { it[0] = 'x'.code.toByte() }
        assertFailsWith<IllegalArgumentException> { ApkValidation.validateDexHeader("classes.dex", badMagic) }

        val badVersion = minimalDex().also { it[4] = '9'.code.toByte(); it[5] = '9'.code.toByte(); it[6] = '9'.code.toByte() }
        assertFailsWith<IllegalArgumentException> { ApkValidation.validateDexHeader("classes.dex", badVersion) }

        val badSize = minimalDex().also { it[32] = (it[32] + 1).toByte() }
        assertFailsWith<IllegalArgumentException> { ApkValidation.validateDexHeader("classes.dex", badSize) }

        val badAdler = minimalDex().also { it[8] = (it[8].toInt() xor 0x01).toByte() }
        assertFailsWith<IllegalArgumentException> { ApkValidation.validateDexHeader("classes.dex", badAdler) }
        val badSignature = minimalDex().also { bytes ->
            bytes[12] = (bytes[12].toInt() xor 0x01).toByte()
            val checksum = java.util.zip.Adler32().apply { update(bytes, 12, bytes.size - 12) }.value
            repeat(4) { bytes[8 + it] = (checksum ushr (it * 8)).toByte() }
        }
        val signatureError = assertFailsWith<IllegalArgumentException> {
            ApkValidation.validateDexHeader("classes.dex", badSignature)
        }
        assertTrue(signatureError.message.orEmpty().contains("SHA-1"))
    }

    private fun classBytes(internalName: String, fieldNames: List<Pair<String, String>>): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        fieldNames.forEach { (name, descriptor) ->
            writer.visitField(Opcodes.ACC_PUBLIC, name, descriptor, null, null).visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun workJar(vararg entries: Pair<String, ByteArray>): Path {
        val jar = Files.createTempFile("work-", ".jar")
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
    fun keepRetentionFailsWhenExcludedClassWasRenamed() {
        val intact = workJar(
            "com/example/Kept.class" to classBytes("com/example/Kept", listOf("CREATOR" to "Landroid/os/Parcelable\$Creator;")),
        )
        val plan = ApkKeepRuleSynthesis.ApkKeepPlan(
            rules = emptyList(),
            excludedClassNames = setOf("com/example/Kept"),
            memberKeeps = emptyList(),
            keepClassCount = 1,
            warnings = emptyList(),
        )
        ApkValidation.validateKeepRetention(intact, plan)

        val renamed = workJar(
            "com/example/a.class" to classBytes("com/example/a", listOf("CREATOR" to "Landroid/os/Parcelable\$Creator;")),
        )
        val error = assertFailsWith<IllegalArgumentException> {
            ApkValidation.validateKeepRetention(renamed, plan)
        }
        assertTrue(error.message!!.contains("com/example/Kept"))
    }

    @Test
    fun keepRetentionFailsWhenCreatorFieldWasRenamed() {
        val renamedField = workJar(
            "com/example/Parc.class" to classBytes("com/example/Parc", listOf("a" to "Landroid/os/Parcelable\$Creator;")),
            "com/example/Other.class" to classBytes("com/example/Other", listOf("CREATOR" to "Landroid/os/Parcelable\$Creator;")),
        )
        val plan = ApkKeepRuleSynthesis.ApkKeepPlan(
            rules = emptyList(),
            excludedClassNames = setOf("com/example/Parc"),
            memberKeeps = listOf(
                ApkKeepRuleSynthesis.ApkMemberKeep(
                    owner = "com/example/Parc",
                    name = "CREATOR",
                    descriptor = "Landroid/os/Parcelable\$Creator;",
                    kind = "field",
                    reason = "parcelable-creator",
                ),
            ),
            keepClassCount = 1,
            warnings = emptyList(),
        )
        val error = assertFailsWith<IllegalArgumentException> {
            ApkValidation.validateKeepRetention(renamedField, plan)
        }
        assertTrue(error.message!!.contains("com/example/Parc#CREATOR"))
    }

    @Test
    fun outputArchiveValidationCatchesDataMutation() {
        val dir = Files.createTempDirectory("outval-")
        val inputApk = dir.resolve("in.apk")
        Files.write(
            inputApk,
            ApkTestFixtures.syntheticApk(
                extraEntries = listOf(ApkTestFixtures.ApkTemplateEntry("res/raw/data.bin", "payload".toByteArray())),
            ),
        )
        val unpacked = ApkInputUnpacker.read(inputApk)
        val mutatedApk = dir.resolve("mutated.apk")
        Files.write(
            mutatedApk,
            ApkTestFixtures.syntheticApk(
                extraEntries = listOf(ApkTestFixtures.ApkTemplateEntry("res/raw/data.bin", "PAYLOAD!".toByteArray())),
            ),
        )
        val output = dir.resolve("out.apk")
        val newDex = listOf("classes.dex" to minimalDex())
        ApkOutputPacker.pack(
            ApkInputUnpacker.read(inputApk),
            newDex,
            dir.resolve("good.apk"),
            4096,
        )
        ApkValidation.validateOutputArchive(unpacked, dir.resolve("good.apk"), listOf("classes.dex"), 4096)

        ApkOutputPacker.pack(
            ApkInputUnpacker.read(mutatedApk),
            newDex,
            output,
            4096,
        )
        val error = assertFailsWith<IllegalArgumentException> {
            ApkValidation.validateOutputArchive(unpacked, output, listOf("classes.dex"), 4096)
        }
        assertTrue(error.message!!.contains("res/raw/data.bin"))
    }
}
