package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.bytecode.shuffleClassMembers
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.metadata.shuffleMembers
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

class MemberShuffleTransformsTest {
    @Test
    fun class_member_shuffle_is_complete_stable_and_removes_declaration_prefix() {
        val original = memberRichClass("fixture/MemberRich", 12)
        val entropy = ByteArray(32) { index -> (index * 7 + 3).toByte() }

        val first = shuffleClassMembers(original, entropy, "fixture/MemberRich")
        val second = shuffleClassMembers(original, entropy, "fixture/MemberRich")
        val originalMembers = memberOrders(original)
        val shuffledMembers = memberOrders(first)

        assertTrue(first.contentEquals(second), "same build entropy must produce byte-identical class layout")
        assertEquals(originalMembers.fields.toSet(), shuffledMembers.fields.toSet())
        assertEquals(originalMembers.methods.toSet(), shuffledMembers.methods.toSet())
        assertEquals(originalMembers.fields.size, shuffledMembers.fields.size)
        assertEquals(originalMembers.methods.size, shuffledMembers.methods.size)
        assertNotEquals(originalMembers.fields.first(), shuffledMembers.fields.first())
        assertNotEquals(originalMembers.methods.first(), shuffledMembers.methods.first())
    }

    @Test
    fun independent_build_contexts_diverge_class_member_and_jar_entry_order() {
        val classArtifacts = (0 until 12).map { index ->
            val internalName = "fixture/C%02d".format(index)
            val bytes = memberRichClass(internalName, 10)
            ClassArtifact("$internalName.class", analyzeClassBytes(bytes), bytes)
        }
        val resources = (0 until 12).map { index ->
            JarEntryData("assets/r%02d.bin".format(index), byteArrayOf(index.toByte()))
        }
        val config = testConfig(ruleSet = RuleSet(listOf(RuleSpec("*", "member-shuffle"))))
        val artifact = testAttachedArtifact(
            classArtifacts = classArtifacts,
            jarEntries = classArtifacts.map { JarEntryData(it.entryName, it.bytes) } + resources,
            config = config,
        )
        val matches = buildRuleMatches(config.ruleSet, artifact.analysisSummary.classSummaries)

        val firstContext = context(0x11)
        val secondContext = context(0x55)
        val first = withVbc4BuildContext(firstContext) { shuffleMembers(artifact, matches, emptyMap()).artifact }
        val firstAgain = withVbc4BuildContext(firstContext) { shuffleMembers(artifact, matches, emptyMap()).artifact }
        val second = withVbc4BuildContext(secondContext) { shuffleMembers(artifact, matches, emptyMap()).artifact }

        assertEquals(first.classArtifacts.map { it.entryName }, firstAgain.classArtifacts.map { it.entryName })
        assertEquals(first.jarEntries.map { it.name }, firstAgain.jarEntries.map { it.name })
        assertTrue(first.classArtifacts.zip(firstAgain.classArtifacts).all { (a, b) -> a.bytes.contentEquals(b.bytes) })
        assertNotEquals(artifact.classArtifacts.first().entryName, first.classArtifacts.first().entryName)
        assertNotEquals(artifact.jarEntries.first().name, first.jarEntries.first().name)
        assertEquals(artifact.classArtifacts.map { it.entryName }.toSet(), first.classArtifacts.map { it.entryName }.toSet())
        assertEquals(artifact.jarEntries.map { it.name }.toSet(), first.jarEntries.map { it.name }.toSet())
        assertNotEquals(first.classArtifacts.map { it.entryName }, second.classArtifacts.map { it.entryName })
        assertNotEquals(first.jarEntries.map { it.name }, second.jarEntries.map { it.name })
        val firstMemberOrders = first.classArtifacts.associate { it.summary.internalName to memberOrders(it.bytes) }
        val secondMemberOrders = second.classArtifacts.associate { it.summary.internalName to memberOrders(it.bytes) }
        assertTrue(
            firstMemberOrders.any { (name, order) -> order != secondMemberOrders.getValue(name) },
            "independent build contexts must diverge member order for at least one identical class",
        )
    }

    private fun context(marker: Int): Vbc4BuildContext {
        val key = ByteArray(32) { index -> (marker + index).toByte() }
        val layout = ByteArray(32) { index -> (marker * 3 + index).toByte() }
        val random = java.security.SecureRandom.getInstance("SHA1PRNG").apply { setSeed(marker.toLong()) }
        return Vbc4BuildContext(
            masterKey = key,
            nativeSeed = marker.toLong(),
            jarLayoutDigest = layout,
            runtimeKeyPartitions = RuntimeKeyPartitions.generate(random),
        )
    }

    private data class MemberOrders(val fields: List<String>, val methods: List<String>)

    private fun memberOrders(bytes: ByteArray): MemberOrders {
        val node = ClassNode()
        ClassReader(bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return MemberOrders(
            fields = node.fields.map { "${it.name}:${it.desc}" },
            methods = node.methods.map { "${it.name}${it.desc}" },
        )
    }

    private fun memberRichClass(internalName: String, count: Int): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        repeat(count) { index ->
            writer.visitField(Opcodes.ACC_PUBLIC, "field%02d".format(index), "I", null, null).visitEnd()
        }
        repeat(count) { index ->
            val method: MethodVisitor = writer.visitMethod(Opcodes.ACC_PUBLIC, "method%02d".format(index), "()I", null, null)
            method.visitCode()
            method.visitLdcInsn(index)
            method.visitInsn(Opcodes.IRETURN)
            method.visitMaxs(1, 1)
            method.visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }
}
