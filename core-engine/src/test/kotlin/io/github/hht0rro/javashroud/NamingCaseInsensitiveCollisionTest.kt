package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.naming.NameGenerator
import io.github.hht0rro.javashroud.naming.RenameConfig
import io.github.hht0rro.javashroud.naming.buildClassRenameMap
import java.nio.file.Files
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NamingCaseInsensitiveCollisionTest {

    @Test
    fun ooO0_dictionary_generates_large_case_insensitively_unique_class_map() {
        val artifacts = (0 until 4_096).map { testClassArtifact("sample/Original$it") }
        val matchedClassNames = artifacts.mapTo(mutableSetOf()) { it.summary.internalName }

        val renameMap = buildClassRenameMap(
            classArtifacts = artifacts,
            matchedClassNames = matchedClassNames,
            config = RenameConfig(
                dictionaryStyle = "ooO0oO",
                seed = 0x10B,
                collisionPolicy = "append-index",
            ),
        )

        assertEquals(artifacts.size, renameMap.size)
        val normalizedNames = renameMap.values.map { it.lowercase(Locale.ROOT) }
        assertEquals(normalizedNames.size, normalizedNames.toSet().size)
    }

    @Test
    fun append_index_resolves_case_only_dictionary_collisions() {
        withCaseOnlyDictionary { dictionaryPath ->
            val generator = NameGenerator(
                RenameConfig(
                    dictionaryStyle = "custom-file",
                    dictionaryFile = dictionaryPath,
                    collisionPolicy = "append-index",
                ),
            )

            assertEquals(listOf("Alpha", "alpha_1", "ALPHA_2"), List(3) { generator.generateSimpleName("") })
        }
    }

    @Test
    fun rehash_resolves_case_only_dictionary_collisions() {
        withCaseOnlyDictionary { dictionaryPath ->
            val generator = NameGenerator(
                RenameConfig(
                    dictionaryStyle = "custom-file",
                    dictionaryFile = dictionaryPath,
                    collisionPolicy = "rehash",
                    seed = 0x10B,
                ),
            )

            val generatedNames = List(2) { generator.generateSimpleName("") }
            assertEquals(2, generatedNames.map { it.lowercase(Locale.ROOT) }.toSet().size)
        }
    }

    @Test
    fun fail_rejects_case_only_dictionary_collisions() {
        withCaseOnlyDictionary { dictionaryPath ->
            val generator = NameGenerator(
                RenameConfig(
                    dictionaryStyle = "custom-file",
                    dictionaryFile = dictionaryPath,
                    collisionPolicy = "fail",
                ),
            )

            assertEquals("Alpha", generator.generateSimpleName(""))
            assertFailsWith<IllegalStateException> { generator.generateSimpleName("") }
        }
    }

    @Test
    fun class_map_skips_preexisting_name_with_different_case() {
        val artifacts = listOf(
            testClassArtifact("com/example/Alpha"),
            testClassArtifact("COM/EXAMPLE/c0000"),
        )

        val renameMap = buildClassRenameMap(
            classArtifacts = artifacts,
            matchedClassNames = setOf("com/example/Alpha"),
        )

        assertEquals("com/example/C0001", renameMap["com/example/Alpha"])
    }

    private fun withCaseOnlyDictionary(block: (String) -> Unit) {
        val dictionary = Files.createTempFile("javashroud-case-collision", ".txt")
        try {
            Files.writeString(dictionary, "Alpha\nalpha\nALPHA\n")
            block(dictionary.toString())
        } finally {
            Files.deleteIfExists(dictionary)
        }
    }
}
