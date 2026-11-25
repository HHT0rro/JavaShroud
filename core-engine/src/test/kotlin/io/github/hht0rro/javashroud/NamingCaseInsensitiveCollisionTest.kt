package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.naming.NameGenerator
import io.github.hht0rro.javashroud.naming.RenameConfig
import io.github.hht0rro.javashroud.naming.applyPackageRenameMap
import io.github.hht0rro.javashroud.naming.buildClassRenameMap
import io.github.hht0rro.javashroud.naming.buildPackageRenameMap
import java.nio.file.Files
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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

    @Test
    fun package_map_skips_case_folded_final_path_collisions() {
        val artifacts = listOf(
            testClassArtifact("foo/A"),
            testClassArtifact("P0000/A"),
        )

        val packageRenameMap = buildPackageRenameMap(
            classArtifacts = artifacts,
            matchedClassNames = setOf("foo/A"),
            config = RenameConfig(dictionaryStyle = "sequential", seed = 1L),
        )
        val classRenameMap = applyPackageRenameMap(artifacts, packageRenameMap)

        assertFalse(packageRenameMap.getValue("foo").equals("p0000", ignoreCase = true))
        assertFalse(classRenameMap.getValue("foo/A").equals("P0000/A", ignoreCase = true))
        val normalized = (listOf("P0000/A") + classRenameMap.values).map { it.lowercase(Locale.ROOT) }
        assertEquals(normalized.size, normalized.toSet().size)
    }

    @Test
    fun package_map_projects_only_selected_classes_from_mixed_package() {
        val artifacts = listOf(
            testClassArtifact("foo/Selected"),
            testClassArtifact("foo/Unselected"),
        )
        val selectedClassNames = setOf("foo/Selected")

        val packageRenameMap = buildPackageRenameMap(
            classArtifacts = artifacts,
            matchedClassNames = selectedClassNames,
            config = RenameConfig(dictionaryStyle = "sequential", seed = 1L),
        )
        val classRenameMap = applyPackageRenameMap(
            classArtifacts = artifacts,
            packageRenameMap = packageRenameMap,
            selectedClassNames = selectedClassNames,
        )

        assertEquals(setOf("foo/Selected"), classRenameMap.keys)
        assertFalse("foo/Unselected" in classRenameMap)
    }

    @Test
    fun package_map_disambiguates_selected_case_folded_simple_name_collisions() {
        // Pre-obfuscated inputs routinely carry a/A in one package. The package
        // rename keeps them grouped and disambiguates the case-folded collision
        // with a generated simple name instead of failing the whole run.
        val artifacts = listOf(
            testClassArtifact("foo/Alpha"),
            testClassArtifact("foo/alpha"),
        )
        val matched = artifacts.mapTo(mutableSetOf()) { it.summary.internalName }

        val packageRenameMap = buildPackageRenameMap(
            classArtifacts = artifacts,
            matchedClassNames = matched,
        )
        val classRenameMap = applyPackageRenameMap(artifacts, packageRenameMap, matched)

        assertEquals(matched, classRenameMap.keys)
        val normalized = classRenameMap.values.map { it.lowercase(Locale.ROOT) }
        assertEquals(normalized.size, normalized.toSet().size, "final names must stay case-fold unique: $classRenameMap")
        // One of the two keeps its simple name; the other moves to a generated one.
        val simpleNames = classRenameMap.values.map { it.substringAfterLast('/') }
        assertEquals(2, simpleNames.toSet().size)
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
