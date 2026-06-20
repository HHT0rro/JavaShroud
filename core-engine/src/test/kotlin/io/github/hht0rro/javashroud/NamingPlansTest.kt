package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.naming.applyPackageRenameMap
import io.github.hht0rro.javashroud.naming.buildClassRenameMap
import io.github.hht0rro.javashroud.naming.buildFieldRenameMap
import io.github.hht0rro.javashroud.naming.buildMemberKey
import io.github.hht0rro.javashroud.naming.buildMethodKey
import io.github.hht0rro.javashroud.naming.buildMethodRenameMap
import io.github.hht0rro.javashroud.naming.buildPackageRenameMap
import io.github.hht0rro.javashroud.naming.RenameConfig
import io.github.hht0rro.javashroud.naming.canRenameMethod
import io.github.hht0rro.javashroud.naming.isEnumClass
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NamingPlansTest {

    @Test
    fun buildClassRenameMap_renames_matched_classes_sequentially() {
        val artifacts = listOf(
            testClassArtifact("com/example/Beta"),
            testClassArtifact("com/example/Alpha"),
        )
        val map = buildClassRenameMap(artifacts, setOf("com/example/Alpha", "com/example/Beta"))
        assertEquals("com/example/C0000", map["com/example/Alpha"])
        assertEquals("com/example/C0001", map["com/example/Beta"])
    }

    @Test
    fun buildClassRenameMap_excludes_unmatched_classes() {
        val artifacts = listOf(
            testClassArtifact("com/example/Foo"),
            testClassArtifact("com/example/Bar"),
        )
        val map = buildClassRenameMap(artifacts, setOf("com/example/Foo"))
        assertEquals(1, map.size)
        assertEquals("com/example/C0000", map["com/example/Foo"])
    }

    @Test
    fun buildClassRenameMap_returns_empty_for_no_matches() {
        val artifacts = listOf(testClassArtifact("com/example/Foo"))
        val map = buildClassRenameMap(artifacts, emptySet())
        assertTrue(map.isEmpty())
    }

    @Test
    fun buildClassRenameMap_preserves_package_prefix() {
        val artifacts = listOf(testClassArtifact("org/lib/MyClass"))
        val map = buildClassRenameMap(artifacts, setOf("org/lib/MyClass"))
        assertEquals("org/lib/C0000", map["org/lib/MyClass"])
    }

    @Test
    fun buildClassRenameMap_handles_default_package() {
        val artifacts = listOf(testClassArtifact("Standalone"))
        val map = buildClassRenameMap(artifacts, setOf("Standalone"))
        assertEquals("C0000", map["Standalone"])
    }

    @Test
    fun buildPackageRenameMap_extracts_and_renames_packages() {
        val artifacts = listOf(
            testClassArtifact("com/alpha/Foo"),
            testClassArtifact("com/alpha/Bar"),
            testClassArtifact("com/beta/Baz"),
        )
        val map = buildPackageRenameMap(artifacts, setOf("com/alpha/Foo", "com/alpha/Bar", "com/beta/Baz"))
        assertEquals("p0000", map["com/alpha"])
        assertEquals("p0001", map["com/beta"])
    }

    @Test
    fun buildPackageRenameMap_can_preserve_original_segment_count() {
        val artifacts = listOf(
            testClassArtifact("com/alpha/Foo"),
            testClassArtifact("com/beta/Baz"),
        )
        val map = buildPackageRenameMap(
            artifacts,
            setOf("com/alpha/Foo", "com/beta/Baz"),
            RenameConfig(shufflePackageSegmentCount = false),
        )
        assertEquals("p0000/p0001", map["com/alpha"])
        assertEquals("p0002/p0003", map["com/beta"])
    }

    @Test
    fun buildPackageRenameMap_preserves_configured_leading_segments_when_shuffling_count() {
        val artifacts = listOf(testClassArtifact("com/example/deep/Foo"))
        val map = buildPackageRenameMap(
            artifacts,
            setOf("com/example/deep/Foo"),
            RenameConfig(preservePackageDepth = 1),
        )
        assertEquals("com/p0000", map["com/example/deep"])
    }

    @Test
    fun buildPackageRenameMap_ignores_default_package() {
        val artifacts = listOf(testClassArtifact("Standalone"))
        val map = buildPackageRenameMap(artifacts, setOf("Standalone"))
        assertTrue(map.isEmpty())
    }

    @Test
    fun applyPackageRenameMap_applies_renames() {
        val artifacts = listOf(
            testClassArtifact("com/example/Foo"),
            testClassArtifact("com/example/Bar"),
        )
        val packageMap = mapOf("com/example" to "p0000")
        val result = applyPackageRenameMap(artifacts, packageMap)
        assertEquals("p0000/Foo", result["com/example/Foo"])
        assertEquals("p0000/Bar", result["com/example/Bar"])
    }

    @Test
    fun applyPackageRenameMap_returns_empty_for_empty_map() {
        val artifacts = listOf(testClassArtifact("com/example/Foo"))
        val result = applyPackageRenameMap(artifacts, emptyMap())
        assertTrue(result.isEmpty())
    }

    @Test
    fun applyPackageRenameMap_skips_unmapped_packages() {
        val artifacts = listOf(testClassArtifact("com/example/Foo"))
        val packageMap = mapOf("org/other" to "p0000")
        val result = applyPackageRenameMap(artifacts, packageMap)
        assertTrue(result.isEmpty())
    }

    @Test
    fun buildMethodRenameMap_renames_matched_methods() {
        val matchedMembers = listOf(
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "alpha", descriptor = "()V"),
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "beta", descriptor = "()V"),
        )
        val map = buildMethodRenameMap(matchedMembers)
        assertEquals(2, map.size)
        assertEquals("m0000", map[MemberKey("com/example/Foo", "alpha", "()V")]?.renamedName)
        assertEquals("m0001", map[MemberKey("com/example/Foo", "beta", "()V")]?.renamedName)
    }

    @Test
    fun buildMethodRenameMap_excludes_fields() {
        val matchedMembers = listOf(
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.FIELD, name = "value", descriptor = "I"),
        )
        val map = buildMethodRenameMap(matchedMembers)
        assertTrue(map.isEmpty())
    }

    @Test
    fun buildMethodRenameMap_excludes_jvm_lifecycle_and_compiler_accessors() {
        val matchedMembers = listOf(
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "<init>", descriptor = "()V"),
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "<clinit>", descriptor = "()V"),
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "lambda${'$'}run${'$'}0", descriptor = "()V"),
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "access${'$'}000", descriptor = "()V"),
        )
        val map = buildMethodRenameMap(matchedMembers)
        assertEquals(1, map.size)
        assertTrue(MemberKey("com/example/Foo", "lambda${'$'}run${'$'}0", "()V") in map)
        assertFalse(MemberKey("com/example/Foo", "access${'$'}000", "()V") in map)
    }

    @Test
    fun buildFieldRenameMap_renames_matched_fields() {
        val matchedMembers = listOf(
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.FIELD, name = "alpha", descriptor = "I"),
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.FIELD, name = "beta", descriptor = "I"),
        )
        val map = buildFieldRenameMap(matchedMembers)
        assertEquals(2, map.size)
        assertEquals("f0000", map[MemberKey("com/example/Foo", "alpha", "I")]?.renamedName)
        assertEquals("f0001", map[MemberKey("com/example/Foo", "beta", "I")]?.renamedName)
    }

    @Test
    fun buildFieldRenameMap_excludes_methods() {
        val matchedMembers = listOf(
            MatchedMember(owner = "com/example/Foo", kind = MemberKind.METHOD, name = "doWork", descriptor = "()V"),
        )
        val map = buildFieldRenameMap(matchedMembers)
        assertTrue(map.isEmpty())
    }

    @Test
    fun canRenameMethod_returns_true_for_regular_methods() {
        assertTrue(canRenameMethod("doWork"))
        assertTrue(canRenameMethod("process"))
        assertTrue(canRenameMethod("a"))
    }

    @Test
    fun canRenameMethod_rejects_jvm_lifecycle_and_compiler_accessors() {
        assertFalse(canRenameMethod("<init>"))
        assertFalse(canRenameMethod("<clinit>"))
        assertTrue(canRenameMethod("lambda${'$'}run${'$'}0"))
        assertFalse(canRenameMethod("access${'$'}000"))
        assertTrue(canRenameMethod("a_bsm0"))
        assertTrue(canRenameMethod("\$_f_bsm"))
        assertTrue(canRenameMethod("\$_habc123"))
        assertTrue(canRenameMethod("\$_j_mh_0"))
        assertTrue(canRenameMethod("\$_j_mcs_0"))
    }

    @Test
    fun isEnumClass_detects_acc_enum() {
        assertTrue(isEnumClass(Opcodes.ACC_ENUM))
        assertTrue(isEnumClass(Opcodes.ACC_ENUM or Opcodes.ACC_PUBLIC))
    }

    @Test
    fun isEnumClass_returns_false_for_regular_class() {
        assertFalse(isEnumClass(Opcodes.ACC_PUBLIC))
        assertFalse(isEnumClass(0))
    }

    @Test
    fun buildMethodKey_concatenates_name_and_descriptor() {
        assertEquals("doWork:()V", buildMethodKey("doWork", "()V"))
        assertEquals("get:(I)Ljava/lang/String;", buildMethodKey("get", "(I)Ljava/lang/String;"))
    }

    @Test
    fun buildMemberKey_concatenates_kind_name_descriptor() {
        assertEquals("METHOD:doWork:()V", buildMemberKey(MemberKind.METHOD, "doWork", "()V"))
        assertEquals("FIELD:value:I", buildMemberKey(MemberKind.FIELD, "value", "I"))
    }
}
