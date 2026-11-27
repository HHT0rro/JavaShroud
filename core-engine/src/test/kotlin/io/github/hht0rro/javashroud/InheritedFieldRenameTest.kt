package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.rename.renameFields
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InheritedFieldRenameTest {
    @Test
    fun renameFieldsResolvesParentFieldsReferencedThroughSubclassOwners() {
        val classes = mapOf(
            PARENT to fixtureClass(PARENT) { visitField(Opcodes.ACC_PUBLIC, "resumeMode", "I", null, null).visitEnd() },
            CHILD to fixtureClass(CHILD, PARENT),
            LEAF to fixtureClass(LEAF, CHILD),
            CALLER to instanceCaller(listOf(Triple("Parent", PARENT, "I"), Triple("Child", CHILD, "I"), Triple("Leaf", LEAF, "I"))),
        )
        val renamed = rename(classes)
        val loader = isolatedLoader(renamed)
        val instance = loader.loadClass(LEAF.replace('/', '.')).getConstructor().newInstance()

        access(loader, "writeChild", instance, 17)
        assertEquals(17, access(loader, "readParent", instance))
        assertEquals(17, access(loader, "readLeaf", instance))
        access(loader, "writeLeaf", instance, 29)
        assertEquals(29, access(loader, "readChild", instance))
        assertFalse(loader.loadClass(PARENT.replace('/', '.')).declaredFields.any { it.name == "resumeMode" })
        assertTrue(loader.loadClass(CHILD.replace('/', '.')).declaredFields.isEmpty())
    }

    @Test
    fun renameFieldsKeepsRenamedHiddenFieldsIndependent() {
        assertHiddenFields(keptOwners = emptySet())
    }

    @Test
    fun renameFieldsStopsAtKeptHiddenDeclarations() {
        assertHiddenFields(keptOwners = setOf(CHILD))
    }

    @Test
    fun renameFieldsFollowsRenamedDeclarationsThroughKeptReferenceOwners() {
        assertHiddenFields(keptOwners = setOf(LEAF))
    }

    @Test
    fun renameFieldsPreservesKeptParentsAndUnrelatedSameNameFields() {
        assertHiddenFields(keptOwners = setOf(PARENT, UNRELATED))
    }

    @Test
    fun renameFieldsResolvesFieldsByBothNameAndDescriptor() {
        val classes = mapOf(
            PARENT to fixtureClass(PARENT) { visitField(Opcodes.ACC_PUBLIC, "resumeMode", "I", null, null).visitEnd() },
            CHILD to fixtureClass(CHILD, PARENT) { visitField(Opcodes.ACC_PUBLIC, "resumeMode", "J", null, null).visitEnd() },
            LEAF to fixtureClass(LEAF, CHILD),
            CALLER to instanceCaller(listOf(Triple("Parent", LEAF, "I"), Triple("Child", LEAF, "J"))),
        )
        val loader = isolatedLoader(rename(classes))
        val instance = loader.loadClass(LEAF.replace('/', '.')).getConstructor().newInstance()

        access(loader, "writeParent", instance, 41)
        access(loader, "writeChild", instance, 9_000_000_007L)
        assertEquals(41, access(loader, "readParent", instance))
        assertEquals(9_000_000_007L, access(loader, "readChild", instance))
    }

    @Test
    fun renameFieldsResolvesInterfaceStaticFieldsBeforeSuperclassFields() {
        assertInterfaceFields(keptOwners = emptySet())
    }

    @Test
    fun renameFieldsStopsAtKeptInterfaceStaticDeclarations() {
        assertInterfaceFields(keptOwners = setOf(ROOT_INTERFACE))
    }

    @Test
    fun renameFieldsPreservesReferencesAcrossUnknownInterfaceBoundaries() {
        val externalInterface = fixtureClass(ROOT_INTERFACE, isInterface = true) {
            visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "resumeMode", "I", null, 53).visitEnd()
        }
        val classes = mapOf(
            PARENT to fixtureClass(PARENT) {
                visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "resumeMode", "I", null, 13).visitEnd()
            },
            CHILD to fixtureClass(CHILD, PARENT, arrayOf(ROOT_INTERFACE)),
            CALLER to fixtureClass(CALLER) {
                visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read", "()I", null, null).apply {
                    visitCode()
                    visitFieldInsn(Opcodes.GETSTATIC, CHILD, "resumeMode", "I")
                    visitInsn(Opcodes.IRETURN)
                    visitMaxs(0, 0)
                    visitEnd()
                }
            },
        )
        val loader = isolatedLoader(rename(classes) + (ROOT_INTERFACE to externalInterface))
        assertEquals(53, access(loader, "read"))
    }

    @Test
    fun renameFieldsKeepsPossibleParentDeclarationsAcrossUnknownEmptyInterfaces() {
        val externalInterface = fixtureClass(ROOT_INTERFACE, isInterface = true)
        val classes = mapOf(
            PARENT to fixtureClass(PARENT) {
                visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "resumeMode", "I", null, 13).visitEnd()
            },
            CHILD to fixtureClass(CHILD, PARENT, arrayOf(ROOT_INTERFACE)),
            UNRELATED to fixtureClass(UNRELATED) {
                visitField(Opcodes.ACC_PUBLIC, "resumeMode", "I", null, null).visitEnd()
            },
            CALLER to fixtureClass(CALLER) {
                visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read", "()I", null, null).apply {
                    visitCode()
                    visitFieldInsn(Opcodes.GETSTATIC, CHILD, "resumeMode", "I")
                    visitInsn(Opcodes.IRETURN)
                    visitMaxs(0, 0)
                    visitEnd()
                }
            },
        )
        val loader = isolatedLoader(rename(classes) + (ROOT_INTERFACE to externalInterface))
        assertEquals(13, access(loader, "read"))
        assertTrue(loader.loadClass(PARENT.replace('/', '.')).declaredFields.single().name == "resumeMode")
        assertFalse(loader.loadClass(UNRELATED.replace('/', '.')).declaredFields.single().name == "resumeMode")
    }

    private fun assertHiddenFields(keptOwners: Set<String>) {
        val classes = mapOf(
            PARENT to fixtureClass(PARENT) { visitField(Opcodes.ACC_PUBLIC, "resumeMode", "I", null, null).visitEnd() },
            CHILD to fixtureClass(CHILD, PARENT) { visitField(Opcodes.ACC_PUBLIC, "resumeMode", "I", null, null).visitEnd() },
            LEAF to fixtureClass(LEAF, CHILD),
            UNRELATED to fixtureClass(UNRELATED) { visitField(Opcodes.ACC_PUBLIC, "resumeMode", "I", null, null).visitEnd() },
            CALLER to instanceCaller(listOf(Triple("Parent", PARENT, "I"), Triple("Child", CHILD, "I"), Triple("Leaf", LEAF, "I"))),
        )
        val loader = isolatedLoader(rename(classes, keptOwners))
        val instance = loader.loadClass(LEAF.replace('/', '.')).getConstructor().newInstance()

        access(loader, "writeParent", instance, 11)
        access(loader, "writeLeaf", instance, 23)
        assertEquals(11, access(loader, "readParent", instance))
        assertEquals(23, access(loader, "readChild", instance))
        access(loader, "writeChild", instance, 37)
        assertEquals(11, access(loader, "readParent", instance))
        assertEquals(37, access(loader, "readLeaf", instance))
        for (owner in listOf(PARENT, CHILD, UNRELATED)) {
            assertEquals(
                owner in keptOwners,
                loader.loadClass(owner.replace('/', '.')).declaredFields.single().name == "resumeMode",
                "Field preservation must follow its declaration in $owner",
            )
        }
    }

    private fun assertInterfaceFields(keptOwners: Set<String>) {
        val classes = mapOf(
            ROOT_INTERFACE to fixtureClass(ROOT_INTERFACE, isInterface = true) {
                visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "resumeMode", "I", null, null).visitEnd()
                visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null).apply {
                    visitCode()
                    visitIntInsn(Opcodes.BIPUSH, 31)
                    visitFieldInsn(Opcodes.PUTSTATIC, ROOT_INTERFACE, "resumeMode", "I")
                    visitInsn(Opcodes.RETURN)
                    visitMaxs(0, 0)
                    visitEnd()
                }
            },
            SUB_INTERFACE to fixtureClass(SUB_INTERFACE, interfaces = arrayOf(ROOT_INTERFACE), isInterface = true),
            PARENT to fixtureClass(PARENT) {
                visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "resumeMode", "I", null, 13).visitEnd()
            },
            CHILD to fixtureClass(CHILD, PARENT, arrayOf(SUB_INTERFACE)),
            LEAF to fixtureClass(LEAF, CHILD),
            CALLER to fixtureClass(CALLER) {
                for ((label, owner) in listOf("Interface" to ROOT_INTERFACE, "SubInterface" to SUB_INTERFACE, "Leaf" to LEAF, "Parent" to PARENT)) {
                    visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read$label", "()I", null, null).apply {
                        visitCode()
                        visitFieldInsn(Opcodes.GETSTATIC, owner, "resumeMode", "I")
                        visitInsn(Opcodes.IRETURN)
                        visitMaxs(0, 0)
                        visitEnd()
                    }
                }
            },
        )
        val loader = isolatedLoader(rename(classes, keptOwners))
        assertEquals(31, access(loader, "readInterface"))
        assertEquals(31, access(loader, "readSubInterface"))
        assertEquals(31, access(loader, "readLeaf"))
        assertEquals(13, access(loader, "readParent"))
    }

    private fun rename(classes: Map<String, ByteArray>, keptOwners: Set<String> = emptySet()): Map<String, ByteArray> {
        val artifact = testAttachedArtifact(
            classArtifacts = classes.map { (owner, bytes) -> ClassArtifact("$owner.class", analyzeClassBytes(bytes), bytes) },
        )
        val ruleSet = RuleSet(rules = keptOwners.map { RuleSpec(target = it, action = "exclude") })
        val result = renameFields(
            artifact,
            buildRuleMatches(ruleSet, artifact.analysisSummary.classSummaries),
            emptyMap(),
        )
        return result.artifact.classArtifacts.associate { it.summary.internalName to it.bytes }
    }

    private fun instanceCaller(references: List<Triple<String, String, String>>): ByteArray = fixtureClass(CALLER) {
        for ((label, owner, descriptor) in references) {
            val type = Type.getType(descriptor)
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "write$label", "(L$LEAF;$descriptor)V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitVarInsn(type.getOpcode(Opcodes.ILOAD), 1)
                visitFieldInsn(Opcodes.PUTFIELD, owner, "resumeMode", descriptor)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
            visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "read$label", "(L$LEAF;)$descriptor", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitFieldInsn(Opcodes.GETFIELD, owner, "resumeMode", descriptor)
                visitInsn(type.getOpcode(Opcodes.IRETURN))
                visitMaxs(0, 0)
                visitEnd()
            }
        }
    }

    private fun fixtureClass(
        owner: String,
        superName: String = "java/lang/Object",
        interfaces: Array<String> = emptyArray(),
        isInterface: Boolean = false,
        body: ClassWriter.() -> Unit = {},
    ): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        val access = if (isInterface) Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT else Opcodes.ACC_PUBLIC
        writer.visit(Opcodes.V1_8, access, owner, null, superName, interfaces)
        if (!isInterface) {
            writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
                visitCode()
                visitVarInsn(Opcodes.ALOAD, 0)
                visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false)
                visitInsn(Opcodes.RETURN)
                visitMaxs(0, 0)
                visitEnd()
            }
        }
        writer.body()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun isolatedLoader(classes: Map<String, ByteArray>): ClassLoader = object : ClassLoader(null) {
        override fun findClass(name: String): Class<*> {
            val bytes = classes[name.replace('.', '/')] ?: throw ClassNotFoundException(name)
            return defineClass(name, bytes, 0, bytes.size)
        }
    }

    private fun access(loader: ClassLoader, name: String, vararg arguments: Any): Any? =
        loader.loadClass(CALLER.replace('/', '.')).declaredMethods.single { it.name == name }.invoke(null, *arguments)

    private companion object {
        const val PARENT = "inherited/Parent"
        const val CHILD = "inherited/Child"
        const val LEAF = "inherited/Leaf"
        const val UNRELATED = "inherited/Unrelated"
        const val CALLER = "inherited/Caller"
        const val ROOT_INTERFACE = "inherited/RootFields"
        const val SUB_INTERFACE = "inherited/SubFields"
    }
}
