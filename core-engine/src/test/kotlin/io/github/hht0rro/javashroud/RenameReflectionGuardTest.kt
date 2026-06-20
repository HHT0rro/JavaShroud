package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.bytecode.remapMethods
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.naming.MemberKey
import io.github.hht0rro.javashroud.naming.MemberRename
import io.github.hht0rro.javashroud.transforms.rename.renameClasses
import io.github.hht0rro.javashroud.transforms.rename.renameFields
import io.github.hht0rro.javashroud.transforms.rename.renameMethods
import io.github.hht0rro.javashroud.transforms.rename.wellKnownExternalInstanceMethodSignatures
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.LdcInsnNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RenameReflectionGuardTest {
    @Test
    fun wellKnownExternalSignatures_include_jdk_callbacks_for_native_image() {
        assertTrue("run()V" in wellKnownExternalInstanceMethodSignatures("java/lang/Runnable"))
        assertTrue("compare(Ljava/lang/Object;Ljava/lang/Object;)I" in wellKnownExternalInstanceMethodSignatures("java/util/Comparator"))
        assertTrue("actionPerformed(Ljava/awt/event/ActionEvent;)V" in wellKnownExternalInstanceMethodSignatures("java/awt/event/ActionListener"))
        assertTrue("mouseClicked(Ljava/awt/event/MouseEvent;)V" in wellKnownExternalInstanceMethodSignatures("java/awt/event/MouseListener"))
        assertTrue("findClass(Ljava/lang/String;)Ljava/lang/Class;" in wellKnownExternalInstanceMethodSignatures("java/lang/ClassLoader"))
        assertTrue("getResourceAsStream(Ljava/lang/String;)Ljava/io/InputStream;" in wellKnownExternalInstanceMethodSignatures("java/lang/ClassLoader"))
    }

    @Test
    fun renameFields_rewrites_reflection_string_constants_with_field_renames() {
        val classBytes = buildReflectiveFieldLookupClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/ReflectiveFieldLookup",
            bytes = classBytes,
            fieldSummaries = listOf(
                MemberSummary(MemberKind.FIELD, "value", "I", 0),
                MemberSummary(MemberKind.FIELD, "other", "I", 0),
            ),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "lookup", "()Ljava/lang/reflect/Field;", 0)),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameFields(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val renamedFields = readFieldNames(result.artifact.classArtifacts.single().bytes)
        assertTrue("value" !in renamedFields, "Reflectively referenced field must be renamed rather than preserved")
        assertTrue(renamedFields.count { it.startsWith("f") } == 2, "Both fields should be renamed")
        assertTrue(readStringConstants(result.artifact.classArtifacts.single().bytes).any { it.startsWith("f") }, "Reflection field-name LDC must be rewritten to the renamed field")
        assertEquals(2, result.transformedMemberCount)
    }


    @Test
    fun renameFields_does_not_rewrite_non_reflection_status_strings() {
        val classBytes = buildStatusLoggingClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/StatusLogger",
            bytes = classBytes,
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "FAIL", "Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)),
            methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "status", "()Ljava/lang/String;", Opcodes.ACC_PUBLIC)),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameFields(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val constants = readStringConstants(result.artifact.classArtifacts.single().bytes)
        assertTrue("FAIL" in constants, "Non-reflection status strings must not be rewritten as field names")
    }


    @Test
    fun renameMethods_moves_main_body_but_keeps_entrypoint_bridge() {
        val classBytes = buildMainEntrypointClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/MainApp",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "main", "([Ljava/lang/String;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            ),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val methods = readMethodAccesses(result.artifact.classArtifacts.single().bytes)
        val renamedMain = methods.single { it.name != "<init>" && it.name != "main" }
        assertTrue(renamedMain.name.startsWith("m"), "main method body should still be renamed instead of skipped")
        assertTrue(
            methods.any { it.name == "main" && it.desc == "([Ljava/lang/String;)V" && it.access and Opcodes.ACC_BRIDGE != 0 },
            "Original public static main(String[]) entrypoint must remain as a thin ABI bridge",
        )
        assertTrue(
            readMethodCalls(result.artifact.classArtifacts.single().bytes).any { it.owner == "sample/MainApp" && it.name == renamedMain.name && it.desc == renamedMain.desc },
            "Entrypoint bridge must forward to the renamed main body",
        )
    }
    @Test
    fun renameMethods_renames_runnable_run_and_adds_abi_bridge() {
        val classBytes = buildRunnableImplementationClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/UiTask",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "run", "()V", Opcodes.ACC_PUBLIC),
                MemberSummary(MemberKind.METHOD, "helper", "()V", Opcodes.ACC_PUBLIC),
            ),
            interfaceNames = listOf("java/lang/Runnable"),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val renamedMethods = readMethodNames(result.artifact.classArtifacts.single().bytes)
        assertTrue("run" in renamedMethods, "Runnable.run()V bridge must remain for interface dispatch")
        assertTrue(renamedMethods.any { it.startsWith("m") }, "Runnable.run real body and helper should be renamed")
        assertEquals(1, result.transformedMemberCount)
    }


    @Test
    fun renameMethods_renames_comparator_compare_and_adds_abi_bridge() {
        val classBytes = buildComparatorImplementationClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/ScoreComparator",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "compare", "(Ljava/lang/Object;Ljava/lang/Object;)I", Opcodes.ACC_PUBLIC),
                MemberSummary(MemberKind.METHOD, "score", "(Ljava/lang/Object;)I", Opcodes.ACC_PUBLIC),
            ),
            interfaceNames = listOf("java/util/Comparator"),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val renamedMethods = readMethodNames(result.artifact.classArtifacts.single().bytes)
        assertTrue("compare" in renamedMethods, "Comparator.compare(Object,Object)I bridge must remain for JDK callbacks")
        assertTrue(renamedMethods.any { it.startsWith("m") }, "Comparator.compare real body and helper should be renamed")
        assertEquals(1, result.transformedMemberCount)
    }


    @Test
    fun renameMethods_keeps_runnable_bridge_after_class_rename() {
        val classBytes = buildRunnableImplementationClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/UiTask",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "run", "()V", Opcodes.ACC_PUBLIC),
                MemberSummary(MemberKind.METHOD, "helper", "()V", Opcodes.ACC_PUBLIC),
            ),
            interfaceNames = listOf("java/lang/Runnable"),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))
        val ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries)

        val classRenamed = renameClasses(artifact, ruleMatches, emptyMap()).artifact
        val result = renameMethods(
            artifact = classRenamed,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, classRenamed.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val renamedMethods = readMethodNames(result.artifact.classArtifacts.single().bytes)
        assertTrue("run" in renamedMethods, "Runnable.run()V bridge must survive class rename before method rename")
        assertTrue(renamedMethods.any { it.startsWith("m") }, "Real methods should still be renamed after class rename")
    }


    @Test
    fun renameClasses_includes_classes_that_declare_native_methods() {
        val classBytes = buildNativeMethodClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/NativeHost",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "nativeProbe", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_NATIVE),
            ),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameClasses(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val renamedClassName = readClassName(result.artifact.classArtifacts.single().bytes)
        assertTrue(renamedClassName != "sample/NativeHost", "Native-bearing classes must still be renamed and not filtered out")
    }

    @Test
    fun renameMethods_keeps_native_abi_and_adds_renamed_wrapper() {
        val classBytes = buildNativeMethodClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/NativeHost",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "nativeProbe", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_NATIVE),
            ),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val methods = readMethodAccesses(result.artifact.classArtifacts.single().bytes)
        assertTrue(methods.any { it.name == "nativeProbe" && it.access and Opcodes.ACC_NATIVE != 0 }, "Original JNI ABI method must remain native for symbol lookup")
        assertTrue(methods.any { it.name.startsWith("m") && it.desc == "()I" && it.access and Opcodes.ACC_NATIVE == 0 }, "Renamed callable wrapper must exist so rename coverage is real")
        assertEquals(1, result.transformedMemberCount)
    }

    @Test
    fun renameMethods_rewrites_annotation_element_value_names() {
        val annotationBytes = buildAnnotationTypeClass()
        val annotatedBytes = buildAnnotatedConsumerClass()
        val annotationArtifact = testClassArtifact(
            internalName = "sample/Marker",
            bytes = annotationBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "value", "()Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
                MemberSummary(MemberKind.METHOD, "code", "()I", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
            ),
            interfaceNames = listOf("java/lang/annotation/Annotation"),
        )
        val consumerArtifact = testClassArtifact(internalName = "sample/AnnotatedConsumer", bytes = annotatedBytes)
        val artifact = testAttachedArtifact(classArtifacts = listOf(annotationArtifact, consumerArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val updatedAnnotation = result.artifact.classArtifacts.first { it.summary.internalName == "sample/Marker" }.bytes
        val updatedConsumer = result.artifact.classArtifacts.first { it.summary.internalName == "sample/AnnotatedConsumer" }.bytes
        val renamedElements = readMethodNames(updatedAnnotation).filter { it.startsWith("m") }.toSet()
        val annotationValueNames = readRuntimeAnnotationElementNames(updatedConsumer, "Lsample/Marker;")
        assertEquals(2, renamedElements.size, "Annotation element methods must be genuinely renamed")
        assertTrue("value" !in annotationValueNames && "code" !in annotationValueNames, "Stored annotation element-value names must not keep stale originals")
        assertTrue(annotationValueNames.containsAll(renamedElements), "Stored annotation element-value names must follow renamed annotation accessors")
    }


    @Test
    fun renameMethods_rewrites_zero_arg_reflection_for_return_type_bridge_pair() {
        val ownerBytes = buildCallableReflectionOwnerClass()
        val callableBytes = buildCallableAnonymousClass()
        val ownerArtifact = testClassArtifact(
            internalName = "sample/CallableReflectionOwner",
            bytes = ownerBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "lookup", "(Ljava/lang/Object;)Ljava/lang/reflect/Method;", Opcodes.ACC_PUBLIC),
            ),
        )
        val callableArtifact = testClassArtifact(
            internalName = "sample/CallableReflectionOwner$1",
            bytes = callableBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "call", "()Ljava/lang/Long;", Opcodes.ACC_PUBLIC),
                MemberSummary(MemberKind.METHOD, "call", "()Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC),
            ),
            interfaceNames = listOf("java/util/concurrent/Callable"),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(ownerArtifact, callableArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val updatedOwner = result.artifact.classArtifacts.first { it.summary.internalName == "sample/CallableReflectionOwner" }.bytes
        val updatedCallable = result.artifact.classArtifacts.first { it.summary.internalName == "sample/CallableReflectionOwner$1" }.bytes
        val callableMethods = readMethodAccesses(updatedCallable)
        val renamedCallNames = callableMethods
            .filter { it.name != "call" && (it.desc == "()Ljava/lang/Long;" || it.desc == "()Ljava/lang/Object;") }
            .map { it.name }
            .toSet()
        val constants = readStringConstants(updatedOwner)
        assertEquals(1, renamedCallNames.size, "Return-type bridge pair must share one renamed reflection lookup name")
        assertTrue("call" !in constants, "getDeclaredMethod(\"call\") LDC must not keep stale original name")
        assertTrue(constants.containsAll(renamedCallNames), "Reflection LDC must follow renamed bridge-pair method name")
    }


    @Test
    fun renameMethods_rewrites_zero_arg_reflection_with_null_parameter_array() {
        val ownerBytes = buildNullParameterReflectionOwnerClass()
        val targetBytes = buildNullParameterReflectionTargetClass()
        val ownerArtifact = testClassArtifact(
            internalName = "sample/NullReflectionOwner",
            bytes = ownerBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "lookup", "()Ljava/lang/reflect/Method;", Opcodes.ACC_PUBLIC),
            ),
        )
        val targetArtifact = testClassArtifact(
            internalName = "sample/NullReflectionTarget",
            bytes = targetBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "add", "()V", Opcodes.ACC_PRIVATE),
            ),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(ownerArtifact, targetArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val updatedOwner = result.artifact.classArtifacts.first { it.summary.internalName == "sample/NullReflectionOwner" }.bytes
        val updatedTarget = result.artifact.classArtifacts.first { it.summary.internalName == "sample/NullReflectionTarget" }.bytes
        val renamedAddName = readMethodNames(updatedTarget).single { it != "<init>" && it != "add" }
        val constants = readStringConstants(updatedOwner)
        assertTrue("add" !in constants, "getDeclaredMethod(\"add\", null) LDC must not keep stale original name")
        assertTrue(renamedAddName in constants, "Null Class[] reflection lookup must follow renamed zero-arg method")
    }
    @Test
    fun renameMethods_keeps_regular_method_abi_bridge_for_vm_captured_calls() {
        val classBytes = buildLockedBoardClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/LockedBoard",
            bytes = classBytes,
            fieldSummaries = listOf(MemberSummary(MemberKind.FIELD, "locked", "Z", Opcodes.ACC_PRIVATE)),
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "setLocked", "(Z)V", Opcodes.ACC_PUBLIC),
            ),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val methods = readMethodAccesses(result.artifact.classArtifacts.single().bytes)
        val renamedSetter = methods.single { it.name != "<init>" && it.name != "setLocked" }
        assertTrue(renamedSetter.name.startsWith("m"), "Regular business method body should still be renamed")
        assertTrue(
            methods.none { it.name == "setLocked" && it.desc == "(Z)V" && it.access and Opcodes.ACC_BRIDGE != 0 },
            "Regular business methods must not expose extra ABI bridges because reflection getDeclaredMethods observes them",
        )
        assertTrue(
            readMethodCalls(result.artifact.classArtifacts.single().bytes).none { it.name == renamedSetter.name && it.desc == renamedSetter.desc },
            "Regular method rename should not add a bridge call unless the method is externally ABI-bound",
        )
        assertEquals(1, result.transformedMemberCount)
    }

    @Test
    fun remapMethods_bridge_injection_does_not_require_application_classpath_for_frames() {
        val classBytes = buildMissingClasspathFrameMergeClass()
        val key = MemberKey("sample/FrameMergeHost", "choose", "(Z)Ljava/lang/Object;")
        val renamedBytes = remapMethods(
            classBytes = classBytes,
            methodRenameMap = mapOf(
                key to MemberRename(
                    owner = key.owner,
                    originalName = key.name,
                    descriptor = key.descriptor,
                    renamedName = "m0000",
                ),
            ),
            bridgeMethodKeys = setOf(key),
        )

        val methods = readMethodAccesses(renamedBytes)
        assertTrue(methods.any { it.name == "m0000" && it.desc == "(Z)Ljava/lang/Object;" }, "Original method body must be renamed even when method frames mention classes absent from the engine classpath")
        assertTrue(methods.any { it.name == "choose" && it.desc == "(Z)Ljava/lang/Object;" && it.access and Opcodes.ACC_BRIDGE != 0 }, "ABI bridge must still be injected without recomputing unrelated application frames")
    }
    @Test
    fun renameMethods_preserves_compiler_synthetic_accessor_for_vm_captured_calls() {
        val classBytes = buildSyntheticAccessorHostClass()
        val classArtifact = testClassArtifact(
            internalName = "sample/AccessorHost",
            bytes = classBytes,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "<init>", "()V", 0),
                MemberSummary(MemberKind.METHOD, "access\$700", "(Lsample/AccessorHost;)Ljava/lang/Object;", Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC),
            ),
        )
        val artifact = testAttachedArtifact(classArtifacts = listOf(classArtifact))

        val result = renameMethods(
            artifact = artifact,
            ruleMatches = buildRuleMatches(testConfig().ruleSet, artifact.analysisSummary.classSummaries),
            params = emptyMap(),
        )

        val methods = readMethodAccesses(result.artifact.classArtifacts.single().bytes)
        assertTrue(
            methods.any { it.name == "access\$700" && it.desc == "(Lsample/AccessorHost;)Ljava/lang/Object;" },
            "Compiler synthetic accessor name must remain callable for VM/native captured callsites",
        )
        assertEquals(0, result.transformedMemberCount)
    }
    private fun buildLockedBoardClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/LockedBoard", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PRIVATE, "locked", "Z", null, null).visitEnd()
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val setter = writer.visitMethod(Opcodes.ACC_PUBLIC, "setLocked", "(Z)V", null, null)
        setter.visitCode()
        setter.visitVarInsn(Opcodes.ALOAD, 0)
        setter.visitVarInsn(Opcodes.ILOAD, 1)
        setter.visitFieldInsn(Opcodes.PUTFIELD, "sample/LockedBoard", "locked", "Z")
        setter.visitInsn(Opcodes.RETURN)
        setter.visitMaxs(2, 2)
        setter.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildMissingClasspathFrameMergeClass(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_5, Opcodes.ACC_PUBLIC, "sample/FrameMergeHost", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val choose = writer.visitMethod(Opcodes.ACC_PUBLIC, "choose", "(Z)Ljava/lang/Object;", null, null)
        val elseLabel = org.objectweb.asm.Label()
        val endLabel = org.objectweb.asm.Label()
        choose.visitCode()
        choose.visitVarInsn(Opcodes.ILOAD, 1)
        choose.visitJumpInsn(Opcodes.IFEQ, elseLabel)
        choose.visitTypeInsn(Opcodes.NEW, "missing/FrameA")
        choose.visitInsn(Opcodes.DUP)
        choose.visitMethodInsn(Opcodes.INVOKESPECIAL, "missing/FrameA", "<init>", "()V", false)
        choose.visitJumpInsn(Opcodes.GOTO, endLabel)
        choose.visitLabel(elseLabel)
        choose.visitTypeInsn(Opcodes.NEW, "missing/FrameB")
        choose.visitInsn(Opcodes.DUP)
        choose.visitMethodInsn(Opcodes.INVOKESPECIAL, "missing/FrameB", "<init>", "()V", false)
        choose.visitLabel(endLabel)
        choose.visitInsn(Opcodes.ARETURN)
        choose.visitMaxs(2, 2)
        choose.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
    private fun buildSyntheticAccessorHostClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/AccessorHost", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val accessor = writer.visitMethod(
            Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "access\$700",
            "(Lsample/AccessorHost;)Ljava/lang/Object;",
            null,
            null,
        )
        accessor.visitCode()
        accessor.visitTypeInsn(Opcodes.NEW, "java/lang/Object")
        accessor.visitInsn(Opcodes.DUP)
        accessor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        accessor.visitInsn(Opcodes.ARETURN)
        accessor.visitMaxs(2, 1)
        accessor.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
    private fun buildAnnotationTypeClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(
            Opcodes.V17,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_ANNOTATION or Opcodes.ACC_ABSTRACT or Opcodes.ACC_INTERFACE,
            "sample/Marker",
            null,
            "java/lang/Object",
            arrayOf("java/lang/annotation/Annotation"),
        )
        writer.visitAnnotation("Ljava/lang/annotation/Retention;", true).apply {
            visitEnum("value", "Ljava/lang/annotation/RetentionPolicy;", "RUNTIME")
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT, "value", "()Ljava/lang/String;", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT, "code", "()I", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildAnnotatedConsumerClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/AnnotatedConsumer", null, "java/lang/Object", null)
        writer.visitAnnotation("Lsample/Marker;", true).apply {
            visit("value", "ok")
            visit("code", 7)
            visitEnd()
        }
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildReflectiveFieldLookupClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/ReflectiveFieldLookup", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PRIVATE, "value", "I", null, null).visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE, "other", "I", null, null).visitEnd()
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC, "lookup", "()Ljava/lang/reflect/Field;", null, arrayOf("java/lang/NoSuchFieldException"))
        method.visitCode()
        method.visitLdcInsn(org.objectweb.asm.Type.getObjectType("sample/ReflectiveFieldLookup"))
        method.visitLdcInsn("value")
        method.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredField",
            "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
            false,
        )
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(2, 1)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }


    private fun buildStatusLoggingClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/StatusLogger", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "FAIL", "Ljava/lang/String;", null, null).visitEnd()
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC, "status", "()Ljava/lang/String;", null, null)
        method.visitCode()
        method.visitLdcInsn("FAIL")
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(1, 1)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildMainEntrypointClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/MainApp", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val main = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        main.visitCode()
        main.visitInsn(Opcodes.RETURN)
        main.visitMaxs(0, 1)
        main.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
    private fun buildRunnableImplementationClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/UiTask", null, "java/lang/Object", arrayOf("java/lang/Runnable"))
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val run = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null)
        run.visitCode()
        run.visitInsn(Opcodes.RETURN)
        run.visitMaxs(0, 1)
        run.visitEnd()
        val helper = writer.visitMethod(Opcodes.ACC_PUBLIC, "helper", "()V", null, null)
        helper.visitCode()
        helper.visitInsn(Opcodes.RETURN)
        helper.visitMaxs(0, 1)
        helper.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildComparatorImplementationClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/ScoreComparator", null, "java/lang/Object", arrayOf("java/util/Comparator"))
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val compare = writer.visitMethod(Opcodes.ACC_PUBLIC, "compare", "(Ljava/lang/Object;Ljava/lang/Object;)I", null, null)
        compare.visitCode()
        compare.visitInsn(Opcodes.ICONST_0)
        compare.visitInsn(Opcodes.IRETURN)
        compare.visitMaxs(1, 3)
        compare.visitEnd()
        val score = writer.visitMethod(Opcodes.ACC_PUBLIC, "score", "(Ljava/lang/Object;)I", null, null)
        score.visitCode()
        score.visitInsn(Opcodes.ICONST_1)
        score.visitInsn(Opcodes.IRETURN)
        score.visitMaxs(1, 2)
        score.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }


    private fun buildNativeMethodClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/NativeHost", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_NATIVE, "nativeProbe", "()I", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }


    private fun buildCallableReflectionOwnerClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/CallableReflectionOwner", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC, "lookup", "(Ljava/lang/Object;)Ljava/lang/reflect/Method;", null, arrayOf("java/lang/NoSuchMethodException"))
        method.visitCode()
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false)
        method.visitLdcInsn("call")
        method.visitInsn(Opcodes.ICONST_0)
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class")
        method.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            false,
        )
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(3, 2)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildCallableAnonymousClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_FINAL, "sample/CallableReflectionOwner$1", null, "java/lang/Object", arrayOf("java/util/concurrent/Callable"))
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val typedCall = writer.visitMethod(Opcodes.ACC_PUBLIC, "call", "()Ljava/lang/Long;", null, null)
        typedCall.visitCode()
        typedCall.visitLdcInsn(7L)
        typedCall.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
        typedCall.visitInsn(Opcodes.ARETURN)
        typedCall.visitMaxs(2, 1)
        typedCall.visitEnd()
        val bridgeCall = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC, "call", "()Ljava/lang/Object;", null, null)
        bridgeCall.visitCode()
        bridgeCall.visitVarInsn(Opcodes.ALOAD, 0)
        bridgeCall.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "sample/CallableReflectionOwner$1", "call", "()Ljava/lang/Long;", false)
        bridgeCall.visitInsn(Opcodes.ARETURN)
        bridgeCall.visitMaxs(1, 1)
        bridgeCall.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildNullParameterReflectionOwnerClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/NullReflectionOwner", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC, "lookup", "()Ljava/lang/reflect/Method;", null, arrayOf("java/lang/NoSuchMethodException"))
        method.visitCode()
        method.visitLdcInsn(org.objectweb.asm.Type.getObjectType("sample/NullReflectionTarget"))
        method.visitLdcInsn("add")
        method.visitInsn(Opcodes.ACONST_NULL)
        method.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            false,
        )
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(3, 1)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildNullParameterReflectionTargetClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/NullReflectionTarget", null, "java/lang/Object", null)
        val constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        constructor.visitCode()
        constructor.visitVarInsn(Opcodes.ALOAD, 0)
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        constructor.visitInsn(Opcodes.RETURN)
        constructor.visitMaxs(1, 1)
        constructor.visitEnd()
        val add = writer.visitMethod(Opcodes.ACC_PRIVATE, "add", "()V", null, null)
        add.visitCode()
        add.visitInsn(Opcodes.RETURN)
        add.visitMaxs(0, 1)
        add.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
    private fun readRuntimeAnnotationElementNames(bytes: ByteArray, descriptor: String): Set<String> {
        val node = org.objectweb.asm.tree.ClassNode()
        ClassReader(bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        val annotation = node.visibleAnnotations.orEmpty().first { it.desc == descriptor }
        val values = annotation.values.orEmpty()
        return values.filterIndexed { index, _ -> index % 2 == 0 }.filterIsInstance<String>().toSet()
    }

    private fun readStringConstants(bytes: ByteArray): Set<String> {
        val constants = linkedSetOf<String>()
        val node = org.objectweb.asm.tree.ClassNode()
        ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        for (method in node.methods) {
            for (instruction in method.instructions) {
                val value = (instruction as? LdcInsnNode)?.cst as? String ?: continue
                constants += value
            }
        }
        return constants
    }


    private data class MethodAccess(val name: String, val desc: String, val access: Int)

    private fun readClassName(bytes: ByteArray): String = ClassReader(bytes).className

    private fun readMethodAccesses(bytes: ByteArray): List<MethodAccess> {
        val methods = mutableListOf<MethodAccess>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): org.objectweb.asm.MethodVisitor? {
                if (name != null && descriptor != null) methods += MethodAccess(name, descriptor, access)
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return methods
    }

    private data class MethodCall(val owner: String, val name: String, val desc: String)

    private fun readMethodCalls(bytes: ByteArray): List<MethodCall> {
        val calls = mutableListOf<MethodCall>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): org.objectweb.asm.MethodVisitor {
                return object : org.objectweb.asm.MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                        calls += MethodCall(owner, name, descriptor)
                    }
                }
            }
        }, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return calls
    }
    private fun readMethodNames(bytes: ByteArray): Set<String> {
        val names = linkedSetOf<String>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): org.objectweb.asm.MethodVisitor? {
                if (name != null) names += name
                return super.visitMethod(access, name, descriptor, signature, exceptions)
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return names
    }

    private fun readFieldNames(bytes: ByteArray): Set<String> {
        val names = linkedSetOf<String>()
        ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitField(access: Int, name: String?, descriptor: String?, signature: String?, value: Any?): org.objectweb.asm.FieldVisitor? {
                if (name != null) names += name
                return super.visitField(access, name, descriptor, signature, value)
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return names
    }
}

