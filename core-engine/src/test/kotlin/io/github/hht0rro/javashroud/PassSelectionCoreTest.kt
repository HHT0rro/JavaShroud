package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.analysis.effectiveRuleSetForPass
import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.analysis.eligibleMembersForAction
import io.github.hht0rro.javashroud.config.decodeConfig
import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.PassSelectionSpec
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PassSelectionCoreTest {
    private val mapper = ObjectMapper()
    private val configPath = Path.of("C:/tmp/pass-selection.toml")

    @Test
    fun selectedOnly_compiles_all_obfuscation_baseline_without_local_rules() {
        val config = testConfig(
            passes = listOf(testPassSpec(id = "method-virtualization")),
            ruleSet = buildTargetedRuleSet(
                passIds = listOf("method-virtualization"),
                targetedClasses = setOf("sample/GlobalOnly"),
            ),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = emptyList(),
                ),
            ),
        )
        val classes = listOf(
            testClassArtifact(
                internalName = "sample/Target",
                methodSummaries = listOf(
                    MemberSummary(MemberKind.METHOD, "selected", "()I", 0),
                    MemberSummary(MemberKind.METHOD, "other", "()I", 0),
                ),
            ),
            testClassArtifact(
                internalName = "sample/GlobalOnly",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "other", "()I", 0)),
            ),
        )

        val effective = effectiveRuleSetForPass(config, "method-virtualization")
        val matches = buildRuleMatches(effective, classes.map { it.summary })
        val classNames = eligibleClassNamesForAction(classes, matches, "method-virtualization")
        val methods = eligibleMembersForAction(classes, matches, "method-virtualization")
            .filter { it.kind == MemberKind.METHOD }

        assertEquals(setOf("sample/Target", "sample/GlobalOnly"), classNames)
        assertEquals(
            setOf("sample/Target#selected()I", "sample/Target#other()I", "sample/GlobalOnly#other()I"),
            methods.map { "${it.owner}#${it.name}${it.descriptor}" }.toSet(),
        )
        assertEquals(listOf(RuleSpec("*", "method-virtualization")), effective.rules)
    }

    @Test
    fun selectedOnly_excludes_only_the_exact_method_and_preserves_overloads() {
        val config = testConfig(
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(RuleSpec("sample/Target#find:(I)Ljava/lang/String;", "exclude")),
                ),
            ),
        )
        val classes = listOf(
            testClassArtifact(
                internalName = "sample/Target",
                methodSummaries = listOf(
                    MemberSummary(MemberKind.METHOD, "find", "(Ljava/lang/String;)Ljava/lang/String;", 0),
                    MemberSummary(MemberKind.METHOD, "find", "(I)Ljava/lang/String;", 0),
                    MemberSummary(MemberKind.METHOD, "other", "()V", 0),
                ),
            ),
            testClassArtifact(
                internalName = "sample/Other",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "value", "()I", 0)),
            ),
        )

        val matches = buildRuleMatches(
            effectiveRuleSetForPass(config, "method-virtualization"),
            classes.map { it.summary },
        )
        val eligibleMethods = eligibleMembersForAction(classes, matches, "method-virtualization")
            .filter { it.kind == MemberKind.METHOD }
            .map { "${it.owner}#${it.name}${it.descriptor}" }
            .toSet()

        assertEquals(
            setOf(
                "sample/Target#find(Ljava/lang/String;)Ljava/lang/String;",
                "sample/Target#other()V",
                "sample/Other#value()I",
            ),
            eligibleMethods,
        )
    }

    @Test
    fun selectedOnly_class_exclusion_can_restore_a_more_specific_method() {
        val config = testConfig(
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(
                        RuleSpec("sample/Target", "exclude"),
                        RuleSpec("sample/Target#restored:()I", "obfuscate"),
                    ),
                ),
            ),
        )
        val classes = listOf(
            testClassArtifact(
                internalName = "sample/Target",
                methodSummaries = listOf(
                    MemberSummary(MemberKind.METHOD, "first", "()I", 0),
                    MemberSummary(MemberKind.METHOD, "restored", "()I", 0),
                    MemberSummary(MemberKind.METHOD, "last", "()I", 0),
                ),
            ),
            testClassArtifact(
                internalName = "sample/Other",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "other", "()I", 0)),
            ),
        )

        val effective = effectiveRuleSetForPass(config, "method-virtualization")
        val matches = buildRuleMatches(effective, classes.map { it.summary })
        val eligibleMethods = eligibleMembersForAction(classes, matches, "method-virtualization")
            .filter { it.kind == MemberKind.METHOD }

        assertEquals(setOf("sample/Target", "sample/Other"), eligibleClassNamesForAction(classes, matches, "method-virtualization"))
        assertEquals(
            setOf("sample/Target#restored()I", "sample/Other#other()I"),
            eligibleMethods.map { "${it.owner}#${it.name}${it.descriptor}" }.toSet(),
        )
    }

    @Test
    fun selectedOnly_class_exclusion_removes_the_class_and_all_members() {
        val config = testConfig(
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(RuleSpec("sample/Target", "exclude")),
                ),
            ),
        )
        val classes = listOf(
            testClassArtifact(
                internalName = "sample/Target",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "hidden", "()I", 0)),
            ),
            testClassArtifact(
                internalName = "sample/Other",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "visible", "()I", 0)),
            ),
        )

        val matches = buildRuleMatches(effectiveRuleSetForPass(config, "method-virtualization"), classes.map { it.summary })

        assertEquals(setOf("sample/Other"), eligibleClassNamesForAction(classes, matches, "method-virtualization"))
        assertEquals(
            setOf("sample/Other#visible()I"),
            eligibleMembersForAction(classes, matches, "method-virtualization")
                .filter { it.kind == MemberKind.METHOD }
                .map { "${it.owner}#${it.name}${it.descriptor}" }
                .toSet(),
        )
    }

    @Test
    fun inheritGlobal_keeps_legacy_member_precedence_when_class_and_method_actions_mix() {
        val classes = listOf(
            testClassArtifact(
                internalName = "sample/Legacy",
                methodSummaries = listOf(
                    MemberSummary(MemberKind.METHOD, "first", "()I", 0),
                    MemberSummary(MemberKind.METHOD, "selected", "()I", 0),
                ),
            ),
        )
        val matches = buildRuleMatches(
            io.github.hht0rro.javashroud.model.config.RuleSet(
                rules = listOf(
                    RuleSpec("sample/Legacy", "method-virtualization"),
                    RuleSpec("sample/Legacy#selected:()I", "method-virtualization"),
                ),
            ),
            classes.map { it.summary },
        )

        assertEquals(
            listOf("selected"),
            eligibleMembersForAction(classes, matches, "method-virtualization")
                .filter { it.kind == MemberKind.METHOD }
                .map { it.name },
        )
    }

    @Test
    fun inheritGlobal_uses_global_rules_without_copying_them() {
        val globalRules = buildTargetedRuleSet(
            passIds = listOf("strip-compile-debug-info"),
            targetedClasses = setOf("sample/Global"),
        )
        val config = testConfig(
            passes = listOf(testPassSpec(id = "strip-compile-debug-info")),
            ruleSet = globalRules,
            passSelections = listOf(PassSelectionSpec("strip-compile-debug-info", PassSelectionMode.INHERIT_GLOBAL)),
        )

        assertEquals(globalRules, effectiveRuleSetForPass(config, "strip-compile-debug-info"))
    }

    @Test
    fun decodeConfig_reads_root_passSelections() {
        val config = decodeConfig(
            mapper.readTree(
                """
                {
                  "inputJarPath": "C:/tmp/input.jar",
                  "outputJarPath": "C:/tmp/output.jar",
                  "passes": [{"id": "method-virtualization", "enabled": true}],
                  "passSelections": [{
                    "passId": "method-virtualization",
                    "mode": "selected-only",
                    "rules": [{"target": "sample/Target#value:()I", "action": "obfuscate"}]
                  }]
                }
                """.trimIndent(),
            ),
            configPath,
        )

        assertEquals(PassSelectionMode.SELECTED_ONLY, config.passSelections.single().mode)
        assertEquals("sample/Target#value:()I", config.passSelections.single().rules.single().target)
    }

    @Test
    fun validateConfig_normalizes_pass_selection_identifiers() {
        val input = Files.createTempFile("javashroud-pass-selection-normalize", ".jar")
        try {
            val normalized = validateConfig(
                testConfig(
                    inputJarPath = input.toString(),
                    outputJarPath = input.resolveSibling("out.jar").toString(),
                    passes = listOf(testPassSpec(id = " method-virtualization ")),
                    allowOptInPasses = true,
                    passSelections = listOf(
                        PassSelectionSpec(
                            passId = " method-virtualization ",
                            mode = PassSelectionMode.SELECTED_ONLY,
                            rules = listOf(RuleSpec(" sample/Target#value:()I ", " obfuscate ")),
                        ),
                    ),
                ),
                configPath,
            )

            assertEquals("method-virtualization", normalized.passes.first { it.id == "method-virtualization" }.id)
            assertEquals("method-virtualization", normalized.passSelections.single().passId)
            assertEquals("sample/Target#value:()I", normalized.passSelections.single().rules.single().target)
            assertEquals("obfuscate", normalized.passSelections.single().rules.single().action)
        } finally {
            Files.deleteIfExists(input)
        }
    }

    @Test
    fun selectedOnly_nonMatching_exclusions_leave_the_independent_scope_available() {
        val config = testConfig(
            passes = listOf(testPassSpec(id = "method-virtualization")),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = "method-virtualization",
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(
                        RuleSpec("sample/Missing", "exclude"),
                        RuleSpec("sample/Target#missing:()I", "exclude"),
                    ),
                ),
            ),
        )
        val classes = listOf(
            testClassArtifact(
                internalName = "sample/Target",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "present", "()I", 0)),
            ),
            testClassArtifact(
                internalName = "sample/Other",
                methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "other", "()I", 0)),
            ),
        )
        val matches = buildRuleMatches(
            effectiveRuleSetForPass(config, "method-virtualization"),
            classes.map { it.summary },
        )

        assertEquals(setOf("sample/Target", "sample/Other"), eligibleClassNamesForAction(classes, matches, "method-virtualization"))
        assertEquals(2, eligibleMembersForAction(classes, matches, "method-virtualization").count { it.kind == MemberKind.METHOD })
    }

    @Test
    fun validateConfig_rejects_selectedOnly_wildcard_selectors() {
        val input = Files.createTempFile("javashroud-pass-selection-wildcard", ".jar")
        try {
            val base = testConfig(
                inputJarPath = input.toString(),
                outputJarPath = input.resolveSibling("out.jar").toString(),
                passes = listOf(testPassSpec(id = "method-virtualization")),
                allowOptInPasses = true,
            )
            for (target in listOf(
                "*",
                "sample/*",
                "sample.*",
                "sample/*/Target",
                "sample/Target#*:()V",
                "sample/Target#value:(*)V",
            )) {
                val error = assertFailsWith<IllegalArgumentException> {
                    validateConfig(
                        base.copy(
                            passSelections = listOf(
                                PassSelectionSpec(
                                    passId = "method-virtualization",
                                    mode = PassSelectionMode.SELECTED_ONLY,
                                    rules = listOf(RuleSpec(target, "obfuscate")),
                                ),
                            ),
                        ),
                        configPath,
                    )
                }
                assertTrue(
                    error.message.orEmpty().contains("must target one concrete class or method"),
                    "expected concrete-selector error for $target, actual=${error.message}",
                )
            }
        } finally {
            Files.deleteIfExists(input)
        }
    }

    @Test
    fun validateConfig_rejects_nonCanonical_selectedOnly_selectors() {
        val input = Files.createTempFile("javashroud-pass-selection-canonical", ".jar")
        try {
            val base = testConfig(
                inputJarPath = input.toString(),
                outputJarPath = input.resolveSibling("out.jar").toString(),
                passes = listOf(testPassSpec(id = "method-virtualization")),
                allowOptInPasses = true,
            )
            for (target in listOf(
                "sample.Target",
                "sample\\Target",
                "sample/Target#value:()Q",
                "sample/Target#value:(V)V",
                "sample/Target#value:(Ljava.lang.String;)V",
                "sample/Target#value:([)V",
                "sample/Target#<init>:()I",
                "sample/Target#<clinit>:(I)V",
            )) {
                val error = assertFailsWith<IllegalArgumentException> {
                    validateConfig(
                        base.copy(
                            passSelections = listOf(
                                PassSelectionSpec(
                                    passId = "method-virtualization",
                                    mode = PassSelectionMode.SELECTED_ONLY,
                                    rules = listOf(RuleSpec(target, "obfuscate")),
                                ),
                            ),
                        ),
                        configPath,
                    )
                }
                assertTrue(
                    error.message.orEmpty().contains("canonical class or JVM method selector"),
                    "expected canonical-selector error for $target, actual=${error.message}",
                )
            }
        } finally {
            Files.deleteIfExists(input)
        }
    }

    @Test
    fun validateConfig_rejects_selectedOnly_field_selector() {
        val input = Files.createTempFile("javashroud-pass-selection-field", ".jar")
        try {
            val config = testConfig(
                inputJarPath = input.toString(),
                outputJarPath = input.resolveSibling("out.jar").toString(),
                passes = listOf(testPassSpec(id = "method-virtualization")),
                allowOptInPasses = true,
                passSelections = listOf(
                    PassSelectionSpec(
                        passId = "method-virtualization",
                        mode = PassSelectionMode.SELECTED_ONLY,
                        rules = listOf(RuleSpec("sample/Target#field:I", "obfuscate")),
                    ),
                ),
            )

            val error = assertFailsWith<IllegalArgumentException> { validateConfig(config, configPath) }
            assertTrue(error.message.orEmpty().contains("field selectors are not supported"))
        } finally {
            Files.deleteIfExists(input)
        }
    }

    @Test
    fun validateConfig_accepts_empty_selectedOnly_scope_and_rejects_disabled_or_capability_mismatch() {
        val input = Files.createTempFile("javashroud-pass-selection", ".jar")
        try {
            val base = testConfig(
                inputJarPath = input.toString(),
                outputJarPath = input.resolveSibling("out.jar").toString(),
                passes = listOf(testPassSpec(id = "strip-compile-debug-info")),
            )
            val normalized = validateConfig(
                base.copy(
                    passSelections = listOf(
                        PassSelectionSpec("strip-compile-debug-info", PassSelectionMode.SELECTED_ONLY),
                    ),
                ),
                configPath,
            )
            assertEquals(emptyList(), normalized.passSelections.single().rules)
            assertFailsWith<IllegalArgumentException> {
                validateConfig(
                    base.copy(
                        passes = listOf(testPassSpec(id = "strip-compile-debug-info", enabled = false)),
                        passSelections = listOf(
                            PassSelectionSpec(
                                "strip-compile-debug-info",
                                PassSelectionMode.SELECTED_ONLY,
                                listOf(RuleSpec("sample/Target", "obfuscate")),
                            ),
                        ),
                    ),
                    configPath,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                validateConfig(
                    base.copy(
                        passSelections = listOf(
                            PassSelectionSpec(
                                "strip-compile-debug-info",
                                PassSelectionMode.SELECTED_ONLY,
                                listOf(RuleSpec("sample/Target#value:()I", "obfuscate")),
                            ),
                        ),
                    ),
                    configPath,
                )
            }
        } finally {
            Files.deleteIfExists(input)
        }
    }
}
