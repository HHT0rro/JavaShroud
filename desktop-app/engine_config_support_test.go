package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareConfigFile_RejectsInvalidRuleAction(t *testing.T) {
	request := ObfuscationRequest{
		InputJarPath:  writeTempJar(t),
		OutputJarPath: filepath.Join(t.TempDir(), "out.jar"),
		Passes: []PassSpec{
			{ID: "string-encryption", Enabled: true, Params: map[string]json.RawMessage{}},
		},
		Rules: []RuleItem{
			{ID: "rule-1", Target: "com/example/App", Action: "delete"},
		},
	}

	tempDir, _, cleanup, err := prepareConfigFile(request)
	defer cleanup()
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err == nil {
		t.Fatalf("expected prepareConfigFile to reject invalid rule action")
	}
	if !strings.Contains(err.Error(), "rule action is invalid") {
		t.Fatalf("expected invalid rule action error, got %q", err.Error())
	}
}

func TestPrepareConfigFile_RejectsRequestsWithoutEnabledPass(t *testing.T) {
	request := ObfuscationRequest{
		InputJarPath:  writeTempJar(t),
		OutputJarPath: filepath.Join(t.TempDir(), "out.jar"),
		Passes: []PassSpec{
			{ID: "string-encryption", Enabled: false, Params: map[string]json.RawMessage{}},
		},
	}

	tempDir, _, cleanup, err := prepareConfigFile(request)
	defer cleanup()
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err == nil {
		t.Fatalf("expected prepareConfigFile to reject request without enabled pass")
	}
	if !strings.Contains(err.Error(), "no enabled passes") {
		t.Fatalf("expected no enabled passes error, got %q", err.Error())
	}
}

func TestPrepareConfigFile_PreservesExplicitRuntimeAllowances(t *testing.T) {
	inputJarPath := writeTempJar(t)
	outputJarPath := filepath.Join(t.TempDir(), "out.jar")

	request := ObfuscationRequest{
		InputJarPath:  inputJarPath,
		OutputJarPath: outputJarPath,
		Passes: []PassSpec{
			{ID: "method-virtualization", Enabled: true, Params: map[string]json.RawMessage{}},
		},
		Rules: []RuleItem{},
	}

	tempDir, configPath, cleanup, err := prepareConfigFile(request)
	if err != nil {
		t.Fatalf("prepareConfigFile returned error: %v", err)
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	config := readEngineConfig(t, configPath)
	if filepath.Ext(configPath) != ".toml" {
		t.Fatalf("expected TOML config path, got %s", configPath)
	}
	if config.AllowOptInPasses {
		t.Fatalf("expected allowOptInPasses to default to false")
	}
	if config.AllowRedundantPasses {
		t.Fatalf("expected allowRedundantPasses to default to false")
	}

	request.AllowOptInPasses = true
	request.AllowRedundantPasses = true
	tempDir, configPath, cleanup, err = prepareConfigFile(request)
	if err != nil {
		t.Fatalf("prepareConfigFile with explicit opt-in returned error: %v", err)
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	config = readEngineConfig(t, configPath)
	if !config.AllowOptInPasses {
		t.Fatalf("expected allowOptInPasses to preserve explicit true request")
	}
	if !config.AllowRedundantPasses {
		t.Fatalf("expected allowRedundantPasses to preserve explicit true request")
	}
}

func TestPrepareConfigFile_OmitsNullPassParams(t *testing.T) {
	request := ObfuscationRequest{
		InputJarPath:  writeTempJar(t),
		OutputJarPath: filepath.Join(t.TempDir(), "out.jar"),
		Passes: []PassSpec{
			{
				ID:      "anti-dump-constant-pool",
				Enabled: true,
				Params: map[string]json.RawMessage{
					"migrationStrategy": json.RawMessage(`"runtime-builder"`),
					"seed":              json.RawMessage(`null`),
				},
			},
		},
		Rules: []RuleItem{},
	}

	tempDir, configPath, cleanup, err := prepareConfigFile(request)
	if err != nil {
		t.Fatalf("prepareConfigFile returned error: %v", err)
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	payload, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}
	content := string(payload)
	if strings.Contains(content, "seed") {
		t.Fatalf("expected null seed param to be omitted, got %s", content)
	}
	if !strings.Contains(content, `migrationStrategy = "runtime-builder"`) {
		t.Fatalf("expected non-null params to be preserved, got %s", content)
	}
}

func TestPrepareConfigFile_WritesSelectedOnlyPassSelections(t *testing.T) {
	request := validPassSelectionRequest(t)
	request.PassSelections = []PassSelection{
		{
			PassID: "method-virtualization",
			Mode:   PassSelectionModeSelectedOnly,
			Rules: []RuleItem{
				{ID: "selection-allow", Target: "example/Target#value:()I", Action: "obfuscate"},
				{ID: "selection-exclude", Target: "example/Target#skip:()V", Action: "exclude"},
			},
		},
	}

	tempDir, configPath, cleanup, err := prepareConfigFile(request)
	if err != nil {
		t.Fatalf("prepareConfigFile returned error: %v", err)
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	payload, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}
	content := string(payload)
	for _, expected := range []string{
		"[[passSelections]]",
		`passId = "method-virtualization"`,
		`mode = "selected-only"`,
		"[[passSelections.rules]]",
		`target = "example/Target#value:()I"`,
		`action = "obfuscate"`,
		`target = "example/Target#skip:()V"`,
		`action = "exclude"`,
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected pass selection TOML fragment %q, got %s", expected, content)
		}
	}
}

func TestPrepareConfigFile_WritesEmptySelectedOnlyPassSelection(t *testing.T) {
	request := validPassSelectionRequest(t)
	request.PassSelections = []PassSelection{{
		PassID: "method-virtualization",
		Mode:   PassSelectionModeSelectedOnly,
		Rules:  []RuleItem{},
	}}

	tempDir, configPath, cleanup, err := prepareConfigFile(request)
	if err != nil {
		t.Fatalf("prepareConfigFile returned error for empty independent scope: %v", err)
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	payload, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}
	content := string(payload)
	if !strings.Contains(content, "[[passSelections]]") ||
		!strings.Contains(content, `passId = "method-virtualization"`) ||
		!strings.Contains(content, `mode = "selected-only"`) {
		t.Fatalf("expected empty selected-only table, got %s", content)
	}
	if strings.Contains(content, "[[passSelections.rules]]") {
		t.Fatalf("expected empty independent scope to omit rule tables, got %s", content)
	}
}

func TestPrepareConfigFile_OnlyCopiesSelectedOnlyPassSelections(t *testing.T) {
	request := validPassSelectionRequest(t)
	request.PassSelections = []PassSelection{
		{
			PassID: "string-encryption",
			Mode:   PassSelectionModeInheritGlobal,
			Rules:  []RuleItem{{ID: "inherited", Target: "example/Inherited", Action: "obfuscate"}},
		},
		{
			PassID: "method-virtualization",
			Mode:   PassSelectionModeSelectedOnly,
			Rules: []RuleItem{
				{ID: "selection-z", Target: "example/Z", Action: "obfuscate"},
				{ID: "selection-a", Target: "example/A", Action: "exclude"},
			},
		},
	}

	selections := cloneSelectedOnlyPassSelections(request.PassSelections)
	if len(selections) != 1 {
		t.Fatalf("expected exactly one selected-only pass selection, got %#v", selections)
	}
	if selections[0].PassID != "method-virtualization" {
		t.Fatalf("expected inherit-global selection to be omitted, got %#v", selections)
	}
	if selections[0].Rules[0].Target != "example/A" || selections[0].Rules[1].Target != "example/Z" {
		t.Fatalf("expected selection rules to be serialized in stable target order, got %#v", selections[0].Rules)
	}
	request.PassSelections[1].Rules[1].Target = "example/Mutated"
	if selections[0].Rules[1].Target != "example/Z" {
		t.Fatalf("expected cloned selection rules to be independent, got %#v", selections)
	}
}

func TestValidateObfuscationRequest_RejectsInvalidPassSelections(t *testing.T) {
	testCases := []struct {
		name       string
		selections []PassSelection
		passes     []PassSpec
		expected   string
	}{
		{
			name: "duplicate pass ID",
			selections: []PassSelection{
				{PassID: "method-virtualization", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "example/First", Action: "obfuscate"}}},
				{PassID: "method-virtualization", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "example/Second", Action: "obfuscate"}}},
			},
			expected: "pass selection passId is duplicated",
		},
		{
			name: "unknown pass ID",
			selections: []PassSelection{
				{PassID: "missing-pass", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "example/Target", Action: "obfuscate"}}},
			},
			expected: "pass selection passId is unknown or disabled",
		},
		{
			name: "disabled pass ID",
			passes: []PassSpec{
				{ID: "method-virtualization", Enabled: false, Params: map[string]json.RawMessage{}},
				{ID: "string-encryption", Enabled: true, Params: map[string]json.RawMessage{}},
			},
			selections: []PassSelection{
				{PassID: "method-virtualization", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "example/Target", Action: "obfuscate"}}},
			},
			expected: "pass selection passId is unknown or disabled",
		},
		{
			name: "inherit global in execution request",
			selections: []PassSelection{
				{PassID: "method-virtualization", Mode: PassSelectionModeInheritGlobal, Rules: []RuleItem{{Target: "example/Target", Action: "obfuscate"}}},
			},
			expected: "inherit-global pass selection must not be sent in execution request",
		},
		{
			name: "invalid mode",
			selections: []PassSelection{
				{PassID: "method-virtualization", Mode: PassSelectionMode("custom"), Rules: []RuleItem{{Target: "example/Target", Action: "obfuscate"}}},
			},
			expected: "pass selection mode is invalid",
		},
		{
			name: "invalid rule action",
			selections: []PassSelection{
				{PassID: "method-virtualization", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "example/Target", Action: "invalid"}}},
			},
			expected: "rule action is invalid",
		},
		{
			name: "empty rule target",
			selections: []PassSelection{
				{PassID: "method-virtualization", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "", Action: "obfuscate"}}},
			},
			expected: "rule target is empty",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := validPassSelectionRequest(t)
			if testCase.passes != nil {
				request.Passes = testCase.passes
			}
			request.PassSelections = testCase.selections

			err := validateObfuscationRequest(request)
			if err == nil {
				t.Fatalf("expected validation to fail")
			}
			if !strings.Contains(err.Error(), testCase.expected) {
				t.Fatalf("expected error containing %q, got %q", testCase.expected, err.Error())
			}
		})
	}
}

func TestValidateObfuscationRequest_NormalizesAndRejectsDuplicateIdentifiers(t *testing.T) {
	request := validPassSelectionRequest(t)
	request.Passes = append(request.Passes, PassSpec{ID: " method-virtualization ", Enabled: true, Params: map[string]json.RawMessage{}})
	if err := validateObfuscationRequest(request); err == nil || !strings.Contains(err.Error(), "enabled pass id is duplicated") {
		t.Fatalf("expected trim-normalized duplicate enabled pass rejection, got %v", err)
	}

	request = validPassSelectionRequest(t)
	request.PassSelections = []PassSelection{
		{PassID: "method-virtualization", Mode: PassSelectionModeSelectedOnly, Rules: []RuleItem{{Target: "example/First", Action: "obfuscate"}}},
		{PassID: " method-virtualization ", Mode: PassSelectionMode(" selected-only "), Rules: []RuleItem{{Target: "example/Second", Action: "obfuscate"}}},
	}
	if err := validateObfuscationRequest(request); err == nil || !strings.Contains(err.Error(), "pass selection passId is duplicated") {
		t.Fatalf("expected trim-normalized duplicate selection rejection, got %v", err)
	}
}

func TestValidateObfuscationRequest_RejectsDuplicateAndMalformedSelectionTargets(t *testing.T) {
	testCases := []struct {
		name     string
		targets  []string
		expected string
	}{
		{
			name:     "duplicate target after trim",
			targets:  []string{"example/Target", " example/Target "},
			expected: "pass selection rule target is duplicated",
		},
		{
			name:     "package wildcard",
			targets:  []string{"example/*/Target"},
			expected: "not a concrete class or JVM method selector",
		},
		{
			name:     "field selector",
			targets:  []string{"example/Target#field:I"},
			expected: "not a concrete class or JVM method selector",
		},
		{
			name:     "invalid method descriptor",
			targets:  []string{"example/Target#value:(V)V"},
			expected: "not a concrete class or JVM method selector",
		},
		{
			name:     "constructor with non-void return",
			targets:  []string{"example/Target#<init>:()I"},
			expected: "not a concrete class or JVM method selector",
		},
		{
			name:     "class initializer with parameters",
			targets:  []string{"example/Target#<clinit>:(I)V"},
			expected: "not a concrete class or JVM method selector",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := validPassSelectionRequest(t)
			rules := make([]RuleItem, 0, len(testCase.targets))
			for _, target := range testCase.targets {
				rules = append(rules, RuleItem{Target: target, Action: "obfuscate"})
			}
			request.PassSelections = []PassSelection{{
				PassID: " method-virtualization ",
				Mode:   PassSelectionMode(" selected-only "),
				Rules:  rules,
			}}
			if err := validateObfuscationRequest(request); err == nil || !strings.Contains(err.Error(), testCase.expected) {
				t.Fatalf("expected error containing %q, got %v", testCase.expected, err)
			}
		})
	}
}

func TestPrepareConfigFile_NormalizesPassSelectionValues(t *testing.T) {
	request := validPassSelectionRequest(t)
	request.Passes[0].ID = " method-virtualization "
	request.PassSelections = []PassSelection{{
		PassID: " method-virtualization ",
		Mode:   PassSelectionMode(" selected-only "),
		Rules:  []RuleItem{{Target: " example/Target#value:()I ", Action: " obfuscate "}},
	}}

	tempDir, configPath, cleanup, err := prepareConfigFile(request)
	if err != nil {
		t.Fatalf("prepareConfigFile returned error: %v", err)
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	payload, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}
	content := string(payload)
	for _, expected := range []string{
		`id = "method-virtualization"`,
		`passId = "method-virtualization"`,
		`mode = "selected-only"`,
		`target = "example/Target#value:()I"`,
		`action = "obfuscate"`,
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected normalized TOML fragment %q, got %s", expected, content)
		}
	}
}

func validPassSelectionRequest(t *testing.T) ObfuscationRequest {
	t.Helper()
	return ObfuscationRequest{
		InputJarPath:  writeTempJar(t),
		OutputJarPath: filepath.Join(t.TempDir(), "out.jar"),
		Passes: []PassSpec{
			{ID: "method-virtualization", Enabled: true, Params: map[string]json.RawMessage{}},
		},
		Rules: []RuleItem{},
	}
}

func writeTempJar(t *testing.T) string {
	t.Helper()
	jarPath := filepath.Join(t.TempDir(), "input.jar")
	if err := os.WriteFile(jarPath, []byte("jar"), 0o600); err != nil {
		t.Fatalf("write temp jar failed: %v", err)
	}
	return jarPath
}

func readEngineConfig(t *testing.T, configPath string) EngineConfig {
	t.Helper()
	payload, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}

	content := string(payload)
	if !strings.Contains(content, "[[passes]]") {
		t.Fatalf("expected TOML pass array in config, got %s", content)
	}
	if strings.Contains(strings.TrimSpace(content), "{") {
		t.Fatalf("expected TOML config, got JSON-looking payload: %s", content)
	}
	return EngineConfig{
		AllowOptInPasses:     strings.Contains(content, "allowOptInPasses = true"),
		AllowRedundantPasses: strings.Contains(content, "allowRedundantPasses = true"),
	}
}
