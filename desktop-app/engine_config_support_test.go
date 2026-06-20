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
