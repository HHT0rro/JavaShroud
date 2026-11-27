package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		switch os.Getenv("JAVASHROUD_TEST_XENOLITH") {
		case "valid":
			fmt.Fprintln(os.Stdout, "xenolith fixture")
			os.Exit(0)
		case "empty":
			os.Exit(0)
		case "fail":
			fmt.Fprintln(os.Stderr, "fixture version failure")
			os.Exit(7)
		}
	}
	os.Exit(m.Run())
}

func TestResolveXenolithCliRejectsInvalidOverride(t *testing.T) {
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid.exe")
	if err := os.WriteFile(invalidPath, []byte("invalid executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "missing", path: filepath.Join(dir, "missing.exe")},
		{name: "directory", path: dir},
		{name: "invalid executable", path: invalidPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(xenolithCliEnvKey, test.path)
			result, err := (&App{}).ResolveXenolithCli()
			if result != "" || err == nil || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("expected unavailable CLI with path in error: result=%q error=%v", result, err)
			}
		})
	}
}

func TestResolveXenolithCliVersionProbe(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(xenolithCliEnvKey, binary)
	for _, mode := range []string{"valid", "fail", "empty"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("JAVASHROUD_TEST_XENOLITH", mode)
			result, err := (&App{}).ResolveXenolithCli()
			if mode == "valid" {
				var info XenolithCliInfo
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(result), &info); err != nil {
					t.Fatal(err)
				}
				if info.Path != binary || info.Source != "env" || info.Version != "xenolith fixture" {
					t.Fatalf("unexpected CLI info: %+v", info)
				}
				return
			}
			if result != "" || err == nil || !strings.Contains(err.Error(), binary) || !strings.Contains(err.Error(), "--version") {
				t.Fatalf("expected unavailable CLI with probe error: result=%q error=%v", result, err)
			}
			if mode == "fail" && (!strings.Contains(err.Error(), "exit status 7") || !strings.Contains(err.Error(), "fixture version failure")) {
				t.Fatalf("expected exit status and diagnostic, got %v", err)
			}
		})
	}
}

func TestResolveXenolithCliPathPrefersEnvOverride(t *testing.T) {
	overrideDir := t.TempDir()
	overridePath := filepath.Join(overrideDir, "xenolith.exe")
	if err := os.WriteFile(overridePath, []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write override failed: %v", err)
	}

	path, source := resolveXenolithCliPathFromSources(
		overridePath,
		func() (string, error) { return "", os.ErrNotExist },
		nil,
		func(string) (string, error) { return "", os.ErrNotExist },
	)
	if filepath.Clean(path) != filepath.Clean(overridePath) {
		t.Fatalf("expected env override path %q, got %q", overridePath, path)
	}
	if source != "env" {
		t.Fatalf("expected source env, got %q", source)
	}
}

func TestResolveXenolithCliPathPrefersEmbeddedOverCandidates(t *testing.T) {
	path, source := resolveXenolithCliPathFromSources(
		"",
		func() (string, error) { return `C:\cache\JavaShroud\tools\xenolith\abc\xenolith.exe`, nil },
		[]xenolithCliCandidate{{path: `C:\app\tools\xenolith.exe`, source: "tools"}},
		func(string) (string, error) { return "", os.ErrNotExist },
	)
	if !strings.HasSuffix(filepath.ToSlash(path), "tools/xenolith/abc/xenolith.exe") {
		t.Fatalf("expected embedded path, got %q", path)
	}
	if source != "embedded" {
		t.Fatalf("expected source embedded, got %q", source)
	}
}

func TestResolveXenolithCliPathFallsThroughCandidatesThenLookup(t *testing.T) {
	candidateDir := t.TempDir()
	candidatePath := filepath.Join(candidateDir, "tools", "xenolith.exe")
	if err := os.MkdirAll(filepath.Dir(candidatePath), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(candidatePath, []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write candidate failed: %v", err)
	}

	path, source := resolveXenolithCliPathFromSources(
		"",
		func() (string, error) { return "", os.ErrNotExist },
		[]xenolithCliCandidate{{path: filepath.Join(candidateDir, "missing", "xenolith.exe"), source: "sibling"}, {path: candidatePath, source: "tools"}},
		func(string) (string, error) { return "", os.ErrNotExist },
	)
	if filepath.Clean(path) != filepath.Clean(candidatePath) {
		t.Fatalf("expected candidate path %q, got %q", candidatePath, path)
	}
	if source != "tools" {
		t.Fatalf("expected source tools, got %q", source)
	}

	lookupPath := filepath.Join(candidateDir, "on-path-xenolith.exe")
	if err := os.WriteFile(lookupPath, []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write lookup failed: %v", err)
	}
	lookupResult, lookupSource := resolveXenolithCliPathFromSources(
		"",
		func() (string, error) { return "", os.ErrNotExist },
		nil,
		func(string) (string, error) { return lookupPath, nil },
	)
	if filepath.Clean(lookupResult) != filepath.Clean(lookupPath) || lookupSource != "path" {
		t.Fatalf("expected PATH lookup, got %q/%q", lookupResult, lookupSource)
	}
}

func TestResolveXenolithCliPathReturnsEmptyWhenNothingIsFound(t *testing.T) {
	path, source := resolveXenolithCliPathFromSources(
		"",
		func() (string, error) { return "", os.ErrNotExist },
		[]xenolithCliCandidate{{path: filepath.Join(t.TempDir(), "xenolith.exe"), source: "tools"}},
		func(string) (string, error) { return "", os.ErrNotExist },
	)
	if path != "" || source != "" {
		t.Fatalf("expected empty resolution, got %q/%q", path, source)
	}
}

func TestXenolithCliInfoJsonShape(t *testing.T) {
	encoded, err := json.Marshal(XenolithCliInfo{Path: `C:\x\xenolith.exe`, Version: "xenolith 0.1.0", Source: "embedded"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	decoded := string(encoded)
	for _, expected := range []string{`"path"`, `"version"`, `"source"`, "xenolith 0.1.0", "embedded"} {
		if !strings.Contains(decoded, expected) {
			t.Fatalf("expected %s in %s", expected, decoded)
		}
	}
}

func TestXenolithCliCandidatesForExecutableDir(t *testing.T) {
	candidates := xenolithCliCandidatesForExecutableDir(filepath.Join("E", "app", "bin"))
	if len(candidates) != 3 {
		t.Fatalf("expected 3 candidates, got %d", len(candidates))
	}
	if candidates[0].source != "tools" || !strings.HasSuffix(filepath.ToSlash(candidates[0].path), "app/bin/tools/xenolith.exe") {
		t.Fatalf("unexpected tools candidate: %+v", candidates[0])
	}
	if candidates[1].source != "sibling" || !strings.Contains(filepath.ToSlash(candidates[1].path), "Xenolith/target/release/xenolith.exe") {
		t.Fatalf("unexpected sibling release candidate: %+v", candidates[1])
	}
	if candidates[2].source != "sibling" || !strings.Contains(filepath.ToSlash(candidates[2].path), "Xenolith/dist/xenolith.exe") {
		t.Fatalf("unexpected sibling dist candidate: %+v", candidates[2])
	}
}

func TestXenolithSiblingReleasePreferredOverStaleDist(t *testing.T) {
	root := t.TempDir()
	executableDir := filepath.Join(root, "JavaShroud-public", "build", "desktop-app", "bin")
	candidates := xenolithCliCandidatesForExecutableDir(executableDir)
	for _, candidate := range candidates[1:] {
		if err := os.MkdirAll(filepath.Dir(candidate.path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(candidate.path, []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path, source := resolveXenolithCliPathFromSources("", func() (string, error) { return "", os.ErrNotExist }, candidates, nil)
	if filepath.Clean(path) != filepath.Clean(candidates[1].path) || source != "sibling" {
		t.Fatalf("expected fresh release candidate, got %q/%q", path, source)
	}
	if err := os.Remove(candidates[1].path); err != nil {
		t.Fatal(err)
	}
	path, source = resolveXenolithCliPathFromSources("", func() (string, error) { return "", os.ErrNotExist }, candidates, nil)
	if filepath.Clean(path) != filepath.Clean(candidates[2].path) || source != "sibling" {
		t.Fatalf("expected dist when release is absent, got %q/%q", path, source)
	}
}
