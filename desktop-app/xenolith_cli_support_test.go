package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].source != "tools" || !strings.HasSuffix(filepath.ToSlash(candidates[0].path), "app/bin/tools/xenolith.exe") {
		t.Fatalf("unexpected tools candidate: %+v", candidates[0])
	}
	if candidates[1].source != "sibling" || !strings.Contains(filepath.ToSlash(candidates[1].path), "Xenolith/dist/xenolith.exe") {
		t.Fatalf("unexpected sibling candidate: %+v", candidates[1])
	}
}
