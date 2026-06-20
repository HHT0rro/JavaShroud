package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestToEngineAbsoluteJarPath_NormalizesWindowsSeparators(t *testing.T) {
	inputPath := `C:\Users\Public\Desktop\obfuscator-engine.jar`

	normalizedPath, err := toEngineAbsoluteJarPath(inputPath)
	if err != nil {
		t.Fatalf("toEngineAbsoluteJarPath returned error: %v", err)
	}

	if runtime.GOOS == "windows" {
		expectedPath := filepath.ToSlash(filepath.Clean(inputPath))
		if normalizedPath != expectedPath {
			t.Fatalf("expected normalized path %q, got %q", expectedPath, normalizedPath)
		}
		return
	}

	expectedPath, err := filepath.Abs(inputPath)
	if err != nil {
		t.Fatalf("filepath.Abs returned error: %v", err)
	}
	if normalizedPath != filepath.ToSlash(filepath.Clean(expectedPath)) {
		t.Fatalf("expected absolute normalized path %q, got %q", filepath.ToSlash(filepath.Clean(expectedPath)), normalizedPath)
	}
}
