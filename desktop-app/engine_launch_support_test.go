package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestEnsureReadableJarPath_AcceptsJarAndApkFiles(t *testing.T) {
	for _, inputName := range []string{"input.jar", "input.apk"} {
		inputPath := filepath.Join(t.TempDir(), inputName)
		if err := os.WriteFile(inputPath, []byte("artifact"), 0o600); err != nil {
			t.Fatalf("write temp input failed: name=%s: %v", inputName, err)
		}

		if err := ensureReadableJarPath(inputPath); err != nil {
			t.Fatalf("expected %s input to be readable, got %v", inputName, err)
		}
	}
}

func TestEnsureReadableJarPath_RejectsOtherExtensionsAndDirectories(t *testing.T) {
	tempDir := t.TempDir()

	unsupportedPath := filepath.Join(tempDir, "input.zip")
	if err := os.WriteFile(unsupportedPath, []byte("zip"), 0o600); err != nil {
		t.Fatalf("write temp input failed: %v", err)
	}
	err := ensureReadableJarPath(unsupportedPath)
	if err == nil || !strings.Contains(err.Error(), "path extension is not .jar or .apk") {
		t.Fatalf("expected unsupported extension error, got %v", err)
	}

	if err = ensureReadableJarPath(tempDir); err == nil || !strings.Contains(err.Error(), "path is a directory") {
		t.Fatalf("expected directory error, got %v", err)
	}
}

func TestBuildDefaultOutputJarName_KeepsArtifactExtension(t *testing.T) {
	cases := map[string]string{
		"app.jar":         "app-shrouded.jar",
		"app.apk":         "app-shrouded.apk",
		"APP.APK":         "APP-shrouded.apk",
		"app-release.apk": "app-release-shrouded.apk",
		"app.bin":         "app.bin-shrouded.jar",
		"":                "output-shrouded.jar",
	}
	for inputName, expectedName := range cases {
		if actualName := buildDefaultOutputJarName(inputName); actualName != expectedName {
			t.Fatalf("expected default output %q for input %q, got %q", expectedName, inputName, actualName)
		}
	}
}
