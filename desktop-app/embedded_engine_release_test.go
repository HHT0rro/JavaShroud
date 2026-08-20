//go:build javashroud_embed_engine

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEngineLaunchSpecUsesCurrentEmbeddedNativeEngine(t *testing.T) {
	launchSpec, err := resolveEngineLaunchSpec(filepath.Join(t.TempDir(), "obfuscation-config.toml"))
	if err != nil {
		t.Fatalf("resolveEngineLaunchSpec returned error: %v", err)
	}
	if launchSpec.Mode != "native-exe" {
		t.Fatalf("expected embedded native engine mode, got %q", launchSpec.Mode)
	}

	embeddedHash := sha256.Sum256(embeddedNativeEngine)
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("os.UserCacheDir returned error: %v", err)
	}
	expectedPath := filepath.Join(
		cacheRoot,
		"JavaShroud",
		"engine",
		hex.EncodeToString(embeddedHash[:]),
		"obfuscator-engine.exe",
	)
	if filepath.Clean(launchSpec.CommandPath) != filepath.Clean(expectedPath) {
		t.Fatalf("expected embedded engine path %q, got %q", expectedPath, launchSpec.CommandPath)
	}

	extractedBytes, err := os.ReadFile(launchSpec.CommandPath)
	if err != nil {
		t.Fatalf("read extracted embedded engine failed: %v", err)
	}
	if !bytes.Equal(extractedBytes, embeddedNativeEngine) {
		t.Fatal("extracted native engine bytes differ from the current embedded payload")
	}
}
