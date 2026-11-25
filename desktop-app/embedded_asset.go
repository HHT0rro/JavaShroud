package main

import (
	"bytes"
	"fmt"
	"os"
)

// ensureEmbeddedBinaryAsset materializes an embedded binary (engine exe,
// Xenolith CLI) under dir/path, rewriting it whenever the cached copy differs
// from the embedded bytes. Shared by the tag-gated embed files.
func ensureEmbeddedBinaryAsset(assetDir string, assetPath string, assetBytes []byte) error {
	if isExistingEmbeddedBinaryAsset(assetPath, assetBytes) {
		return nil
	}

	if err := os.MkdirAll(assetDir, 0o700); err != nil {
		return fmt.Errorf("create embedded binary directory failed: dir=%s: %w", assetDir, err)
	}

	temporaryPath := assetPath + ".tmp"
	if err := os.WriteFile(temporaryPath, assetBytes, 0o700); err != nil {
		return fmt.Errorf("write embedded binary failed: path=%s: %w", temporaryPath, err)
	}
	if err := os.Rename(temporaryPath, assetPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("activate embedded binary failed: source=%s target=%s: %w", temporaryPath, assetPath, err)
	}

	return nil
}

func isExistingEmbeddedBinaryAsset(assetPath string, assetBytes []byte) bool {
	existingBytes, err := os.ReadFile(assetPath)
	if err != nil {
		return false
	}

	return bytes.Equal(existingBytes, assetBytes)
}
