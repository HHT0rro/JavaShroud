//go:build javashroud_embed_engine

package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed embedded/obfuscator-engine.exe
var embeddedNativeEngine []byte

func resolveEmbeddedNativeEnginePath() (string, error) {
	if len(embeddedNativeEngine) == 0 {
		return "", fmt.Errorf("embedded native engine is empty: resource=embedded/obfuscator-engine.exe")
	}

	engineHash := sha256.Sum256(embeddedNativeEngine)
	engineHashText := hex.EncodeToString(engineHash[:])
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve embedded native engine cache failed: %w", err)
	}

	engineDir := filepath.Join(cacheRoot, "JavaShroud", "engine", engineHashText)
	enginePath := filepath.Join(engineDir, "obfuscator-engine.exe")
	if err = ensureEmbeddedNativeEngine(engineDir, enginePath, embeddedNativeEngine); err != nil {
		return "", fmt.Errorf("extract embedded native engine failed: path=%s hash=%s: %w", enginePath, engineHashText, err)
	}

	return enginePath, nil
}

func ensureEmbeddedNativeEngine(engineDir string, enginePath string, engineBytes []byte) error {
	if isExistingEmbeddedNativeEngine(enginePath, engineBytes) {
		return nil
	}

	if err := os.MkdirAll(engineDir, 0o700); err != nil {
		return fmt.Errorf("create embedded native engine directory failed: dir=%s: %w", engineDir, err)
	}

	temporaryPath := enginePath + ".tmp"
	if err := os.WriteFile(temporaryPath, engineBytes, 0o700); err != nil {
		return fmt.Errorf("write embedded native engine failed: path=%s: %w", temporaryPath, err)
	}
	if err := os.Rename(temporaryPath, enginePath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("activate embedded native engine failed: source=%s target=%s: %w", temporaryPath, enginePath, err)
	}

	return nil
}

func isExistingEmbeddedNativeEngine(enginePath string, engineBytes []byte) bool {
	existingBytes, err := os.ReadFile(enginePath)
	if err != nil {
		return false
	}

	return bytes.Equal(existingBytes, engineBytes)
}
