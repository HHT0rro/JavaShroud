//go:build javashroud_embed_engine

package main

import (
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
	if err = ensureEmbeddedBinaryAsset(engineDir, enginePath, embeddedNativeEngine); err != nil {
		return "", fmt.Errorf("extract embedded native engine failed: path=%s hash=%s: %w", enginePath, engineHashText, err)
	}

	return enginePath, nil
}
