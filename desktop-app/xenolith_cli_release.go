//go:build javashroud_embed_xenolith

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed embedded/xenolith.exe
var embeddedXenolithCli []byte

func resolveEmbeddedXenolithCliPath() (string, error) {
	if len(embeddedXenolithCli) == 0 {
		return "", fmt.Errorf("embedded xenolith cli is empty: resource=embedded/xenolith.exe")
	}

	cliHash := sha256.Sum256(embeddedXenolithCli)
	cliHashText := hex.EncodeToString(cliHash[:])
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve embedded xenolith cli cache failed: %w", err)
	}

	cliDir := filepath.Join(cacheRoot, "JavaShroud", "tools", "xenolith", cliHashText)
	cliPath := filepath.Join(cliDir, "xenolith.exe")
	if err = ensureEmbeddedBinaryAsset(cliDir, cliPath, embeddedXenolithCli); err != nil {
		return "", fmt.Errorf("extract embedded xenolith cli failed: path=%s hash=%s: %w", cliPath, cliHashText, err)
	}

	return cliPath, nil
}
