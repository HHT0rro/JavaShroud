//go:build javashroud_embed_xenolith

package main

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedXenolithExtractsAndProbesVersion(t *testing.T) {
	path, err := resolveEmbeddedXenolithCliPath()
	if err != nil {
		t.Fatalf("resolveEmbeddedXenolithCliPath failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("extracted xenolith cli missing: %v", err)
	}
	version, err := probeXenolithCliVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "xenolith ") {
		t.Fatalf("version probe returned %q", version)
	}
	t.Logf("extracted=%s version=%s", path, version)
}
