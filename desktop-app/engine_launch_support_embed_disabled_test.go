//go:build !javashroud_embed_engine

package main

import (
	"strings"
	"testing"
)

func TestResolveNativeEnginePathChainsEmbeddedError(t *testing.T) {
	_, err := resolveNativeEnginePath()
	if err == nil {
		t.Fatal("resolveNativeEnginePath expected an error when the embedded engine is disabled")
	}
	if !strings.Contains(err.Error(), "embeddedError=") {
		t.Fatalf("expected embedded engine error to be chained into the resolution error, got: %v", err)
	}
}
