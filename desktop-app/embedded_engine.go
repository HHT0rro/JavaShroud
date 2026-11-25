//go:build !javashroud_embed_engine

package main

import "fmt"

func resolveEmbeddedNativeEnginePath() (string, error) {
	return "", fmt.Errorf("embedded native engine is not enabled: buildTag=javashroud_embed_engine")
}
