//go:build !javashroud_embed_xenolith

package main

import "fmt"

func resolveEmbeddedXenolithCliPath() (string, error) {
	return "", fmt.Errorf("embedded xenolith cli is not enabled: buildTag=javashroud_embed_xenolith")
}
