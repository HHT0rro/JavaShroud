//go:build !windows

package main

import "context"

type blurApplyResult struct {
	mode    string
	warning string
}

func (a *App) applyWindowVisualEffects(_ context.Context, _ string) {
}

func applyWindowBlurEffect(hwnd uintptr) blurApplyResult {
	return blurApplyResult{warning: "apply window blur failed: native blur adapter is only available on Windows; fallback to Acrylic"}
}
