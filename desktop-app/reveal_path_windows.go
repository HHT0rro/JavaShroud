//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

func revealPathInFileManager(path string) error {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	cmd := exec.Command("explorer", "/select,", absolutePath)
	applyHiddenProcessWindow(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("explorer start failed: %w", err)
	}
	return nil
}
