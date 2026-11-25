//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func revealPathInFileManager(path string) error {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("open", "-R", absolutePath)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("open start failed: %w", err)
		}
		return nil
	default:
		directory := absolutePath
		info, statErr := os.Stat(absolutePath)
		if statErr == nil && !info.IsDir() {
			directory = filepath.Dir(absolutePath)
		}
		cmd := exec.Command("xdg-open", directory)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("xdg-open start failed: %w", err)
		}
		return nil
	}
}
