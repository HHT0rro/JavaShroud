package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadWriteTextFile(t *testing.T) {
	app := NewApp()
	configPath := filepath.Join(t.TempDir(), "javashroud-config.toml")
	content := "[meta]\nformat = \"javashroud-workbench\"\n"

	if err := app.WriteTextFile(configPath, content); err != nil {
		t.Fatalf("expected write to succeed, got %v", err)
	}

	readContent, err := app.ReadTextFile(configPath)
	if err != nil {
		t.Fatalf("expected read to succeed, got %v", err)
	}
	if readContent != content {
		t.Fatalf("expected read content %q, got %q", content, readContent)
	}
}

func TestReadWriteTextFile_RejectsEmptyPath(t *testing.T) {
	app := NewApp()

	if _, err := app.ReadTextFile("  "); err == nil || !strings.Contains(err.Error(), "path is empty") {
		t.Fatalf("expected empty read path error, got %v", err)
	}

	if err := app.WriteTextFile("  ", "content"); err == nil || !strings.Contains(err.Error(), "path is empty") {
		t.Fatalf("expected empty write path error, got %v", err)
	}
}

func TestReadTextFile_ReturnsMissingFileError(t *testing.T) {
	app := NewApp()
	missingPath := filepath.Join(t.TempDir(), "missing.toml")

	_, err := app.ReadTextFile(missingPath)
	if err == nil {
		t.Fatalf("expected missing file error")
	}
	if !strings.Contains(err.Error(), "read text file failed") {
		t.Fatalf("expected contextual read error, got %q", err.Error())
	}
	if !os.IsNotExist(err) && !strings.Contains(err.Error(), "cannot find") {
		t.Fatalf("expected not-exist detail, got %q", err.Error())
	}
}
