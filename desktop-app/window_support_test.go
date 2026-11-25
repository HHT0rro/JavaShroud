package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportReplacesOnlyARegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "workbench.toml")
	app := &App{}
	if err := app.WriteTextFile(target, "first"); err != nil {
		t.Fatal(err)
	}
	if err := app.WriteTextFile(target, "second"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "second" {
		t.Fatalf("exported file %q, error %v", got, err)
	}
	if err := app.WriteTextFile(dir, "must not replace the directory"); err == nil {
		t.Fatal("export should reject a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "workbench.toml" {
		t.Fatalf("unexpected files after export: %v, error %v", entries, err)
	}
}
